from Mobile.ForkFilingState import (
  FilingClaim,
  FilingState,
  FilingObservation,
  claim_filing,
  finish_filing,
  load_filing,
  filing_pending
)
from Mobile.Codec import mobile_read_u64
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, local_context, seal_local, open_local
from Storage.Records import store_updated_session
from Tests.Support import database_path, repeated, append

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn required(value :: Option<FilingClaim>) -> FilingClaim!String do
  case value do
    Some(claim) -> Ok(claim)
    None -> Err("missing filing claim")
  end
end

fn attempt(path :: String, now :: U64) -> Option<FilingClaim>!String do
  let key = platform_key()?
  claim_filing(path, key, repeated(1, 32)?, repeated(2, 32)?, 3, now)
end

fn binding_write_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let pending = filing_pending(wide("90")?)?
  for status in ["prepared", "settled"] do
    let path = database_path("filing-binding-write")?
    ensure_schema(path)?
    let claim = required(attempt(path, wide("1000")?)?)?
    let observation = %{pending |
      status: status,
      finder: repeated(7, 32)?,
      receipt_format: 2,
      receipt_binding: repeated(8, 32)?,
      units: if status == "settled" do
        wide("9223372036854775808")?
      else
        wide("0")?
      end,
      morse_units: if status == "settled" do
        wide("18446744073709551615")?
      else
        wide("0")?
      end
    }
    let before = load_blob(path, "fork-filing/v1")?
    for length in [0, 1, 31, 33] do
      let invalid = %{observation | receipt_binding: repeated(8, length)?}
      case finish_filing(path, key, claim, wide("1001")?, 0, invalid) do
        Err(error) -> assert(error == "invalid_filing_state")
        Ok(_) -> assert(false)
      end
      assert(Bytes.secure_equals(before, load_blob(path, "fork-filing/v1")?))
    end
    finish_filing(path, key, claim, wide("1002")?, 0, observation)?
    assert(load_filing(path, key, repeated(1, 32)?)?.observation == observation)
    File.delete(path)?
  end
  Ok(true)
end

test("prepared and settled MPR2 persist only with the supplied full receipt binding and reopen unchanged") do
  case binding_write_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("filing-state")?
  ensure_schema(path)?
  let scope = repeated(1, 32)?
  let first = required(attempt(path, wide("1000")?)?)?
  assert(attempt(path, wide("60999")?)? == None)
  # A crashed request consumes its first minute; retry receives a different token.
  let retry = required(attempt(path, wide("61000")?)?)?
  assert(!Bytes.secure_equals(first.token, retry.token))
  case finish_filing(path, key, first, wide("61001")?, 3, filing_pending(wide("80")?)?) do
    Err(error) -> assert(error == "filing_claim_superseded")
    Ok(_) -> assert(false)
  end
  finish_filing(path, key, retry, wide("61001")?, 2, filing_pending(wide("80")?)?)?
  let state = load_filing(path, key, scope)?
  assert(state.accepted == 2 && state.targets == 3 && state.tier == 2)
  assert(state.observation.context_slot == wide("80")?)
  assert(state.observation.receipt_format == 0 && state.observation.morse_units == wide("0")?)
  assert(state.next_attempt == wide("361000")?)
  # Endpoint rotation cannot reset the rate limit or authenticated context floor.
  assert(claim_filing(path, key, scope, repeated(3, 32)?, 2, wide("61002")?)? == None)
  let next = required(claim_filing(path, key, scope, repeated(2, 32)?, 3, wide("361000")?)?)?
  # A wake that crashes before completion cannot erase the last acknowledgment.
  assert(load_filing(path, key, scope)?.accepted == 2)
  assert(next.minimum_slot == wide("80")?)
  case finish_filing(path, key, next, wide("361001")?, 1, filing_pending(wide("79")?)?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let paid = FilingObservation {
    status: "settled",
    context_slot: wide("90")?,
    finder: repeated(7, 32)?,
    units: wide("18446744073709551615")?,
    morse_units: wide("0")?,
    receipt_format: 1,
    receipt_binding: Bytes.empty()
  }
  finish_filing(path, key, next, wide("361002")?, 1, paid)?
  assert(claim_filing(path, key, scope, repeated(4, 32)?, 8, wide("99999999")?)? == None)
  let terminal = load_filing(path, key, scope)?
  assert(terminal.observation.units == wide("18446744073709551615")?)
  assert(terminal.observation.receipt_format == 1 && terminal.observation.morse_units == wide("0")?)
  assert(Bytes.secure_equals(terminal.observation.finder, repeated(7, 32)?))
  assert(!Bytes.secure_equals(load_blob(path, "fork-filing/v1")?, repeated(7, 32)?))
  # A new judge/proof identity starts separately; stale completions cannot cross it.
  let other = required(claim_filing(path,
    key,
    repeated(9, 32)?,
    repeated(4, 32)?,
    0,
    wide("99999999")?)?)?
  case finish_filing(path, key, next, wide("99999999")?, 1, paid) do
    Err(error) -> assert(error == "filing_claim_superseded")
    Ok(_) -> assert(false)
  end
  case finish_filing(path, key, other, wide("1")?, 0, filing_pending(wide("0")?)?) do
    Err(error) -> assert(error == "invalid_filing_clock")
    Ok(_) -> assert(false)
  end
  File.delete(path)?
  Ok(true)
end

test("encrypted filing state preserves retry budgets, receipt finality and stale-completion fences") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn race_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("filing-race")?
  ensure_schema(path)?
  let results = Job.map([0, 1, 2, 3, 4, 5, 6, 7], fn(_) do attempt(path, wide("1000")?) end)
  let claims = for result in results do
    result??
  end
  assert(List.length(List.filter(claims, fn(value) do value != None end)) == 1)
  let before = load_blob(path, "fork-filing/v1")?
  case claim_filing(path,
    key,
    repeated(9, 32)?,
    repeated(2, 32)?,
    3,
    wide("18446744073709551615")?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(before, load_blob(path, "fork-filing/v1")?))
  store_updated_session(path, "fork-filing/v1", Bytes.from_utf8("corrupt"))?
  case attempt(path, wide("1000000")?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  File.delete(path)?
  Ok(true)
end

test("simultaneous filing wakes claim once and corruption or overflow cannot reset the budget") do
  case race_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

# Independent durable vectors use big-endian fields: next=361000, started=61000,
# checked=61001, tier=2, targets=3, accepted=2, context=90 and an in-flight token.
fn durable_fixture(magic :: String,
  status :: String,
  receipt :: String,
  finder :: String,
  binding :: String) -> Bytes!String do
  Bytes.from_hex(magic
    <> String.repeat("01", 32)
    <> String.repeat("02", 32)
    <> "0000000000058228000000000000ee48000000000000ee49020302"
    <> status
    <> "000000000000005a"
    <> receipt
    <> "00000010"
    <> String.repeat("06", 16)
    <> finder
    <> binding)
end

fn prepared_restart_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("filing-prepared-restart")?
  ensure_schema(path)?
  let bytes = durable_fixture("46465332",
    "04",
    "0000000000000000000000000000000002",
    "00000020" <> String.repeat("07", 32),
    "00000020" <> String.repeat("08", 32))?
  assert(Bytes.length(bytes) == 213)
  store_updated_session(path,
    "fork-filing/v1",
    seal_local(bytes, key, local_context("fork-filing/v1")?)?)?
  let state = load_filing(path, key, repeated(1, 32)?)?
  assert(state.observation.status == "prepared")
  assert(state.observation.units == wide("0")?)
  assert(state.observation.morse_units == wide("0")? && state.observation.receipt_format == 2)
  assert(Bytes.secure_equals(state.observation.finder, repeated(7, 32)?))
  assert(Bytes.secure_equals(state.observation.receipt_binding, repeated(8, 32)?))
  assert(state.accepted == 2 && state.tier == 2)
  assert(attempt(path, wide("360999")?)? == None)
  let claim = required(attempt(path, wide("361000")?)?)?
  assert(claim.minimum_slot == wide("90")?)
  let reserved = load_filing(path, key, repeated(1, 32)?)?
  assert(reserved.observation == state.observation && reserved.accepted == 2)
  assert(reserved.tier == 3 && reserved.next_attempt == wide("1261000")?)
  let before = load_blob(path, "fork-filing/v1")?
  case finish_filing(path, key, claim, wide("361001")?, 1, filing_pending(wide("89")?)?) do
    Err(error) -> assert(error == "filing_context_regressed")
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(before, load_blob(path, "fork-filing/v1")?))
  let prepared = %{state.observation | context_slot: wide("95")?}
  finish_filing(path, key, claim, wide("361002")?, 1, prepared)?
  assert(load_filing(path, key, repeated(1, 32)?)?.observation == prepared)
  # Rotation keeps the prepared context and budget, but resets relay acknowledgments.
  assert(claim_filing(path, key, repeated(1, 32)?, repeated(4, 32)?, 8, wide("1260999")?)? == None)
  let recheck = required(claim_filing(path,
    key,
    repeated(1, 32)?,
    repeated(4, 32)?,
    8,
    wide("1261000")?)?)?
  assert(recheck.minimum_slot == wide("95")?)
  assert(load_filing(path, key, repeated(1, 32)?)?.accepted == 0)
  case finish_filing(path, key, claim, wide("1261001")?, 1, prepared) do
    Err(error) -> assert(error == "filing_claim_superseded")
    Ok(_) -> assert(false)
  end
  let settled = %{prepared |
    status: "settled",
    context_slot: wide("100")?,
    units: wide("9223372036854775808")?,
    morse_units: wide("18446744073709551615")?
  }
  finish_filing(path, key, recheck, wide("1261002")?, 0, settled)?
  assert(load_filing(path, key, repeated(1, 32)?)?.observation == settled)
  assert(attempt(path, wide("18446744073709551615")?)? == None)
  File.delete(path)?
  Ok(true)
end

fn legacy_restart_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("filing-legacy-restart")?
  ensure_schema(path)?
  for code in 0..4 do
    let settled = code == 3
    let bytes = durable_fixture("46465331",
      List.get(["00", "01", "02", "03"], code),
      if settled do
        "ffffffffffffffff"
      else
        "0000000000000000"
      end,
      if settled do
        "00000020" <> String.repeat("07", 32)
      else
        "00000000"
      end,
      "")?
    let blob = seal_local(bytes, key, local_context("fork-filing/v1")?)?
    store_updated_session(path, "fork-filing/v1", blob)?
    let state = load_filing(path, key, repeated(1, 32)?)?
    assert(state.observation.status == List.get([
          "pending",
          "rpc_unavailable",
          "rpc_disagree",
          "settled"
        ],
        code))
    assert(state.observation.receipt_format == if settled do
        1
      else
        0
      end)
    assert(state.observation.morse_units == wide("0")?)
    assert(state.observation.receipt_binding == Bytes.empty())
    assert(state.observation.units == if settled do
        wide("18446744073709551615")?
      else
        wide("0")?
      end)
    assert(state.observation.context_slot == wide("90")?)
    assert(Bytes.secure_equals(state.observation.finder,
      if settled do
        repeated(7, 32)?
      else
        Bytes.empty()
      end))
    assert(Bytes.secure_equals(state.identity, repeated(1, 32)?))
    assert(Bytes.secure_equals(state.target_hash, repeated(2, 32)?))
    assert(Bytes.secure_equals(state.token, repeated(6, 16)?))
    assert(state.next_attempt == wide("361000")? && state.started_at == wide("61000")?)
    assert(state.checked_at == wide("61001")?
      && state.tier == 2
      && state.targets == 3
      && state.accepted == 2)
    assert(Bytes.secure_equals(blob, load_blob(path, "fork-filing/v1")?))
    assert(attempt(path, wide("360999")?)? == None)
    if settled do
      assert(attempt(path, wide("18446744073709551615")?)? == None)
    else
      # A worker claimed before the upgrade can finish after restart unchanged.
      let old_claim = FilingClaim {
        identity: state.identity,
        target_hash: state.target_hash,
        token: state.token,
        started_at: state.started_at,
        targets: state.targets,
        minimum_slot: state.observation.context_slot
      }
      finish_filing(path, key, old_claim, wide("61002")?, 1, state.observation)?
      let upgraded = load_filing(path, key, state.identity)?
      assert(upgraded.observation == state.observation && upgraded.accepted == 1)
      let plaintext = open_local(load_blob(path, "fork-filing/v1")?,
        key,
        local_context("fork-filing/v1")?)?
      assert(Bytes.secure_equals(Bytes.slice(plaintext, 0, 4)?, Bytes.from_utf8("FFS2")))
      assert(Bytes.get(plaintext, 95)? == code)
      assert(attempt(path, wide("360999")?)? == None)
      let retry = required(attempt(path, wide("361000")?)?)?
      assert(retry.minimum_slot == wide("90")?)
      assert(load_filing(path, key, state.identity)?.next_attempt == wide("1261000")?)
    end
  end
  File.delete(path)?
  Ok(true)
end

test("strict FFS1 recovery preserves all status indices, full units and in-flight upgrade claims") do
  case legacy_restart_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn observation_contract_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let zero = wide("0")?
  let maximum = wide("18446744073709551615")?
  let pending = filing_pending(wide("90")?)?
  let prepared = %{pending |
    status: "prepared",
    finder: repeated(7, 32)?,
    receipt_format: 2,
    receipt_binding: repeated(8, 32)?
  }
  let legacy = %{prepared | status: "settled", receipt_format: 1}
  let settled = %{prepared | status: "settled"}
  let observations = [
    pending,
    %{pending | status: "rpc_unavailable"},
    %{pending | status: "rpc_disagree"},
    prepared,
    legacy,
    %{legacy | units: maximum},
    %{legacy | receipt_binding: Bytes.empty()},
    settled,
    %{settled | units: maximum},
    %{settled | morse_units: maximum},
    %{settled | units: maximum, morse_units: maximum}
  ]
  let codes = [0, 1, 2, 4, 3, 3, 3, 3, 3, 3, 3]
  for index in 0..List.length(observations) do
    let observation = List.get(observations, index)
    let path = database_path("filing-receipt-format")?
    ensure_schema(path)?
    assert(load_filing(path, key, repeated(1, 32)?)?.observation == filing_pending(zero)?)
    let claim = required(attempt(path, wide("1000")?)?)?
    finish_filing(path, key, claim, wide("1001")?, 0, observation)?
    assert(load_filing(path, key, repeated(1, 32)?)?.observation == observation)
    let plaintext = open_local(load_blob(path, "fork-filing/v1")?,
      key,
      local_context("fork-filing/v1")?)?
    assert(Bytes.secure_equals(Bytes.slice(plaintext, 0, 4)?, Bytes.from_utf8("FFS2")))
    assert(Bytes.get(plaintext, 95)? == List.get(codes, index))
    assert(mobile_read_u64(Bytes.slice(plaintext, 104, 8)?)? == observation.units)
    assert(mobile_read_u64(Bytes.slice(plaintext, 112, 8)?)? == observation.morse_units)
    assert(Bytes.get(plaintext, 120)? == observation.receipt_format)
    File.delete(path)?
  end
  let invalid = [
    %{pending | receipt_format: 1},
    %{pending | receipt_format: 2},
    %{pending | units: maximum},
    %{pending | morse_units: maximum},
    %{pending | finder: prepared.finder},
    %{pending | receipt_binding: prepared.receipt_binding},
    %{pending | status: "rpc_unavailable", receipt_format: 2},
    %{pending | status: "rpc_disagree", morse_units: maximum},
    %{pending | status: "unknown"},
    %{prepared | receipt_format: 0},
    %{prepared | receipt_format: 1},
    %{prepared | receipt_format: 3},
    %{prepared | units: maximum},
    %{prepared | morse_units: maximum},
    %{prepared | finder: Bytes.empty()},
    %{prepared | finder: repeated(0, 32)?},
    %{prepared | finder: repeated(7, 31)?},
    %{prepared | finder: repeated(7, 33)?},
    %{settled | receipt_format: 0},
    %{settled | receipt_format: -1},
    %{settled | receipt_format: 3},
    %{legacy | morse_units: maximum},
    %{legacy | receipt_binding: repeated(8, 1)?},
    %{legacy | receipt_binding: repeated(8, 31)?},
    %{legacy | receipt_binding: repeated(8, 33)?},
    %{settled | finder: Bytes.empty()},
    %{settled | finder: repeated(0, 32)?}
  ]
  let path = database_path("filing-invalid-observation")?
  ensure_schema(path)?
  let claim = required(attempt(path, wide("1000")?)?)?
  let before = load_blob(path, "fork-filing/v1")?
  for observation in invalid do
    case finish_filing(path, key, claim, wide("1001")?, 0, observation) do
      Err(error) -> assert(error == "invalid_filing_state")
      Ok(_) -> assert(false)
    end
    assert(Bytes.secure_equals(before, load_blob(path, "fork-filing/v1")?))
  end
  # Rejections preserve the claim, not merely the previous display state.
  finish_filing(path, key, claim, wide("1002")?, 0, prepared)?
  assert(load_filing(path, key, repeated(1, 32)?)?.observation == prepared)
  File.delete(path)?
  Ok(true)
end

test("FFS2 receipt formats enforce prepared and missing invariants and preserve arbitrary U64 settlements") do
  case observation_contract_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn strict_decode_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("filing-strict-decode")?
  ensure_schema(path)?
  let zero = "0000000000000000"
  let finder = "00000020" <> String.repeat("07", 32)
  let binding = "00000020" <> String.repeat("08", 32)
  let old = durable_fixture("46465331", "03", "ffffffffffffffff", finder, "")?
  let prepared = durable_fixture("46465332", "04", zero <> zero <> "02", finder, binding)?
  let invalid = [
    durable_fixture("46465330", "03", zero, finder, "")?,
    durable_fixture("46465331", "04", zero, finder, "")?,
    durable_fixture("46465331", "ff", zero, "00000000", "")?,
    durable_fixture("46465331", "00", "ffffffffffffffff", "00000000", "")?,
    durable_fixture("46465331", "03", zero, "00000000", "")?,
    durable_fixture("46465331", "03", zero, "00000020" <> String.repeat("00", 32), "")?,
    append(old, Bytes.from_hex("00")?)?,
    append(old, Bytes.from_hex("00000000")?)?,
    append(old, Bytes.from_hex(binding)?)?,
    Bytes.slice(old, 0, Bytes.length(old) - 1)?,
    durable_fixture("46465332", "03", zero, finder, binding)?,
    durable_fixture("46465332", "05", zero <> zero <> "02", finder, binding)?,
    durable_fixture("46465332", "04", zero <> zero <> "01", finder, binding)?,
    durable_fixture("46465332", "04", "ffffffffffffffff" <> zero <> "02", finder, binding)?,
    durable_fixture("46465332", "04", zero <> "ffffffffffffffff02", finder, binding)?,
    durable_fixture("46465332",
      "04",
      zero <> zero <> "02",
      "00000020" <> String.repeat("00", 32),
      binding)?,
    durable_fixture("46465332", "00", zero <> zero <> "02", "00000000", binding)?,
    durable_fixture("46465332", "00", zero <> "ffffffffffffffff00", "00000000", "00000000")?,
    durable_fixture("46465332", "00", zero <> zero <> "00", "00000000", binding)?,
    durable_fixture("46465332", "03", zero <> "ffffffffffffffff01", finder, binding)?,
    durable_fixture("46465332",
      "03",
      zero <> zero <> "01",
      finder,
      "0000001f" <> String.repeat("08", 31))?,
    durable_fixture("46465332", "03", zero <> zero <> "00", finder, binding)?,
    durable_fixture("46465332", "03", zero <> zero <> "03", finder, binding)?,
    append(prepared, Bytes.from_hex("00")?)?,
    Bytes.slice(prepared, 0, Bytes.length(prepared) - 1)?
  ]
  for bytes in invalid do
    let blob = seal_local(bytes, key, local_context("fork-filing/v1")?)?
    store_updated_session(path, "fork-filing/v1", blob)?
    assert(Result.is_err(load_filing(path, key, repeated(1, 32)?)))
    assert(Result.is_err(attempt(path, wide("99999999")?)))
    assert(Bytes.secure_equals(blob, load_blob(path, "fork-filing/v1")?))
  end
  File.delete(path)?
  Ok(true)
end

test("authenticated malformed FFS1 and FFS2 records fail closed without resetting durable budgets") do
  case strict_decode_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("authenticated FFS2 prepared receipt survives restart and can be rechecked after its budget") do
  case prepared_restart_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn binding_decode_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("filing-binding-decode")?
  ensure_schema(path)?
  let zero = "0000000000000000"
  let finder = "00000020" <> String.repeat("07", 32)
  for status in ["04", "03"] do
    let unbound = durable_fixture("46465332", status, zero <> zero <> "02", finder, "")?
    let invalid = [
      unbound,
      append(unbound, Bytes.from_hex("00000000")?)?,
      append(unbound, Bytes.from_hex("0000001f" <> String.repeat("08", 31))?)?,
      append(unbound, Bytes.from_hex("00000021" <> String.repeat("08", 33))?)?,
      append(unbound, Bytes.from_hex("00000021" <> String.repeat("08", 32))?)?,
      append(unbound, Bytes.from_hex("00000020" <> String.repeat("08", 31))?)?,
      append(unbound, Bytes.from_hex("000000")?)?,
      append(unbound, Bytes.from_hex("00000020" <> String.repeat("08", 32) <> "00")?)?
    ]
    for bytes in invalid do
      let blob = seal_local(bytes, key, local_context("fork-filing/v1")?)?
      store_updated_session(path, "fork-filing/v1", blob)?
      assert(Result.is_err(load_filing(path, key, repeated(1, 32)?)))
      assert(Result.is_err(attempt(path, wide("99999999")?)))
      assert(Bytes.secure_equals(blob, load_blob(path, "fork-filing/v1")?))
    end
  end
  File.delete(path)?
  Ok(true)
end

test("FFS2 prepared and settled MPR2 reject missing, malformed and trailing receipt bindings") do
  case binding_decode_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
