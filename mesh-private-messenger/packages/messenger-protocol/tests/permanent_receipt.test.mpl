from Transparency.PermanentReceipt import (
  PermanentReceiptPins,
  PermanentReceipt,
  permanent_receipt_keys,
  decode_permanent_receipt_snapshot,
  read_permanent_receipt
)
from Transparency.AnchorLog import decode_anchor_log
from Transparency.RpcTransport import RpcTransport, RpcEndpoint, RpcTls, webpki_rpc_transport
from Solana.Read import Pubkey, AccountInfo, AccountSlice, OptionalAccountSlicesAtSlot, pubkey

fn number(text :: String) -> U64!String do
  U64.parse(text)
end

fn text(row :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(row, key)?)
end

fn account(row :: Json, role :: String) -> AccountSlice!String do
  let value = Json.object_get(Json.object_get(row, "accounts")?, role)?
  Ok(AccountSlice {
    space: number(text(value, "space")?)?,
    info: AccountInfo {
      data: Bytes.from_hex(text(value, "data_hex")?)?,
      executable: Json.as_bool(Json.object_get(value, "executable")?)?,
      lamports: number(text(value, "lamports")?)?,
      owner: pubkey(text(value, "owner")?)?,
      rent_epoch: number("0")?
    }
  })
end

fn fixture(name :: String) -> (PermanentReceiptPins, Bytes, OptionalAccountSlicesAtSlot)!String do
  let path = Env.get("MORSE_PERMANENT_RECEIPT_FIXTURES_PATH", "")
  if path == "" do
    return Err("actual SBF fixtures required: MORSE_PERMANENT_RECEIPT_FIXTURES_PATH")
  end
  let raw = File.read(path)?
  if Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(raw))) != "448e6668036e6dd2184bc7a4fd60e2740545b1270ba070c59858c9bb7eb196b5" do
    return Err("frozen SBF fixture hash mismatch")
  end
  let rows = Json.object_get(Json.parse(raw)?, "snapshots")?
  for index in 0..Json.array_length(rows)? do
    let row = Json.array_get(rows, index)?
    if text(row, "name")? == name do
      let log = decode_anchor_log(account(row, "log")?.info.data)?
      let data = account(row, "judge_data")?
      let receipt = account(row, "proof")?
      let pins = PermanentReceiptPins {
        judge: pubkey(text(row, "program")?)?,
        token: pubkey(text(row, "token_program")?)?,
        log_name: text(row, "log_name")?,
        usdc: pubkey(text(Json.object_get(Json.object_get(row, "accounts")?, "usdc")?,
          "address")?)?,
        judge_slot: number(Bytes.read_uint_le(data.info.data, 4, 8)?)?,
        service_key: log.service_public_key,
        log_version: log.version
      }
      let hash = Bytes.slice(receipt.info.data, 40, 32)?
      let snapshot = OptionalAccountSlicesAtSlot {
        slot: number(text(row, "context_slot")?)?,
        accounts: [
          Some(account(row, "judge")?),
          Some(data),
          Some(account(row, "log")?),
          Some(receipt)
        ]
      }
      let keys = permanent_receipt_keys(pins, hash)?
      for pair in [(0, "judge"), (1, "judge_data"), (2, "log"), (3, "proof")] do
        let (at, role) = pair
        assert(List.get(keys, at) == pubkey(text(Json.object_get(Json.object_get(row, "accounts")?,
              role)?,
            "address")?)?)
      end
      return Ok((pins, hash, snapshot))
    end
  end
  Err("missing frozen SBF snapshot")
end

fn selected(snapshot :: OptionalAccountSlicesAtSlot, at :: Int) -> AccountSlice!String do
  case List.get(snapshot.accounts, at) do
    None -> Err("test account missing")
    Some(value) -> Ok(value)
  end
end

fn with_account(snapshot :: OptionalAccountSlicesAtSlot,
  at :: Int,
  account :: Option<AccountSlice>) -> OptionalAccountSlicesAtSlot do
  %{snapshot |
    accounts: for index in 0..List.length(snapshot.accounts) do
      if index == at do
        account
      else
        List.get(snapshot.accounts, index)
      end
    end
  }
end

fn replace(raw :: Bytes, at :: Int, value :: Bytes) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.slice(raw, 0, at)?, value)?,
    Bytes.slice(raw, at + Bytes.length(value), Bytes.length(raw) - at - Bytes.length(value))?)
end

fn with_bytes(snapshot :: OptionalAccountSlicesAtSlot,
  at :: Int,
  bytes :: Bytes) -> OptionalAccountSlicesAtSlot!String do
  let a = selected(snapshot, at)?
  Ok(with_account(snapshot, at, Some(%{a | info: %{a.info | data: bytes}})))
end

fn refused(pins :: PermanentReceiptPins, hash :: Bytes, snapshot :: OptionalAccountSlicesAtSlot) do
  assert(Result.is_err(decode_permanent_receipt_snapshot(pins, hash, snapshot.slot, snapshot)))
end

fn actual_snapshots() -> Bool!String do
  for name in ["mixed-proof-prepared", "mixed-proof-settled"] do
    let (pins, hash, snapshot) = fixture(name)?
    let state = decode_permanent_receipt_snapshot(pins, hash, snapshot.slot, snapshot)?
    assert(state.status == if name == "mixed-proof-prepared" do
        "prepared"
      else
        "settled"
      end)
    assert(state.address == List.get(permanent_receipt_keys(pins, hash)?, 3))
    assert(state.proof_hash == hash && state.context_slot == snapshot.slot)
    assert(Bytes.length(state.digest) == 32)
    case state.value do
      Some(MixedReceipt(r)) ->
        assert(r.settled == (name == "mixed-proof-settled"))
        assert(List.length(r.rows) == 2)
        assert(List.get(r.rows, 0).asset != List.get(r.rows, 1).asset)
        if r.settled do
          assert(U64.compare(r.usdc_slashed, number("0")?) > 0)
          assert(U64.compare(r.morse_slashed, number("0")?) > 0)
        end
      _ -> assert(false)
    end
    # The snapshot contains only permanent roles. No oracle, binding, bond,
    # registry, token code revision or rewards deployment is an authority.
    assert(List.length(snapshot.accounts) == 4)
    assert(Result.is_ok(decode_permanent_receipt_snapshot(pins, hash, number("0")?, snapshot)))
    for at in 0..4 do
      let a = selected(snapshot, at)?
      refused(pins,
        hash,
        with_account(snapshot, at, Some(%{a | info: %{a.info | owner: pins.usdc}})))
      refused(pins,
        hash,
        with_account(snapshot, at, Some(%{a | info: %{a.info | executable: !a.info.executable}})))
      refused(pins,
        hash,
        with_account(snapshot, at, Some(%{a | info: %{a.info | lamports: number("0")?}})))
      if at != 3 do
        refused(pins, hash, with_account(snapshot, at, None))
      end
    end
    refused(pins, hash, %{snapshot | accounts: List.take(snapshot.accounts, 3)})
    assert(Result.is_err(decode_permanent_receipt_snapshot(pins,
      hash,
      U64.add(snapshot.slot, number("1")?)?,
      snapshot)))
    refused(%{pins | judge_slot: U64.add(pins.judge_slot, number("1")?)?}, hash, snapshot)
    refused(%{pins | service_key: Bytes.from_hex(String.repeat("11", 32))?}, hash, snapshot)
    refused(%{pins | log_version: 3}, hash, snapshot)
    refused(%{pins | usdc: pins.judge}, hash, snapshot)
    refused(%{pins | token: pins.judge}, hash, snapshot)
    refused(pins, Bytes.from_hex(String.repeat("22", 32))?, snapshot)
    let image = selected(snapshot, 0)?
    for at in [0, 4] do
      refused(pins,
        hash,
        with_bytes(snapshot, 0, replace(image.info.data, at, Bytes.from_hex("ff")?)?)?)
    end
    let data = selected(snapshot, 1)?
    for size in ["44", "10485761", "45"] do
      refused(pins, hash, with_account(snapshot, 1, Some(%{data | space: number(size)?})))
    end
    for size in [44, 9217] do
      refused(pins, hash, with_bytes(snapshot, 1, Bytes.from_hex(String.repeat("00", size))?)?)
    end
    for at in [0, 12] do
      refused(pins,
        hash,
        with_bytes(snapshot, 1, replace(data.info.data, at, Bytes.from_hex("ff")?)?)?)
    end
    let future = U64.add(snapshot.slot, number("1")?)?
    refused(%{pins | judge_slot: future},
      hash,
      with_bytes(snapshot,
        1,
        replace(data.info.data, 4, Bytes.write_uint_le(U64.to_string(future), 8)?)?)?)
    # A retained loader header alone still authenticates the full allocation.
    assert(Result.is_ok(decode_permanent_receipt_snapshot(pins,
      hash,
      snapshot.slot,
      with_bytes(snapshot, 1, Bytes.slice(data.info.data, 0, 45)?)?)))
    assert(Result.is_ok(decode_permanent_receipt_snapshot(pins,
      hash,
      snapshot.slot,
      with_account(snapshot, 1, Some(%{data | space: number("10485760")?})))))
    let log = selected(snapshot, 2)?
    refused(pins, hash, with_account(snapshot, 2, Some(%{log | space: number("353")?})))
    for at in [0, 8, 40, 72] do
      refused(pins,
        hash,
        with_bytes(snapshot, 2, replace(log.info.data, at, Bytes.from_hex("ff")?)?)?)
    end
    let receipt = selected(snapshot, 3)?
    for at in [0, 8, 40, 136, 168, 392, 400, 432] do
      refused(pins,
        hash,
        with_bytes(snapshot, 3, replace(receipt.info.data, at, Bytes.from_hex("ff")?)?)?)
    end
    for mask in ["0", "1", "2", "17179869184", "18446744073709551615"] do
      refused(pins,
        hash,
        with_bytes(snapshot, 3, replace(receipt.info.data, 320, Bytes.write_uint_le(mask, 8)?)?)?)
    end
    let anchored = replace(receipt.info.data, 5, Bytes.from_hex("01")?)?
    refused(pins, hash, with_bytes(snapshot, 3, anchored)?)
    let anchored = replace(anchored, 320, Bytes.write_uint_le("61", 8)?)?
    assert(Result.is_ok(decode_permanent_receipt_snapshot(pins,
      hash,
      snapshot.slot,
      with_bytes(snapshot, 3, anchored)?)))
    refused(pins,
      hash,
      with_account(snapshot, 3, Some(%{receipt | space: U64.add(receipt.space, number("1")?)?})))
    # Every envelope field and the exact bank slot contributes to agreement.
    for at in 0..4 do
      let a = selected(snapshot, at)?
      for changed in [
        %{a | info: %{a.info | lamports: U64.add(a.info.lamports, number("1")?)?}},
        %{a | info: %{a.info | rent_epoch: number("1")?}}
      ] do
        let other = decode_permanent_receipt_snapshot(pins,
          hash,
          snapshot.slot,
          with_account(snapshot, at, Some(changed)))?
        assert(other.digest != state.digest)
      end
    end
    assert(decode_permanent_receipt_snapshot(pins,
      hash,
      snapshot.slot,
      %{snapshot | slot: future})?.digest != state.digest)
    assert(decode_permanent_receipt_snapshot(pins,
      hash,
      snapshot.slot,
      with_account(snapshot,
        1,
        Some(%{data | space: U64.add(data.space, number("1")?)?})))?.digest != state.digest)
    assert(decode_permanent_receipt_snapshot(pins,
      hash,
      snapshot.slot,
      with_bytes(snapshot,
        1,
        replace(data.info.data, 46, Bytes.from_hex("ff")?)?)?)?.digest != state.digest)
  end
  Ok(true)
end

fn absence() -> Bool!String do
  let (pins, hash, snapshot) = fixture("mixed-proof-settled")?
  let absent = decode_permanent_receipt_snapshot(pins,
    hash,
    snapshot.slot,
    with_account(snapshot, 3, None))?
  assert(absent.status == "missing" && absent.value == None)
  let empty = AccountSlice {
    space: number("0")?,
    info: AccountInfo {
      data: Bytes.empty(),
      owner: pubkey("11111111111111111111111111111111")?,
      executable: false,
      lamports: number("500")?,
      rent_epoch: number("0")?
    }
  }
  let prefunded = decode_permanent_receipt_snapshot(pins,
    hash,
    snapshot.slot,
    with_account(snapshot, 3, Some(empty)))?
  assert(prefunded.status == "missing"
    && prefunded.value == None
    && prefunded.digest != absent.digest)
  let other_hash = Bytes.from_hex(String.repeat("22", 32))?
  let other = decode_permanent_receipt_snapshot(pins,
    other_hash,
    snapshot.slot,
    with_account(snapshot, 3, None))?
  assert(other.address != absent.address && other.digest != absent.digest)
  for bad in [
    %{empty | space: number("1")?},
    %{empty | info: %{empty.info | owner: pins.judge}},
    %{empty | info: %{empty.info | owner: pins.usdc}},
    %{empty | info: %{empty.info | executable: true}},
    %{empty | info: %{empty.info | data: Bytes.from_hex("00")?}}
  ] do
    refused(pins, hash, with_account(snapshot, 3, Some(bad)))
  end
  # Absence cannot bypass code or immutable log authentication.
  refused(%{pins | judge_slot: U64.add(pins.judge_slot, number("1")?)?},
    hash,
    with_account(snapshot, 3, None))
  refused(%{pins | service_key: Bytes.from_hex(String.repeat("11", 32))?},
    hash,
    with_account(snapshot, 3, None))
  Ok(true)
end

fn legacy() -> Bool!String do
  let (pins, hash, snapshot) = fixture("mixed-proof-settled")?
  let raw = selected(snapshot, 3)?.info.data
  # A valid MPR1 directory-only receipt uses the same permanent PDA and mint.
  let parts = [
    Bytes.from_hex("4d50520103000000")?,
    Bytes.slice(raw, 8, 160)?,
    Bytes.slice(raw, 200, 64)?,
    Bytes.slice(raw, 384, 8)?,
    Bytes.write_uint_le("10", 8)?,
    Bytes.write_uint_le("1", 8)?,
    Bytes.write_uint_le("10", 8)?,
    Bytes.write_uint_le("3", 8)?,
    Bytes.from_hex(String.repeat("00", 16))?
  ]
  let bytes = List.reduce(parts,
    Ok(Bytes.empty()),
    fn(result, part) do Bytes.concat(result?, part) end)?
  let a = selected(snapshot, 3)?
  let old = with_account(snapshot,
    3,
    Some(%{a | space: number("288")?, info: %{a.info | data: bytes}}))
  let state = decode_permanent_receipt_snapshot(pins, hash, old.slot, old)?
  assert(state.status == "settled")
  case state.value do
    Some(LegacyReceipt(r)) -> assert(r.total_slashed == number("10")?
      && r.finder_amount == number("1")?)
    _ -> assert(false)
  end
  for at in [0, 7, 8, 40, 136, 272] do
    refused(pins, hash, with_bytes(old, 3, replace(bytes, at, Bytes.from_hex("ff")?)?)?)
  end
  for mask in ["0", "1", "2", "17179869184"] do
    refused(pins, hash, with_bytes(old, 3, replace(bytes, 264, Bytes.write_uint_le(mask, 8)?)?)?)
  end
  Ok(true)
end

fn local_rpc(mode :: String) -> RpcTransport!String do
  let origins = Env.get("MORSE_PERMANENT_RECEIPT_RPC_ORIGINS", "")
  if origins == "" do
    return Err("loopback RPC fixture required: run protocol/check.py")
  end
  webpki_rpc_transport(for origin in String.split(origins, ",") do
    origin <> "/" <> mode
  end)
end

fn reader_quorums() -> Bool!String do
  let (pins, hash, snapshot) = fixture("mixed-proof-prepared")?
  for mode in ["prepared", "third-invalid", "first-invalid", "rent-pair", "space-pair"] do
    let state = read_permanent_receipt(local_rpc(mode)?, pins, hash, snapshot.slot)?
    assert(state.status == "prepared" && state.context_slot == snapshot.slot)
  end
  let settled = read_permanent_receipt(local_rpc("settled")?, pins, hash, snapshot.slot)?
  assert(settled.status == "settled")
  for mode in [
    "slot-disagree",
    "data-disagree",
    "rent-disagree",
    "space-disagree",
    "two-good-disagree"
  ] do
    assert(read_permanent_receipt(local_rpc(mode)?,
      pins,
      hash,
      snapshot.slot) == Err("anchor_rpc_disagree"))
  end
  assert(read_permanent_receipt(local_rpc("one-good")?,
    pins,
    hash,
    snapshot.slot) == Err("anchor_rpc_unavailable"))
  assert(read_permanent_receipt(local_rpc("bad-owner")?,
    pins,
    hash,
    snapshot.slot) == Err("anchor_rpc_unavailable"))
  let valid = local_rpc("prepared")?
  let third = List.get(valid.sources, 2)
  let invalid = %{third | tls: OriginRoots("https://foreign.example", Bytes.from_utf8("invalid"))}
  let fatal_third = %{valid |
    sources: [List.get(valid.sources, 0), List.get(valid.sources, 1), invalid]
  }
  assert(read_permanent_receipt(fatal_third,
    pins,
    hash,
    snapshot.slot) == Err("rpc_tls_config_invalid"))
  let marker = Env.get("MORSE_PERMANENT_RECEIPT_RETIRED_PATH", "")
  if marker == "" do
    return Err("loopback current marker required")
  end
  File.write(marker, "current")?
  let retired = %{local_rpc("retire-third")? |
    require_current: fn() do
      if File.read(marker)? == "retired" do
        Err("retired")
      else
        Ok(nil)
      end
    end
  }
  assert(read_permanent_receipt(retired,
    pins,
    hash,
    snapshot.slot) == Err("rpc_context_changed:retired"))
  Ok(true)
end

fn reader_guards() -> Bool!String do
  let (pins, hash, snapshot) = fixture("mixed-proof-prepared")?
  let urls = ["http://127.0.0.1:1", "http://127.0.0.1:2", "http://127.0.0.1:3"]
  let base = webpki_rpc_transport(urls)?
  let stale = %{base | require_current: fn() do Err("retired") end}
  assert(read_permanent_receipt(stale,
    pins,
    hash,
    snapshot.slot) == Err("rpc_context_changed:retired"))
  let duplicate = webpki_rpc_transport([
    "https://same.example/a",
    "https://same.example/b",
    "https://third.example"
  ])?
  assert(read_permanent_receipt(duplicate,
    pins,
    hash,
    snapshot.slot) == Err("invalid_anchor_sources"))
  let endpoint = List.get(base.sources, 0)
  let invalid = %{endpoint |
    tls: OriginRoots("https://foreign.example", Bytes.from_utf8("invalid"))
  }
  let bad_tls = %{base | sources: [invalid, List.get(base.sources, 1), List.get(base.sources, 2)]}
  assert(read_permanent_receipt(bad_tls,
    pins,
    hash,
    snapshot.slot) == Err("rpc_tls_config_invalid"))
  Ok(true)
end

test("actual SBF MPR2 prepared and settled receipts authenticate only permanent roles") do
  case actual_snapshots() do
    Ok(value) -> assert(value)
    Err(error) ->
      println(error)
      assert(false)
  end
end

test("only null or a system owned empty zero allocation is absence") do
  case absence() do
    Ok(value) -> assert(value)
    Err(error) ->
      println(error)
      assert(false)
  end
end

test("permanent reader preserves current and TLS guards and independent sources") do
  case reader_guards() do
    Ok(value) -> assert(value)
    Err(error) ->
      println(error)
      assert(false)
  end
end

test("legacy MPR1 receipts retain strict identity and codec validation") do
  case legacy() do
    Ok(value) -> assert(value)
    Err(error) ->
      println(error)
      assert(false)
  end
end

test("loopback raw SBF quorums compare complete envelopes and preserve fatal third errors") do
  case reader_quorums() do
    Ok(value) -> assert(value)
    Err(error) ->
      println(error)
      assert(false)
  end
end
