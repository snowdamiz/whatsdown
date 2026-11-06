from Receipt import decode_receipt_snapshot
from Tests.RelayMpr2Fixture import fixture_receipt

fn permanent_receipt() -> Bool!String do
  let (pins, hash, snapshot) = fixture_receipt("mixed-proof-settled")?
  let state = decode_receipt_snapshot(pins, hash, snapshot.slot, snapshot)?
  Ok(state.status == "settled")
end

test("permanent MPR2 receipt authenticates without current source or bonds") do
  case permanent_receipt() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

from Receipt import receipt_report, receipt_quorum
from Solana.Read import OptionalAccountSlicesAtSlot, pubkey

fn negatives() -> Bool!String do
  let (pins, hash, snapshot) = fixture_receipt("mixed-proof-prepared")?
  let state = decode_receipt_snapshot(pins, hash, snapshot.slot, snapshot)?
  assert(state.status == "prepared")
  let report = Json.parse(receipt_report(state))?
  let receipt = Json.object_get(report, "receipt")?
  assert(Json.as_string(Json.object_get(receipt, "status")?)? == "prepared")
  assert(Json.as_string(Json.object_get(receipt, "usdc_finder_units")?)? == "0")
  assert(Json.as_string(Json.object_get(receipt, "morse_finder_units")?)? == "0")
  assert(Result.is_err(decode_receipt_snapshot(pins,
    hash,
    U64.add(snapshot.slot, U64.parse("1")?)?,
    snapshot)))
  assert(Result.is_err(decode_receipt_snapshot(pins,
    Bytes.from_hex(String.repeat("ab", 32))?,
    snapshot.slot,
    snapshot)))
  assert(Result.is_err(decode_receipt_snapshot(%{pins | judge_slot: U64.parse("9")?},
    hash,
    snapshot.slot,
    snapshot)))
  let original = case List.get(snapshot.accounts, 3) do
    None -> return Err("fixture receipt missing")
    Some(value) -> value
  end
  for bad in [
    %{original | info: %{original.info | executable: true}},
    %{original | info: %{original.info | owner: pubkey("11111111111111111111111111111111")?}},
    %{original | info: %{original.info | lamports: U64.parse("0")?}},
    %{original | space: U64.parse("400")?}
  ] do
    assert(Result.is_err(decode_receipt_snapshot(pins,
      hash,
      snapshot.slot,
      %{snapshot | accounts: List.take(snapshot.accounts, 3) ++ [Some(bad)]})))
  end
  let missing = decode_receipt_snapshot(pins,
    hash,
    snapshot.slot,
    %{snapshot | accounts: List.take(snapshot.accounts, 3) ++ [None]})?
  assert(missing.status == "missing")
  let prefunded = %{original |
    space: U64.parse("0")?,
    info: %{original.info | owner: pubkey("11111111111111111111111111111111")?, data: Bytes.empty()}
  }
  assert(decode_receipt_snapshot(pins,
    hash,
    snapshot.slot,
    %{snapshot |
      accounts: List.take(snapshot.accounts, 3) ++ [Some(prefunded)]
    })?.status == "missing")
  assert(Result.is_err(receipt_quorum(Ok(state), Ok(missing), Err("offline"))))
  assert(receipt_quorum(Ok(state), Err("offline"), Ok(state))?.status == "prepared")
  Ok(true)
end

test("prepared is unpaid and receipt identity failures never become absence") do
  case negatives() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn legacy_compatibility() -> Bool!String do
  let (pins, hash, snapshot) = fixture_receipt("legacy-settled")?
  let state = decode_receipt_snapshot(pins, hash, snapshot.slot, snapshot)?
  let report = Json.parse(receipt_report(state))?
  let receipt = Json.object_get(report, "receipt")?
  assert(state.status == "settled")
  assert(Json.as_int(Json.object_get(receipt, "schema_version")?)? == 1)
  assert(Json.as_string(Json.object_get(receipt,
    "mint")?)? == "1117mWrzzrZr312ebPDHu8tbfMwFNvCvMbr6WepCNG")
  assert(Result.is_err(Json.object_get(receipt, "morse_mint")))
  Ok(true)
end

test("MPR1 at the same pay-once PDA retains its original immutable report") do
  case legacy_compatibility() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
