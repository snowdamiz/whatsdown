from CollateralReceipt import decode_public_collateral_receipt

fn bytes(value :: Json, key :: String) -> Bytes!String do
  Bytes.from_hex(Json.as_string(Json.object_get(value, key)?)?)
end

fn sample(root :: Json, name :: String) -> Bytes!String do
  let snapshots = Json.object_get(root, "snapshots")?
  for index in 0..Json.array_length(snapshots)? do
    let value = Json.array_get(snapshots, index)?
    if Json.as_string(Json.object_get(value, "name")?)? == name do
      return bytes(Json.object_get(Json.object_get(value, "accounts")?, "proof")?, "data_hex")
    end
  end
  Err("missing_actual_sbf_receipt")
end

fn replace(input :: Bytes, at :: Int, value :: Bytes) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.slice(input, 0, at)?, value)?,
    Bytes.slice(input, at + Bytes.length(value), Bytes.length(input) - at - Bytes.length(value))?)
end

fn byte(value :: Int) -> Bytes!String do
  Bytes.write_uint_le(Int.to_string(value), 1)
end

fn proof() -> Bool!String do
  let path = Env.get("MORSE_PUBLIC_COLLATERAL_FIXTURES_PATH", "")
  if path == "" do
    return Err("actual SBF collateral fixtures are required")
  end
  let root = Json.parse(File.read(path)?)?
  let prepared = sample(root, "mixed-proof-prepared")?
  let settled = sample(root, "mixed-proof-settled")?
  let pending = decode_public_collateral_receipt(prepared)?
  let paid = decode_public_collateral_receipt(settled)?
  assert(!pending.settled && paid.settled && List.length(paid.rows) == 2)
  assert(pending.proof_hash == paid.proof_hash)
  assert(paid.verified_signature_mask == U64.parse("63")?)
  assert(paid.verified_signatures == U64.parse("6")?)
  assert(pending.verified_signature_mask == paid.verified_signature_mask)
  assert(pending.verified_signatures == paid.verified_signatures)
  assert(paid.usdc_slashed == U64.parse("600000008")?)
  assert(paid.morse_slashed == U64.parse("133333358")?)
  assert(List.get(paid.rows, 0).asset == 0 && List.get(paid.rows, 1).asset == 1)
  for bad in [
    Bytes.slice(settled, 0, Bytes.length(settled) - 1)?,
    Bytes.concat(settled, byte(0)?)?,
    replace(settled, 3, byte(1)?)?,
    replace(settled, 4, byte(0)?)?,
    replace(settled, 6, byte(17)?)?,
    replace(settled, 7, byte(2)?)?,
    replace(settled, 377, byte(1)?)?,
    replace(settled, 496, byte(2)?)?,
    replace(settled, 497, byte(1)?)?,
    replace(settled, 536, byte(1)?)?,
    replace(settled, 544, Bytes.slice(settled, 400, 32)?)?,
    replace(settled, 280, Bytes.write_uint_le("18446744073709551615", 8)?)?,
    replace(settled, 528, Bytes.write_uint_le("0", 8)?)?,
    replace(prepared, 272, byte(1)?)?
  ] do
    assert(Result.is_err(decode_public_collateral_receipt(bad)))
  end
  Ok(true)
end

test("v2 receipt decodes exact mixed-asset SBF verdicts and rejects malformed totals and rows") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

from CollateralPins import (
  CollateralPins,
  CollateralSelection,
  collateral_bond_keys,
  collateral_receipt_keys
)
from Transparency.Merkle import WitnessKey
from Solana.Read import Pubkey, pubkey, get_multiple_accounts_slice_request

fn fixture_address(accounts :: Json, role :: String) -> Pubkey!String do
  pubkey(Json.as_string(Json.object_get(Json.object_get(accounts, role)?, "address")?)?)
end

fn maximum_selection() -> Bool!String do
  let path = Env.get("MORSE_PUBLIC_COLLATERAL_FIXTURES_PATH", "")
  if path == "" do
    return Err("actual SBF collateral fixtures are required")
  end
  let root = Json.parse(File.read(path)?)?
  let s = Json.array_get(Json.object_get(root, "snapshots")?, 1)?
  let a = Json.object_get(s, "accounts")?
  let pins = CollateralPins {
    token: fixture_address(a, "token")?,
    token_governance: fixture_address(a, "usdc")?,
    token_slot: U64.parse("0")?,
    usdc: fixture_address(a, "usdc")?,
    morse: fixture_address(a, "morse")?,
    judge: fixture_address(a, "judge")?,
    judge_slot: U64.parse("0")?,
    rewards: fixture_address(a, "rewards")?,
    rewards_slot: U64.parse("0")?,
    rewards_governance: fixture_address(a, "usdc")?,
    log_name: "custody-test",
    log_version: 1,
    service_key: Bytes.from_hex(String.repeat("11", 32))?,
    network_started: U64.parse("1")?
  }
  # Synthetic selected identifiers exercise canonical request bounds only.
  # They never form an accepted account, snapshot or monetary expectation.
  let witnesses = for index in 0..16 do
    WitnessKey {
      witness_id: "bounded-#{index}",
      public_key: Bytes.from_hex(String.repeat("11", 32))?
    }
  end
  let proofs = for index in 0..16 do
    Crypto.sha256(Bytes.from_utf8("bounded-proof-#{index}"))
  end
  let selected = CollateralSelection { pins: pins, witnesses: witnesses, proofs: proofs }
  let bonds = collateral_bond_keys(selected)?
  let receipts = collateral_receipt_keys(selected)?
  assert(List.length(bonds) == 98 && List.length(receipts) == 30)
  for keys in [bonds, receipts] do
    for index in 0..List.length(keys) do
      for prior in 0..index do
        assert(List.get(keys, index) != List.get(keys, prior))
      end
    end
    let request = get_multiple_accounts_slice_request(1,
      keys,
      "finalized",
      0,
      8416,
      Some(U64.parse("1")?))?
    assert(request.method == "getMultipleAccounts")
    let requested = Json.array_get(Json.parse(request.params_json)?, 0)?
    assert(Json.array_length(requested)? == List.length(keys))
  end
  Ok(true)
end

test("maximum explicit selections fit separate canonical finalized RPC batches") do
  case maximum_selection() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
