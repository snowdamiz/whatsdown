from Transparency.TokenCustody import (
  decode_token_collateral_bond,
  decode_token_collateral_economics,
  decode_token_collateral_pending,
  decode_token_collateral_binding,
  token_binding_address,
  token_pending_address
)
from Solana.Read import pubkey
from Transparency.AnchorBond import decode_anchor_economics, decode_anchor_bond

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn changed(bytes :: Bytes, at :: Int, value :: Bytes) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.slice(bytes, 0, at)?, value)?,
    Bytes.slice(bytes, at + Bytes.length(value), Bytes.length(bytes) - at - Bytes.length(value))?)
end

fn raw_account(accounts :: Json, name :: String) -> Bytes!String do
  Bytes.from_hex(field(Json.object_get(accounts, name)?, "data_hex")?)
end

fn address(accounts :: Json, name :: String) -> Bytes!String do
  Ok(pubkey(field(Json.object_get(accounts, name)?, "address")?)?.bytes)
end

fn actual_accounts() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_CUSTODY_FIXTURES_PATH", ""))?)?
  let snapshots = Json.object_get(root, "snapshots")?
  let checked = for index in 0..Json.array_length(snapshots)? do
    let snapshot = Json.array_get(snapshots, index)?
    let subjects = Json.object_get(snapshot, "subjects")?
    let accounts = Json.object_get(snapshot, "accounts")?
    let judge = pubkey(field(snapshot, "program")?)?
    let binding_raw = raw_account(accounts, "binding")?
    let binding = decode_token_collateral_binding(binding_raw)?
    let economics_raw = raw_account(accounts, "economics")?
    let economics = decode_token_collateral_economics(economics_raw)?
    assert(Result.is_err(decode_anchor_economics(economics_raw)))
    assert(binding.log == address(accounts, "log")? && binding.log_id == economics.log_id)
    assert(binding.token_program == pubkey(field(snapshot, "token_program")?)?.bytes)
    assert(binding.rewards_program == pubkey(field(snapshot, "rewards_program")?)?.bytes)
    assert(binding.config == address(accounts, "token_config")?
      && binding.mint == address(accounts, "morse")?)
    assert(economics.usdc_mint == address(accounts, "usdc")? && economics.usdc_mint != binding.mint)
    assert(token_binding_address(judge, economics.log_id)?.bytes == address(accounts, "binding")?)
    assert(Result.is_err(decode_token_collateral_binding(changed(binding_raw,
      308,
      Bytes.from_hex("01")?)?)))
    assert(Result.is_err(decode_token_collateral_economics(changed(economics_raw,
      166,
      Bytes.from_hex("01")?)?)))
    assert(Result.is_err(decode_token_collateral_economics(changed(economics_raw,
      3,
      Bytes.from_hex("01")?)?)))
    for row in 0..Json.array_length(subjects)? do
      let subject = Json.array_get(subjects, row)?
      let account = Json.object_get(accounts, "bond" <> Int.to_string(row))?
      let raw = Bytes.from_hex(field(account, "data_hex")?)?
      if Bytes.get(raw, 3)? == 2 do
        let bond = decode_token_collateral_bond(raw)?
        assert(Result.is_err(decode_anchor_bond(raw)))
        assert(bond.principal == U64.parse(field(subject, "principal")?)?)
        assert(bond.bonded_at == U64.parse(field(subject, "bonded_at")?)?)
        assert(bond.underwater_since == U64.parse(field(subject, "underwater_since")?)?)
        assert(bond.log_id == economics.log_id)
        assert(bond.witness_address == address(accounts, "witness" <> Int.to_string(row))?)
        assert(bond.mint == if bond.asset == 0 do
            economics.usdc_mint
          else
            binding.mint
          end)
        let pending = decode_token_collateral_pending(raw_account(accounts,
          "pending" <> Int.to_string(row))?)?
        assert(pending.bond == address(accounts, "bond" <> Int.to_string(row))?
          && pending.mint == bond.mint)
        assert(pending.amount == U64.parse(field(subject, "pending_recorded")?)?
          && pending.target_usd == U64.parse(field(subject, "target")?)?)
        assert(token_pending_address(judge,
          pubkey(field(account, "address")?)?)?.bytes == address(accounts,
            "pending" <> Int.to_string(row))?)
        assert(Result.is_err(decode_token_collateral_bond(changed(raw, 7, Bytes.from_hex("01")?)?)))
        assert(Result.is_err(decode_token_collateral_bond(changed(raw,
          176,
          Bytes.from_hex("ffffffffffffffff")?)?)))
        assert(Result.is_err(decode_token_collateral_bond(changed(raw, 3, Bytes.from_hex("01")?)?)))
        let bad_principal = if bond.status == 1 || bond.status == 2 do
          "0"
        else
          "1"
        end
        assert(Result.is_err(decode_token_collateral_bond(changed(raw,
          168,
          Bytes.write_uint_le(bad_principal, 8)?)?)))
        1
      else
        0
      end
    end
  end
  assert(List.reduce(List.flatten(checked), 0, fn(total, count) do total + count end) >= 10)
  Ok(true)
end

test("strict token collateral units replay actual SBF lifetimes") do
  assert(actual_accounts() == Ok(true))
end
