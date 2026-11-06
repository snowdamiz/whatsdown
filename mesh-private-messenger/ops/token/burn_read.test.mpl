from Transparency.TokenBurn import decode_token_burn_profile
from Transparency.TokenBurnRead import (
  TokenBurnReadPins,
  token_burn_read_keys,
  decode_token_burn_snapshot
)
from Transparency.TokenChain import decode_token_config
from Solana.Read import Pubkey, AccountInfo, AccountSlice, OptionalAccountSlicesAtSlot, pubkey

fn read_text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn read_fixture_account(root :: Json, name :: String) -> AccountSlice!String do
  let value = Json.object_get(root, name)?
  Ok(AccountSlice {
    space: U64.parse(read_text(value, "space")?)?,
    info: AccountInfo {
      owner: pubkey(read_text(value, "owner")?)?,
      data: Bytes.from_hex(read_text(value, "data_hex")?)?,
      lamports: U64.parse(read_text(value, "lamports")?)?,
      rent_epoch: U64.parse("0")?,
      executable: Json.as_bool(Json.object_get(value, "executable")?)?
    }
  })
end

fn replace_slice(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  value :: Option<AccountSlice>) -> OptionalAccountSlicesAtSlot do
  let accounts = for position in 0..List.length(snapshot.accounts) do
    if position == index do
      value
    else
      List.get(snapshot.accounts, position)
    end
  end
  %{snapshot | accounts: accounts}
end

fn read_actual_burns() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_BURN_FIXTURES_PATH", ""))?)?
  let entries = Json.object_get(root, "accounts")?
  let profile = decode_token_burn_profile(Bytes.from_hex(read_text(root, "profile_hex")?)?)?
  let config = decode_token_config(Bytes.from_hex(read_text(root, "config_hex")?)?)?
  let pins = TokenBurnReadPins {
    program: pubkey(read_text(root, "program")?)?,
    governance: config.governance,
    program_slot: U64.parse("0")?,
    usdc: profile.usdc,
    treasury: profile.treasury,
    factory: profile.factory
  }
  let epoch = U64.parse(read_text(Json.array_get(Json.object_get(root, "weeks")?, 3)?, "epoch")?)?
  let names = [
    "config",
    "morse",
    "profile",
    "usdc",
    "oracle",
    "clock",
    "jupiter",
    "jupiter_data",
    "raydium",
    "raydium_data",
    "pool",
    "factory",
    "vault0",
    "vault1",
    "observation",
    "week3",
    "week_vault3",
    "program",
    "program_data"
  ]
  let keys = token_burn_read_keys(pins, epoch)?
  assert(List.length(keys) == 19)
  let accounts = for position in 0..19 do
    let name = List.get(names, position)
    assert(List.get(keys, position) == pubkey(read_text(Json.object_get(entries, name)?,
        "address")?)?)
    Some(read_fixture_account(entries, name)?)
  end
  let snapshot = OptionalAccountSlicesAtSlot {
    slot: U64.parse(read_text(root, "context_slot")?)?,
    accounts: accounts
  }
  let state = decode_token_burn_snapshot(pins, epoch, snapshot.slot, snapshot)?
  assert(state.supply == U64.parse(read_text(root, "supply_after")?)?
    && state.code_current
    && state.spot == Some(U64.parse("2000000")?)
    && state.twap == Some(U64.parse("2000000")?)
    && state.remaining == U64.parse("0")?
    && state.vault_surplus == U64.parse("0")?)
  let week = case state.week do
    None -> return Err("missing_finalized_week")
    Some(value) -> value
  end
  assert(week.completion_mask == U64.parse("16777215")?)
  assert(Result.is_err(decode_token_burn_snapshot(pins,
    epoch,
    U64.add(snapshot.slot, U64.parse("1")?)?,
    snapshot)))
  for position in 0..19 do
    let account = read_fixture_account(entries, List.get(names, position))?
    let wrong_owner = %{account | info: %{account.info | owner: pins.governance}}
    assert(Result.is_err(decode_token_burn_snapshot(pins,
      epoch,
      snapshot.slot,
      replace_slice(snapshot, position, Some(wrong_owner)))))
    assert(Result.is_err(decode_token_burn_snapshot(pins,
      epoch,
      snapshot.slot,
      replace_slice(snapshot, position, Some(%{account | space: U64.parse("0")?})))))
  end
  let vault = read_fixture_account(entries, "week_vault3")?
  let fake_balance = Bytes.concat(Bytes.concat(Bytes.slice(vault.info.data, 0, 64)?,
      Bytes.write_uint_le("77", 8)?)?,
    Bytes.slice(vault.info.data, 72, 93)?)?
  let donation = decode_token_burn_snapshot(pins,
    epoch,
    snapshot.slot,
    replace_slice(snapshot, 16, Some(%{vault | info: %{vault.info | data: fake_balance}})))?
  assert(donation.vault_surplus == U64.parse("77")? && donation.remaining == U64.parse("0")?)
  let prefunded = decode_token_burn_snapshot(pins,
    epoch,
    snapshot.slot,
    replace_slice(replace_slice(snapshot,
        16,
        Some(%{vault | info: %{vault.info | data: fake_balance}})),
      15,
      None))?
  assert(prefunded.week == None
    && prefunded.remaining == U64.parse("0")?
    && prefunded.vault_surplus == U64.parse("77")?)
  let pd = read_fixture_account(entries, "jupiter_data")?
  let changed = Bytes.concat(Bytes.concat(Bytes.slice(pd.info.data, 0, 4)?,
      Bytes.write_uint_le("1", 8)?)?,
    Bytes.slice(pd.info.data, 12, Bytes.length(pd.info.data) - 12)?)?
  let paused = decode_token_burn_snapshot(pins,
    epoch,
    snapshot.slot,
    replace_slice(snapshot, 7, Some(%{pd | info: %{pd.info | data: changed}})))?
  assert(!paused.code_current && paused.week == state.week && paused.supply == state.supply)
  Ok(true)
end

test("Authenticated Mesh reader binds all actual burn state owners, addresses, slices, code pins and liabilities") do
  let result = read_actual_burns()
  case result do
    Err(reason) -> println(reason)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
