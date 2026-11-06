from Transparency.TokenBurnExpiryRead import (
  token_burn_expiry_read_keys,
  decode_token_burn_expiry_snapshot
)
from Transparency.TokenBurnRead import TokenBurnReadPins
from Solana.Read import Pubkey, AccountInfo, AccountSlice, OptionalAccountSlicesAtSlot, pubkey

fn field(root :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(root, key)?)
end

fn replace(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  a :: Option<AccountSlice>) -> OptionalAccountSlicesAtSlot do
  %{snapshot |
    accounts: for at in 0..List.length(snapshot.accounts) do
      if at == index do
        a
      else
        List.get(snapshot.accounts, at)
      end
    end
  }
end

fn required(snapshot :: OptionalAccountSlicesAtSlot, index :: Int) -> AccountSlice!String do
  case List.get(snapshot.accounts, index) do
    None -> Err("missing_expiry_fixture")
    Some(value) -> Ok(value)
  end
end

fn proof() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_EXPIRY_FIXTURES_PATH",
    "ops/token-expiry/fixtures/tombstone.json"))?)?
  let rows = Json.object_get(root, "accounts")?
  let snapshot = OptionalAccountSlicesAtSlot {
    slot: U64.parse(field(root, "context_slot")?)?,
    accounts: for index in 0..Json.array_length(rows)? do
      let row = Json.array_get(rows, index)?
      Some(AccountSlice {
        space: U64.parse(field(row, "space")?)?,
        info: AccountInfo {
          owner: pubkey(field(row, "owner")?)?,
          data: Bytes.from_hex(field(row, "data_hex")?)?,
          lamports: U64.parse(field(row, "lamports")?)?,
          executable: Json.as_bool(Json.object_get(row, "executable")?)?,
          rent_epoch: U64.parse("0")?
        }
      })
    end
  }
  let pins = TokenBurnReadPins {
    program: pubkey(field(root, "program")?)?,
    governance: pubkey(field(root, "governance")?)?,
    usdc: pubkey(field(root, "usdc")?)?,
    treasury: pubkey(field(root, "treasury")?)?,
    factory: pubkey(field(root, "factory")?)?,
    program_slot: U64.parse(field(root, "program_slot")?)?
  }
  let epoch = U64.parse(field(root, "epoch")?)?
  let keys = token_burn_expiry_read_keys(pins, epoch)?
  assert(List.length(keys) == 9)
  for index in 0..9 do
    assert(List.get(keys, index) == pubkey(field(Json.array_get(rows, index)?, "address")?)?)
  end
  let state = decode_token_burn_expiry_snapshot(pins, epoch, snapshot.slot, snapshot)?
  assert(state.raw_frame == required(snapshot, 5)?.info.data
    && state.raw_receipt == required(snapshot, 6)?.info.data)
  assert(Option.is_some(state.frame) && Option.is_some(state.receipt))
  let absent = replace(replace(snapshot, 5, None), 6, None)
  let empty = decode_token_burn_expiry_snapshot(pins, epoch, snapshot.slot, absent)?
  assert(Option.is_none(empty.frame) && Option.is_none(empty.receipt))
  let prefunded = AccountSlice {
    space: U64.parse("0")?,
    info: AccountInfo {
      owner: pubkey("11111111111111111111111111111111")?,
      data: Bytes.empty(),
      lamports: U64.parse("77")?,
      executable: false,
      rent_epoch: U64.parse("0")?
    }
  }
  let donated = decode_token_burn_expiry_snapshot(pins,
    epoch,
    snapshot.slot,
    replace(replace(absent, 5, Some(prefunded)), 6, Some(prefunded)))?
  assert(donated.footprint == empty.footprint)
  assert(Result.is_err(decode_token_burn_expiry_snapshot(pins,
    epoch,
    snapshot.slot,
    replace(snapshot, 6, None))))
  assert(Result.is_err(decode_token_burn_expiry_snapshot(pins,
    epoch,
    snapshot.slot,
    replace(snapshot, 5, None))))
  assert(Result.is_err(decode_token_burn_expiry_snapshot(pins,
    epoch,
    U64.add(snapshot.slot, U64.parse("1")?)?,
    snapshot)))
  assert(Result.is_err(decode_token_burn_expiry_snapshot(%{pins | program_slot: U64.parse("1")?},
    epoch,
    snapshot.slot,
    snapshot)))
  for index in 0..9 do
    let a = required(snapshot, index)?
    let wrong = %{a | info: %{a.info | owner: pubkey("11111111111111111111111111111111")?}}
    assert(Result.is_err(decode_token_burn_expiry_snapshot(pins,
      epoch,
      snapshot.slot,
      replace(snapshot, index, Some(wrong)))))
    assert(Result.is_err(decode_token_burn_expiry_snapshot(pins,
      epoch,
      snapshot.slot,
      replace(snapshot, index, Some(%{a | info: %{a.info | lamports: U64.parse("0")?}})))))
  end
  let clock = required(snapshot, 4)?
  let future = Bytes.from_hex(Bytes.to_hex(Bytes.slice(clock.info.data, 0, 32)?)
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(U64.subtract(state.timestamp,
        U64.parse("1")?)?),
      8)?))?
  assert(Result.is_err(decode_token_burn_expiry_snapshot(pins,
    epoch,
    snapshot.slot,
    replace(snapshot, 4, Some(%{clock | info: %{clock.info | data: future}})))))
  IO.eprintln("MORSE_BURN_EXPIRY_BANK actual_sbf9_context_owners_pdas_mints_release_clock_canonical_absence_prefunding_and_exact_pair")
  Ok(true)
end

test("expiry reader authenticates complete nine-account bank and canonical absent or permanent terminal pair") do
  let result = proof()
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
