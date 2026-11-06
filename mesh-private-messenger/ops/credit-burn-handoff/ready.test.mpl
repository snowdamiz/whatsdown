from Payment.TreasuryBurn import decode_treasury_burn_ready
from Transparency.TokenBurnRead import TokenBurnReadPins
from Solana.Read import Pubkey, AccountInfo, AccountSlice, OptionalAccountSlicesAtSlot, pubkey

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn owned(root :: Json) -> Option<AccountSlice>!String do
  if Result.is_ok(Json.object_get(root, "missing")) do
    return Ok(None)
  end
  Ok(Some(AccountSlice {
    space: U64.parse(field(root, "space")?)?,
    info: AccountInfo {
      owner: pubkey(field(root, "owner")?)?,
      data: Bytes.from_hex(field(root, "data_hex")?)?,
      lamports: U64.parse(field(root, "lamports")?)?,
      executable: Json.as_bool(Json.object_get(root, "executable")?)?,
      rent_epoch: U64.parse("0")?
    }
  }))
end

fn some(snapshot :: OptionalAccountSlicesAtSlot, index :: Int) -> AccountSlice!String do
  case List.get(snapshot.accounts, index) do
    None -> Err("missing_ready_account")
    Some(value) -> Ok(value)
  end
end

fn replace(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  account :: AccountSlice) -> OptionalAccountSlicesAtSlot do
  %{snapshot |
    accounts: for at in 0..List.length(snapshot.accounts) do
      if at == index do
        Some(account)
      else
        List.get(snapshot.accounts, at)
      end
    end
  }
end

fn proof() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_CREDIT_BURN_READY_FIXTURES_PATH",
    "ops/credit-burn-handoff/fixtures/ready-accounts.json"))?)?
  let raw = Json.object_get(root, "accounts")?
  let accounts = for index in 0..Json.array_length(raw)? do
    owned(Json.array_get(raw, index)?)?
  end
  let snapshot = OptionalAccountSlicesAtSlot {
    slot: U64.parse(field(root, "context_slot")?)?,
    accounts: accounts
  }
  let pins = TokenBurnReadPins {
    program: pubkey(field(root, "program")?)?,
    governance: pubkey(field(root, "governance")?)?,
    program_slot: U64.parse(field(root, "program_slot")?)?,
    usdc: pubkey(field(root, "usdc")?)?,
    treasury: pubkey(field(root, "treasury")?)?,
    factory: pubkey(field(root, "factory")?)?
  }
  let epoch = U64.parse(field(root, "epoch")?)?
  let now = U64.parse(Bytes.read_uint_le(some(snapshot, 5)?.info.data, 32, 8)?)?
  let state = decode_treasury_burn_ready(pins, epoch, snapshot.slot, now, snapshot)?
  assert(state.available_carry == U64.parse("230000000")?)
  assert(U64.compare(state.source_balance, U64.parse("120000000")?) >= 0)
  assert(state.profile_bytes == some(snapshot, 2)?.info.data)
  assert(Result.is_err(decode_treasury_burn_ready(pins,
    epoch,
    U64.add(snapshot.slot, U64.parse("1")?)?,
    now,
    snapshot)))
  assert(Result.is_err(decode_treasury_burn_ready(pins,
    epoch,
    snapshot.slot,
    U64.add(now, U64.parse("61")?)?,
    snapshot)))
  assert(Result.is_err(decode_treasury_burn_ready(pins,
    U64.add(epoch, U64.parse("2")?)?,
    snapshot.slot,
    now,
    snapshot)))
  let source = some(snapshot, 21)?
  let system = pubkey("11111111111111111111111111111111")?
  assert(Result.is_err(decode_treasury_burn_ready(pins,
    epoch,
    snapshot.slot,
    now,
    replace(snapshot, 21, %{source | info: %{source.info | owner: system}}))))
  let wrong_mint = Bytes.concat(pins.treasury.bytes, Bytes.slice(source.info.data, 32, 133)?)?
  assert(Result.is_err(decode_treasury_burn_ready(pins,
    epoch,
    snapshot.slot,
    now,
    replace(snapshot, 21, %{source | info: %{source.info | data: wrong_mint}}))))
  let donated = some(snapshot, 20)?
  let amount = U64.parse(Bytes.read_uint_le(donated.info.data, 64, 8)?)?
  let richer = Bytes.concat(Bytes.concat(Bytes.slice(donated.info.data, 0, 64)?,
      Bytes.write_uint_le(U64.to_string(U64.add(amount, U64.parse("5000000")?)?), 8)?)?,
    Bytes.slice(donated.info.data, 72, 93)?)?
  let donation = decode_treasury_burn_ready(pins,
    epoch,
    snapshot.slot,
    now,
    replace(snapshot, 20, %{donated | info: %{donated.info | data: richer}}))?
  assert(donation.available_carry == state.available_carry)
  IO.eprintln("MORSE_CREDIT_BURN_READY actual22role_sbf_bank_source_carry_donation_and_fresh_clock")
  Ok(true)
end

test("burn preparation authenticates the complete current22-account bank and excludes carry donations") do
  let result = proof()
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
