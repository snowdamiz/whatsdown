from Payment.SolConversionPacket import SolConversionProfile
from Payment.SolConversionBank import admit_sol_conversion_bank, sol_conversion_bank_keys
from Solana.Read import Pubkey, AccountInfo, OptionalAccountsAtSlot, pubkey, account_info

fn text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn key(root :: Json, name :: String) -> Pubkey!String do
  pubkey(text(root, name)?)
end

fn load_profile(root :: Json) -> SolConversionProfile!String do
  Ok(SolConversionProfile {
    treasury_config: Bytes.from_hex(text(root, "treasury_config")?)?,
    owner: key(root, "owner")?,
    payer: key(root, "payer")?,
    usdc: key(root, "usdc")?,
    pool: key(root, "pool")?,
    amm_config: key(root, "amm_config")?,
    authority: key(root, "authority")?,
    input_vault: key(root, "input_vault")?,
    output_vault: key(root, "output_vault")?,
    observation: key(root, "observation")?,
    oracle: key(root, "oracle")?,
    raydium_code: Bytes.from_hex(text(root, "raydium_code")?)?,
    token_code: Bytes.from_hex(text(root, "token_code")?)?,
    amm_hash: Bytes.from_hex(text(root, "amm_hash")?)?,
    rent: U64.parse(text(root, "rent")?)?,
    maximum_fee: U64.parse("100000")?
  })
end

fn replace(bank :: OptionalAccountsAtSlot,
  at :: Int,
  account :: Option<AccountInfo>) -> OptionalAccountsAtSlot do
  %{bank |
    accounts: for index in 0..List.length(bank.accounts) do
      if index == at do
        account
      else
        List.get(bank.accounts, index)
      end
    end
  }
end

fn required(bank :: OptionalAccountsAtSlot, at :: Int) -> AccountInfo!String do
  case List.get(bank.accounts, at) do
    Some(value) -> Ok(value)
    None -> Err("fixture_missing")
  end
end

fn cases() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_BANK", ""))?)?
  let p = load_profile(root)?
  let id = Bytes.from_hex(text(root, "id")?)?
  let raw_rows = Json.object_get(root, "accounts")?
  let rows = for index in 0..Json.array_length(raw_rows)? do
    Json.array_get(raw_rows, index)?
  end
  let accounts = for address in sol_conversion_bank_keys(p, id)? do
    let selected = List.filter(rows,
      fn(row) do text(row, "address") == Ok(Bytes.to_base58(address.bytes)) end)
    if List.length(selected) != 1 do
      return Err("fixture_snapshot_key_missing")
    end
    let raw = Json.object_get(List.head(selected), "account")?
    if Json.encode(raw) == "null" do
      None
    else
      Some(account_info(Json.encode(raw))?)
    end
  end
  let bank = OptionalAccountsAtSlot { slot: U64.parse(text(root, "slot")?)?, accounts: accounts }
  let admitted = admit_sol_conversion_bank(p, id, bank)?
  assert(admitted.now == U64.parse(text(root, "now")?)?)
  assert(admitted.usd_micros == U64.parse("150000000")?)
  assert(Result.is_err(admit_sol_conversion_bank(p,
    id,
    %{bank | slot: U64.add(bank.slot, U64.parse("1")?)?})))
  assert(Result.is_err(admit_sol_conversion_bank(p,
    id,
    replace(bank, 14, Some(required(bank, 0)?)))))
  assert(Result.is_err(admit_sol_conversion_bank(p,
    id,
    replace(bank, 4, Some(%{required(bank, 4)? | executable: false})))))
  assert(Result.is_err(admit_sol_conversion_bank(p,
    id,
    replace(bank, 10, Some(required(bank, 11)?)))))
  assert(Result.is_err(admit_sol_conversion_bank(p,
    id,
    replace(bank, 2, Some(%{required(bank, 2)? | executable: true})))))
  assert(Result.is_err(admit_sol_conversion_bank(p,
    id,
    %{bank | accounts: List.take(bank.accounts, 16)})))
  Ok(true)
end

test("actual SBF bank admits only exact code, oracle, custody and absent intent escrow") do
  assert(cases() == Ok(true))
end
