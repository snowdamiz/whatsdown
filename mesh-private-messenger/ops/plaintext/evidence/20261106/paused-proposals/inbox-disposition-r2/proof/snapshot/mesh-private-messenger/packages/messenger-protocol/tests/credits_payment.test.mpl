from Credits.Payment import solana_pay_url
from Credits.Issuance import CreditQuote
from Solana.Address import find_program_address
from Solana.Read import pubkey, spl_token_program

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn quote() -> CreditQuote!String do
  let owner = bytes("22", 32)?
  let mint = bytes("44", 32)?
  let destination = find_program_address(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?,
    [owner, spl_token_program()?.bytes, mint])?.address.bytes
  Ok(CreditQuote {
    quote_id: bytes("11", 32)?,
    deposit_owner: owner,
    destination: destination,
    mint: mint,
    asset: 0,
    amount: U64.parse("5000000")?,
    purpose: 1,
    credits: 100,
    issued_at: U64.parse("1700000000")?,
    expires_at: U64.parse("1700000900")?,
    issuer_key_id: bytes("55", 32)?,
    batch_hash: bytes("88", 32)?
  })
end

fn proof() -> Bool!String do
  let value = quote()?
  let now = U64.parse("1700000001")?
  let recipient = Bytes.to_base58(value.deposit_owner)
  let suffix = "&reference="
    <> Bytes.to_base58(value.quote_id)
    <> "&label=Morse&message=100%20credits"
  assert(solana_pay_url(value, value.mint, 1, now)? == "solana:"
      <> recipient
      <> "?amount=5.000000&spl-token="
      <> Bytes.to_base58(value.mint)
      <> suffix)
  let sol = %{value |
    asset: 1,
    mint: bytes("00", 32)?,
    destination: value.deposit_owner,
    amount: U64.parse("1")?
  }
  assert(solana_pay_url(sol, value.mint, 1, now)? == "solana:"
      <> recipient
      <> "?amount=0.000000001"
      <> suffix)
  assert(solana_pay_url(%{sol | amount: U64.parse("18446744073709551615")?},
    value.mint,
    1,
    now)? == "solana:" <> recipient <> "?amount=18446744073.709551615" <> suffix)
  assert(Result.is_err(solana_pay_url(value, value.mint, 1, value.expires_at)))
  assert(Result.is_err(solana_pay_url(value, value.mint, 1, U64.parse("1699999999")?)))
  assert(Result.is_err(solana_pay_url(value, value.mint, 0, now)))
  assert(Result.is_err(solana_pay_url(value, bytes("66", 32)?, 1, now)))
  assert(Result.is_err(solana_pay_url(%{value | destination: bytes("77", 32)?},
    value.mint,
    1,
    now)))
  assert(Result.is_err(solana_pay_url(%{value | quote_id: value.deposit_owner},
    value.mint,
    1,
    now)))
  assert(Result.is_err(solana_pay_url(sol, bytes("00", 32)?, 1, now)))
  Ok(true)
end

test("external payment URLs preserve quote recipient reference and exact amounts with native pins") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
