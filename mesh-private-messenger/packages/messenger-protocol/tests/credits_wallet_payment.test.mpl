from Credits.Issuance import CreditQuote
from Credits.WalletPayment import wallet_payment_instructions, authenticate_wallet_payment
from Solana.Read import Hash, Pubkey, pubkey, spl_token_program
from Solana.Address import find_program_address
from Solana.Tx import compile_legacy_message, serialize_legacy_message

fn repeated(value :: Int) -> Bytes!String do
  case Bytes.repeat(value, 32) do
    Err(_) -> Err("test bytes")
    Ok(output)
  end
end

fn proof() -> Bool!String do
  let key = case Crypto.signing_generate() do
    Err(_) -> return Err("test key")
    Ok(value) -> value
  end
  let payer = Pubkey { bytes: key.public_key.bytes }
  let mint = repeated(7)?
  let deposit = repeated(21)?
  let hash = repeated(4)?
  let token = spl_token_program()?
  let destination = find_program_address(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?,
    [deposit, token.bytes, mint])?.address.bytes
  for reference in [repeated(71)?, token.bytes, mint, payer.bytes] do
    let quote = CreditQuote {
      quote_id: reference,
      deposit_owner: deposit,
      destination: destination,
      mint: mint,
      asset: 0,
      amount: U64.parse("5000000")?,
      purpose: 1,
      credits: 100,
      issued_at: U64.parse("1000")?,
      expires_at: U64.parse("1900")?,
      issuer_key_id: repeated(8)?,
      batch_hash: repeated(9)?
    }
    let message = serialize_legacy_message(compile_legacy_message(payer,
      Hash { bytes: hash },
      wallet_payment_instructions(quote, payer)?)?)?
    let signature = case Crypto.sign(key.private_key, message) do
      Err(_) -> return Err("test sign")
      Ok(value) -> value
    end
    let wire = Bytes.concat(Bytes.concat(Bytes.from_hex("01")?, signature.bytes)?, message)?
    if Bytes.secure_equals(reference, repeated(71)?) do
      assert(Bytes.secure_equals(authenticate_wallet_payment(wire, quote, mint, 1, hash)?.signature,
        signature.bytes))
    else
      assert(Result.is_err(authenticate_wallet_payment(wire, quote, mint, 1, hash)))
    end
  end
  Ok(true)
end

test("signed wallet payment rejects reference aliases even with a valid payer signature") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
