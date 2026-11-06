from Credits.Issuance import CreditQuote, encode_credit_quote
from Solana.Read import pubkey, spl_token_program
from Solana.Address import find_program_address

# Use decimal strings, never floating point, for the exact requested amount.
fn decimal_amount(amount :: U64, decimals :: Int) -> String do
  let digits = U64.to_string(amount)
  let padded = if String.length(digits) <= decimals do
    String.repeat("0", decimals + 1 - String.length(digits)) <> digits
  else
    digits
  end
  let split = String.length(padded) - decimals
  String.slice(padded, 0, split) <> "." <> String.slice(padded, split, String.length(padded))
end

# The quote must already belong to the native client's durable blind batch.
# Mint and purpose are native release pins, never fields from a UI request.
# Opening the URL is a user action; it does not prove payment or grant credits.
pub fn solana_pay_url(quote :: CreditQuote,
  pinned_mint :: Bytes,
  purpose :: Int,
  now :: U64) -> String!String do
  encode_credit_quote(quote)?
  if Bytes.length(pinned_mint) != 32
    || Bytes.to_hex(pinned_mint) == String.repeat("00", 32)
    || quote.purpose != purpose
    || U64.compare(now, quote.issued_at) < 0
    || U64.compare(now, quote.expires_at) >= 0
    || Bytes.secure_equals(quote.quote_id, quote.deposit_owner)
    || Bytes.secure_equals(quote.quote_id, quote.destination) do
    return Err("invalid_payment_quote")
  end
  if quote.asset == 0 do
    let associated = find_program_address(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?,
      [quote.deposit_owner, spl_token_program()?.bytes, pinned_mint])?.address.bytes
    if !Bytes.secure_equals(quote.mint, pinned_mint)
      || !Bytes.secure_equals(quote.destination, associated) do
      return Err("invalid_payment_mint_or_destination")
    end
  end
  # Solana Pay requires the owner as recipient; the external wallet derives its
  # canonical ATA from spl-token. The random quote reference is the only ID.
  let url = "solana:"
    <> Bytes.to_base58(quote.deposit_owner)
    <> "?amount="
    <> decimal_amount(quote.amount,
      if quote.asset == 0 do
        6
      else
        9
      end)
  let token = if quote.asset == 0 do
    "&spl-token=" <> Bytes.to_base58(quote.mint)
  else
    ""
  end
  Ok(url
    <> token
    <> "&reference="
    <> Bytes.to_base58(quote.quote_id)
    <> "&label=Morse&message="
    <> Int.to_string(quote.credits)
    <> "%20credits")
end
