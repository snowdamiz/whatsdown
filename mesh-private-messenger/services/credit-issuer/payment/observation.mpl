from Credits.Issuance import CreditQuote
from Payment.Verify import PaymentReceipt, observe_payment_transfer, check_payment_quote
from Solana.TransactionRead import FinalizedTransaction, get_finalized_transaction

pub struct CreditDepositObservation do
  quote_id :: Bytes
  asset :: Int
  mint :: Bytes
  deposit_owner :: Bytes
  destination :: Bytes
  payment :: PaymentReceipt
  wire_sha256 :: Bytes
  # 0 accepted amount; 1 positive underpayment; 2 unsupported excess.
  disposition :: Int
end

fn observation(value :: FinalizedTransaction,
  quote :: CreditQuote,
  pinned_mint :: Bytes,
  price_observed_at :: U64,
  now :: U64) -> CreditDepositObservation!String do
  let payment = observe_payment_transfer(value, quote, pinned_mint, price_observed_at, now)?
  let maximum = U128.divide(U128.multiply(U128.parse(U64.to_string(quote.amount))?,
      U128.parse("101")?)?,
    U128.parse("100")?)?
  let disposition = if U64.compare(payment.received_amount, quote.amount) < 0 do
    1
  else if U128.compare(U128.parse(U64.to_string(payment.received_amount))?, maximum) > 0 do
    2
  else
    0
  end
  Ok(CreditDepositObservation {
    quote_id: quote.quote_id,
    asset: quote.asset,
    mint: quote.mint,
    deposit_owner: quote.deposit_owner,
    destination: quote.destination,
    payment: payment,
    wire_sha256: Crypto.sha256(value.signed.wire),
    disposition: disposition
  })
end

# This fetches the configured chain proof itself. No HTTP caller supplies a
# Boolean, payer, amount, destination or transaction execution metadata.
pub fn observe_credit_deposit(client :: Int,
  url :: String,
  signature :: Bytes,
  id :: Int,
  quote :: CreditQuote,
  pinned_mint :: Bytes,
  price_observed_at :: U64,
  now :: U64) -> Option<CreditDepositObservation>!String do
  check_payment_quote(quote, pinned_mint, price_observed_at, now)?
  case get_finalized_transaction(client, url, signature, id, 10000, 262144)? do
    None -> Ok(None)
    Some(value) -> Ok(Some(observation(value, quote, pinned_mint, price_observed_at, now)?))
  end
end
