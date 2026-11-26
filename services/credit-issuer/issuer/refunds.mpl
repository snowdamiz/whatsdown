##! Refunds (plan §6.11): an underpaid or late payment issues nothing and is
##! refunded on request to the payer, never automatically. `credit-issuer
##! refund <quote>` prints the plan; the operator repeats it with `--confirm
##! <quote>` to send. The whole deposit goes back (the fee payer pays the fee).
##! Lightning cannot underpay (LND settles only the full amount) and has no
##! refund path here.

from Issuer.Chain import (
  issuer_balance,
  issuer_close_token_account,
  issuer_send,
  issuer_sol_transfer,
  issuer_token_balance,
  issuer_usdc_transfer
)
from Issuer.Derivation import issuer_deposit_key, issuer_fee_payer_index
from Issuer.Settings import IssuerSettings

pub struct RefundPlan do
  quote_id :: Bytes
  asset :: String
  state :: String
  deposit_index :: Int
  deposit_address :: String
  deposit_account :: String
  destination :: String
  amount :: Int
end

fn text(value :: DbValue) -> String do
  case value do
    Text(output) -> output
    _ -> ""
  end
end

## What a refund of `quote_id` would send, from the chain as it is now.

pub fn issuer_refund_plan(pool :: PoolHandle,
  settings :: IssuerSettings,
  quote_id :: Bytes) -> RefundPlan!String do
  let rows = Pool.query_values(pool,
    "SELECT quote.asset, quote.state, quote.deposit_index::text AS deposit_index, quote.deposit_address, payment.deposit_account, CASE WHEN quote.asset = 'usdc' THEN payment.payer_account ELSE payment.payer END AS destination FROM quotes AS quote JOIN payments AS payment ON payment.quote_id = quote.quote_id WHERE quote.quote_id = $1",
    [Binary(quote_id)])?
  let row = case rows do
    [value] -> Ok(value)
    _ -> Err("no payment for this quote")
  end?
  let state = text(Map.get(row, "state"))
  let asset = text(Map.get(row, "asset"))
  if state != "underpaid" && state != "late" do
    return Err("only underpaid or late quotes are refunded (this one is #{state})")
  end
  if asset == "btc" || text(Map.get(row, "destination")) == "" do
    return Err("this payment has no refund destination")
  end
  let index = case String.to_int(text(Map.get(row, "deposit_index"))) do
    Some(value) -> Ok(value)
    None -> Err("invalid deposit index")
  end?
  let account = text(Map.get(row, "deposit_account"))
  let amount = if asset == "sol" do
    issuer_balance(settings.rpc_url, text(Map.get(row, "deposit_address")))?
  else
    issuer_token_balance(settings.rpc_url, account)?
  end
  Ok(RefundPlan {
    quote_id: quote_id,
    asset: asset,
    state: state,
    deposit_index: index,
    deposit_address: text(Map.get(row, "deposit_address")),
    deposit_account: account,
    destination: text(Map.get(row, "destination")),
    amount: amount
  })
end

pub fn issuer_refund_plan_json(plan :: RefundPlan) -> String do
  "{\"quote_id\":"
    <> Json.encode_string(Bytes.to_hex(plan.quote_id))
    <> ",\"asset\":"
    <> Json.encode_string(plan.asset)
    <> ",\"state\":"
    <> Json.encode_string(plan.state)
    <> ",\"from\":"
    <> Json.encode_string(plan.deposit_address)
    <> ",\"to\":"
    <> Json.encode_string(plan.destination)
    <> ",\"amount\":"
    <> Json.encode_string(Int.to_string(plan.amount))
    <> "}"
end

## Sends the refund when `confirmation` repeats the quote ID, and records it.
## Returns the refund transaction's signature.

pub fn issuer_refund(pool :: PoolHandle,
  settings :: IssuerSettings,
  quote_id :: Bytes,
  confirmation :: String) -> String!String do
  if confirmation != Bytes.to_hex(quote_id) do
    return Err("confirm the refund with --confirm #{Bytes.to_hex(quote_id)}")
  end
  let plan = issuer_refund_plan(pool, settings, quote_id)?
  if plan.amount <= 0 do
    return Err("the deposit is empty")
  end
  let fee_payer = issuer_deposit_key(settings.deposit_seed, issuer_fee_payer_index())?
  let deposit = issuer_deposit_key(settings.deposit_seed, plan.deposit_index)?
  let instructions = if plan.asset == "sol" do
    [issuer_sol_transfer(deposit.address, plan.destination, plan.amount)?]
  else
    [
      issuer_usdc_transfer(plan.deposit_account,
        settings.usdc_mint,
        plan.destination,
        deposit.address,
        plan.amount)?,
      issuer_close_token_account(plan.deposit_account, fee_payer.address, deposit.address)?
    ]
  end
  let signature = issuer_send(settings.rpc_url, fee_payer, [deposit], instructions)?
  Pool.execute_values(pool,
    "INSERT INTO refunds (quote_id, refund_signature, refunded_amount, destination) VALUES ($1, $2, $3::bigint, $4)",
    [Binary(quote_id), Text(signature), Text(Int.to_string(plan.amount)), Text(plan.destination)])?
  Pool.execute_values(pool,
    "UPDATE quotes SET state = 'refunded' WHERE quote_id = $1",
    [Binary(quote_id)])?
  Ok(signature)
end
