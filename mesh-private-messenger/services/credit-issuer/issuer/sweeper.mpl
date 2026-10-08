##! The sweeper (plan §6.11): moves issued quotes' deposits to the treasury in
##! batches, each deposit only after its own random delay (set at issuance,
##! MORSE_CREDIT_SWEEP_MIN/MAX_DELAY_S), in random order. The fee payer
##! (m/44'/501'/2147483645'/0') pays every fee and collects the rent of the
##! emptied USDC deposit accounts. Sweeps are public, like any transfer.
##! Underpaid and late deposits are never swept: they wait for a refund.

from Issuer.Chain import (
  issuer_balance,
  issuer_close_token_account,
  issuer_send,
  issuer_signature_status,
  issuer_sol_transfer,
  issuer_token_balance,
  issuer_usdc_transfer
)
from Issuer.Derivation import DepositKey, issuer_deposit_key, issuer_fee_payer_index
from Issuer.Settings import IssuerSettings
from Solana.Tx import Instruction

pub struct SweepRun do
  sent :: Int
  finalized :: Int
  retried :: Int
end

struct Due do
  quote_id :: Bytes
  deposit_index :: Int
  deposit_account :: String
end

fn text(value :: DbValue) -> String do
  case value do
    Text(output) -> output
    _ -> ""
  end
end

fn binary(value :: DbValue) -> Bytes do
  case value do
    Binary(output) -> output
    _ -> Bytes.empty()
  end
end

fn due(pool :: PoolHandle, asset :: String, limit :: Int) -> List<Due>!String do
  let rows = Pool.query_values(pool,
    "SELECT quote.quote_id, quote.deposit_index::text AS deposit_index, COALESCE(payment.deposit_account, quote.deposit_address) AS deposit_account FROM quotes AS quote JOIN payments AS payment ON payment.quote_id = quote.quote_id WHERE quote.state = 'issued' AND quote.asset = $1 AND quote.sweep_after <= now() AND quote.sweep_signature IS NULL AND quote.swept_at IS NULL ORDER BY random() LIMIT $2::integer",
    [Text(asset), Text(Int.to_string(limit))])?
  let values = for row in rows do
    due_row(row)?
  end
  Ok(values)
end

fn due_row(row :: Map<String, DbValue>) -> Due!String do
  let index = case String.to_int(text(Map.get(row, "deposit_index"))) do
    Some(value) -> Ok(value)
    None -> Err("invalid deposit index")
  end?
  Ok(Due {
    quote_id: binary(Map.get(row, "quote_id")),
    deposit_index: index,
    deposit_account: text(Map.get(row, "deposit_account"))
  })
end

fn sol_move(settings :: IssuerSettings, key :: DepositKey) -> List<Instruction>!String do
  let balance = issuer_balance(settings.rpc_url, key.address)?
  if balance > 0 do
    Ok([issuer_sol_transfer(key.address, settings.treasury_address, balance)?])
  else
    Ok([])
  end
end

fn sol_instructions(settings :: IssuerSettings,
  keys :: List<DepositKey>) -> List<Instruction>!String do
  let transfers = for key in keys do
    sol_move(settings, key)?
  end
  Ok(List.flatten(transfers))
end

fn usdc_move(settings :: IssuerSettings,
  fee_payer :: DepositKey,
  key :: DepositKey,
  account :: String) -> List<Instruction>!String do
  let amount = issuer_token_balance(settings.rpc_url, account)?
  let close = issuer_close_token_account(account, fee_payer.address, key.address)?
  if amount > 0 do
    Ok([
      issuer_usdc_transfer(account,
        settings.usdc_mint,
        settings.treasury_usdc_account,
        key.address,
        amount)?,
      close
    ])
  else
    Ok([close])
  end
end

fn usdc_instructions(settings :: IssuerSettings,
  fee_payer :: DepositKey,
  keys :: List<DepositKey>,
  accounts :: List<String>) -> List<Instruction>!String do
  let moves = for index in 0..List.length(keys) do
    usdc_move(settings, fee_payer, List.get(keys, index), List.get(accounts, index))?
  end
  Ok(List.flatten(moves))
end

fn mark_sent(pool :: PoolHandle,
  asset :: String,
  deposits :: List<Due>,
  signature :: String) -> Result<(), String> do
  Pool.execute_values(pool,
    "INSERT INTO sweeps (sweep_signature, asset, deposits) VALUES ($1, $2, $3::integer)",
    [Text(signature), Text(asset), Text(Int.to_string(List.length(deposits)))])?
  for deposit in deposits do
    Pool.execute_values(pool,
      "UPDATE quotes SET sweep_signature = $2 WHERE quote_id = $1",
      [Binary(deposit.quote_id), Text(signature)])?
  end
  Ok(nil)
end

fn mark_empty(pool :: PoolHandle, deposits :: List<Due>) -> Result<(), String> do
  for deposit in deposits do
    Pool.execute_values(pool,
      "UPDATE quotes SET swept_at = now() WHERE quote_id = $1",
      [Binary(deposit.quote_id)])?
  end
  Ok(nil)
end

fn sweep_batch(pool :: PoolHandle,
  settings :: IssuerSettings,
  asset :: String,
  limit :: Int) -> Int!String do
  let deposits = due(pool, asset, limit)?
  if List.length(deposits) == 0 do
    return Ok(0)
  end
  let fee_payer = issuer_deposit_key(settings.deposit_seed, issuer_fee_payer_index())?
  let keys = for deposit in deposits do
    issuer_deposit_key(settings.deposit_seed, deposit.deposit_index)?
  end
  let instructions = if asset == "sol" do
    sol_instructions(settings, keys)?
  else
    usdc_instructions(settings,
      fee_payer,
      keys,
      List.map(deposits, fn deposit -> deposit.deposit_account end))?
  end
  if List.length(instructions) == 0 do
    mark_empty(pool, deposits)?
    Ok(0)
  else
    mark_sent(pool, asset, deposits, issuer_send(settings.rpc_url, fee_payer, keys, instructions)?)?
    Ok(List.length(deposits))
  end
end

# A sent sweep either finalizes (its deposits are swept) or, failed or still
# unknown three minutes on (its blockhash has expired), is released to be
# swept again.

fn confirm_one(pool :: PoolHandle,
  settings :: IssuerSettings,
  row :: Map<String, DbValue>) -> (Int, Int)!String do
  let signature = text(Map.get(row, "sweep_signature"))
  let status = issuer_signature_status(settings.rpc_url, signature)?
  if status == "finalized" do
    Pool.execute_values(pool,
      "UPDATE sweeps SET finalized_at = now() WHERE sweep_signature = $1",
      [Text(signature)])?
    Pool.execute_values(pool,
      "UPDATE quotes SET swept_at = now() WHERE sweep_signature = $1",
      [Text(signature)])?
    Ok((1, 0))
  else if status == "failed" || text(Map.get(row, "stale")) == "true" do
    Pool.execute_values(pool,
      "UPDATE sweeps SET failed_at = now() WHERE sweep_signature = $1",
      [Text(signature)])?
    Pool.execute_values(pool,
      "UPDATE quotes SET sweep_signature = NULL WHERE sweep_signature = $1 AND swept_at IS NULL",
      [Text(signature)])?
    Ok((0, 1))
  else
    Ok((0, 0))
  end
end

fn confirm(pool :: PoolHandle, settings :: IssuerSettings) -> (Int, Int)!String do
  let rows = Pool.query_values(pool,
    "SELECT sweep_signature, (sent_at < now() - interval '3 minutes')::text AS stale FROM sweeps WHERE finalized_at IS NULL AND failed_at IS NULL",
    [])?
  let outcomes = for row in rows do
    confirm_one(pool, settings, row)?
  end
  Ok(List.reduce(outcomes,
    (0, 0),
    fn total, outcome -> (Tuple.first(total) + Tuple.first(outcome),
      Tuple.second(total) + Tuple.second(outcome)) end))
end

## One sweeper pass: confirms earlier sweeps, then sends at most one SOL batch
## (8 deposits) and one USDC batch (4 deposits, each with its account close).
## Nothing when the treasury is not configured.

pub fn issuer_sweep(pool :: PoolHandle, settings :: IssuerSettings) -> SweepRun!String do
  if settings.treasury_address == "" || Bytes.length(settings.deposit_seed) == 0 do
    return Ok(SweepRun { sent: 0, finalized: 0, retried: 0 })
  end
  let (finalized, retried) = confirm(pool, settings)?
  let sol = sweep_batch(pool, settings, "sol", 8)?
  let usdc = if settings.treasury_usdc_account == "" do
    0
  else
    sweep_batch(pool, settings, "usdc", 4)?
  end
  Ok(SweepRun { sent: sol + usdc, finalized: finalized, retried: retried })
end
