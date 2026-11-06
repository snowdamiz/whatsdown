from Runtime.Config import configured_server
from Runtime.BtcConversion import configured_btc_conversion
from Runtime.BtcConversionFunding import (
  BtcWitnessFundingConfig,
  validate_btc_witness_funding,
  prepare_btc_witness_output,
  reconcile_btc_witness_output
)
from Storage.BtcConversionFunding import load_btc_witness_funding
from Storage.TreasuryFunding import TreasuryFundingIntent

fn report(value :: TreasuryFundingIntent) -> String do
  json {
    schemaVersion: 1,
    id: Bytes.to_hex(value.intent_id),
    batch: U64.to_string(value.batch_id),
    epoch: U64.to_string(value.epoch),
    pool: Bytes.to_base58(value.pool),
    funder: Bytes.to_base58(value.funder),
    source: Bytes.to_base58(value.source),
    mint: Bytes.to_base58(value.mint),
    amount: U64.to_string(value.amount),
    state: value.state
  }
    |> Json.encode()
end

fn run() -> String!String do
  let args = Env.args()
  if List.length(args) != 3
    || !List.contains(["prepare", "reconcile", "status"], List.get(args, 1)) do
    return Err("usage: btc-witness-funding prepare|reconcile|status 32-byte-id-hex")
  end
  let id = Bytes.from_hex(List.get(args, 2))?
  if Bytes.length(id) != 32 || Bytes.to_hex(id) != List.get(args, 2) do
    return Err("invalid_btc_funding_identity")
  end
  let server = configured_server()?
  let treasury = case server.treasury do
    Some(value) -> value
    None -> return Err("treasury_disabled")
  end
  let config = BtcWitnessFundingConfig {
    conversion: configured_btc_conversion(server)?,
    treasury: treasury
  }
  validate_btc_witness_funding(config)?
  let pool = Pool.open(server.database_url, 1, 4, 5000)?
  let result = case List.get(args, 1) do
    "prepare" -> prepare_btc_witness_output(pool, config, id)
    "reconcile" -> reconcile_btc_witness_output(pool, config, id)
    _ -> Repo.transaction(pool,
      fn(conn :: borrow PgConn) do load_btc_witness_funding(conn,
        config.conversion,
        config.treasury.chain,
        id) end)
  end
  Pool.close(pool)
  Ok(report(result?))
end

fn main() do
  case run() do
    Ok(value) -> println(value)
    Err(error) -> do
      IO.eprintln(error)
      Process.exit(1)
    end
  end
end
