from Runtime.SolConversionConfig import parse_sol_conversion_operator
from Runtime.Treasury import TreasuryWorkerConfig
from Runtime.TreasuryBurn import (
  prepare_credit_burn_funding,
  reconcile_credit_burn_handoff,
  prepare_credit_burn_expiry,
  credit_burn_funding_json
)
from Storage.TreasuryBurn import load_credit_burn_handoff
from Transparency.TokenBurnRead import TokenBurnReadPins
from Transparency.TokenBurnExpiry import token_burn_expire_instruction
from Solana.Read import Hash, pubkey, rpc_send
from Solana.TransactionRead import signed_transaction
from Solana.TransactionSend import send_transaction_request
from Solana.Tx import (
  compile_legacy_message,
  serialize_legacy_message,
  compute_unit_limit_instruction
)
from Runtime.KeySync import issuer_now

fn text(root :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(root, key)?)
end

fn run() -> Result<(), String> do
  let args = Env.args()
  let config = parse_sol_conversion_operator(File.read(List.get(args, 1))?)?
  let bank = Json.parse(File.read(List.get(args, 2))?)?
  let worker = TreasuryWorkerConfig {
    chain: config.worker.chain,
    providers: config.worker.providers,
    test_mode: true
  }
  let pins = TokenBurnReadPins {
    program: pubkey(text(bank, "program")?)?,
    governance: pubkey(text(bank, "governance")?)?,
    program_slot: U64.parse(text(bank, "program_slot")?)?,
    usdc: pubkey(text(bank, "usdc")?)?,
    treasury: pubkey(text(bank, "treasury")?)?,
    factory: pubkey(text(bank, "factory")?)?
  }
  let pool = Pool.open(config.database_url, 1, 8, 5000)?
  let action = List.get(args, 3)
  let epoch = U64.parse(text(bank, "epoch")?)?
  if action == "prepare" do
    let result = prepare_credit_burn_funding(pool,
      worker,
      pins,
      epoch,
      U64.parse("0")?,
      issuer_now()?)?
    let stored = case result do
      None -> return Err("owned_common_no_sources")
      Some(value) -> value
    end
    if stored.intent.cash != U64.parse("299003525")? do
      return Err("owned_common_cash_mismatch")
    end
    let source_ids = for value in stored.intent.allocations do
      value.batch_id
    end
    if source_ids != [U64.parse("1")?, U64.parse("2")?, U64.parse("9223372036854775809")?] do
      return Err("owned_common_source_namespace_mismatch")
    end
    let plan = credit_burn_funding_json(stored)
    File.write(List.get(args, 4), plan)?
    let message = serialize_legacy_message(compile_legacy_message(config.worker.profile.payer,
      Hash { bytes: Bytes.from_base58(text(bank, "blockhash")?)? },
      [compute_unit_limit_instruction(1000000)?, stored.intent.instruction])?)?
    File.write(List.get(args, 5), Bytes.to_base64(message))?
    println(plan)
  else if action == "reconcile" do
    let stored = reconcile_credit_burn_handoff(pool,
      worker,
      pins,
      Bytes.from_hex(List.get(args, 4))?)?
    println(credit_burn_funding_json(stored))
  else if action == "expiry" do
    let report = prepare_credit_burn_expiry(pool, worker, pins, epoch)?
    let stored = Repo.transaction(pool,
      fn(conn :: borrow PgConn) do load_credit_burn_handoff(conn,
        Bytes.from_hex(List.get(args, 4))?) end)?
    let instruction = token_burn_expire_instruction(stored.intent.program,
      stored.intent.payer,
      stored.intent.profile,
      stored.intent.epoch)?
    let message = serialize_legacy_message(compile_legacy_message(config.worker.profile.payer,
      Hash { bytes: Bytes.from_base58(text(bank, "blockhash")?)? },
      [compute_unit_limit_instruction(1000000)?, instruction])?)?
    File.write(List.get(args, 5), Bytes.to_base64(message))?
    println(report)
  else if action == "submit" do
    let stored = Repo.transaction(pool,
      fn(conn :: borrow PgConn) do load_credit_burn_handoff(conn,
        Bytes.from_hex(List.get(args, 4))?) end)?
    let instruction = if List.get(args, 6) == "fund" do
      stored.intent.instruction
    else
      token_burn_expire_instruction(stored.intent.program,
        stored.intent.payer,
        stored.intent.profile,
        stored.intent.epoch)?
    end
    let expected = serialize_legacy_message(compile_legacy_message(config.worker.profile.payer,
      Hash { bytes: Bytes.from_base58(text(bank, "blockhash")?)? },
      [compute_unit_limit_instruction(1000000)?, instruction])?)?
    let wire = Bytes.from_base64(File.read(List.get(args, 5))?)?
    let parsed = signed_transaction(wire, Bytes.slice(wire, 1, 64)?)?
    if parsed.message != expected || !config.worker.test_mode do
      return Err("owned_common_wire_mismatch")
    end
    let client = Http.client()
    let response = rpc_send(client,
      List.head(worker.providers),
      send_transaction_request(1, wire, parsed.signature, U64.parse("0")?)?,
      3000,
      4096)
    Http.client_close(client)
    let accepted = response?
    if !accepted.ok do
      return Err("owned_common_send_refused")
    end
    println("owned exact packet acknowledged")
  else
    return Err("owned_common_action")
  end
  Pool.close(pool)
  Ok(nil)
end

fn main() do
  case run() do
    Ok(_) -> nil
    Err(error) -> do
      println(error)
      Process.exit(1)
    end
  end
end
