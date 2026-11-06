from BurnWorker import token_burn_worker_tick, token_burn_worker_report
from BurnWorkerConfig import TokenBurnWorkerCommand, decode_token_burn_worker_config

fn worker_run(command :: TokenBurnWorkerCommand,
  wrapping :: borrow StorageKey,
  payer :: borrow SigningPrivateKey,
  client :: Int,
  tick :: Int,
  minimum :: U64) -> Bool!String do
  if tick >= command.ticks do
    return Ok(true)
  end
  let result = token_burn_worker_tick(command.journal_path,
    wrapping,
    %{command.config | minimum_slot: minimum},
    payer,
    client,
    tick % 3)
  let next = case result do
    Err(_) -> do
      println("{\"schema_version\":1,\"status\":\"reconcile:observation-or-journal\"}")
      minimum
    end
    Ok(value) -> do
      println(token_burn_worker_report(value))
      value.context_slot
    end
  end
  if tick + 1 < command.ticks do
    Timer.sleep(command.interval_ms)
  end
  worker_run(command, wrapping, payer, client, tick + 1, next)
end

fn execute() -> Bool!String do
  let args = Env.args()
  if List.length(args) != 2 do
    return Err("usage: burn-worker CONFIG.json")
  end
  let command = decode_token_burn_worker_config(File.read(List.get(args, 1))?)?
  let seed = case Env.get_secret_hex("MORSE_BURN_WORKER_PAYER_SEED_HEX") do
    Err(_) -> return Err("burn_worker_payer_unavailable")
    Ok(value) -> value
  end
  let pair = case Crypto.signing_from_secret(seed) do
    Err(_) -> return Err("burn_worker_payer_unavailable")
    Ok(value) -> value
  end
  if pair.public_key.bytes != command.config.payer.bytes do
    Secret.destroy(pair.private_key)
    return Err("burn_worker_payer_mismatch")
  end
  let wrapping = case StorageKey.file(command.key_directory) do
    Err(_) -> do
      Secret.destroy(pair.private_key)
      return Err("burn_worker_storage_unavailable")
    end
    Ok(value) -> value
  end
  let client = Http.client()
  let result = worker_run(command,
    wrapping,
    pair.private_key,
    client,
    0,
    command.config.minimum_slot)
  Http.client_close(client)
  Secret.destroy(pair.private_key)
  Secret.destroy(wrapping)
  result
end

fn main() do
  case execute() do
    Err(_) -> do
      IO.eprintln("burn_worker_failed")
      Process.exit(1)
    end
    Ok(_) -> nil
  end
end
