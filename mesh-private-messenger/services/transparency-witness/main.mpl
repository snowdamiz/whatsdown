from Transparency.Merkle import TransparencyCheckpoint
from Witness.Config import witness_mode, witness_poll_ms, witness_setup_from_env, witness_signer
from Witness.Round import WitnessOutcome, witness_pull, witness_restore, witness_round

# Exit codes: 0 done, 1 error (retry), 3 halted: the witness refuses to sign
# until an operator restores continuity (systemd does not restart on 3).

fn halted(reason :: String) -> Int!String do
  io_eprintln("witness halted: #{reason}")
  Ok(3)
end

fn restore() -> Int!String do
  let setup = witness_setup_from_env(false)?
  let encoded = case Bytes.from_hex(Env.get("MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX", "")) do
    Err(_) -> Err("restore needs MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX")
    Ok(value)
  end?
  let restored = witness_restore(setup, encoded)?
  println("witness continuity restored at checkpoint #{U64.to_string(restored.sequence)}")
  Ok(0)
end

fn pull() -> Int!String do
  let setup = witness_setup_from_env(true)?
  let signer = witness_signer(setup)?
  let poll_ms = witness_poll_ms(Env.get("MESSENGER_WITNESS_POLL_MS", "15000"))?
  Process.install_shutdown_signals()
  println("witness #{setup.witness_id} pulling every #{poll_ms} ms")
  case witness_pull(setup, signer.private_key, poll_ms, 0, Bytes.empty()) do
    Err(reason) -> halted(reason)
    Ok(_) -> Ok(0)
  end
end

fn once() -> Int!String do
  let setup = witness_setup_from_env(false)?
  let signer = witness_signer(setup)?
  let now_ms = DateTime.to_unix_ms(DateTime.utc_now())
  case witness_round(setup, signer.private_key, now_ms, Bytes.empty())? do
    WitnessHalted(reason) -> halted(reason)
    WitnessRefused(reason) -> Err("checkpoint refused: #{reason}")
    WitnessSigned(_) -> Ok(0)
    WitnessRepublished(_) -> Ok(0)
    WitnessCurrent(_) -> Ok(0)
    WitnessIdle -> Ok(0)
  end
end

fn run() -> Int!String do
  let mode = witness_mode(Env.get("MESSENGER_WITNESS_MODE", "once"))?
  if mode == "restore" do
    restore()
  else if mode == "pull" do
    pull()
  else
    once()
  end
end

fn main() do
  case run() do
    Err(error) -> do
      io_eprintln("witness failed: #{error}")
      Process.exit(1)
    end
    Ok(0) -> println("witness check completed")
    Ok(code) -> Process.exit(code)
  end
end
