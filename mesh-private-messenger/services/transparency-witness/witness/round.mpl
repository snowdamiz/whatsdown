##! One witness round: fetch the directory's checkpoint, check it against the
##! last checkpoint this witness signed, commit it to the state, then sign and
##! submit. The pull loop repeats rounds; restore re-establishes continuity
##! after a halt.

from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  checkpoint_hash,
  sign_witness,
  verify_checkpoint,
  verify_witnesses
)
from Transparency.Wire import decode_checkpoint, encode_checkpoint, encode_witnesses
from Witness.Config import WitnessSetup
from Witness.Directory import (
  witness_fetch_attestations,
  witness_fetch_checkpoint,
  witness_relay,
  witness_submit
)
from Witness.Evidence import WitnessEvidence, witness_fork_proof, witness_write_evidence
from Witness.History import WitnessHistory, witness_check_history
from Witness.State import (
  witness_clear_halt,
  witness_halt,
  witness_halted,
  witness_state_exists,
  witness_state_read,
  witness_state_write,
  witness_write_atomic
)

pub type WitnessOutcome do
  # The directory has no checkpoint yet.
  WitnessIdle
  WitnessSigned(hash :: Bytes)
  # Signed before; the signature was submitted again.
  WitnessRepublished(hash :: Bytes)
  # Signed before, and the directory holds the signature.
  WitnessCurrent(hash :: Bytes)
  # Not signed this round (W1 timestamps); a later checkpoint may be.
  WitnessRefused(reason :: String)
  # Stopped until an operator restores continuity: a stale state, broken
  # history (evidence kept), or no explicit start for a new state.
  WitnessHalted(reason :: String)
end deriving(Eq, Debug)

fn log_key(setup :: WitnessSetup) -> SigningPublicKey do
  SigningPublicKey { bytes: setup.log_key }
end

fn first_line(text :: String) -> String do
  List.head(String.split(text, "\n"))
end

fn sequence_text(value :: Option<TransparencyCheckpoint>) -> String do
  case value do
    None -> "none"
    Some(checkpoint) -> U64.to_string(checkpoint.sequence)
  end
end

fn signed_before(previous :: Option<TransparencyCheckpoint>, hash :: Bytes) -> Bool!String do
  case previous do
    None -> Ok(false)
    Some(prior) -> Ok(Bytes.secure_equals(checkpoint_hash(prior)?, hash))
  end
end

fn newer(previous :: Option<TransparencyCheckpoint>, current :: TransparencyCheckpoint) -> Bool do
  case previous do
    None -> true
    Some(prior) -> U64.compare(current.sequence, prior.sequence) > 0
  end
end

# The guard's checkpoint when it is newer than the state: this host signed
# it, so the state was restored from an older copy.

fn guard_ahead(setup :: WitnessSetup,
  previous :: Option<TransparencyCheckpoint>) -> Option<TransparencyCheckpoint>!String do
  if String.length(setup.guard_path) == 0 do
    Ok(None)
  else
    case witness_state_read(setup.guard_path)? do
      None -> Ok(None)
      Some(signed) -> if newer(previous, signed) do
        Ok(Some(signed))
      else
        Ok(None)
      end
    end
  end
end

fn record_guard(setup :: WitnessSetup, value :: TransparencyCheckpoint) -> Result<(), String> do
  if String.length(setup.guard_path) == 0 do
    Ok(nil)
  else
    witness_write_atomic(setup.guard_path, Bytes.to_base64(encode_checkpoint(value)?))
  end
end

# Whether the directory holds this witness's own valid signature on current.

fn signed_by_us(setup :: WitnessSetup,
  current :: TransparencyCheckpoint,
  attestations :: List<WitnessAttestation>) -> Bool!String do
  let ours = List.filter(attestations, fn value -> value.witness_id == setup.witness_id end)
  if List.length(ours) == 0 do
    Ok(false)
  else
    verify_witnesses(current,
      List.take(ours, 16),
      [WitnessKey { witness_id: setup.witness_id, public_key: setup.witness_key }],
      1)
  end
end

fn submit(setup :: WitnessSetup,
  signer :: borrow SigningPrivateKey,
  current :: TransparencyCheckpoint) -> Result<(), String> do
  witness_submit(setup.base_url, sign_witness(setup.witness_id, signer, current)?)
end

fn republish(setup :: WitnessSetup,
  signer :: borrow SigningPrivateKey,
  current :: TransparencyCheckpoint,
  hash :: Bytes,
  published :: Bytes) -> WitnessOutcome!String do
  if Bytes.secure_equals(published, hash) do
    Ok(WitnessCurrent(hash))
  else if signed_by_us(setup, current, witness_fetch_attestations(setup.base_url)?)? do
    Ok(WitnessCurrent(hash))
  else
    submit(setup, signer, current)?
    Ok(WitnessRepublished(hash))
  end
end

# The directory shows this witness's signature on a checkpoint newer than its
# state: the state was restored from a backup (or lost), and signing on from
# it could sign a fork of what the witness already signed.

fn stale(setup :: WitnessSetup,
  previous :: Option<TransparencyCheckpoint>,
  current :: TransparencyCheckpoint) -> WitnessOutcome!String do
  let reason = "stale state: this witness already signed checkpoint #{U64.to_string(current.sequence)} but its state holds #{sequence_text(previous)}; restore continuity before it signs again"
  witness_halt(setup.state_path,
    "#{reason}\ncheckpoint #{Bytes.to_hex(encode_checkpoint(current)?)}\n")?
  Ok(WitnessHalted(reason))
end

fn relay_all(urls :: List<String>, frk :: Bytes) do
  if Bytes.length(frk) > 0 do
    for url in urls do
      case witness_relay(url, frk) do
        Err(error) -> io_eprintln("fork evidence relay #{url} failed: #{error}")
        Ok(status) -> println("fork evidence relay #{url} answered #{status}")
      end
    end
  end
end

# Keeps the evidence, halts (never signs again until an operator restores
# continuity), then files any fork proof with the relays.

fn capture(setup :: WitnessSetup,
  now_ms :: Int,
  reason :: String,
  prior :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint,
  proof :: Bytes,
  attestations :: List<WitnessAttestation>) -> WitnessOutcome!String do
  let frk = case witness_fork_proof(setup.log_key, prior, current) do
    Err(_) -> Bytes.empty()
    Ok(value) -> value
  end
  let evidence = WitnessEvidence {
    witness_id: setup.witness_id,
    reason: reason,
    detected_at_ms: now_ms,
    previous: prior,
    current: current,
    proof: proof,
    attestations: encode_witnesses(List.take(attestations, 16))?
  }
  let path = case witness_write_evidence(setup.evidence_dir, evidence, frk) do
    Err(error) -> "not written (#{error})"
    Ok(value) -> value
  end
  let summary = "#{reason}: the directory's checkpoint #{U64.to_string(current.sequence)} does not extend the last signed checkpoint #{U64.to_string(prior.sequence)}"
  witness_halt(setup.state_path, "#{summary}\nevidence #{path}\n")?
  io_eprintln("witness halted: #{summary}; evidence #{path}")
  relay_all(setup.relay_urls, frk)
  Ok(WitnessHalted(summary))
end

fn sign_new(setup :: WitnessSetup,
  signer :: borrow SigningPrivateKey,
  now_ms :: Int,
  previous :: Option<TransparencyCheckpoint>,
  current :: TransparencyCheckpoint,
  hash :: Bytes) -> WitnessOutcome!String do
  let attestations = witness_fetch_attestations(setup.base_url)?
  if newer(previous, current) && signed_by_us(setup, current, attestations)? do
    stale(setup, previous, current)
  else
    case witness_check_history(setup.base_url, previous, current, now_ms)? do
      HistoryRefused(reason) -> Ok(WitnessRefused(reason))
      HistoryBroken(reason, proof) -> case previous do
        None -> Err("history broken without a previous checkpoint")
        Some(prior) -> capture(setup, now_ms, reason, prior, current, proof, attestations)
      end
      HistoryAccepted -> do
        # Commit continuity before releasing a signature; a failed submission
        # is retried by the next round.
        witness_state_write(setup.state_path, previous, current)?
        record_guard(setup, current)?
        submit(setup, signer, current)?
        Ok(WitnessSigned(hash))
      end
    end
  end
end

fn judge(setup :: WitnessSetup,
  signer :: borrow SigningPrivateKey,
  now_ms :: Int,
  published :: Bytes,
  previous :: Option<TransparencyCheckpoint>,
  current :: TransparencyCheckpoint) -> WitnessOutcome!String do
  if !verify_checkpoint(current, log_key(setup))? do
    Err("transparency checkpoint signature failed")
  else
    let hash = checkpoint_hash(current)?
    if signed_before(previous, hash)? do
      republish(setup, signer, current, hash, published)
    else
      sign_new(setup, signer, now_ms, previous, current, hash)
    end
  end
end

fn cached(setup :: WitnessSetup) -> Option<TransparencyCheckpoint>!String do
  let previous = witness_state_read(setup.state_path)?
  case previous do
    None -> Ok(None)
    Some(prior) -> if verify_checkpoint(prior, log_key(setup))? do
      Ok(Some(prior))
    else
      Err("cached witness checkpoint signature failed")
    end
  end
end

fn observe(setup :: WitnessSetup,
  signer :: borrow SigningPrivateKey,
  now_ms :: Int,
  published :: Bytes) -> WitnessOutcome!String do
  let previous = cached(setup)?
  case guard_ahead(setup, previous)? do
    Some(signed) -> stale(setup, previous, signed)
    None -> case witness_fetch_checkpoint(setup.base_url)? do
      None -> case previous do
        None -> Ok(WitnessIdle)
        Some(_) -> Err("checkpoint missing after initialization")
      end
      Some(current) -> judge(setup, signer, now_ms, published, previous, current)
    end
  end
end

# Re-establishes continuity from a checkpoint the operator vouches for (the
# one a halt marker names, or a transfer): it must be signed by the log and
# not older than the state. Clears the halt marker.

pub fn witness_restore(setup :: WitnessSetup, encoded :: Bytes) -> TransparencyCheckpoint!String do
  let value = decode_checkpoint(encoded)?
  if !verify_checkpoint(value, log_key(setup))? do
    Err("restore checkpoint signature failed")
  else
    let current = witness_state_read(setup.state_path)?
    let older = case current do
      None -> false
      Some(prior) -> U64.compare(value.sequence, prior.sequence) < 0
    end
    if older do
      Err("restore checkpoint is older than the witness state")
    else if Option.is_some(guard_ahead(setup, Some(value))?) do
      Err("restore checkpoint is older than this host's last signed checkpoint")
    else
      witness_state_write(setup.state_path, current, value)?
      record_guard(setup, value)?
      witness_clear_halt(setup.state_path)?
      Ok(value)
    end
  end
end

# A pull-mode witness with no state starts only when told how: as a new
# identity (nothing signed yet), or from a transferred checkpoint.

fn started(setup :: WitnessSetup) -> Bool!String do
  if !setup.require_bootstrap || setup.bootstrap == "new-identity" do
    Ok(true)
  else if witness_state_exists(setup.state_path)? do
    Ok(true)
  else if String.length(setup.bootstrap) == 0 do
    Ok(false)
  else
    let encoded = case Bytes.from_hex(setup.bootstrap) do
      Err(_) -> Err("invalid MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX")
      Ok(value)
    end?
    witness_restore(setup, encoded)?
    Ok(true)
  end
end

# published: the hash of the checkpoint whose signature this process last saw
# accepted (empty when unknown), so a quiet log costs one request per round.

pub fn witness_round(setup :: WitnessSetup,
  signer :: borrow SigningPrivateKey,
  now_ms :: Int,
  published :: Bytes) -> WitnessOutcome!String do
  case witness_halted(setup.state_path)? do
    Some(text) -> Ok(WitnessHalted(first_line(text)))
    None -> if started(setup)? do
      observe(setup, signer, now_ms, published)
    else
      Ok(WitnessHalted("witness requires explicit checkpoint transfer: set MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX to new-identity or to the last checkpoint this witness signed"))
    end
  end
end

fn now_ms() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn reported(outcome :: WitnessOutcome!String, published :: Bytes) -> Bytes do
  case outcome do
    Ok(WitnessSigned(hash)) -> do
      println("witness signed checkpoint #{Bytes.to_hex(hash)}")
      hash
    end
    Ok(WitnessRepublished(hash)) -> do
      println("witness resubmitted checkpoint #{Bytes.to_hex(hash)}")
      hash
    end
    Ok(WitnessCurrent(hash)) -> hash
    Ok(WitnessIdle) -> published
    Ok(WitnessRefused(reason)) -> do
      io_eprintln("witness refused checkpoint: #{reason}")
      published
    end
    Ok(WitnessHalted(_)) -> published
    Err(error) -> do
      io_eprintln("witness round failed: #{error}")
      published
    end
  end
end

# Polls every poll_ms. rounds limits the loop for tests (0: until shutdown).
# Returns Err with the reason when the witness halts.

pub fn witness_pull(setup :: WitnessSetup,
  signer :: borrow SigningPrivateKey,
  poll_ms :: Int,
  rounds :: Int,
  published :: Bytes) -> Result<(), String> do
  let outcome = witness_round(setup, signer, now_ms(), published)
  case outcome do
    Ok(WitnessHalted(reason)) -> Err(reason)
    _ -> do
      let next = reported(outcome, published)
      if rounds == 1 || Process.shutdown_requested() do
        Ok(nil)
      else
        Timer.sleep(poll_ms)
        witness_pull(setup, signer, poll_ms, rounds - 1, next)
      end
    end
  end
end
