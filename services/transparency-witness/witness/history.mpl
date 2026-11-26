##! What a witness checks before it signs a checkpoint it has not signed
##! before: that it extends the last one it signed (no rollback, no second
##! checkpoint at one sequence, an intact previous-checkpoint link, a valid
##! consistency proof), and that its timestamp is within 60 s of the witness's
##! clock and later than the last one it signed (key-transparency-v1, W1).

from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash
from Witness.Directory import witness_consistency

pub type WitnessHistory do
  HistoryAccepted
  # Not signed now; a later checkpoint may be.
  HistoryRefused(reason :: String)
  # Proof the directory misbehaved: evidence is kept and signing stops.
  HistoryBroken(reason :: String, proof :: Bytes)
end deriving(Eq, Debug)

fn clock_window_ms() -> Int do
  60000
end

fn int_of(value :: U64) -> Int!String do
  U64.to_int(value)
end

fn fresh(current :: TransparencyCheckpoint, now_ms :: Int) -> WitnessHistory!String do
  let stamp = int_of(current.timestamp)?
  if stamp > now_ms + clock_window_ms() || stamp < now_ms - clock_window_ms() do
    Ok(HistoryRefused("checkpoint timestamp is more than 60 s from the witness clock"))
  else
    Ok(HistoryAccepted)
  end
end

fn timely(prior :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint,
  now_ms :: Int) -> WitnessHistory!String do
  if U64.compare(current.timestamp, prior.timestamp) <= 0 do
    Ok(HistoryRefused("checkpoint timestamp is not later than the last signed checkpoint"))
  else
    fresh(current, now_ms)
  end
end

fn next_sequence(prior :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint) -> Bool!String do
  Ok(int_of(current.sequence)? == int_of(prior.sequence)? + 1)
end

# A break visible from the two checkpoints alone, or None.

fn structural_break(prior :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint) -> Option<String>!String do
  if U64.compare(current.sequence, prior.sequence) < 0
    || U64.compare(current.tree_size, prior.tree_size) < 0 do
    Ok(Some("rollback"))
  else if U64.compare(current.sequence, prior.sequence) == 0 do
    Ok(Some("conflict"))
  else if next_sequence(prior, current)?
    && !Bytes.secure_equals(current.previous_checkpoint_hash, checkpoint_hash(prior)?) do
    Ok(Some("broken-link"))
  else
    Ok(None)
  end
end

fn consistent(base_url :: String,
  prior :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint,
  now_ms :: Int) -> WitnessHistory!String do
  if U64.compare(current.tree_size, prior.tree_size) == 0 do
    # The honest refresh: the same tree under the next sequence.
    if Bytes.secure_equals(current.tree_root, prior.tree_root) do
      timely(prior, current, now_ms)
    else
      Ok(HistoryBroken("inconsistency", Bytes.empty()))
    end
  else
    let reply = witness_consistency(base_url, prior, current)?
    if reply.valid do
      timely(prior, current, now_ms)
    else
      Ok(HistoryBroken("inconsistency", reply.body))
    end
  end
end

# previous is the last checkpoint this witness signed (None for a new
# identity). The caller has checked both service signatures and that current
# is not previous itself.

pub fn witness_check_history(base_url :: String,
  previous :: Option<TransparencyCheckpoint>,
  current :: TransparencyCheckpoint,
  now_ms :: Int) -> WitnessHistory!String do
  case previous do
    None -> fresh(current, now_ms)
    Some(prior) -> case structural_break(prior, current)? do
      Some(reason) -> Ok(HistoryBroken(reason, Bytes.empty()))
      None -> consistent(base_url, prior, current, now_ms)
    end
  end
end
