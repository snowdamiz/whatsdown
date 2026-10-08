##! Evidence a witness keeps when the directory's history breaks: both signed
##! checkpoints, the proof bytes and attestation list the directory sent, and
##! when it was seen; plus an FRK v1 proof when the two checkpoints alone show
##! a fork (same size, or a rollback), for relays to file with the judge.

from Transparency.Fork import ForkEvidence, ForkLog, fork_encode, fork_kind_between, fork_verify
from Transparency.Merkle import TransparencyCheckpoint
from Transparency.Wire import encode_checkpoint
from Witness.State import witness_write_atomic

pub struct WitnessEvidence do
  witness_id :: String
  reason :: String
  detected_at_ms :: Int
  previous :: TransparencyCheckpoint
  current :: TransparencyCheckpoint
  proof :: Bytes
  attestations :: Bytes
end

fn zeroes(count :: Int) -> Bytes!String do
  case Bytes.repeat(0, count) do
    Err(_) -> Err("witness evidence encoding failed")
    Ok(value)
  end
end

# ponytail: the proof carries no attestations. This witness keeps no other
# witness's signatures on the older checkpoint, so none would implicate
# anyone; relays and monitors that hold both lists can add them.

fn fork_proof(kind :: Int,
  log_key :: Bytes,
  previous :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint) -> Bytes!String do
  let evidence = ForkEvidence {
    kind: kind,
    finder: zeroes(32)?,
    service_public_key: log_key,
    first: previous,
    second: Some(current),
    ring_index: 0,
    attestations: List.new(),
    leaf_index: 0,
    first_path: List.new(),
    first_leaf: Bytes.empty(),
    second_path: List.new(),
    second_leaf: Bytes.empty()
  }
  fork_verify(evidence, ForkLog { service_public_key: log_key, witnesses: List.new() }, None)?
  fork_encode(evidence)
end

# The FRK bytes when the two checkpoints form a fork on their own, else empty
# (a failed consistency proof needs a leaf comparison, FRK kind 2, which a
# witness holding only checkpoints cannot build).

pub fn witness_fork_proof(log_key :: Bytes,
  previous :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint) -> Bytes!String do
  let kind = fork_kind_between(previous, current)?
  if kind == 0 do
    Ok(Bytes.empty())
  else
    fork_proof(kind, log_key, previous, current)
  end
end

fn field(name :: String, value :: String) -> String do
  Json.encode_string(name) <> ":" <> Json.encode_string(value)
end

pub fn witness_evidence_json(value :: WitnessEvidence, frk :: Bytes) -> String!String do
  let fields = [
    "\"version\":1",
    field("witness_id", value.witness_id),
    field("reason", value.reason),
    "\"detected_at_ms\":#{value.detected_at_ms}",
    field("previous_checkpoint", Bytes.to_hex(encode_checkpoint(value.previous)?)),
    field("current_checkpoint", Bytes.to_hex(encode_checkpoint(value.current)?)),
    field("consistency_proof", Bytes.to_hex(value.proof)),
    field("attestations", Bytes.to_hex(value.attestations)),
    field("fork_evidence", Bytes.to_hex(frk))
  ]
  Ok("{" <> String.join(fields, ",") <> "}\n")
end

# Writes the evidence file into dir and returns its path ("" with no dir).

pub fn witness_write_evidence(dir :: String,
  value :: WitnessEvidence,
  frk :: Bytes) -> String!String do
  if String.length(dir) == 0 do
    Ok("")
  else
    let suffix = case Crypto.random_bytes(4) do
      Err(_) -> Err("witness evidence name failed")
      Ok(bytes) -> Ok(Bytes.to_hex(bytes))
    end?
    let path = "#{dir}/evidence-#{value.witness_id}-#{value.detected_at_ms}-#{value.reason}-#{suffix}.json"
    witness_write_atomic(path, witness_evidence_json(value, frk)?)?
    Ok(path)
  end
end
