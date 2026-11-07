from Mobile.Platform import native_security_config
from Mobile.AnchorCheck import anchor_service_refused
from Mobile.Bounty import retain_bounty_fork
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local
from Transparency.Config import SecurityConfig, witness_policy_for_log, LogWitnessPolicy
from Transparency.Fork import (
  ForkProof,
  decode_fork,
  encode_fork,
  fork_same_size,
  fork_rollback,
  fork_contradiction
)
from Transparency.Merkle import TransparencyCheckpoint

# Evidence is retained independently of contacts or ratchet sessions. Only the
# shared proof verifier can create the durable pause; a hint cannot set it.
pub fn retained_fork(path :: String, key :: borrow StorageKey) -> Bytes!String do
  let label = "transparency-fork/v1"
  case load_blob(path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_local(blob, key, local_context(label)?)
  end
end

pub fn require_log_changes_allowed(path :: String,
  key :: borrow StorageKey) -> Result<(), String> do
  if Bytes.length(retained_fork(path, key)?) > 0 do
    Err("transparency_fork_detected")
  else if anchor_service_refused(path, key)? do
    Err("anchor_service_slashed")
  else
    Ok(nil)
  end
end

pub fn retain_fork(path :: String,
  key :: borrow StorageKey,
  proof :: ForkProof) -> Result<(), String> do
  let config = native_security_config()?
  let policy = witness_policy_for_log(config, proof.first.version)?
  let log = SigningPublicKey { bytes: config.service_public_key }
  if proof.kind == 1 do
    fork_same_size(proof, log, policy.keys)?
  else if proof.kind == 2 do
    fork_contradiction(proof, log, policy.keys)?
  else
    fork_rollback(proof, log, policy.keys)?
  end
  # Keep the first valid proof and its collection preference in one native CAS.
  retain_bounty_fork(path, key, encode_fork(proof)?)
end
