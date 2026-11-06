from Transparency.Config import decode_security_config, pinned_legacy_witness_keys
from Transparency.Merkle import WitnessKey

pub struct WitnessPolicy do
  log_version :: Int
  legacy_keys :: List<WitnessKey>
  legacy_threshold :: Int
end

# A rollout frame is installed by the operator, never learned from the log.
# Older deployments retain v1 until they explicitly install the v3 policy.
pub fn configured_policy(trusted :: SigningPublicKey) -> WitnessPolicy!String do
  let frame = Env.get("MESSENGER_SECURITY_CONFIG", "")
  if frame == "" do
    return Ok(WitnessPolicy { log_version: 1, legacy_keys: List.new(), legacy_threshold: 0 })
  end
  let config = decode_security_config(Bytes.from_utf8(frame))?
  if !Bytes.secure_equals(config.service_public_key, trusted.bytes) do
    return Err("witness policy service key mismatch")
  end
  Ok(WitnessPolicy {
    log_version: config.log_version,
    legacy_keys: pinned_legacy_witness_keys(config),
    legacy_threshold: config.legacy_threshold
  })
end
