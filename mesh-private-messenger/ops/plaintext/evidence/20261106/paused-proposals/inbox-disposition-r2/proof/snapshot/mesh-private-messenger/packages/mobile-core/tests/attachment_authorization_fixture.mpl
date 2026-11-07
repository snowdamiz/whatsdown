from Mobile.AttachmentRecipients import attachment_authorization
from Mobile.Codec import current_time
from Mobile.Transparency import verify_transparency_response
from Mobile.Types import MobileTransparencyRequest
from Mobile.Profile import load_profile
from Protocol.DirectoryWire import encode_device_set
from Protocol.V1 import DeviceSet
from Transparency.Config import SecurityConfig
from Transparency.Merkle import (
  leaf_hash_for,
  merkle_root_for,
  sign_tree_checkpoint_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence, encode_transparency_evidence
from Transport.Packet import ClientProfile
from Tests.Support import repeated

## Actual signed current log evidence for a synthetic single-device target.
## No capability, freshness, signature or authorization checker is bypassed.
pub fn fixture_paid_attachment_authorization(path :: String,
  profile :: ClientProfile,
  config :: SecurityConfig,
  signer :: borrow SigningPrivateKey,
  witness :: borrow SigningPrivateKey) -> Bytes!String do
  let devices = case encode_device_set(DeviceSet {
    version: 1,
    username: profile.username,
    account_identity: profile.entry.account_identity,
    sequence: profile.account.directory_sequence,
    devices: [profile.entry],
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("fixture device set")
    Ok(value) -> value
  end
  let leaves = [leaf_hash_for(config.log_version, devices)?]
  let checkpoint = sign_tree_checkpoint_for(config.log_version,
    signer,
    config.service_public_key,
    U64.parse("1")?,
    U64.parse("1")?,
    merkle_root_for(config.log_version, leaves)?,
    repeated(0, 32)?,
    current_time()?)?
  let evidence = encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: devices,
    checkpoint: checkpoint,
    inclusion: compact_inclusion_proof_for(config.log_version, leaves, 0)?,
    consistency: compact_consistency_proof_for(config.log_version, [], leaves)?,
    witnesses: [sign_witness(List.head(config.witnesses).witness_id, witness, checkpoint)?]
  })?
  if !Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("2\n1\nhttps://core.example\nhttps://edge.example\nhttps://objects.example\nwss://core.example/v1/mailbox/stream\n1")) do
    return Err("fixture network pins")
  end
  verify_transparency_response(MobileTransparencyRequest {
    database_path: path,
    username: profile.username,
    evidence: evidence,
    directory_url: "https://core.example"
  })?
  attachment_authorization(path, load_profile(path)?, 4, profile.account_id)
end
