from Fixture.Legacy import LegacyAttachmentManifest, legacy_fixture_chunk

# Proof-only native boundary. Production dependencies are immutable and unmodified.
from MobileCore import initialize
from Attachments.Protocol import (
  AttachmentManifest,
  AttachmentError,
  generate_attachment_key,
  seal_manifest,
  seal_bound_chunk
)
from Identity.Device import issue_hybrid_device_credential
from Mobile.Attachments import encode_reference, decode_reference, attachment_manifest
from Mobile.AttachmentRecipients import attachment_authorization, require_attachment_authorization
from Mobile.Codec import current_time, mobile_utf8, mobile_join
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.CreditAttachment import credit_attachment_reference
from Mobile.NetworkPins import native_network_pins
from Mobile.Platform import native_security_config
from Mobile.Profile import (
  load_profile,
  open_account,
  open_device,
  open_post_quantum_prekey,
  device_keys
)
from Mobile.Transparency import verify_transparency_response
from Mobile.Types import MobileAttachmentReference, MobileTransparencyRequest
from Prekeys.Bundle import (
  generate_signed_prekey,
  generate_one_time_prekey,
  build_hybrid_prekey_bundle,
  generate_post_quantum_prekey
)
from Protocol.DirectoryWire import encode_device_set
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import DeviceSet, DirectoryEntry
from Storage.Credits import CreditWalletIdentity
from Storage.Keys import platform_key
from Transparency.Merkle import (
  leaf_hash_for,
  merkle_root_for,
  sign_tree_checkpoint_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence, encode_transparency_evidence
from Transport.Packet import decode_client_profile

fn fixture_bytes(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("fixture_bytes")
    Ok(output)
  end
end

fn protocol(value :: Result<Bytes, AttachmentError>) -> Bytes!String do
  case value do
    Err(_) -> Err("fixture_crypto")
    Ok(output)
  end
end

fn request(input :: Bytes, count :: Int) -> List<Bytes>!String do
  let parts = unpack_credit_parts(input, count, 40000)?
  if List.length(parts) != count do
    return Err("fixture_request")
  end
  Ok(parts)
end

fn fixture_entry(path :: String, mask :: Int, linked :: Bool) -> DirectoryEntry!String do
  let key = platform_key()?
  let profile = decode_client_profile(load_profile(path)?)?
  let account = open_account(profile, key, path)?
  let device = if linked do
    device_keys()
  else
    open_device(profile, key, path)
  end?
  let pq = if linked do
    case generate_post_quantum_prekey() do
      Err(_) -> Err("fixture_pq")
      Ok(value)
    end
  else
    open_post_quantum_prekey(profile, key, path)
  end?
  let credential = case issue_hybrid_device_credential(account,
    device,
    pq.public_key,
    U64.parse(Int.to_string(mask))?,
    profile.credential.created_at,
    profile.credential.expires_at,
    profile.credential.directory_sequence) do
    Err(_) -> return Err("fixture_credential")
    Ok(value) -> value
  end
  let signed = case generate_signed_prekey(device,
    credential,
    U64.parse("7")?,
    credential.expires_at) do
    Err(_) -> return Err("fixture_prekey")
    Ok(value) -> value
  end
  let one = case generate_one_time_prekey(U64.parse("8")?) do
    Err(_) -> return Err("fixture_one_time")
    Ok(value) -> value
  end
  let bundle = case build_hybrid_prekey_bundle(credential, signed, one, pq) do
    Err(_) -> return Err("fixture_bundle")
    Ok(value) -> value
  end
  let wire = case encode_prekey_bundle(bundle) do
    Err(_) -> return Err("fixture_bundle_wire")
    Ok(value) -> value
  end
  Ok(%{profile.entry |
    prekey_bundle: wire,
    mailbox_token: if linked do
      fixture_bytes(211, 32)?
    else
      profile.entry.mailbox_token
    end
  })
end

# Modes: 0 authentic current own device; 1 authentic legacy own device;
# 2 current own plus legacy linked device; 3 deliberately forged witness;
# 4 authentic ACH3-only own device; 5 current own plus ACH3-only linked device.
# All use real native pins and the production transparency verifier/cache.
@export("mesh_ach3_fixture_install")
pub fn install_fixture(input :: Bytes) -> Bytes!String do
  let parts = request(input, 2)?
  let path = mobile_utf8(List.head(parts), "fixture_path")?
  if Bytes.length(List.get(parts, 1)) != 1 do
    return Err("fixture_mode")
  end
  let mode = Bytes.get(List.get(parts, 1), 0)?
  if mode > 5 do
    return Err("fixture_mode")
  end
  let profile = decode_client_profile(load_profile(path)?)?
  let config = native_security_config()?
  let signer = case Crypto.signing_from_seed(fixture_bytes(53, 32)?) do
    Err(_) -> return Err("fixture_signer")
    Ok(value) -> value
  end
  let witness = case Crypto.signing_from_seed(fixture_bytes(if mode == 3 do
      55
    else
      54
    end,
    32)?) do
    Err(_) -> return Err("fixture_witness")
    Ok(value) -> value
  end
  let entries = if mode == 1 do
    [fixture_entry(path, 1, false)?]
  else if mode == 2 do
    [profile.entry, fixture_entry(path, 1, true)?]
  else if mode == 4 do
    [fixture_entry(path, 3, false)?]
  else if mode == 5 do
    [profile.entry, fixture_entry(path, 3, true)?]
  else
    [profile.entry]
  end
  let devices = case encode_device_set(DeviceSet {
    version: 1,
    username: profile.username,
    account_identity: profile.entry.account_identity,
    sequence: profile.account.directory_sequence,
    devices: entries,
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("fixture_device_set")
    Ok(value) -> value
  end
  let leaves = [leaf_hash_for(config.log_version, devices)?]
  let checkpoint = sign_tree_checkpoint_for(config.log_version,
    signer.private_key,
    config.service_public_key,
    U64.parse("1")?,
    U64.parse("1")?,
    merkle_root_for(config.log_version, leaves)?,
    fixture_bytes(0, 32)?,
    current_time()?)?
  let evidence = encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: devices,
    checkpoint: checkpoint,
    inclusion: compact_inclusion_proof_for(config.log_version, leaves, 0)?,
    consistency: compact_consistency_proof_for(config.log_version, [], leaves)?,
    witnesses: [
      sign_witness(List.head(config.witnesses).witness_id, witness.private_key, checkpoint)?
    ]
  })?
  verify_transparency_response(MobileTransparencyRequest {
    database_path: path,
    username: profile.username,
    evidence: evidence,
    directory_url: native_network_pins()?.core_origin
  })?
  Ok(evidence)
end

@export("mesh_ach3_fixture_ticket")
pub fn fixture_ticket(input :: Bytes) -> Bytes!String do
  let parts = request(input, 1)?
  let path = mobile_utf8(List.head(parts), "fixture_path")?
  let profile_wire = load_profile(path)?
  let profile = decode_client_profile(profile_wire)?
  attachment_authorization(path, profile_wire, 4, profile.account_id)
end

@export("mesh_ach3_fixture_require")
pub fn fixture_require(input :: Bytes) -> Bytes!String do
  let parts = request(input, 2)?
  require_attachment_authorization(mobile_utf8(List.head(parts), "fixture_path")?,
    List.get(parts, 1))?
  Ok(Bytes.empty())
end

# Encrypted reference only, after the real unfunded prepare persisted status3.
@export("mesh_ach3_fixture_paid_reference")
pub fn paid_reference(input :: Bytes) -> Bytes!String do
  let parts = request(input, 2)?
  let path = mobile_utf8(List.head(parts), "fixture_path")?
  let profile = decode_client_profile(load_profile(path)?)?
  let config = native_security_config()?
  let wrapping = platform_key()?
  credit_attachment_reference(path,
    wrapping,
    CreditWalletIdentity {
      account_id: profile.account_id,
      device_id: profile.device_id,
      service_key: config.service_public_key,
      purpose: 1
    },
    List.get(parts, 1))
end

# Returns only an encrypted substitution. No plaintext fixture export or new
# display/declassification boundary is added to the selected production ABI.
@export("mesh_ach3_fixture_alternate")
pub fn alternate_reference(input :: Bytes) -> Bytes!String do
  let parts = request(input, 2)?
  let path = mobile_utf8(List.head(parts), "fixture_path")?
  let profile = decode_client_profile(load_profile(path)?)?
  let wrapping = platform_key()?
  let device = open_device(profile, wrapping, path)?
  let reference = decode_reference(List.get(parts, 1))?
  let secret = case Crypto.hpke_open_secret(device.identity_private_key,
    Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap"),
    mobile_join([Bytes.from_utf8("mesh-msg/v1/attachment-reference"), reference.object_id],
      0,
      Bytes.empty())?,
    reference.wrapped_key) do
    Err(_) -> return Err("fixture_unwrap")
    Ok(value) -> value
  end
  let manifest = attachment_manifest(device, List.get(parts, 1))?
  let encrypted = protocol(seal_manifest(secret, manifest))?
  encode_reference(%{reference | encrypted_manifest: encrypted})
end

# Legacy ciphertext is generated only from proof-owned public literal metadata.
# This immutable closure retains its legacy writer solely for migration tests.
@export("mesh_ach3_fixture_legacy")
pub fn legacy_fixture(input :: Bytes) -> Bytes!String do
  let parts = request(input, 2)?
  let profile = decode_client_profile(load_profile(mobile_utf8(List.head(parts),
    "fixture_path")?)?)?
  let version = Bytes.get(List.get(parts, 1), 0)?
  if version != 1 && version != 2 && version != 3 do
    return Err("fixture_version")
  end
  let secret = case generate_attachment_key() do
    Err(_) -> return Err("fixture_key")
    Ok(value) -> value
  end
  let id = fixture_bytes(40 + version, 32)?
  let manifest = AttachmentManifest {
    version: if version == 3 do
      2
    else
      version
    end,
    attachment_id: id,
    chunk_size: 65536,
    chunk_count: if version == 1 do
      2
    else
      257
    end,
    plaintext_size: if version == 1 do
      65537
    else
      16777217
    end,
    filename: Bytes.from_utf8("public-legacy-fixture.bin"),
    mime_type: Bytes.from_utf8("application/octet-stream"),
    expires_at: U64.parse("4102444800000")?
  }
  let legacy_manifest = LegacyAttachmentManifest {
    version: manifest.version,
    attachment_id: id,
    chunk_size: 65536,
    chunk_count: manifest.chunk_count,
    plaintext_size: manifest.plaintext_size,
    filename: Bytes.from_utf8("public-legacy-fixture.bin"),
    mime_type: Bytes.from_utf8("application/octet-stream"),
    expires_at: U64.parse("4102444800000")?
  }
  let encrypted = protocol(seal_manifest(secret, manifest))?
  let wrapped = case Crypto.hpke_seal_secret(X25519PublicKey {
      bytes: profile.credential.dh_public_key
    },
    Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap"),
    mobile_join([Bytes.from_utf8("mesh-msg/v1/attachment-reference"), id], 0, Bytes.empty())?,
    secret) do
    Err(_) -> return Err("fixture_wrap")
    Ok(value) -> value
  end
  let reference = encode_reference(MobileAttachmentReference {
    object_id: id,
    download_capability: fixture_bytes(49, 32)?,
    encrypted_manifest: encrypted,
    wrapped_key: wrapped
  })?
  pack_credit_parts([
    reference,
    if version == 3 do
      protocol(seal_bound_chunk(secret, encrypted, 0, fixture_bytes(37, 65536)?))?
    else
      protocol(legacy_fixture_chunk(secret, legacy_manifest, 0, fixture_bytes(37, 65536)?))?
    end,
    if version == 3 do
      protocol(seal_bound_chunk(secret,
        encrypted,
        manifest.chunk_count - 1,
        fixture_bytes(37, 1)?))?
    else
      protocol(legacy_fixture_chunk(secret,
        legacy_manifest,
        manifest.chunk_count - 1,
        fixture_bytes(37, 1)?))?
    end
  ])
end
