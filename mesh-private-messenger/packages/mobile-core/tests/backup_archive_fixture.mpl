from Mobile.Types import MobileHistoryAttachment
from MobileCore import create_account_export
from Mobile.Profile import load_profile, open_account, open_device
from Identity.Device import AccountKeys, DeviceKeys, generate_device, issue_device_credential
from Prekeys.Bundle import SignedPrekeySecrets, generate_signed_prekey
from Protocol.IdentityWire import encode_device_credential
from Protocol.PrekeyWire import encode_prekey_bundle
from Mobile.Codec import current_time, mobile_join, mobile_vector, mobile_byte, mobile_write_u32
from Mobile.Platform import decode_native_security_config
from Mobile.OhttpContext import capture_native_ohttp_context
from Mobile.Transparency import (
  BackupCapturedTransparencyInputs,
  encode_verified_transparency_set,
  transparency_device_set_label,
  transparency_view_storage
)
from Mobile.Types import MobileVerifiedTransparencySet, MobileTransparencyView
from Storage.AccountGuard import AccountBasis, load_account_basis
from Storage.FanoutCommit import FanoutSnapshot
from Storage.Keys import platform_key, local_context, seal_local, open_local
from Storage.Records import store_updated_blobs, erase_local_state
from Tests.GroupConsistencySupport import request, signing_pair, encode_set, wide
from Tests.Support import append, repeated
from Transport.Packet import ClientProfile, decode_client_profile
from Protocol.V1 import DeviceSet, DeviceCredential, DirectoryEntry, PrekeyBundle, InnerEnvelope
from Mobile.Types import MobileHistoryEntry
from Mobile.HistoryWire import encode_history
from Storage.HistoryBlobs import seal_history_blob
from Backups.PortableV2 import (
  PortableBackupV2Content,
  PortableBackupV2Created,
  create_portable_backup_v2,
  restore_portable_backup
)
from Backups.TextArchive import (
  BackupArchiveRecord,
  BackupArchiveScope,
  BackupTextArchive,
  decode_text_archive,
  encode_text_archive
)
from Transparency.Config import SecurityConfig, encode_security_config, witness_policy_for_log
from Transparency.Client import verify_evidence
from Transparency.C2spText import checkpoint_note_text
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  leaf_hash_for,
  merkle_root_for,
  sign_tree_checkpoint_for,
  inclusion_proof,
  consistency_proof,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  checkpoint_hash,
  sign_witness
)
from Transparency.Wire import (
  TransparencyEvidence,
  encode_checkpoint,
  encode_witnesses,
  encode_consistency_proof
)

pub struct D4CoreFixture do
  path :: String
  public_profile :: Bytes
  input :: BackupCapturedTransparencyInputs
  config :: SecurityConfig
  now :: U64
  expected_fresh_through :: U64
  original :: FanoutSnapshot
  account_id :: Bytes
  archive_id :: Bytes
  source_label :: String
  source_ciphertext :: Bytes
end

fn d4_core_cosign(key :: borrow SigningPrivateKey,
  checkpoint :: TransparencyCheckpoint,
  seconds :: U64) -> WitnessAttestation!String do
  let text = "cosignature/v1\ntime "
    <> U64.to_string(seconds)
    <> "\n"
    <> checkpoint_note_text(encode_checkpoint(checkpoint)?)?
  let signature = case Crypto.sign(key, Bytes.from_utf8(text)) do
    Err(_) -> return Err("d4_fixture_sign")
    Ok(value) -> value.bytes
  end
  let stamp = case Bytes.write_u64_be(seconds) do
    Err(_) -> return Err("d4_fixture_time")
    Ok(value) -> value
  end
  Ok(WitnessAttestation {
    witness_id: "witness-a",
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    signature: append(stamp, signature)?
  })
end

fn d4_core_captured(before :: AccountBasis,
  label :: String,
  key :: borrow StorageKey) -> Bytes!String do
  for index in 0..List.length(before.labels) do
    if List.get(before.labels, index) == label do
      return open_local(List.get(before.records, index), key, local_context(label)?)
    end
  end
  Err("d4_fixture_missing_capture")
end

## Real account/keys, signed leaf/root and two witnessed attestations; no HTTP.
## Every opened helper input below comes from the same original AccountBasis.
pub fn d4_core_fixture() -> D4CoreFixture!String do
  d4_core_fixture_with_membership(0, 2)
end

pub fn d4_core_revoked_fixture() -> D4CoreFixture!String do
  d4_core_fixture_with_membership(1, 2)
end

pub fn d4_core_expired_fixture() -> D4CoreFixture!String do
  d4_core_fixture_with_membership(2, 2)
end

pub fn d4_core_legacy_fixture() -> D4CoreFixture!String do
  d4_core_fixture_with_membership(0, 1)
end

fn d4_core_fixture_with_membership(mode :: Int, log_version :: Int) -> D4CoreFixture!String do
  if !Test.install_in_memory_secure_store() do
    return Err("d4_fixture_secure_store")
  end
  let root = Env.get("MORSE_C1_FIXTURE_ROOT", "")
  if String.length(root) == 0 do
    return Err("d4_fixture_root_required")
  end
  let entropy = case Crypto.random_bytes(8) do
    Err(_) -> return Err("d4_fixture_path")
    Ok(value) -> value
  end
  let path = root <> "/d4-core-" <> Bytes.to_hex(entropy) <> ".db"
  create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8("backupcore")])?)?
  let public_profile = load_profile(path)?
  let profile = decode_client_profile(public_profile)?
  let (member, revoked) = d4_core_member(profile, path, mode)?
  let devices = encode_set(DeviceSet {
    version: 1,
    username: profile.username,
    account_identity: profile.entry.account_identity,
    sequence: profile.account.directory_sequence,
    devices: [member],
    revoked_device_ids: revoked
  })?
  let service_pair = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> return Err("d4_fixture_delivery")
    Ok(value) -> value
  end
  let frame = Bytes.from_utf8(String.join([
      "3",
      Bytes.to_hex(service_pair.public_key.bytes),
      Bytes.to_hex(delivery.public_key.bytes),
      "8",
      "2",
      "2",
      "witness-a " <> Bytes.to_hex(a.public_key.bytes) <> " Morse",
      "witness-b " <> Bytes.to_hex(b.public_key.bytes) <> " Other",
      "-",
      "0",
      "-",
      "2",
      "2",
      "2",
      "witness-a " <> Bytes.to_hex(a.public_key.bytes) <> " Morse",
      "witness-b " <> Bytes.to_hex(b.public_key.bytes) <> " Other"
    ],
    "\n"))
  let config = decode_native_security_config(frame)?
  let network = Bytes.from_utf8("2\n1\nhttps://core.example\nhttps://edge.example\nhttps://objects.example\nwss://core.example/v1/mailbox/stream\n1")
  let companion = Bytes.from_utf8(String.join([
      "1",
      Bytes.to_hex(Crypto.sha256(network)),
      Bytes.to_hex(Crypto.sha256(encode_security_config(config)?)),
      "1",
      "off",
      "0"
    ],
    "\n"))
  if !Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame) do
    return Err("d4_fixture_native_frame")
  end
  if !Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), network) do
    return Err("d4_fixture_native_frame")
  end
  if !Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"), companion) do
    return Err("d4_fixture_native_frame")
  end
  let initial = load_account_basis(path, [])?
  let _context = capture_native_ohttp_context(path, initial.profile)?
  let now = current_time()?
  let seconds_int = U64.to_int(now)? / 1000
  let seconds = wide(seconds_int)?
  let leaves = [leaf_hash_for(log_version, devices)?]
  let checkpoint = sign_tree_checkpoint_for(log_version,
    service_pair.private_key,
    service_pair.public_key.bytes,
    wide(1)?,
    wide(1)?,
    merkle_root_for(log_version, leaves)?,
    repeated(0, 32)?,
    now)?
  let attestations = if log_version == 1 do
    [
      sign_witness("witness-a", a.private_key, checkpoint)?,
      sign_witness("witness-b", b.private_key, checkpoint)?
    ]
  else
    [
      d4_core_cosign(a.private_key, checkpoint, seconds)?,
      sign_witness("witness-b", b.private_key, checkpoint)?
    ]
  end
  let consistency = if log_version == 1 do
    consistency_proof([], leaves)?
  else
    compact_consistency_proof_for(2, [], leaves)?
  end
  let evidence = TransparencyEvidence {
    entry_bytes: devices,
    inclusion: if log_version == 1 do
      inclusion_proof(leaves, 0)?
    else
      compact_inclusion_proof_for(2, leaves, 0)?
    end,
    consistency: consistency,
    checkpoint: checkpoint,
    witnesses: attestations
  }
  let policy = witness_policy_for_log(config, log_version)?
  if !verify_evidence(evidence,
    service_pair.public_key,
    policy.keys,
    policy.threshold,
    Bytes.empty())? do
    return Err("d4_fixture_evidence_invalid")
  end
  let view = MobileTransparencyView {
    checkpoint: encode_checkpoint(checkpoint)?,
    consistency: encode_consistency_proof(consistency)?,
    service_public_key: service_pair.public_key.bytes,
    set_id: policy.set_id,
    witness_threshold: policy.threshold
  }
  let key = platform_key()?
  let split = transparency_view_storage(view, key)?
  let set_label = transparency_device_set_label(profile.account_id)
  let source_label = "history/v1/#{Bytes.to_hex(repeated(71, 16)?)}"
  let source_ciphertext = seal_local(Bytes.from_utf8("captured source remains exact"),
    key,
    local_context(source_label)?)?
  let extra_labels = [set_label, "transparency-checkpoint/v1"]
    ++ if log_version == 1 do
      []
    else
      ["transparency-witnesses/v2"]
    end
    ++ ["transparency-origin/v1", source_label]
  let extra_blobs = [
    seal_local(encode_verified_transparency_set(MobileVerifiedTransparencySet {
        checkpoint: view.checkpoint,
        device_set: devices
      })?,
      key,
      local_context(set_label)?)?,
    seal_local(view.checkpoint, key, local_context("transparency-checkpoint/v1")?)?
  ]
    ++ if log_version == 1 do
      []
    else
      [
        seal_local(encode_witnesses(attestations)?,
          key,
          local_context("transparency-witnesses/v2")?)?
      ]
    end
    ++ [
      seal_local(Bytes.from_utf8("https://core.example"),
        key,
        local_context("transparency-origin/v1")?)?,
      source_ciphertext
    ]
  store_updated_blobs(path, split.labels ++ extra_labels, split.blobs ++ extra_blobs)?
  let archive_id = repeated(19, 32)?
  let destination = "backup-archive/v1/#{Bytes.to_hex(profile.account_id)}/#{Bytes.to_hex(archive_id)}"
  let index = "backup-archives/v1/#{Bytes.to_hex(profile.account_id)}"
  let before = load_account_basis(path,
    ["device-signing-key/v1", "device-identity-key/v1", "ohttp-revision/v1"]
      ++ split.labels
      ++ extra_labels
      ++ if log_version == 1 do
        ["transparency-witnesses/v2"]
      else
        []
      end
      ++ [destination, index])?
  let input = BackupCapturedTransparencyInputs {
    device_set_cache: d4_core_captured(before, set_label, key)?,
    shared_checkpoint: d4_core_captured(before, "transparency-checkpoint/v1", key)?,
    view_manifest: d4_core_captured(before, "transparency-view/v1", key)?,
    view_chunks: for i in 0..3 do
      d4_core_captured(before, "transparency-view-chunk/v1/#{Int.to_string(i)}", key)?
    end,
    witnesses: if log_version == 1 do
      Bytes.empty()
    else
      d4_core_captured(before, "transparency-witnesses/v2", key)?
    end,
    proof_label: "",
    proof: Bytes.empty()
  }
  Secret.destroy(key)
  Secret.destroy(service_pair.private_key)
  Secret.destroy(a.private_key)
  Secret.destroy(b.private_key)
  Secret.destroy(delivery.private_key)
  Ok(D4CoreFixture {
    path: path,
    public_profile: public_profile,
    input: input,
    config: config,
    now: now,
    expected_fresh_through: if log_version == 1 do
      U64.add(now, wide(300000)?)?
    else
      wide(seconds_int * 1000 + 300000)?
    end,
    original: FanoutSnapshot { bases: [before] },
    account_id: profile.account_id,
    archive_id: archive_id,
    source_label: source_label,
    source_ciphertext: source_ciphertext
  })
end

pub fn d4_core_cleanup(fixture :: D4CoreFixture) -> Result<(), String> do
  erase_local_state(fixture.path)?
  File.delete(fixture.path)?
  Ok(nil)
end

fn d4_core_member_wire(profile :: ClientProfile,
  credential :: DeviceCredential,
  signed :: borrow SignedPrekeySecrets) -> DirectoryEntry!String do
  let credential_wire = case encode_device_credential(credential) do
    Err(_) -> return Err("d4_fixture_member_credential_encoding")
    Ok(value) -> value
  end
  let wire = case encode_prekey_bundle(PrekeyBundle {
    version: 1,
    suite: 1,
    device_credential: credential_wire,
    identity_dh_public_key: credential.dh_public_key,
    signing_public_key: credential.signing_public_key,
    signed_prekey_id: signed.id,
    signed_prekey: signed.public_key.bytes,
    signed_prekey_signature: signed.signature.bytes,
    one_time_prekey_id: wide(0)?,
    one_time_prekey: Bytes.empty(),
    post_quantum_prekey: Bytes.empty(),
    supported_suites: [1],
    expires_at: signed.expires_at,
    extensions: []
  }) do
    Err(_) -> return Err("d4_fixture_member_bundle_encoding")
    Ok(value) -> value
  end
  let mailbox = case Crypto.random_bytes(32) do
    Err(_) -> return Err("d4_fixture_member_mailbox")
    Ok(value) -> value
  end
  Ok(%{profile.entry | prekey_bundle: wire, mailbox_token: mailbox})
end

fn d4_core_member_entry(profile :: ClientProfile,
  account :: borrow AccountKeys,
  device :: borrow DeviceKeys,
  mode :: Int) -> DirectoryEntry!String do
  let now = current_time()?
  let expiry = if mode == 2 do
    profile.credential.created_at
  else
    U64.add(now, wide(600000)?)?
  end
  let credential = case issue_device_credential(account,
    device,
    profile.credential.capabilities,
    profile.credential.created_at,
    expiry,
    profile.account.directory_sequence) do
    Err(_) -> return Err("d4_fixture_member_credential")
    Ok(value) -> value
  end
  let signed = case generate_signed_prekey(device, credential, wide(9)?, expiry) do
    Err(_) -> return Err("d4_fixture_member_prekey")
    Ok(value) -> value
  end
  let result = d4_core_member_wire(profile, credential, signed)
  Secret.destroy(signed.private_key)
  result
end

fn d4_core_member_with_key(profile :: ClientProfile,
  path :: String,
  mode :: Int,
  key :: borrow StorageKey) -> DirectoryEntry!String do
  let account = open_account(profile, key, path)?
  let opened = if mode == 1 do
    case generate_device() do
      Err(_) -> Err("d4_fixture_member_device")
      Ok(value)
    end
  else
    open_device(profile, key, path)
  end
  let result = case opened do
    Err(error)
    Ok(device) -> do
      let built = d4_core_member_entry(profile, account, device, mode)
      d4_core_drop_device(device)
      built
    end
  end
  Secret.destroy(account.private_key)
  result
end

fn d4_core_member(profile :: ClientProfile,
  path :: String,
  mode :: Int) -> Result<(DirectoryEntry, List<Bytes>), String> do
  if mode == 0 do
    return Ok((profile.entry, []))
  end
  let key = platform_key()?
  let result = d4_core_member_with_key(profile, path, mode, key)
  Secret.destroy(key)
  let entry = result?
  Ok((entry,
    if mode == 1 do
      [profile.device_id]
    else
      []
    end))
end

# Consume the aggregate once; existing affine cleanup destroys both key fields.
fn d4_core_drop_device(device :: consume DeviceKeys) do
  nil
end

pub fn d4_core_install_direct_history(f :: D4CoreFixture) -> Result<(), String> do
  let profile = decode_client_profile(f.public_profile)?
  let selected = repeated(71, 16)?
  let unrelated = repeated(72, 16)?
  let session = repeated(21, 32)?
  let other_session = repeated(22, 32)?
  let selected_label = "session/v1/#{Bytes.to_hex(session)}"
  let unrelated_label = "session/v1/#{Bytes.to_hex(other_session)}"
  let other_history = "history/v1/#{Bytes.to_hex(unrelated)}"
  let metadata = d4_core_direct_metadata(profile, selected, repeated(37, 32)?, repeated(38, 16)?)?
  let other_metadata = d4_core_direct_metadata(profile,
    unrelated,
    repeated(47, 32)?,
    repeated(48, 16)?)?
  let wire = d4_core_direct_wire(profile,
    selected,
    repeated(38, 16)?,
    repeated(24, 16)?,
    f.now,
    "actual captured canonical direct text")?
  let other_wire = d4_core_direct_wire(profile,
    unrelated,
    repeated(48, 16)?,
    repeated(25, 16)?,
    f.now,
    "UNSELECTED HISTORY MUST REMAIN OUTSIDE BACKUP")?
  let key = platform_key()?
  let prepared = d4_core_direct_blobs(Bytes.concat(session, other_session)?,
    selected_label,
    unrelated_label,
    metadata,
    other_metadata,
    wire,
    other_wire,
    f.source_label,
    other_history,
    key)
  Secret.destroy(key)
  store_updated_blobs(f.path,
    ["sessions/v1", selected_label, unrelated_label, f.source_label, other_history],
    prepared?)
end

fn d4_core_direct_metadata(profile :: ClientProfile,
  conversation :: Bytes,
  peer :: Bytes,
  peer_device :: Bytes) -> Bytes!String do
  mobile_join(for value in [
      Bytes.from_utf8("OPAQUE SNAPSHOT MUST NEVER BE RESTORED OR EXPORTED"),
      profile.account_id,
      profile.device_id,
      peer,
      peer_device,
      Bytes.from_utf8("peer"),
      repeated(39, 32)?,
      conversation,
      mobile_byte(0)?,
      mobile_byte(0)?,
      mobile_byte(0)?,
      mobile_byte(0)?,
      mobile_write_u32(0)?,
      mobile_byte(1)?,
      repeated(0, 64)?,
      repeated(0, 32)?
    ] do
      mobile_vector(value)?
    end,
    0,
    Bytes.empty())
end

fn d4_core_direct_wire(profile :: ClientProfile,
  conversation :: Bytes,
  peer_device :: Bytes,
  id :: Bytes,
  timestamp :: U64,
  text :: String) -> Bytes!String do
  encode_history([
    MobileHistoryEntry {
      attachment_kind: HistoryOrdinary,
      direction: 1,
      inner: InnerEnvelope {
        version: 1,
        sender_account_id: profile.account_id,
        sender_device_id: profile.device_id,
        recipient_device_id: peer_device,
        conversation_id: conversation,
        client_message_id: id,
        client_timestamp: timestamp,
        message_type: 1,
        body: Bytes.from_utf8(text),
        reply_reference: Bytes.empty(),
        attachment_manifest: Bytes.empty(),
        receipt_policy: 0,
        disappearing_seconds: 0,
        extensions: []
      }
    }
  ])
end

pub fn d4_core_corrupt_direct_history(f :: D4CoreFixture) -> Bytes!String do
  let key = platform_key()?
  let prepared = seal_history_blob(Bytes.from_utf8("badparse"), key, f.source_label)
  Secret.destroy(key)
  let blob = prepared?
  store_updated_blobs(f.path, [f.source_label], [blob])?
  Ok(blob)
end

fn d4_core_direct_blobs(index :: Bytes,
  selected_label :: String,
  unrelated_label :: String,
  metadata :: Bytes,
  other_metadata :: Bytes,
  wire :: Bytes,
  other_wire :: Bytes,
  history_label :: String,
  other_history :: String,
  key :: borrow StorageKey) -> List<Bytes>!String do
  Ok([
    seal_local(index, key, local_context("sessions/v1")?)?,
    seal_local(metadata, key, local_context(selected_label)?)?,
    seal_local(other_metadata, key, local_context(unrelated_label)?)?,
    seal_history_blob(wire, key, history_label)?,
    seal_history_blob(other_wire, key, other_history)?
  ])
end

fn d4_core_created_oracle(f :: D4CoreFixture,
  created :: PortableBackupV2Created,
  started :: U64,
  finished :: U64) -> Bool!String do
  let public_id = d4_core_backup_id(created.wire)?
  let payload = case restore_portable_backup(created.recovery_code, created.wire) do
    Err(_) -> return Err("d4_fixture_restore")
    Ok(value) -> value
  end
  d4_core_payload_oracle(f, public_id, payload, started, finished)
end

fn d4_core_payload_oracle(f :: D4CoreFixture,
  public_id :: Bytes,
  payload :: Plaintext<Bytes>,
  started :: U64,
  finished :: U64) -> Bool!String do
  let profile = decode_client_profile(f.public_profile)?
  let realm = Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-backup-service-realm/v1\n"),
    Bytes.concat(Bytes.from_utf8("https://core.example"), f.config.service_public_key)?)?)
  let archive = case decode_text_archive(payload) do
    Err(_) -> return Err("d4_fixture_archive_schema")
    Ok(value) -> value
  end
  let expected = case encode_text_archive(BackupTextArchive {
    backup_id: public_id,
    owner_account: profile.account_id,
    owner_authorization_key: profile.account.authorization_public_key,
    service_realm: realm,
    created_at: archive.created_at,
    candidate_count: 1,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 0,
    scopes: [
      BackupArchiveScope {
        kind: 1,
        id: repeated(71, 16)?,
        peer: repeated(37, 32)?,
        name: "",
        entries: [
          BackupArchiveRecord {
            ordinal: 0,
            direction: 1,
            message_id: repeated(24, 16)?,
            sender_account: profile.account_id,
            sender_device: profile.device_id,
            timestamp: f.now,
            attachment_omitted: false,
            text: Bytes.from_utf8("actual captured canonical direct text")
          }
        ]
      }
    ]
  }) do
    Err(_) -> return Err("d4_fixture_expected_archive")
    Ok(value) -> value
  end
  Ok(U64.compare(archive.created_at, started) >= 0
    && U64.compare(archive.created_at, finished) <= 0
    && Bytes.secure_equals(payload, expected))
end

# Only explicitly authored synthetic fixture data can reach this test-only site.
pub fn d4_core_created_matches(f :: D4CoreFixture,
  created :: PortableBackupV2Created,
  started :: U64,
  finished :: U64) -> Bool do
  let matches = case d4_core_created_oracle(f, created, started, finished) do
    Err(_) -> false
    Ok(value) -> value
  end
  d4_core_observe_synthetic(matches)
end

pub fn d4_core_stored_matches(f :: D4CoreFixture,
  id :: Bytes,
  raw :: Result<Plaintext<Bytes>, String>) -> Bool do
  let matches = case raw do
    Err(_) -> false
    Ok(payload) -> case d4_core_payload_oracle(f, id, payload, f.now, f.now) do
      Err(_) -> false
      Ok(value) -> value
    end
  end
  d4_core_observe_synthetic(matches)
end

fn d4_core_observe_synthetic(matches :: Bool) -> Bool do
  declassify(matches,
    "TEST ONLY authored synthetic backup owner admission or refusal and canonical payload owner scope record equality and bounded creation-time predicate; no real history hash key or arbitrary error is disclosed")
end

pub fn d4_core_backup_id(wire :: Bytes) -> Bytes!String do
  case Bytes.slice(wire, 38, 32) do
    Err(_) -> Err("d4_fixture_wire_id")
    Ok(value)
  end
end

pub fn d4_core_import_bundle(f :: D4CoreFixture,
  foreign :: Bool) -> PortableBackupV2Created!String do
  let profile = decode_client_profile(f.public_profile)?
  let owner = if foreign do
    repeated(61, 32)?
  else
    profile.account_id
  end
  let authorization = if foreign do
    repeated(63, 32)?
  else
    profile.account.authorization_public_key
  end
  let device = if foreign do
    repeated(62, 16)?
  else
    profile.device_id
  end
  let realm = Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-backup-service-realm/v1\n"),
    Bytes.concat(Bytes.from_utf8("https://core.example"), f.config.service_public_key)?)?)
  let content :: Plaintext<PortableBackupV2Content> = PortableBackupV2Content {
    owner_account: owner,
    owner_authorization_key: authorization,
    service_realm: realm,
    candidate_count: 1,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 0,
    scopes: [
      BackupArchiveScope {
        kind: 1,
        id: repeated(71, 16)?,
        peer: repeated(37, 32)?,
        name: "",
        entries: [
          BackupArchiveRecord {
            ordinal: 0,
            direction: 1,
            message_id: repeated(24, 16)?,
            sender_account: owner,
            sender_device: device,
            timestamp: f.now,
            attachment_omitted: false,
            text: Bytes.from_utf8("actual captured canonical direct text")
          }
        ]
      }
    ]
  }
  case create_portable_backup_v2(content, f.now) do
    Err(_) -> Err("d4_fixture_portable_create")
    Ok(value)
  end
end

from Backups.Protocol import (
  BackupProfile,
  BackupManifest,
  create_backup_profile,
  derive_backup_key,
  seal_backup_manifest,
  seal_backup_chunk
)
from Backups.Recovery import create_backup_recovery
from Backups.FileBundle import BackupFileBundle, encode_backup_file

# Independent authenticated Wire-v1 builder. It deliberately reuses a public
# backup ID; no root-accepting v2 production API or caller write plan is added.
pub fn d4_core_legacy_import_bundle(f :: D4CoreFixture,
  backup_id :: Bytes,
  conflict :: Bool) -> PortableBackupV2Created!String do
  let profile = decode_client_profile(f.public_profile)?
  let realm = Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-backup-service-realm/v1\n"),
    Bytes.concat(Bytes.from_utf8("https://core.example"), f.config.service_public_key)?)?)
  let text = if conflict do
    "authenticated conflicting payload under the same backup id"
  else
    "actual captured canonical direct text"
  end
  let payload = case encode_text_archive(BackupTextArchive {
    backup_id: backup_id,
    owner_account: profile.account_id,
    owner_authorization_key: profile.account.authorization_public_key,
    service_realm: realm,
    created_at: f.now,
    candidate_count: 1,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 0,
    scopes: [
      BackupArchiveScope {
        kind: 1,
        id: repeated(71, 16)?,
        peer: repeated(37, 32)?,
        name: "",
        entries: [
          BackupArchiveRecord {
            ordinal: 0,
            direction: 1,
            message_id: repeated(24, 16)?,
            sender_account: profile.account_id,
            sender_device: profile.device_id,
            timestamp: f.now,
            attachment_omitted: false,
            text: Bytes.from_utf8(text)
          }
        ]
      }
    ]
  }) do
    Err(_) -> return Err("d4_fixture_legacy_payload")
    Ok(value) -> value
  end
  let kdf = case create_backup_profile() do
    Err(_) -> return Err("d4_fixture_legacy_profile")
    Ok(value) -> value
  end
  let (root, code) = case create_backup_recovery() do
    Err(_) -> return Err("d4_fixture_legacy_recovery")
    Ok(value) -> value
  end
  let derived = derive_backup_key(root, kdf)
  Secret.destroy(root)
  let master = case derived do
    Err(_) -> return Err("d4_fixture_legacy_derive")
    Ok(value) -> value
  end
  let prepared = d4_core_legacy_seal(master, kdf, backup_id, f.now, payload)
  Secret.destroy(master)
  Ok(PortableBackupV2Created { wire: prepared?, recovery_code: code })
end

fn d4_core_legacy_seal(master :: borrow SecretBytes,
  profile :: BackupProfile,
  backup_id :: Bytes,
  created_at :: U64,
  payload :: Bytes) -> Bytes!String do
  let manifest = BackupManifest {
    version: 1,
    backup_id: backup_id,
    created_at: created_at,
    chunk_size: 65536,
    chunk_count: 1,
    plaintext_size: Bytes.length(payload),
    snapshot_hash: Crypto.sha256(payload)
  }
  let sealed = case seal_backup_manifest(master, profile, manifest) do
    Err(_) -> return Err("d4_fixture_legacy_manifest")
    Ok(value) -> value
  end
  let chunk = case seal_backup_chunk(master, manifest, 0, payload) do
    Err(_) -> return Err("d4_fixture_legacy_chunk")
    Ok(value) -> value
  end
  case encode_backup_file(BackupFileBundle { manifest: sealed, chunks: [chunk] }) do
    Err(_) -> Err("d4_fixture_legacy_file")
    Ok(value)
  end
end

from Storage.Records import with_record_transaction, put_blobs, delete_blob
from Storage.Blobs import blob_record_hash

pub fn d4_core_restore_fixture_index(f :: D4CoreFixture,
  id :: Bytes,
  previous_index :: Bytes) -> Result<(), String> do
  let row = "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(id)}"
  let index = "backup-archives/v1/#{Bytes.to_hex(f.account_id)}"
  with_record_transaction(f.path,
    fn(database) do
      delete_blob(database, row)?
      put_blobs(database, [index], [previous_index], 0)
    end)
end

pub fn d4_core_index_fault(f :: D4CoreFixture, install :: Bool) -> Result<(), String> do
  let index = "backup-archives/v1/#{Bytes.to_hex(f.account_id)}"
  with_record_transaction(f.path,
    fn(database) do
      if install do
        let hash = blob_record_hash(database, index)?
        Sqlite.execute(database,
          "CREATE TRIGGER d4_backup_index_fault BEFORE INSERT ON encrypted_blobs WHEN NEW.record_hash = '#{hash}' BEGIN SELECT RAISE(ABORT, 'd4_index_write_fault'); END",
          [])?
      else
        Sqlite.execute(database, "DROP TRIGGER d4_backup_index_fault", [])?
      end
      Ok(nil)
    end)
end

from Protocol.V1 import ProtocolExtension
from Mobile.Codec import encode_output_list, mobile_write_u64
from Mobile.GroupState import group_history_label, group_state_label
from Storage.AccountGuard import load_account_basis_bounded

pub fn d4_core_synthetic_content(f :: D4CoreFixture,
  scopes :: List<BackupArchiveScope>,
  candidates :: Int,
  timed :: Int,
  unknown :: Int,
  nontext :: Int,
  empty :: Int,
  attachments :: Int) -> PortableBackupV2Content!String do
  let profile = decode_client_profile(f.public_profile)?
  let realm = Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-backup-service-realm/v1\n"),
    Bytes.concat(Bytes.from_utf8("https://core.example"), f.config.service_public_key)?)?)
  Ok(PortableBackupV2Content {
    owner_account: profile.account_id,
    owner_authorization_key: profile.account.authorization_public_key,
    service_realm: realm,
    candidate_count: candidates,
    omitted_timed: timed,
    omitted_unknown: unknown,
    omitted_nontext: nontext,
    omitted_empty: empty,
    attachment_messages: attachments,
    scopes: scopes
  })
end

fn d4_core_content_payload(content :: PortableBackupV2Content,
  id :: Bytes,
  time :: U64) -> Bytes!String do
  case encode_text_archive(BackupTextArchive {
    backup_id: id,
    owner_account: content.owner_account,
    owner_authorization_key: content.owner_authorization_key,
    service_realm: content.service_realm,
    created_at: time,
    candidate_count: content.candidate_count,
    omitted_timed: content.omitted_timed,
    omitted_unknown: content.omitted_unknown,
    omitted_nontext: content.omitted_nontext,
    omitted_empty: content.omitted_empty,
    attachment_messages: content.attachment_messages,
    scopes: content.scopes
  }) do
    Err(_) -> Err("d4_fixture_content_encode")
    Ok(value)
  end
end

fn d4_core_content_oracle(created :: PortableBackupV2Created,
  expected :: PortableBackupV2Content,
  started :: U64,
  finished :: U64) -> Bool!String do
  let payload = case restore_portable_backup(created.recovery_code, created.wire) do
    Err(_) -> return Err("d4_fixture_content_restore")
    Ok(value) -> value
  end
  let decoded = case decode_text_archive(payload) do
    Err(_) -> return Err("d4_fixture_content_decode")
    Ok(value) -> value
  end
  let id = d4_core_backup_id(created.wire)?
  Ok(U64.compare(decoded.created_at, started) >= 0
    && U64.compare(decoded.created_at, finished) <= 0
    && Bytes.secure_equals(payload, d4_core_content_payload(expected, id, decoded.created_at)?))
end

pub fn d4_core_content_matches(created :: PortableBackupV2Created,
  expected :: PortableBackupV2Content,
  started :: U64,
  finished :: U64) -> Bool do
  let matches = case d4_core_content_oracle(created, expected, started, finished) do
    Err(_) -> false
    Ok(value) -> value
  end
  d4_core_observe_synthetic(matches)
end

fn d4_core_matrix_row(profile :: ClientProfile, index :: Int) -> MobileHistoryEntry!String do
  let timestamp = if index == 0 do
    "9"
  else if index == 1 do
    "10"
  else if index == 2 do
    "20"
  else if index == 9 do
    "21"
  else
    "15"
  end
  let text = if index == 1 do
    "at-start"
  else if index == 2 do
    "at-end"
  else if index == 6 || index == 7 do
    ""
  else
    "must-not-be-exported"
  end
  Ok(MobileHistoryEntry {
    attachment_kind: HistoryOrdinary,
    direction: 1,
    inner: InnerEnvelope {
      version: 1,
      sender_account_id: profile.account_id,
      sender_device_id: profile.device_id,
      recipient_device_id: repeated(38, 16)?,
      conversation_id: repeated(71, 16)?,
      client_message_id: repeated(index + 30, 16)?,
      client_timestamp: U64.parse(timestamp)?,
      message_type: if index == 4 do
        99
      else if index == 5 do
        2
      else
        1
      end,
      body: Bytes.from_utf8(text),
      reply_reference: Bytes.empty(),
      attachment_manifest: if index == 3 || index == 4 || index == 5 || index == 7 do
        Bytes.from_utf8("opaque attachment reference")
      else
        Bytes.empty()
      end,
      receipt_policy: 0,
      disappearing_seconds: if index == 3 do
        1
      else
        0
      end,
      extensions: if index == 8 do
        [
          ProtocolExtension {
            id: 9,
            mandatory: false,
            value: Bytes.from_utf8("unknown optional policy")
          }
        ]
      else
        []
      end
    }
  })
end

pub fn d4_core_install_matrix(f :: D4CoreFixture) -> Result<(), String> do
  d4_core_install_direct_history(f)?
  let profile = decode_client_profile(f.public_profile)?
  let rows = for index in 0..10 do
    d4_core_matrix_row(profile, index)?
  end
  let wire = encode_history(rows)?
  let key = platform_key()?
  let sealed = seal_history_blob(wire, key, f.source_label)
  Secret.destroy(key)
  store_updated_blobs(f.path, [f.source_label], [sealed?])
end

pub fn d4_core_matrix_content(f :: D4CoreFixture) -> PortableBackupV2Content!String do
  let profile = decode_client_profile(f.public_profile)?
  let records = for index in [1, 2, 7] do
    let row = d4_core_matrix_row(profile, index)?
    BackupArchiveRecord {
      ordinal: index,
      direction: 1,
      message_id: row.inner.client_message_id,
      sender_account: profile.account_id,
      sender_device: profile.device_id,
      timestamp: row.inner.client_timestamp,
      attachment_omitted: index == 7,
      text: row.inner.body
    }
  end
  d4_core_synthetic_content(f,
    [
      BackupArchiveScope {
        kind: 1,
        id: repeated(71, 16)?,
        peer: repeated(37, 32)?,
        name: "",
        entries: records
      }
    ],
    8,
    1,
    2,
    1,
    1,
    4)
end

fn d4_core_group_wire(profile :: ClientProfile, fields :: Int, duplicate :: Bool) -> Bytes!String do
  let records = for ordinal in 0..2 do
    encode_output_list([
      mobile_byte(1)?,
      mobile_byte(if ordinal == 0 do
        1
      else
        2
      end)?,
      mobile_write_u64(U64.parse("1")?)?,
      if ordinal == 0 do
        profile.account_id
      else
        repeated(37, 32)?
      end,
      if ordinal == 0 do
        profile.device_id
      else
        repeated(38, 16)?
      end,
      mobile_write_u64(U64.parse("17")?)?,
      Bytes.from_utf8(if ordinal == 0 do
        "first legacy group text"
      else
        "second legacy group text"
      end)
    ]
      ++ if fields >= 8 do
        [Bytes.empty()]
      else
        []
      end
      ++ if fields >= 9 do
        [
          repeated(if duplicate do
              41
            else
              41 + ordinal
            end,
            32)?
        ]
      else
        []
      end)?
  end
  encode_output_list(records)
end

fn d4_core_group_blobs(profile :: ClientProfile,
  id :: Bytes,
  fields :: Int,
  duplicate :: Bool,
  key :: borrow StorageKey) -> List<Bytes>!String do
  Ok([
    seal_local(d4_core_group_wire(profile, fields, duplicate)?,
      key,
      local_context(group_history_label(id))?)?
  ])
end

pub fn d4_core_install_group(f :: D4CoreFixture,
  id :: Bytes,
  fields :: Int,
  duplicate :: Bool) -> Result<(), String> do
  let profile = decode_client_profile(f.public_profile)?
  let key = platform_key()?
  let blobs = d4_core_group_blobs(profile, id, fields, duplicate, key)
  Secret.destroy(key)
  store_updated_blobs(f.path, [group_history_label(id)], blobs?)
end

pub fn d4_core_group_content(f :: D4CoreFixture,
  id :: Bytes,
  fields :: Int) -> PortableBackupV2Content!String do
  let profile = decode_client_profile(f.public_profile)?
  let records = for ordinal in 0..2 do
    BackupArchiveRecord {
      ordinal: ordinal,
      direction: if ordinal == 0 do
        1
      else
        2
      end,
      message_id: if fields < 9 do
        Bytes.empty()
      else
        repeated(41 + ordinal, 32)?
      end,
      sender_account: if ordinal == 0 do
        profile.account_id
      else
        repeated(37, 32)?
      end,
      sender_device: if ordinal == 0 do
        profile.device_id
      else
        repeated(38, 16)?
      end,
      timestamp: U64.parse("17")?,
      attachment_omitted: false,
      text: Bytes.from_utf8(if ordinal == 0 do
        "first legacy group text"
      else
        "second legacy group text"
      end)
    }
  end
  d4_core_synthetic_content(f,
    [BackupArchiveScope { kind: 2, id: id, peer: Bytes.empty(), name: "", entries: records }],
    2,
    0,
    0,
    0,
    0,
    0)
end

fn d4_core_max_content(f :: D4CoreFixture) -> PortableBackupV2Content!String do
  let profile = decode_client_profile(f.public_profile)?
  let text = repeated(65, 65346)?
  let first = for ordinal in 0..256 do
    BackupArchiveRecord {
      ordinal: ordinal,
      direction: 1,
      message_id: Bytes.empty(),
      sender_account: profile.account_id,
      sender_device: profile.device_id,
      timestamp: f.now,
      attachment_omitted: false,
      text: text
    }
  end
  let last = BackupArchiveRecord {
    ordinal: 0,
    direction: 1,
    message_id: Bytes.empty(),
    sender_account: profile.account_id,
    sender_device: profile.device_id,
    timestamp: f.now,
    attachment_omitted: false,
    text: repeated(66, 29864)?
  }
  d4_core_synthetic_content(f,
    [
      BackupArchiveScope {
        kind: 2,
        id: repeated(6, 32)?,
        peer: Bytes.empty(),
        name: "",
        entries: first
      },
      BackupArchiveScope {
        kind: 2,
        id: repeated(7, 32)?,
        peer: Bytes.empty(),
        name: "",
        entries: [last]
      }
    ],
    257,
    0,
    0,
    0,
    0,
    0)
end

pub fn d4_core_max_bundle(f :: D4CoreFixture) -> PortableBackupV2Created!String do
  let content :: Plaintext<PortableBackupV2Content> = d4_core_max_content(f)?
  case create_portable_backup_v2(content, f.now) do
    Err(_) -> Err("d4_fixture_max_create")
    Ok(value)
  end
end

fn d4_core_max_payload_oracle(f :: D4CoreFixture,
  id :: Bytes,
  raw :: Result<Plaintext<Bytes>, String>) -> Bool!String do
  let payload :: Plaintext<Bytes> = raw?
  let expected = d4_core_content_payload(d4_core_max_content(f)?, id, f.now)?
  Ok(Bytes.length(payload) == 16777216 && Bytes.secure_equals(payload, expected))
end

pub fn d4_core_max_read_matches(f :: D4CoreFixture,
  id :: Bytes,
  raw :: Result<Plaintext<Bytes>, String>) -> Bool do
  let matches = case d4_core_max_payload_oracle(f, id, raw) do
    Err(_) -> false
    Ok(value) -> value
  end
  d4_core_observe_synthetic(matches)
end

pub struct D4CoreCipherRow do
  hash :: String
  ciphertext :: Bytes
end

pub struct D4CoreAllRows do
  rows :: List<D4CoreCipherRow>
  index_metadata :: Bytes
end

pub fn d4_core_all_rows(f :: D4CoreFixture) -> D4CoreAllRows!String do
  let database = case Sqlite.open(f.path) do
    Err(_) -> return Err("d4_fixture_snapshot_open")
    Ok(value) -> value
  end
  let raw_rows = Sqlite.query_values_v2(database,
    "SELECT record_hash, ciphertext FROM encrypted_blobs ORDER BY record_hash",
    [],
    33554432)
  let raw_index = Sqlite.query_values(database,
    "SELECT database_id, key_check FROM encrypted_blob_index",
    [])
  Sqlite.close(database)
  let rows = for row in raw_rows? do
    case (Map.get(row, "record_hash"), Map.get(row, "ciphertext")) do
      (Text(hash), Binary(value)) -> D4CoreCipherRow { hash: hash, ciphertext: value }
      _ -> return Err("d4_fixture_snapshot_shape")
    end
  end
  let metadata = raw_index?
  if List.length(metadata) != 1 do
    return Err("d4_fixture_snapshot_index")
  end
  let index_metadata = case (Map.get(List.head(metadata), "database_id"),
    Map.get(List.head(metadata), "key_check")) do
    (Binary(id), Binary(check)) -> append(id, check)?
    _ -> return Err("d4_fixture_snapshot_index")
  end
  Ok(D4CoreAllRows { rows: rows, index_metadata: index_metadata })
end

pub fn d4_core_rows_preserved(before :: D4CoreAllRows,
  changed :: D4CoreAllRows,
  added :: Int) -> Bool do
  List.length(changed.rows) == List.length(before.rows) + added
    && Bytes.secure_equals(before.index_metadata, changed.index_metadata)
    && List.all(before.rows,
      fn(old) -> List.any(changed.rows,
        fn(current) -> current.hash == old.hash
          && Bytes.secure_equals(current.ciphertext, old.ciphertext) end) end)
end

from MobileCore import group_create_export
from Groups.GroupSnapshot import group_snapshot, restore_group
from Groups.Membership import create_group
from Groups.Mls import GroupError, GroupState, GroupSnapshotOutcome, GroupTransparencyPolicy
from Groups.Tree import GroupMember

fn d4_core_group_repeat(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn d4_core_group_wide(value :: Int) -> U64!GroupError do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err(InvalidGroup)
    Ok(output)
  end
end

fn d4_core_group_drop(state :: consume GroupState) do
  nil
end

# Assertion-free fixture constructor: real public member, actual MLS group,
# and actual sealed snapshot under the caller's retained storage-key owner.
fn d4_core_custody_snapshot(key :: borrow StorageKey,
  account :: Bytes,
  device :: Bytes,
  set_id :: Bytes) -> Result<(Bytes, Bytes), GroupError> do
  let signing = case Crypto.signing_generate() do
    Err(error) -> return Err(CryptoFailure(error))
    Ok(value) -> value
  end
  let initial = case Crypto.x25519_generate() do
    Err(error) -> return Err(CryptoFailure(error))
    Ok(value) -> value
  end
  let leaf = case Crypto.x25519_generate() do
    Err(error) -> return Err(CryptoFailure(error))
    Ok(value) -> value
  end
  let checkpoint = d4_core_group_repeat(73, 32)
  let member = GroupMember {
    version: 1,
    account_id: account,
    device_id: device,
    signing_public_key: signing.public_key,
    init_public_key: initial.public_key,
    leaf_public_key: leaf.public_key,
    mailbox_token: d4_core_group_repeat(41, 32),
    directory_sequence: d4_core_group_wide(5)?,
    transparency_checkpoint_hash: checkpoint,
    witness_count: 2,
    extensions: [1]
  }
  Secret.destroy(signing.private_key)
  Secret.destroy(initial.private_key)
  let policy = GroupTransparencyPolicy {
    minimum_directory_sequence: d4_core_group_wide(4)?,
    checkpoint_hash: checkpoint,
    witness_threshold: 2,
    set_id: set_id
  }
  let state = create_group(member, leaf.private_key, [1], policy)?
  let group_id = state.group_id
  case group_snapshot(state, key, account, device, d4_core_group_wide(1)?) do
    GroupSnapshotRejected(rejected, error) -> do
      d4_core_group_drop(rejected)
      Err(error)
    end
    GroupSnapshotSealed(saved, blob) -> do
      d4_core_group_drop(saved)
      Ok((group_id, blob))
    end
  end
end

pub fn d4_core_actual_group(f :: D4CoreFixture) -> Bytes!String do
  group_create_export(Bytes.from_utf8(f.path))
end

fn d4_core_group_identity(state :: borrow GroupState, id :: Bytes) -> Bool do
  Bytes.secure_equals(state.group_id, id)
end

fn d4_core_state_history_blobs(f :: D4CoreFixture,
  key :: borrow StorageKey,
  id :: Bytes,
  state :: Option<Bytes>,
  sender :: Bytes) -> List<Bytes>!String do
  let profile = decode_client_profile(f.public_profile)?
  let entry = encode_output_list([
    mobile_byte(1)?,
    mobile_byte(1)?,
    mobile_write_u64(U64.parse("0")?)?,
    sender,
    profile.device_id,
    mobile_write_u64(U64.parse("17")?)?,
    Bytes.from_utf8("authored group source owner row"),
    Bytes.empty(),
    repeated(41, 32)?
  ])?
  let index = encode_output_list([id])?
  let history = seal_local(encode_output_list([entry])?,
    key,
    local_context(group_history_label(id))?)?
  case state do
    None -> Ok([history])
    Some(raw) -> Ok([
      seal_local(index, key, local_context("groups/v1")?)?,
      seal_local(raw, key, local_context(group_state_label(id)?)?)?,
      history
    ])
  end
end

pub fn d4_core_replace_group_history(f :: D4CoreFixture,
  id :: Bytes,
  sender :: Bytes) -> Result<(), String> do
  let key = platform_key()?
  let blobs = d4_core_state_history_blobs(f, key, id, None, sender)
  Secret.destroy(key)
  store_updated_blobs(f.path, [group_history_label(id)], blobs?)
end

pub fn d4_core_malformed_group(f :: D4CoreFixture) -> Bytes!String do
  let id = d4_core_actual_group(f)?
  let key = platform_key()?
  let blobs = d4_core_state_history_blobs(f,
    key,
    id,
    Some(Bytes.from_utf8("authenticated outer text is not a group snapshot")),
    f.account_id)
  Secret.destroy(key)
  store_updated_blobs(f.path,
    ["groups/v1", group_state_label(id)?, group_history_label(id)],
    blobs?)?
  Ok(id)
end

fn d4_core_foreign_group_on(f :: D4CoreFixture,
  key :: borrow StorageKey) -> Result<(Bytes, List<Bytes>), String> do
  let account = repeated(61, 32)?
  let device = repeated(62, 16)?
  let (id, snapshot) = case d4_core_custody_snapshot(key, account, device, Bytes.empty()) do
    Err(_) -> return Err("d4_fixture_foreign_group_create")
    Ok(value) -> value
  end
  let restored = case restore_group(snapshot, key, account, device, U64.parse("1")?) do
    Err(_) -> return Err("d4_fixture_foreign_group_restore")
    Ok(value) -> value
  end
  let matched = d4_core_group_identity(restored, id)
  d4_core_group_drop(restored)
  if !matched do
    return Err("d4_fixture_foreign_group_identity")
  end
  Ok((id, d4_core_state_history_blobs(f, key, id, Some(snapshot), f.account_id)?))
end

pub fn d4_core_foreign_group(f :: D4CoreFixture) -> Bytes!String do
  let key = platform_key()?
  let ready = d4_core_foreign_group_on(f, key)
  Secret.destroy(key)
  let (id, blobs) = ready?
  store_updated_blobs(f.path,
    ["groups/v1", group_state_label(id)?, group_history_label(id)],
    blobs)?
  Ok(id)
end

pub fn d4_core_foreign_sent_content(f :: D4CoreFixture,
  id :: Bytes) -> PortableBackupV2Content!String do
  let profile = decode_client_profile(f.public_profile)?
  let row = BackupArchiveRecord {
    ordinal: 0,
    direction: 1,
    message_id: repeated(41, 32)?,
    sender_account: repeated(61, 32)?,
    sender_device: profile.device_id,
    timestamp: U64.parse("17")?,
    attachment_omitted: false,
    text: Bytes.from_utf8("authored group source owner row")
  }
  d4_core_synthetic_content(f,
    [BackupArchiveScope { kind: 2, id: id, peer: Bytes.empty(), name: "", entries: [row] }],
    1,
    0,
    0,
    0,
    0,
    0)
end

pub fn d4_core_foreign_sent_bundle(f :: D4CoreFixture,
  id :: Bytes) -> PortableBackupV2Created!String do
  let content :: Plaintext<PortableBackupV2Content> = d4_core_foreign_sent_content(f, id)?
  case create_portable_backup_v2(content, f.now) do
    Err(_) -> Err("d4_fixture_foreign_sent_bundle")
    Ok(value)
  end
end

fn d4_core_injected_foreign_blobs(f :: D4CoreFixture,
  key :: borrow StorageKey,
  id :: Bytes) -> List<Bytes>!String do
  let payload = d4_core_content_payload(d4_core_foreign_sent_content(f, repeated(81, 32)?)?,
    id,
    f.now)?
  let row = "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(id)}"
  let index_label = "backup-archives/v1/#{Bytes.to_hex(f.account_id)}"
  let index = mobile_join([
      mobile_byte(1)?,
      Bytes.from_utf8("BAI"),
      mobile_byte(1)?,
      id,
      Crypto.sha256(payload),
      mobile_write_u64(f.now)?
    ],
    0,
    Bytes.empty())?
  let raw_archive = seal_history_blob(payload, key, row)
  let raw_index = seal_local(index, key, local_context(index_label)?)
  Ok([raw_archive?, raw_index?])
end

pub fn d4_core_inject_foreign_sent(f :: D4CoreFixture, id :: Bytes) -> Result<(), String> do
  let key = platform_key()?
  let ready = d4_core_injected_foreign_blobs(f, key, id)
  Secret.destroy(key)
  store_updated_blobs(f.path,
    [
      "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(id)}",
      "backup-archives/v1/#{Bytes.to_hex(f.account_id)}"
    ],
    ready?)
end

pub fn d4_core_read_refused(raw :: Result<Plaintext<Bytes>, String>) -> Bool do
  let refused = case raw do
    Err(_) -> true
    Ok(_) -> false
  end
  d4_core_observe_synthetic(refused)
end
