from Binary.Reader import BinaryReader, finish, reader
from Mobile.Codec import (
  current_time,
  mobile_append,
  mobile_byte,
  mobile_join,
  mobile_read_byte,
  mobile_read_u32,
  mobile_utf8,
  mobile_vector,
  mobile_write_u32,
  take_fixed,
  take_vector
)
from Mobile.DeviceSet import verified_device_set
from Mobile.Platform import native_security_config
from Mobile.Types import (
  MobilePayloadRequest,
  MobileReadBytes,
  MobileSecurityConfig,
  MobileTransparencyManifest,
  MobileTransparencyRequest,
  MobileTransparencyStorage,
  MobileTransparencyView,
  MobileVerifiedDeviceSet,
  MobileVerifiedTransparencySet
)
from Protocol.V1 import AccountIdentity, DeviceCredential, DeviceSet, DirectoryEntry, PrekeyBundle
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.Records import store_updated_blobs
from Transparency.Client import checkpoint_fresh_at, verify_evidence
from Transparency.Merkle import (
  ConsistencyProof,
  TransparencyCheckpoint,
  WitnessKey,
  verify_checkpoint,
  verify_consistency
)
from Transparency.Wire import (
  TransparencyLookup,
  account_lookup_id,
  decode_checkpoint,
  decode_consistency_proof,
  decode_transparency_evidence,
  encode_checkpoint,
  encode_consistency_proof,
  encode_transparency_lookup
)
from Transport.Packet import ClientProfile

##! Mobile.Transparency implementation.

pub fn transparency_checkpoint_bytes(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes!String do
  let label = "transparency-checkpoint/v1"
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_local(blob, wrapping_key, local_context(label)?)
  end
end

pub fn transparency_device_set_label(account_id :: Bytes) -> String do
  "transparency-device-set/v1/#{Bytes.to_hex(account_id)}"
end

pub fn encode_verified_transparency_set(value :: MobileVerifiedTransparencySet) -> Bytes!String do
  if Bytes.length(value.checkpoint) != 188 || Bytes.length(value.device_set) == 0 || Bytes.length(value.device_set) > 305260 do
    Err("invalid_transparency_cache")
  else
    let checkpoint = decode_checkpoint(value.checkpoint)?
    if !Bytes.secure_equals(encode_checkpoint(checkpoint)?, value.checkpoint) do
      Err("invalid_transparency_cache")
    else
      mobile_join([
          mobile_byte(1)?,
          Bytes.from_utf8("KTS"),
          mobile_vector(value.checkpoint)?,
          mobile_vector(value.device_set)?
        ],
        0,
        Bytes.empty())
    end
  end
end

fn decode_verified_transparency_set(input :: Bytes) -> MobileVerifiedTransparencySet!String do
  case reader(input, 305460) do
    Err(_) -> Err("invalid_transparency_cache")
    Ok(state) -> do
      let version = take_fixed(state, 1)?
      let magic = take_fixed(version.state, 3)?
      let checkpoint = take_vector(magic.state, 188)?
      let device_set = take_vector(checkpoint.state, 305260)?
      case finish(device_set.state) do
        Err(_) -> Err("invalid_transparency_cache")
        Ok(_) -> do
          let value = MobileVerifiedTransparencySet {
            checkpoint: checkpoint.value,
            device_set: device_set.value
          }
          if mobile_read_byte(version.value)? != 1 || !Bytes.secure_equals(magic.value,
            Bytes.from_utf8("KTS")) || Bytes.length(checkpoint.value) != 188 || Bytes.length(device_set.value) == 0 || !Bytes.secure_equals(encode_verified_transparency_set(value)?,
            input) do
            Err("invalid_transparency_cache")
          else
            Ok(value)
          end
        end
      end
    end
  end
end

fn encode_transparency_view(value :: MobileTransparencyView) -> Bytes!String do
  if Bytes.length(value.checkpoint) != 188 || Bytes.length(value.consistency) == 0 || Bytes.length(value.consistency) > 131086 || Bytes.length(value.service_public_key) != 32 || Bytes.length(value.witness_a_public_key) != 32 || Bytes.length(value.witness_b_public_key) != 32 do
    Err("invalid_transparency_view")
  else
    let checkpoint = decode_checkpoint(value.checkpoint)?
    let consistency = decode_consistency_proof(value.consistency)?
    if !Bytes.secure_equals(encode_checkpoint(checkpoint)?, value.checkpoint) || !Bytes.secure_equals(encode_consistency_proof(consistency)?,
      value.consistency) do
      Err("invalid_transparency_view")
    else
      mobile_join([
          mobile_byte(1)?,
          Bytes.from_utf8("KTV"),
          value.service_public_key,
          value.witness_a_public_key,
          value.witness_b_public_key,
          mobile_vector(value.checkpoint)?,
          mobile_vector(value.consistency)?
        ],
        0,
        Bytes.empty())
    end
  end
end

fn decode_transparency_view(input :: Bytes) -> MobileTransparencyView!String do
  case reader(input, 131382) do
    Err(_) -> Err("invalid_transparency_view")
    Ok(state) -> do
      let version = take_fixed(state, 1)?
      let magic = take_fixed(version.state, 3)?
      let service_key = take_fixed(magic.state, 32)?
      let witness_a = take_fixed(service_key.state, 32)?
      let witness_b = take_fixed(witness_a.state, 32)?
      let checkpoint = take_vector(witness_b.state, 188)?
      let consistency = take_vector(checkpoint.state, 131086)?
      case finish(consistency.state) do
        Err(_) -> Err("invalid_transparency_view")
        Ok(_) -> do
          let value = MobileTransparencyView {
            checkpoint: checkpoint.value,
            consistency: consistency.value,
            service_public_key: service_key.value,
            witness_a_public_key: witness_a.value,
            witness_b_public_key: witness_b.value
          }
          if mobile_read_byte(version.value)? != 1 || !Bytes.secure_equals(magic.value,
            Bytes.from_utf8("KTV")) || !Bytes.secure_equals(encode_transparency_view(value)?, input) do
            Err("invalid_transparency_view")
          else
            Ok(value)
          end
        end
      end
    end
  end
end

fn transparency_view_chunk_count(length :: Int) -> Int do
  (length + 65535) / 65536
end

pub fn transparency_view_chunk_label(index :: Int) -> String do
  "transparency-view-chunk/v1/#{Int.to_string(index)}"
end

fn encode_transparency_manifest(value :: MobileTransparencyView) -> Bytes!String do
  let consistency_length = Bytes.length(value.consistency)
  let chunk_count = transparency_view_chunk_count(consistency_length)
  if Bytes.length(value.checkpoint) != 188 || consistency_length == 0 || consistency_length > 131086 || chunk_count < 1 || chunk_count > 3 || Bytes.length(value.service_public_key) != 32 || Bytes.length(value.witness_a_public_key) != 32 || Bytes.length(value.witness_b_public_key) != 32 do
    Err("invalid_transparency_view")
  else
    let checkpoint = decode_checkpoint(value.checkpoint)?
    let consistency = decode_consistency_proof(value.consistency)?
    if !Bytes.secure_equals(encode_checkpoint(checkpoint)?, value.checkpoint) || !Bytes.secure_equals(encode_consistency_proof(consistency)?,
      value.consistency) do
      Err("invalid_transparency_view")
    else
      mobile_join([
          mobile_byte(1)?,
          Bytes.from_utf8("KVM"),
          value.service_public_key,
          value.witness_a_public_key,
          value.witness_b_public_key,
          value.checkpoint,
          mobile_write_u32(consistency_length)?,
          mobile_byte(chunk_count)?,
          Crypto.sha256(value.consistency)
        ],
        0,
        Bytes.empty())
    end
  end
end

fn decode_transparency_manifest(input :: Bytes) -> MobileTransparencyManifest!String do
  case reader(input, 325) do
    Err(_) -> Err("invalid_transparency_view")
    Ok(state) -> do
      let version = take_fixed(state, 1)?
      let magic = take_fixed(version.state, 3)?
      let service_key = take_fixed(magic.state, 32)?
      let witness_a = take_fixed(service_key.state, 32)?
      let witness_b = take_fixed(witness_a.state, 32)?
      let checkpoint = take_fixed(witness_b.state, 188)?
      let consistency_length = take_fixed(checkpoint.state, 4)?
      let chunk_count = take_fixed(consistency_length.state, 1)?
      let consistency_hash = take_fixed(chunk_count.state, 32)?
      case finish(consistency_hash.state) do
        Err(_) -> Err("invalid_transparency_view")
        Ok(_) -> do
          let length_value = mobile_read_u32(consistency_length.value)?
          let count_value = mobile_read_byte(chunk_count.value)?
          let manifest = MobileTransparencyManifest {
            checkpoint: checkpoint.value,
            consistency_length: length_value,
            consistency_hash: consistency_hash.value,
            chunk_count: count_value,
            service_public_key: service_key.value,
            witness_a_public_key: witness_a.value,
            witness_b_public_key: witness_b.value
          }
          if mobile_read_byte(version.value)? != 1 || !Bytes.secure_equals(magic.value,
            Bytes.from_utf8("KVM")) || Bytes.length(checkpoint.value) != 188 || length_value == 0 || length_value > 131086 || count_value != transparency_view_chunk_count(length_value) || count_value < 1 || count_value > 3 || Bytes.length(consistency_hash.value) != 32 do
            Err("invalid_transparency_view")
          else
            Ok(manifest)
          end
        end
      end
    end
  end
end

fn seal_transparency_view_chunks(consistency :: Bytes,
  wrapping_key :: borrow StorageKey,
  index :: Int,
  labels :: List<String>,
  blobs :: List<Bytes>) -> MobileTransparencyStorage!String do
  if index >= 3 do
    Ok(MobileTransparencyStorage { labels: labels, blobs: blobs })
  else
    let offset = index * 65536
    let remaining = Bytes.length(consistency) - offset
    let chunk_length = if remaining <= 0 do
      0
    else if remaining > 65536 do
      65536
    else
      remaining
    end
    let chunk = if chunk_length == 0 do
      Bytes.empty()
    else
      Bytes.slice(consistency, offset, chunk_length)?
    end
    let label = transparency_view_chunk_label(index)
    let blob = seal_local(chunk, wrapping_key, local_context(label)?)?
    seal_transparency_view_chunks(consistency,
      wrapping_key,
      index + 1,
      List.append(labels, label),
      List.append(blobs, blob))
  end
end

pub fn transparency_view_storage(value :: MobileTransparencyView, wrapping_key :: borrow StorageKey) -> MobileTransparencyStorage!String do
  let label = "transparency-view/v1"
  let manifest = encode_transparency_manifest(value)?
  let blob = seal_local(manifest, wrapping_key, local_context(label)?)?
  seal_transparency_view_chunks(value.consistency, wrapping_key, 0, [label], [blob])
end

fn load_transparency_view_chunks(database_path :: String,
  wrapping_key :: borrow StorageKey,
  manifest :: MobileTransparencyManifest,
  index :: Int,
  output :: Bytes) -> Bytes!String do
  if index >= 3 do
    Ok(output)
  else
    let label = transparency_view_chunk_label(index)
    let chunk = open_local(load_blob(database_path, label)?, wrapping_key, local_context(label)?)?
    let offset = index * 65536
    let remaining = manifest.consistency_length - offset
    let expected_length = if index >= manifest.chunk_count do
      0
    else if remaining > 65536 do
      65536
    else
      remaining
    end
    if expected_length < 0 || Bytes.length(chunk) != expected_length do
      Err("invalid_transparency_view")
    else
      let updated = if index < manifest.chunk_count do
        mobile_append(output, chunk)?
      else
        output
      end
      load_transparency_view_chunks(database_path, wrapping_key, manifest, index + 1, updated)
    end
  end
end

fn transparency_view_bytes(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes!String do
  let label = "transparency-view/v1"
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> do
      let manifest = decode_transparency_manifest(open_local(blob,
        wrapping_key,
        local_context(label)?)?)?
      let consistency = load_transparency_view_chunks(database_path,
        wrapping_key,
        manifest,
        0,
        Bytes.empty())?
      if Bytes.length(consistency) != manifest.consistency_length || !Bytes.secure_equals(Crypto.sha256(consistency),
        manifest.consistency_hash) do
        Err("invalid_transparency_view")
      else
        encode_transparency_view(MobileTransparencyView {
          checkpoint: manifest.checkpoint,
          consistency: consistency,
          service_public_key: manifest.service_public_key,
          witness_a_public_key: manifest.witness_a_public_key,
          witness_b_public_key: manifest.witness_b_public_key
        })
      end
    end
  end
end

pub fn load_transparency_view(database_path :: String, wrapping_key :: borrow StorageKey) -> MobileTransparencyView!String do
  let encoded = transparency_view_bytes(database_path, wrapping_key)?
  let checkpoint = transparency_checkpoint_bytes(database_path, wrapping_key)?
  if Bytes.length(encoded) == 0 || Bytes.length(checkpoint) == 0 do
    Err("group_transparency_unverified")
  else
    let view = decode_transparency_view(encoded)?
    if Bytes.secure_equals(view.checkpoint, checkpoint) do
      Ok(view)
    else
      Err("invalid_transparency_view")
    end
  end
end

pub fn canonical_transparency_checkpoint(input :: Bytes) -> TransparencyCheckpoint!String do
  if Bytes.length(input) != 188 do
    Err("invalid_transparency_checkpoint")
  else
    let checkpoint = decode_checkpoint(input)?
    if Bytes.secure_equals(encode_checkpoint(checkpoint)?, input) do
      Ok(checkpoint)
    else
      Err("invalid_transparency_checkpoint")
    end
  end
end

pub fn transparency_checkpoint_in_view(encoded_checkpoint :: Bytes, view :: MobileTransparencyView) -> Bool!String do
  let anchor = canonical_transparency_checkpoint(encoded_checkpoint)?
  let current = canonical_transparency_checkpoint(view.checkpoint)?
  let full_proof = decode_consistency_proof(view.consistency)?
  let anchor_size = U64.to_int(anchor.tree_size)?
  let current_size = U64.to_int(current.tree_size)?
  let sequence_order = U64.compare(anchor.sequence, current.sequence)
  let trusted_key = SigningPublicKey { bytes: view.service_public_key }
  let anchor_proof = ConsistencyProof {
    old_tree_size: anchor_size,
    new_tree_size: current_size,
    leaf_hashes: full_proof.leaf_hashes
  }
  let current_proof = ConsistencyProof {
    old_tree_size: current_size,
    new_tree_size: current_size,
    leaf_hashes: full_proof.leaf_hashes
  }
  if full_proof.new_tree_size != current_size || full_proof.new_tree_size != List.length(full_proof.leaf_hashes) || anchor_size > current_size || sequence_order > 0 || (sequence_order == 0 && !Bytes.secure_equals(encoded_checkpoint,
    view.checkpoint)) do
    Ok(false)
  else
    let anchor_valid = verify_checkpoint(anchor, trusted_key)?
    let current_valid = verify_checkpoint(current, trusted_key)?
    let current_tree_valid = verify_consistency(current.tree_root, current.tree_root, current_proof)?
    let prefix_valid = verify_consistency(anchor.tree_root, current.tree_root, anchor_proof)?
    Ok(anchor_valid && current_valid && current_tree_valid && prefix_valid)
  end
end

pub fn transparency_checkpoint_precedes(first :: Bytes,
  second :: Bytes,
  view :: MobileTransparencyView) -> Bool!String do
  let first_checkpoint = canonical_transparency_checkpoint(first)?
  let second_checkpoint = canonical_transparency_checkpoint(second)?
  let sequence_order = U64.compare(first_checkpoint.sequence, second_checkpoint.sequence)
  let tree_order = U64.compare(first_checkpoint.tree_size, second_checkpoint.tree_size)
  if sequence_order > 0 || tree_order > 0 || (sequence_order == 0 && !Bytes.secure_equals(first,
    second)) do
    Ok(false)
  else
    Ok(transparency_checkpoint_in_view(first, view)? && transparency_checkpoint_in_view(second,
      view)?)
  end
end

pub fn require_transparency_device_set(database_path :: String,
  wrapping_key :: borrow StorageKey,
  devices :: MobileVerifiedDeviceSet) -> Bytes!String do
  let label = transparency_device_set_label(devices.account.account_id)
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Err("device_set_transparency_unverified")
    else
      Err(error)
    end
    Ok(blob) -> do
      let cached = decode_verified_transparency_set(open_local(blob,
        wrapping_key,
        local_context(label)?)?)?
      let view = case load_transparency_view(database_path, wrapping_key) do
        Err(error) -> if error == "group_transparency_unverified" do
          Err("device_set_transparency_unverified")
        else
          Err(error)
        end
        Ok(loaded)
      end?
      if Bytes.secure_equals(cached.device_set, devices.wire) && transparency_checkpoint_in_view(cached.checkpoint,
        view)? do
        if checkpoint_fresh_at(decode_checkpoint(cached.checkpoint)?.timestamp, current_time()?) do
          Ok(cached.checkpoint)
        else
          Err("transparency_stale")
        end
      else
        Err("device_set_transparency_unverified")
      end
    end
  end
end

pub fn verified_transparency_device_set(database_path :: String,
  wrapping_key :: borrow StorageKey,
  devices :: MobileVerifiedDeviceSet,
  baseline_checkpoint :: Bytes) -> Bytes!String do
  let cached_checkpoint = case require_transparency_device_set(database_path, wrapping_key, devices) do
    Err(error) -> if error == "device_set_transparency_unverified" do
      Err("group_transparency_unverified")
    else
      Err(error)
    end
    Ok(checkpoint)
  end?
  let view = load_transparency_view(database_path, wrapping_key)?
  if transparency_checkpoint_precedes(baseline_checkpoint, cached_checkpoint, view)? && transparency_checkpoint_precedes(cached_checkpoint,
    view.checkpoint,
    view)? do
    Ok(cached_checkpoint)
  else
    Err("group_transparency_unverified")
  end
end

pub fn transparency_lookup(request :: MobilePayloadRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let username = mobile_utf8(request.payload, "invalid_username")?
  let checkpoint_bytes = transparency_checkpoint_bytes(request.database_path, platform_key()?)?
  let previous_tree_size = if Bytes.length(checkpoint_bytes) == 0 do
    0
  else
    U64.to_int(decode_checkpoint(checkpoint_bytes)?.tree_size)?
  end
  case encode_transparency_lookup(TransparencyLookup {
    username: username,
    previous_tree_size: previous_tree_size
  }) do
    Err(_) -> Err("invalid_username")
    Ok(encoded)
  end
end

pub fn verify_transparency_response(request :: MobileTransparencyRequest) -> Bytes!String do
  let config = native_security_config()?
  ensure_schema(request.database_path)?
  let evidence = case decode_transparency_evidence(request.evidence) do
    Err(_) -> Err("invalid_transparency_evidence")
    Ok(value)
  end?
  let wrapping_key = platform_key()?
  let previous = transparency_checkpoint_bytes(request.database_path, wrapping_key)?
  let existing_view_bytes = transparency_view_bytes(request.database_path, wrapping_key)?
  let trust_matches = if Bytes.length(existing_view_bytes) == 0 do
    true
  else
    let existing_view = decode_transparency_view(existing_view_bytes)?
    Bytes.secure_equals(existing_view.checkpoint, previous) && Bytes.secure_equals(existing_view.service_public_key,
      config.transparency_service_public_key) && Bytes.secure_equals(existing_view.witness_a_public_key,
      config.witness_a_public_key) && Bytes.secure_equals(existing_view.witness_b_public_key,
      config.witness_b_public_key)
  end
  let trusted_service_key = SigningPublicKey { bytes: config.transparency_service_public_key }
  let trusted_witnesses = [
    WitnessKey { witness_id: "witness-a", public_key: config.witness_a_public_key },
    WitnessKey { witness_id: "witness-b", public_key: config.witness_b_public_key }
  ]
  if !trust_matches do
    Err("transparency_trust_mismatch")
  else if !verify_evidence(evidence, trusted_service_key, trusted_witnesses, 2, previous)? do
    Err("transparency_verification_failed")
  else if !checkpoint_fresh_at(evidence.checkpoint.timestamp, current_time()?) do
    Err("transparency_stale")
  else
    let devices = verified_device_set(evidence.entry_bytes)?
    let expected_account = account_lookup_id(request.username)?
    let matches_recipient = if Bytes.length(expected_account) == 0 do
      devices.value.username == request.username
    else
      Bytes.secure_equals(expected_account, devices.account.account_id)
    end
    if !matches_recipient do
      Err("transparency_username_mismatch")
    else
      let checkpoint_label = "transparency-checkpoint/v1"
      let encoded_checkpoint = encode_checkpoint(evidence.checkpoint)?
      let encoded_consistency = encode_consistency_proof(evidence.consistency)?
      let checkpoint_blob = seal_local(encoded_checkpoint,
        wrapping_key,
        local_context(checkpoint_label)?)?
      let device_set_label = transparency_device_set_label(devices.account.account_id)
      let device_set_blob = seal_local(encode_verified_transparency_set(MobileVerifiedTransparencySet {
          checkpoint: encoded_checkpoint,
          device_set: devices.wire
        })?,
        wrapping_key,
        local_context(device_set_label)?)?
      let view_storage = transparency_view_storage(MobileTransparencyView {
          checkpoint: encoded_checkpoint,
          consistency: encoded_consistency,
          service_public_key: config.transparency_service_public_key,
          witness_a_public_key: config.witness_a_public_key,
          witness_b_public_key: config.witness_b_public_key
        },
        wrapping_key)?
      store_updated_blobs(request.database_path,
        List.append(List.append(view_storage.labels, checkpoint_label), device_set_label),
        List.append(List.append(view_storage.blobs, checkpoint_blob), device_set_blob))?
      Ok(evidence.entry_bytes)
    end
  end
end

pub fn fresh_account_device_set(database_path :: String,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes) -> MobileVerifiedDeviceSet!String do
  let label = transparency_device_set_label(account_id)
  let blob = case load_blob(database_path, label) do
    Ok(value)
    Err(error) -> if error == "local_state_not_found" do
      Err("device_set_transparency_unverified")
    else
      Err(error)
    end
  end?
  let cached = decode_verified_transparency_set(open_local(blob,
    wrapping_key,
    local_context(label)?)?)?
  let devices = verified_device_set(cached.device_set)?
  if !Bytes.secure_equals(devices.account.account_id, account_id) do
    Err("transparency_account_mismatch")
  else
    require_transparency_device_set(database_path, wrapping_key, devices)?
    Ok(devices)
  end
end
