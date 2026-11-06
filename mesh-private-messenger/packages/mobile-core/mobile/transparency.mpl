from Mobile.TransparencyCache import cached_transparency_bytes
from Transparency.LeafProof import LeafProof, compact_leaf_proof, encode_leaf_proof
from Transparency.Migration import decode_legacy_bridge, encode_bridge_query, verify_legacy_bridge
from Transparency.Config import (
  SecurityConfig,
  encode_security_config,
  WitnessPin,
  pinned_witness_keys,
  witness_set_id,
  witness_policy_for_log,
  pinned_legacy_witness_keys
)
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
from Mobile.Platform import native_security_config, decode_native_security_config
from Mobile.OhttpContext import (
  NativeOhttpContext,
  capture_native_ohttp_context,
  require_current_ohttp_context,
  fetch_guarded_ohttp_lookup,
  fetch_guarded_ohttp_lookup_at_origin
)
from Ohttp.LookupPolicy import OhttpLookupOperation, OhttpLookupResult
from Storage.AccountGuard import (
  AccountBasis,
  load_account_basis,
  account_basis_current,
  commit_account_changes
)
from Mobile.TransparencySafety import require_log_changes_allowed
from Mobile.AnchorCheck import AnchorObservation, check_native_anchor_view
from Mobile.Types import (
  MobilePayloadRequest,
  MobileReadBytes,
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
from Storage.Records import store_updated_session
from Storage.TransparencyCommit import commit_transparency_cache, commit_transparency_cache_guarded
from Transparency.Client import checkpoint_fresh_at, verify_evidence
from Transparency.Merkle import (
  ConsistencyProof,
  TransparencyCheckpoint,
  WitnessKey,
  checkpoint_hash,
  leaf_hash_for,
  proof_matches_log,
  verify_checkpoint,
  verify_witnesses_at,
  verify_consistency
)
from Transparency.Wire import (
  TransparencyLookup,
  account_lookup_id,
  decode_checkpoint,
  decode_witnesses,
  decode_consistency_proof,
  decode_transparency_evidence,
  encode_checkpoint,
  encode_witnesses,
  encode_consistency_proof,
  encode_consistency_range,
  encode_transparency_lookup
)
from Transport.Packet import ClientProfile

##! Mobile.Transparency implementation.

pub fn transparency_checkpoint_bytes(database_path :: String,
  wrapping_key :: borrow StorageKey) -> Bytes!String do
  cached_transparency_bytes(database_path, wrapping_key, "transparency-checkpoint/v1")
end

# The original checkpoint/origin snapshot is captured before selecting a request.
# Its ciphertexts are joined with the original revision fence in the final writer.
pub struct NativeTransparencyBasis do
  context :: NativeOhttpContext
  state :: AccountBasis
end

fn native_transparency_guard(before :: NativeTransparencyBasis) -> AccountBasis!String do
  if before.state.labels != ["transparency-checkpoint/v1", "transparency-origin/v1"]
    || List.length(before.state.records) != 2
    || before.context.basis.labels != ["ohttp-revision/v1"]
    || List.length(before.context.basis.records) != 1
    || !Bytes.secure_equals(before.state.profile, before.context.basis.profile) do
    return Err("invalid_transparency_basis")
  end
  Ok(AccountBasis {
    profile: before.state.profile,
    labels: before.context.basis.labels ++ before.state.labels,
    records: before.context.basis.records ++ before.state.records
  })
end

pub fn native_transparency_checkpoint(before :: NativeTransparencyBasis) -> Bytes!String do
  native_transparency_guard(before)?
  let bytes = List.head(before.state.records)
  if Bytes.length(bytes) == 0 do
    return Ok(Bytes.empty())
  end
  let key = platform_key()?
  let result = open_local(bytes, key, local_context("transparency-checkpoint/v1")?)
  Secret.destroy(key)
  result
end

pub fn capture_native_transparency_basis(path :: String,
  context :: NativeOhttpContext) -> NativeTransparencyBasis!String do
  require_current_ohttp_context(path, context)?
  let state = load_account_basis(path, ["transparency-checkpoint/v1", "transparency-origin/v1"])?
  let before = NativeTransparencyBasis { context: context, state: state }
  native_transparency_guard(before)?
  let origin_blob = List.get(state.records, 1)
  if Bytes.length(origin_blob) != 0 do
    let key = platform_key()?
    let origin = mobile_utf8(open_local(origin_blob,
        key,
        local_context("transparency-origin/v1")?)?,
      "invalid_transparency_origin")?
    Secret.destroy(key)
    if context.pins.required && origin != context.pins.network.core_origin do
      return Err("transparency_origin_mismatch")
    end
  end
  Ok(before)
end

pub fn transparency_device_set_label(account_id :: Bytes) -> String do
  "transparency-device-set/v1/#{Bytes.to_hex(account_id)}"
end

pub fn encode_verified_transparency_set(value :: MobileVerifiedTransparencySet) -> Bytes!String do
  if Bytes.length(value.checkpoint) != 188
    || Bytes.length(value.device_set) == 0
    || Bytes.length(value.device_set) > 305260 do
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
          if mobile_read_byte(version.value)? != 1
            || !Bytes.secure_equals(magic.value, Bytes.from_utf8("KTS"))
            || Bytes.length(checkpoint.value) != 188
            || Bytes.length(device_set.value) == 0
            || !Bytes.secure_equals(encode_verified_transparency_set(value)?, input) do
            Err("invalid_transparency_cache")
          else
            Ok(value)
          end
        end
      end
    end
  end
end

struct ReadViewTrust do
  state :: BinaryReader
  set_id :: Bytes
  threshold :: Int
end

pub fn legacy_witness_set_id(witness_a :: Bytes, witness_b :: Bytes) -> Bytes!String do
  witness_set_id([
      WitnessPin { witness_id: "witness-a", public_key: witness_a, operator_label: "Morse" },
      WitnessPin { witness_id: "witness-b", public_key: witness_b, operator_label: "Morse" }
    ],
    2)
end

fn read_view_trust(state :: BinaryReader, version :: Int) -> ReadViewTrust!String do
  if version == 1 do
    let a = take_fixed(state, 32)?
    let b = take_fixed(a.state, 32)?
    Ok(ReadViewTrust {
      state: b.state,
      set_id: legacy_witness_set_id(a.value, b.value)?,
      threshold: 2
    })
  else if version == 2 do
    let digest = take_fixed(state, 32)?
    let threshold = take_fixed(digest.state, 1)?
    let count = mobile_read_byte(threshold.value)?
    if count < 1 || count > 9 do
      Err("invalid_transparency_view")
    else
      Ok(ReadViewTrust { state: threshold.state, set_id: digest.value, threshold: count })
    end
  else
    Err("invalid_transparency_view")
  end
end

fn encode_transparency_view(value :: MobileTransparencyView) -> Bytes!String do
  if Bytes.length(value.checkpoint) != 188
    || Bytes.length(value.consistency) == 0
    || Bytes.length(value.consistency) > 131086
    || Bytes.length(value.service_public_key) != 32
    || Bytes.length(value.set_id) != 32
    || value.witness_threshold < 1
    || value.witness_threshold > 9 do
    Err("invalid_transparency_view")
  else
    let checkpoint = decode_checkpoint(value.checkpoint)?
    let consistency = decode_consistency_proof(value.consistency)?
    if !Bytes.secure_equals(encode_checkpoint(checkpoint)?, value.checkpoint)
      || !Bytes.secure_equals(encode_consistency_proof(consistency)?, value.consistency) do
      Err("invalid_transparency_view")
    else
      mobile_join([
          mobile_byte(2)?,
          Bytes.from_utf8("KTV"),
          value.service_public_key,
          value.set_id,
          mobile_byte(value.witness_threshold)?,
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
      let trust = read_view_trust(service_key.state, mobile_read_byte(version.value)?)?
      let checkpoint = take_vector(trust.state, 188)?
      let consistency = take_vector(checkpoint.state, 131086)?
      case finish(consistency.state) do
        Err(_) -> Err("invalid_transparency_view")
        Ok(_) -> do
          let value = MobileTransparencyView {
            checkpoint: checkpoint.value,
            consistency: consistency.value,
            service_public_key: service_key.value,
            set_id: trust.set_id,
            witness_threshold: trust.threshold
          }
          let canonical = encode_transparency_view(value)?
          if !Bytes.secure_equals(magic.value, Bytes.from_utf8("KTV"))
            || (mobile_read_byte(version.value)? == 2 && !Bytes.secure_equals(canonical, input)) do
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
  if Bytes.length(value.checkpoint) != 188
    || consistency_length == 0
    || consistency_length > 131086
    || chunk_count < 1
    || chunk_count > 3
    || Bytes.length(value.service_public_key) != 32
    || Bytes.length(value.set_id) != 32
    || value.witness_threshold < 1
    || value.witness_threshold > 9 do
    Err("invalid_transparency_view")
  else
    let checkpoint = decode_checkpoint(value.checkpoint)?
    let consistency = decode_consistency_proof(value.consistency)?
    if !Bytes.secure_equals(encode_checkpoint(checkpoint)?, value.checkpoint)
      || !Bytes.secure_equals(encode_consistency_proof(consistency)?, value.consistency) do
      Err("invalid_transparency_view")
    else
      mobile_join([
          mobile_byte(2)?,
          Bytes.from_utf8("KVM"),
          value.service_public_key,
          value.set_id,
          mobile_byte(value.witness_threshold)?,
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
      let trust = read_view_trust(service_key.state, mobile_read_byte(version.value)?)?
      let checkpoint = take_fixed(trust.state, 188)?
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
            set_id: trust.set_id,
            witness_threshold: trust.threshold
          }
          if !Bytes.secure_equals(magic.value, Bytes.from_utf8("KVM"))
            || Bytes.length(checkpoint.value) != 188
            || length_value == 0
            || length_value > 131086
            || count_value != transparency_view_chunk_count(length_value)
            || count_value < 1
            || count_value > 3
            || Bytes.length(consistency_hash.value) != 32 do
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

pub fn transparency_view_storage(value :: MobileTransparencyView,
  wrapping_key :: borrow StorageKey) -> MobileTransparencyStorage!String do
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

fn transparency_view_bytes(database_path :: String,
  wrapping_key :: borrow StorageKey) -> Bytes!String do
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
      if Bytes.length(consistency) != manifest.consistency_length
        || !Bytes.secure_equals(Crypto.sha256(consistency), manifest.consistency_hash) do
        Err("invalid_transparency_view")
      else
        encode_transparency_view(MobileTransparencyView {
          checkpoint: manifest.checkpoint,
          consistency: consistency,
          service_public_key: manifest.service_public_key,
          set_id: manifest.set_id,
          witness_threshold: manifest.witness_threshold
        })
      end
    end
  end
end

fn cached_witnesses_fresh(database_path :: String,
  wrapping_key :: borrow StorageKey,
  checkpoint_bytes :: Bytes,
  config :: SecurityConfig) -> Bool!String do
  let checkpoint = decode_checkpoint(checkpoint_bytes)?
  if checkpoint.version == 1 do
    return Ok(true)
  end
  let label = "transparency-witnesses/v2"
  let blob = case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      return Ok(false)
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  let witnesses = decode_witnesses(open_local(blob, wrapping_key, local_context(label)?)?)?
  verify_witnesses_at(checkpoint,
    witnesses,
    pinned_witness_keys(config),
    config.threshold,
    current_time()?)
end

pub fn load_transparency_view(database_path :: String,
  wrapping_key :: borrow StorageKey) -> MobileTransparencyView!String do
  let encoded = transparency_view_bytes(database_path, wrapping_key)?
  let checkpoint = transparency_checkpoint_bytes(database_path, wrapping_key)?
  if Bytes.length(encoded) == 0 || Bytes.length(checkpoint) == 0 do
    Err("group_transparency_unverified")
  else
    let view = decode_transparency_view(encoded)?
    let config = native_security_config()?
    let policy = witness_policy_for_log(config, decode_checkpoint(checkpoint)?.version)?
    if !Bytes.secure_equals(view.set_id, policy.set_id)
      || view.witness_threshold != policy.threshold
      || !Bytes.secure_equals(view.service_public_key, config.service_public_key) do
      Err("transparency_trust_mismatch")
    else if Bytes.secure_equals(view.checkpoint, checkpoint) do
      if cached_witnesses_fresh(database_path, wrapping_key, checkpoint, config)? do
        Ok(view)
      else
        Err("transparency_stale")
      end
    else
      Err("invalid_transparency_view")
    end
  end
end

# A fresh issuer proof may refresh stale witnesses, but must still extend the
# exact shared cursor and service pin. This helper never authorizes an action.
pub fn check_transparency_baseline(database_path :: String,
  wrapping_key :: borrow StorageKey,
  config :: SecurityConfig,
  expected_checkpoint :: Bytes) -> Result<(), String> do
  if !Bytes.secure_equals(transparency_checkpoint_bytes(database_path, wrapping_key)?,
    expected_checkpoint) do
    return Err("credit_transparency_changed")
  end
  let encoded = transparency_view_bytes(database_path, wrapping_key)?
  if Bytes.length(encoded) > 0 do
    let view = decode_transparency_view(encoded)?
    if !Bytes.secure_equals(view.checkpoint, expected_checkpoint)
      || !Bytes.secure_equals(view.service_public_key, config.service_public_key) do
      return Err("transparency_trust_mismatch")
    end
  end
  Ok(nil)
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

pub fn transparency_checkpoint_in_view(encoded_checkpoint :: Bytes,
  view :: MobileTransparencyView) -> Bool!String do
  let anchor = canonical_transparency_checkpoint(encoded_checkpoint)?
  let current = canonical_transparency_checkpoint(view.checkpoint)?
  let full_proof = decode_consistency_proof(view.consistency)?
  let anchor_size = U64.to_int(anchor.tree_size)?
  let current_size = U64.to_int(current.tree_size)?
  let sequence_order = U64.compare(anchor.sequence, current.sequence)
  let trusted_key = SigningPublicKey { bytes: view.service_public_key }
  if anchor.version != current.version || !proof_matches_log(current.version, full_proof.version) do
    return Ok(false)
  end
  if full_proof.version == 2 || full_proof.version == 3 do
    if full_proof.new_tree_size != current_size
      || !checkpoint_order_valid(encoded_checkpoint, view)? do
      return Ok(false)
    end
    if anchor_size == current_size do
      return Ok(Bytes.secure_equals(anchor.tree_root, current.tree_root))
    end
    return Ok(full_proof.old_tree_size == anchor_size
      && verify_consistency(anchor.tree_root, current.tree_root, full_proof)?)
  end
  let anchor_proof = ConsistencyProof {
    version: 1,
    old_tree_size: anchor_size,
    new_tree_size: current_size,
    leaf_hashes: full_proof.leaf_hashes
  }
  let current_proof = ConsistencyProof {
    version: 1,
    old_tree_size: current_size,
    new_tree_size: current_size,
    leaf_hashes: full_proof.leaf_hashes
  }
  if full_proof.version != 1
    || full_proof.new_tree_size != current_size
    || full_proof.new_tree_size != List.length(full_proof.leaf_hashes)
    || anchor_size > current_size
    || sequence_order > 0
    || (sequence_order == 0 && !Bytes.secure_equals(encoded_checkpoint, view.checkpoint)) do
    Ok(false)
  else
    let anchor_valid = verify_checkpoint(anchor, trusted_key)?
    let current_valid = verify_checkpoint(current, trusted_key)?
    let current_tree_valid = verify_consistency(current.tree_root,
      current.tree_root,
      current_proof)?
    let prefix_valid = verify_consistency(anchor.tree_root, current.tree_root, anchor_proof)?
    Ok(anchor_valid && current_valid && current_tree_valid && prefix_valid)
  end
end

fn checkpoint_order_valid(encoded_checkpoint :: Bytes,
  view :: MobileTransparencyView) -> Bool!String do
  let anchor = canonical_transparency_checkpoint(encoded_checkpoint)?
  let current = canonical_transparency_checkpoint(view.checkpoint)?
  let trusted = SigningPublicKey { bytes: view.service_public_key }
  let order = U64.compare(anchor.sequence, current.sequence)
  Ok(anchor.version == current.version
    && order <= 0
    && U64.compare(anchor.tree_size, current.tree_size) <= 0
    && (order != 0 || Bytes.secure_equals(encoded_checkpoint, view.checkpoint))
    && verify_checkpoint(anchor, trusted)?
    && verify_checkpoint(current, trusted)?)
end

pub fn store_transparency_origin(database_path :: String,
  wrapping_key :: borrow StorageKey,
  origin :: String) -> Result<(), String> do
  if String.length(origin) == 0 do
    return Ok(nil)
  end
  store_updated_session(database_path,
    "transparency-origin/v1",
    transparency_origin_blob(wrapping_key, origin)?)
end

fn transparency_origin_blob(wrapping_key :: borrow StorageKey, origin :: String) -> Bytes!String do
  if String.length(origin) > 2048
    || String.trim(origin) != origin
    || (!String.starts_with(origin, "https://") && !String.starts_with(origin, "http://"))
    || String.contains(origin, "@")
    || String.contains(origin, "?")
    || String.contains(origin, "#")
    || String.contains(origin, "\n")
    || String.contains(origin, "\r") do
    return Err("invalid_transparency_origin")
  end
  let label = "transparency-origin/v1"
  seal_local(Bytes.from_utf8(origin), wrapping_key, local_context(label)?)
end

fn migration_label(previous :: Bytes) -> String!String do
  let slot = Bytes.get(checkpoint_hash(decode_checkpoint(previous)?)?, 0)?
  Ok("transparency-bridge/v2/#{slot}")
end

fn bridge_valid(bytes :: Bytes,
  previous :: Bytes,
  current :: TransparencyCheckpoint,
  config :: SecurityConfig) -> Bool!String do
  let bridge = decode_legacy_bridge(bytes)?
  verify_legacy_bridge(current,
    bridge,
    SigningPublicKey { bytes: config.service_public_key },
    pinned_legacy_witness_keys(config),
    config.legacy_threshold,
    previous)
end

fn migration_bridge(database_path :: String,
  wrapping_key :: borrow StorageKey,
  previous :: Bytes,
  current :: TransparencyCheckpoint,
  config :: SecurityConfig,
  origin :: String,
  context :: Option<NativeOhttpContext>) -> Bytes!String do
  let prior = decode_checkpoint(previous)?
  let trusted = SigningPublicKey { bytes: config.service_public_key }
  if (config.version != 3 && config.version != 4 && config.version != 5)
    || prior.version != 1
    || current.version != 2
    || !verify_checkpoint(prior, trusted)?
    || !verify_checkpoint(current, trusted)? do
    return Err("transparency_verification_failed")
  end
  let label = migration_label(previous)?
  case load_blob(database_path, label) do
    Ok(blob) -> do
      let bytes = open_local(blob, wrapping_key, local_context(label)?)?
      if bridge_valid(bytes, previous, current, config)? do
        return Ok(bytes)
      end
    end
    Err(error) -> if error != "local_state_not_found" do
      return Err(error)
    end
  end
  if String.length(origin) == 0 do
    return Err("transparency_bridge_unavailable")
  end
  transparency_origin_blob(wrapping_key, origin)?
  let query = encode_bridge_query(U64.to_int(prior.tree_size)?, U64.to_int(current.tree_size)?)?
  let response = case context do
    Some(value) -> fetch_guarded_ohttp_lookup_at_origin(database_path,
      value,
      OhttpLegacyBridgeLookup,
      query,
      origin,
      8000)?
    None -> do
      let direct = (Http.build(:post, origin <> "/v2/transparency/legacy-bridge")
        |> Http.header("Content-Type", "application/octet-stream")
        |> Http.body_bytes(query)
        |> Http.timeout(8000)
        |> Http.max_response_bytes(4942)
        |> Http.max_redirects(0)
        |> Http.send())?
      OhttpLookupResult { status: direct.status, body: direct.body_bytes }
    end
  end
  if response.status != 200 do
    return Err("transparency_bridge_unavailable")
  end
  if !bridge_valid(response.body, previous, current, config)? do
    return Err("transparency_verification_failed")
  end
  Ok(response.body)
end

struct NativeProofBasis do
  before :: NativeTransparencyBasis
  cache :: AccountBasis
end

fn capture_native_proof_basis(path :: String,
  view :: MobileTransparencyView,
  label :: String) -> NativeProofBasis!String do
  let context = capture_native_ohttp_context(path, load_blob(path, "profile/v1")?)?
  let before = capture_native_transparency_basis(path, context)?
  if !Bytes.secure_equals(native_transparency_checkpoint(before)?, view.checkpoint) do
    return Err("transparency_state_changed")
  end
  let cache = load_account_basis(path, [label])?
  if !Bytes.secure_equals(cache.profile, before.state.profile) do
    return Err("account_state_changed")
  end
  Ok(NativeProofBasis { before: before, cache: cache })
end

fn commit_native_proof(path :: String,
  basis :: NativeProofBasis,
  label :: String,
  blob :: Bytes) -> Result<(), String> do
  if basis.cache.labels != [label] || List.length(basis.cache.records) != 1 do
    return Err("invalid_transparency_basis")
  end
  let base = native_transparency_guard(basis.before)?
  if !Bytes.secure_equals(base.profile, basis.cache.profile) do
    return Err("invalid_transparency_basis")
  end
  require_current_ohttp_context(path, basis.before.context)?
  commit_account_changes(path,
    AccountBasis {
      profile: base.profile,
      labels: base.labels ++ basis.cache.labels,
      records: base.records ++ basis.cache.records
    },
    [label],
    [blob],
    [])
end

fn legacy_anchor_in_view(database_path :: String,
  wrapping_key :: borrow StorageKey,
  encoded_checkpoint :: Bytes,
  view :: MobileTransparencyView,
  native :: Bool) -> Bool!String do
  let label = migration_label(encoded_checkpoint)?
  let basis = if native do
    Some(capture_native_proof_basis(database_path, view, label)?)
  else
    None
  end
  let config = case basis do
    None -> native_security_config()?
    Some(value) -> decode_native_security_config(value.before.context.security_frame)?
  end
  if (config.version != 3 && config.version != 4 && config.version != 5)
    || !Bytes.secure_equals(config.service_public_key, view.service_public_key) do
    return Ok(false)
  end
  let origin_label = "transparency-origin/v1"
  let origin_ciphertext = case basis do
    None -> load_blob(database_path, origin_label)?
    Some(value) -> List.get(value.before.state.records, 1)
  end
  let origin = mobile_utf8(open_local(origin_ciphertext,
      wrapping_key,
      local_context(origin_label)?)?,
    "invalid_transparency_origin")?
  let bytes = migration_bridge(database_path,
    wrapping_key,
    encoded_checkpoint,
    decode_checkpoint(view.checkpoint)?,
    config,
    origin,
    case basis do
      None
      Some(value) -> Some(value.before.context)
    end)?
  let blob = seal_local(bytes, wrapping_key, local_context(label)?)?
  case basis do
    None -> store_updated_session(database_path, label, blob)?
    Some(value) -> commit_native_proof(database_path, value, label, blob)?
  end
  Ok(true)
end

pub fn transparency_checkpoint_in_cached_view(database_path :: String,
  wrapping_key :: borrow StorageKey,
  encoded_checkpoint :: Bytes,
  view :: MobileTransparencyView) -> Bool!String do
  checkpoint_in_cached_view(database_path, wrapping_key, encoded_checkpoint, view, false)
end

pub fn transparency_checkpoint_in_native_view(database_path :: String,
  wrapping_key :: borrow StorageKey,
  encoded_checkpoint :: Bytes,
  view :: MobileTransparencyView) -> Bool!String do
  checkpoint_in_cached_view(database_path, wrapping_key, encoded_checkpoint, view, true)
end

fn checkpoint_in_cached_view(database_path :: String,
  wrapping_key :: borrow StorageKey,
  encoded_checkpoint :: Bytes,
  view :: MobileTransparencyView,
  native :: Bool) -> Bool!String do
  if transparency_checkpoint_in_view(encoded_checkpoint, view)? do
    return Ok(true)
  end
  if decode_checkpoint(encoded_checkpoint)?.version == 1
    && decode_checkpoint(view.checkpoint)?.version == 2 do
    return legacy_anchor_in_view(database_path, wrapping_key, encoded_checkpoint, view, native)
  end
  let proof_version = decode_consistency_proof(view.consistency)?.version
  if (proof_version != 2 && proof_version != 3)
    || !checkpoint_order_valid(encoded_checkpoint, view)? do
    return Ok(false)
  end
  let anchor = canonical_transparency_checkpoint(encoded_checkpoint)?
  let current = canonical_transparency_checkpoint(view.checkpoint)?
  # A bounded 256-slot cache of anchor proofs. A colliding anchor may evict a
  # proof, never confer trust: every hit verifies both sizes and signed roots.
  # This also avoids accumulating old contact checkpoints on the phone.
  let slot = Bytes.get(checkpoint_hash(anchor)?, 0)?
  let label = "transparency-anchor/v2/#{slot}"
  let basis = if native do
    Some(capture_native_proof_basis(database_path, view, label)?)
  else
    None
  end
  case load_blob(database_path, label) do
    Ok(blob) -> do
      let cached = open_local(blob, wrapping_key, local_context(label)?)?
      if transparency_checkpoint_in_view(encoded_checkpoint, %{view | consistency: cached})? do
        return Ok(true)
      end
    end
    Err(error) -> if error != "local_state_not_found" do
      return Err(error)
    end
  end
  let origin_label = "transparency-origin/v1"
  let origin_ciphertext = case basis do
    None -> load_blob(database_path, origin_label)?
    Some(value) -> List.get(value.before.state.records, 1)
  end
  let origin = mobile_utf8(open_local(origin_ciphertext,
      wrapping_key,
      local_context(origin_label)?)?,
    "invalid_transparency_origin")?
  let route = if current.version == 2 do
    "/v2/transparency/consistency"
  else
    "/v1/transparency/consistency"
  end
  let query = encode_consistency_range(U64.to_int(anchor.tree_size)?,
    U64.to_int(current.tree_size)?)?
  let response = case basis do
    Some(value) -> fetch_guarded_ohttp_lookup_at_origin(database_path,
      value.before.context,
      OhttpConsistencyLookup(current.version),
      query,
      origin,
      8000)?
    None -> do
      let direct = (Http.build(:post, origin <> route)
        |> Http.header("Content-Type", "application/octet-stream")
        |> Http.body_bytes(query)
        |> Http.timeout(8000)
        |> Http.max_response_bytes(1070)
        |> Http.max_redirects(0)
        |> Http.send())?
      OhttpLookupResult { status: direct.status, body: direct.body_bytes }
    end
  end
  if response.status != 200 do
    return Err("transparency_consistency_unavailable")
  end
  let proof = decode_consistency_proof(response.body)?
  if proof.version != current.version + 1
    || !transparency_checkpoint_in_view(encoded_checkpoint,
      %{view | consistency: response.body})? do
    return Err("transparency_consistency_invalid")
  end
  let blob = seal_local(response.body, wrapping_key, local_context(label)?)?
  case basis do
    None -> store_updated_session(database_path, label, blob)?
    Some(value) -> commit_native_proof(database_path, value, label, blob)?
  end
  Ok(true)
end

pub fn transparency_checkpoint_precedes(first :: Bytes,
  second :: Bytes,
  view :: MobileTransparencyView,
  database_path :: String,
  wrapping_key :: borrow StorageKey) -> Bool!String do
  checkpoint_precedes(first, second, view, database_path, wrapping_key, false)
end

fn checkpoint_precedes(first :: Bytes,
  second :: Bytes,
  view :: MobileTransparencyView,
  database_path :: String,
  wrapping_key :: borrow StorageKey,
  native :: Bool) -> Bool!String do
  let first_checkpoint = canonical_transparency_checkpoint(first)?
  let second_checkpoint = canonical_transparency_checkpoint(second)?
  if first_checkpoint.version == 1
    && second_checkpoint.version == 2
    && U64.to_int(second_checkpoint.tree_size)? > 0 do
    return Ok(checkpoint_in_cached_view(database_path, wrapping_key, first, view, native)?
      && checkpoint_in_cached_view(database_path, wrapping_key, second, view, native)?)
  end
  let sequence_order = U64.compare(first_checkpoint.sequence, second_checkpoint.sequence)
  let tree_order = U64.compare(first_checkpoint.tree_size, second_checkpoint.tree_size)
  if first_checkpoint.version != second_checkpoint.version
    || sequence_order > 0
    || tree_order > 0
    || (sequence_order == 0 && !Bytes.secure_equals(first, second)) do
    Ok(false)
  else
    Ok(checkpoint_in_cached_view(database_path, wrapping_key, first, view, native)?
      && checkpoint_in_cached_view(database_path, wrapping_key, second, view, native)?)
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
      if Bytes.secure_equals(cached.device_set, devices.wire)
        && transparency_checkpoint_in_native_view(database_path,
          wrapping_key,
          cached.checkpoint,
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
  let cached_checkpoint = case require_transparency_device_set(database_path,
    wrapping_key,
    devices) do
    Err(error) -> if error == "device_set_transparency_unverified" do
      Err("group_transparency_unverified")
    else
      Err(error)
    end
    Ok(checkpoint)
  end?
  let view = load_transparency_view(database_path, wrapping_key)?
  if checkpoint_precedes(baseline_checkpoint,
    cached_checkpoint,
    view,
    database_path,
    wrapping_key,
    true)?
    && checkpoint_precedes(cached_checkpoint,
      view.checkpoint,
      view,
      database_path,
      wrapping_key,
      true)? do
    Ok(cached_checkpoint)
  else
    Err("group_transparency_unverified")
  end
end

pub fn transparency_lookup(request :: MobilePayloadRequest) -> Bytes!String do
  transparency_lookup_for(request, native_security_config()?.log_version)
end

pub fn transparency_lookup_for(request :: MobilePayloadRequest, version :: Int) -> Bytes!String do
  ensure_schema(request.database_path)?
  let checkpoint_bytes = transparency_checkpoint_bytes(request.database_path, platform_key()?)?
  transparency_lookup_for_config(request, version, native_security_config()?, checkpoint_bytes)
end

pub fn transparency_lookup_for_config(request :: MobilePayloadRequest,
  version :: Int,
  config :: SecurityConfig,
  checkpoint_bytes :: Bytes) -> Bytes!String do
  let username = mobile_utf8(request.payload, "invalid_username")?
  let _policy = witness_policy_for_log(config, version)?
  let previous_tree_size = if Bytes.length(checkpoint_bytes) == 0 do
    0
  else
    let checkpoint = decode_checkpoint(checkpoint_bytes)?
    if checkpoint.version == version do
      U64.to_int(checkpoint.tree_size)?
    else if checkpoint.version == 1 && version == 2 do
      0
    else
      return Err("unsupported_transparency_log")
    end
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
  verify_transparency_with_profile(request, None, None)
end

pub fn verify_transparency_response_guarded(request :: MobileTransparencyRequest,
  profile_guard :: Bytes) -> Bytes!String do
  if Bytes.length(profile_guard) == 0 do
    return Err("directory_identity_changed")
  end
  verify_transparency_with_profile(request, Some(profile_guard), None)
end

pub fn verify_transparency_response_native(request :: MobileTransparencyRequest,
  before :: NativeTransparencyBasis) -> Bytes!String do
  native_transparency_guard(before)?
  require_current_ohttp_context(request.database_path, before.context)?
  # A concurrent authenticated lookup may have advanced the checkpoint/view
  # after plan selection. Retry from a fresh checkpoint, never recapture it
  # inside this verification and accidentally bless the stale response basis.
  if !account_basis_current(request.database_path, before.state) do
    return Err("transparency_state_changed")
  end
  if request.directory_url != before.context.pins.network.core_origin do
    return Err("transparency_origin_mismatch")
  end
  verify_transparency_with_profile(request, Some(before.state.profile), Some(before))
end

fn verify_transparency_with_profile(request :: MobileTransparencyRequest,
  expected_profile :: Option<Bytes>,
  before :: Option<NativeTransparencyBasis>) -> Bytes!String do
  let config = case before do
    None -> native_security_config()?
    Some(value) -> decode_native_security_config(value.context.security_frame)?
  end
  ensure_schema(request.database_path)?
  let evidence = case decode_transparency_evidence(request.evidence) do
    Err(_) -> return Err("invalid_transparency_evidence")
    Ok(value) -> value
  end
  let policy = witness_policy_for_log(config, evidence.checkpoint.version)?
  let wrapping_key = platform_key()?
  let profile_guard = case expected_profile do
    Some(value) -> value
    None -> case load_blob(request.database_path, "profile/v1") do
      Err("local_state_not_found") -> Bytes.empty()
      Err(error) -> return Err(error)
      Ok(value) -> value
    end
  end
  let checkpoint_guard = case before do
    Some(value) -> List.head(value.state.records)
    None -> case load_blob(request.database_path, "transparency-checkpoint/v1") do
      Err("local_state_not_found") -> Bytes.empty()
      Err(error) -> return Err(error)
      Ok(value) -> value
    end
  end
  let previous = if Bytes.length(checkpoint_guard) == 0 do
    Bytes.empty()
  else
    open_local(checkpoint_guard, wrapping_key, local_context("transparency-checkpoint/v1")?)?
  end
  let existing_view_bytes = transparency_view_bytes(request.database_path, wrapping_key)?
  if Bytes.length(existing_view_bytes) != 0 do
    let view = decode_transparency_view(existing_view_bytes)?
    if !Bytes.secure_equals(view.checkpoint, previous)
      || !Bytes.secure_equals(view.service_public_key, config.service_public_key) do
      return Err("transparency_trust_mismatch")
    end
  end
  let migrating = Bytes.length(previous) != 0
    && decode_checkpoint(previous)?.version == 1
    && evidence.checkpoint.version == 2
    && (config.version == 3 || config.version == 4 || config.version == 5)
  let baseline = if migrating do
    Bytes.empty()
  else
    previous
  end
  if !verify_evidence(evidence,
    SigningPublicKey { bytes: config.service_public_key },
    policy.keys,
    policy.threshold,
    baseline)? do
    return Err("transparency_verification_failed")
  end
  if !checkpoint_fresh_at(evidence.checkpoint.timestamp, current_time()?)
    || !verify_witnesses_at(evidence.checkpoint,
      evidence.witnesses,
      policy.keys,
      policy.threshold,
      current_time()?)? do
    return Err("transparency_stale")
  end
  let devices = verified_device_set(evidence.entry_bytes)?
  let expected_account = account_lookup_id(request.username)?
  let matches_recipient = if Bytes.length(expected_account) == 0 do
    devices.value.username == request.username
  else
    Bytes.secure_equals(expected_account, devices.account.account_id)
  end
  if !matches_recipient do
    return Err("transparency_username_mismatch")
  end
  let private_leaf = encode_leaf_proof(compact_leaf_proof(LeafProof {
      leaf_hash: leaf_hash_for(evidence.checkpoint.version, evidence.entry_bytes)?,
      inclusion: evidence.inclusion
    },
    evidence.checkpoint)?)?
  # Only a verified changed/new device set can trigger an early anchor read.
  # A fork or authenticated slash pauses new trust, while the exact devices
  # already trusted here may refresh their checkpoint for established chats.
  let known_label = transparency_device_set_label(devices.account.account_id)
  let changed = case load_blob(request.database_path, known_label) do
    Err(error) -> if error == "local_state_not_found" do
      true
    else
      return Err(error)
    end
    Ok(blob) -> do
      let known = decode_verified_transparency_set(open_local(blob,
        wrapping_key,
        local_context(known_label)?)?)?
      !Bytes.secure_equals(known.device_set, devices.wire)
    end
  end
  if changed do
    check_native_anchor_view(request.database_path,
      encode_checkpoint(evidence.checkpoint)?,
      request.directory_url,
      evidence.witnesses,
      private_leaf)?
    require_log_changes_allowed(request.database_path, wrapping_key)?
  end
  # Authenticate both histories before writing anything. The bridge cache joins
  # the same atomic local commit as checkpoint, witnesses, account view and URL.
  let (bridge_labels, bridge_blobs) = if migrating do
    let bridge = migration_bridge(request.database_path,
      wrapping_key,
      previous,
      evidence.checkpoint,
      config,
      request.directory_url,
      case before do
        None
        Some(value) -> Some(value.context)
      end)?
    let label = migration_label(previous)?
    ([label], [seal_local(bridge, wrapping_key, local_context(label)?)?])
  else
    (List.new(), List.new())
  end
  let checkpoint_label = "transparency-checkpoint/v1"
  let encoded_checkpoint = encode_checkpoint(evidence.checkpoint)?
  let encoded_consistency = encode_consistency_proof(evidence.consistency)?
  let checkpoint_blob = if Bytes.secure_equals(encoded_checkpoint, previous) do
    checkpoint_guard
  else
    seal_local(encoded_checkpoint, wrapping_key, local_context(checkpoint_label)?)?
  end
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
      service_public_key: config.service_public_key,
      set_id: policy.set_id,
      witness_threshold: policy.threshold
    },
    wrapping_key)?
  let witnesses_label = "transparency-witnesses/v2"
  let witnesses_blob = seal_local(encode_witnesses(evidence.witnesses)?,
    wrapping_key,
    local_context(witnesses_label)?)?
  let leaf_label = "transparency-leaf/v1"
  let leaf_blob = seal_local(private_leaf, wrapping_key, local_context(leaf_label)?)?
  let labels = [checkpoint_label]
    ++ view_storage.labels
    ++ [device_set_label, witnesses_label, leaf_label]
    ++ bridge_labels
  let blobs = [checkpoint_blob]
    ++ view_storage.blobs
    ++ [device_set_blob, witnesses_blob, leaf_blob]
    ++ bridge_blobs
  let (all_labels, all_blobs) = if String.length(request.directory_url) == 0 do
    (labels, blobs)
  else
    (List.append(labels, "transparency-origin/v1"),
      List.append(blobs, transparency_origin_blob(wrapping_key, request.directory_url)?))
  end
  if !Bytes.secure_equals(encode_security_config(config)?,
    encode_security_config(native_security_config()?)?) do
    return Err("transparency_trust_mismatch")
  end
  case before do
    None -> commit_transparency_cache(request.database_path,
      profile_guard,
      checkpoint_guard,
      all_labels,
      all_blobs)?
    Some(value) -> do
      require_current_ohttp_context(request.database_path, value.context)?
      commit_transparency_cache_guarded(request.database_path,
        profile_guard,
        checkpoint_guard,
        all_labels,
        all_blobs,
        native_transparency_guard(value)?)?
    end
  end
  Ok(evidence.entry_bytes)
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

# Captured-only backup verification. These ordinary values confer no caller
# authority; whole backup operations capture the ciphertext inputs internally.
from Transparency.Merkle import WitnessAttestation

pub struct BackupCapturedTransparencyInputs do
  device_set_cache :: Bytes
  shared_checkpoint :: Bytes
  view_manifest :: Bytes
  view_chunks :: List<Bytes>
  witnesses :: Bytes
  proof_label :: String
  proof :: Bytes
end

pub struct BackupCapturedTransparencyCheck do
  verified :: MobileVerifiedTransparencySet
  fresh_through :: U64
end

fn backup_earlier(left :: U64, right :: U64) -> U64 do
  if U64.compare(left, right) < 0 do
    left
  else
    right
  end
end

pub fn backup_transparency_proof_label(device_set_cache :: Bytes,
  shared_checkpoint :: Bytes) -> String!String do
  let cached = decode_verified_transparency_set(device_set_cache)?
  let anchor = canonical_transparency_checkpoint(cached.checkpoint)?
  let current = canonical_transparency_checkpoint(shared_checkpoint)?
  if Bytes.secure_equals(cached.checkpoint, shared_checkpoint) do
    return Ok("")
  end
  if anchor.version == 1 && current.version == 2 do
    return migration_label(cached.checkpoint)
  end
  if anchor.version != current.version
    || U64.compare(anchor.sequence, current.sequence) > 0
    || U64.compare(anchor.tree_size, current.tree_size) > 0
    || U64.compare(anchor.sequence, current.sequence) == 0 do
    return Err("device_set_transparency_unverified")
  end
  let slot = Bytes.get(checkpoint_hash(anchor)?, 0)?
  Ok("transparency-anchor/v2/#{slot}")
end

fn backup_captured_chunks(manifest :: MobileTransparencyManifest,
  chunks :: List<Bytes>,
  index :: Int,
  output :: Bytes) -> Bytes!String do
  if index >= 3 do
    return Ok(output)
  end
  let remaining = manifest.consistency_length - index * 65536
  let expected_length = if index >= manifest.chunk_count do
    0
  else if remaining > 65536 do
    65536
  else
    remaining
  end
  let chunk = List.get(chunks, index)
  if expected_length < 0 || Bytes.length(chunk) != expected_length do
    return Err("invalid_transparency_view")
  end
  backup_captured_chunks(manifest, chunks, index + 1, mobile_append(output, chunk)?)
end

fn backup_captured_view(input :: BackupCapturedTransparencyInputs) -> MobileTransparencyView!String do
  # Bounds precede chunk concatenation and every protocol decoder.
  if Bytes.length(input.device_set_cache) > 305460
    || Bytes.length(input.shared_checkpoint) != 188
    || Bytes.length(input.view_manifest) > 325
    || List.length(input.view_chunks) != 3
    || List.any(input.view_chunks, fn(value) -> Bytes.length(value) > 65536 end)
    || Bytes.length(input.witnesses) > 2774
    || String.length(input.proof_label) > 256
    || Bytes.length(input.proof) > 4942 do
    return Err("invalid_transparency_view")
  end
  let manifest = decode_transparency_manifest(input.view_manifest)?
  let consistency = backup_captured_chunks(manifest, input.view_chunks, 0, Bytes.empty())?
  if Bytes.length(consistency) != manifest.consistency_length
    || !Bytes.secure_equals(Crypto.sha256(consistency), manifest.consistency_hash) do
    return Err("invalid_transparency_view")
  end
  let view = MobileTransparencyView {
    checkpoint: manifest.checkpoint,
    consistency: consistency,
    service_public_key: manifest.service_public_key,
    set_id: manifest.set_id,
    witness_threshold: manifest.witness_threshold
  }
  # Reuse the canonical consistency/checkpoint codec, including legacy views.
  encode_transparency_view(view)?
  Ok(view)
end

fn backup_witness_deadline(checkpoint :: TransparencyCheckpoint,
  witnesses :: List<WitnessAttestation>,
  keys :: List<WitnessKey>,
  now :: U64,
  index :: Int,
  deadline :: U64) -> U64!String do
  if index >= List.length(witnesses) do
    return Ok(deadline)
  end
  let attestation = List.get(witnesses, index)
  let next_deadline = if Bytes.length(attestation.signature) == 72
    && verify_witnesses_at(checkpoint, [attestation], keys, 1, now)? do
    let seconds = case Bytes.read_u64_be(attestation.signature, 0) do
      Err(_) -> return Err("invalid_transparency_witness")
      Ok(value) -> value
    end
    let signed_at = U64.multiply(seconds, U64.parse("1000")?)?
    backup_earlier(deadline, U64.add(signed_at, U64.parse("300000")?)?)
  else
    deadline
  end
  backup_witness_deadline(checkpoint, witnesses, keys, now, index + 1, next_deadline)
end

# Pure: no path, native frames, key custody, clock, SQLite, HTTP or cache writes.
pub fn verify_backup_captured_transparency(input :: BackupCapturedTransparencyInputs,
  config :: SecurityConfig,
  now :: U64) -> BackupCapturedTransparencyCheck!String do
  let view = backup_captured_view(input)?
  encode_security_config(config)?
  let cached = decode_verified_transparency_set(input.device_set_cache)?
  let anchor = canonical_transparency_checkpoint(cached.checkpoint)?
  let current = canonical_transparency_checkpoint(input.shared_checkpoint)?
  let policy = witness_policy_for_log(config, current.version)?
  let trusted = SigningPublicKey { bytes: config.service_public_key }
  if !Bytes.secure_equals(view.checkpoint, input.shared_checkpoint)
    || !Bytes.secure_equals(view.service_public_key, config.service_public_key)
    || !Bytes.secure_equals(view.set_id, policy.set_id)
    || view.witness_threshold != policy.threshold
    || !verify_checkpoint(current, trusted)?
    || !verify_checkpoint(anchor, trusted)? do
    return Err("transparency_trust_mismatch")
  end
  if !checkpoint_fresh_at(anchor.timestamp, now) || !checkpoint_fresh_at(current.timestamp, now) do
    return Err("transparency_stale")
  end
  let expected_label = backup_transparency_proof_label(input.device_set_cache,
    input.shared_checkpoint)?
  if input.proof_label != expected_label
    || (expected_label == "" && Bytes.length(input.proof) != 0) do
    return Err("invalid_transparency_proof")
  end
  if !transparency_checkpoint_in_view(cached.checkpoint, view)? do
    let extends = if anchor.version == 1 && current.version == 2 do
      (config.version == 3 || config.version == 4 || config.version == 5)
        && bridge_valid(input.proof, cached.checkpoint, current, config)?
    else
      Bytes.length(input.proof) <= 1070
        && transparency_checkpoint_in_view(cached.checkpoint, %{view | consistency: input.proof})?
    end
    if expected_label == "" || !extends do
      return Err("device_set_transparency_unverified")
    end
  end
  let checkpoint_deadline = backup_earlier(U64.add(anchor.timestamp, U64.parse("300000")?)?,
    U64.add(current.timestamp, U64.parse("300000")?)?)
  let deadline = if current.version == 1 do
    # Existing legacy authorization authenticates the signed cached view.
    checkpoint_deadline
  else
    let witnesses = decode_witnesses(input.witnesses)?
    if !verify_witnesses_at(current, witnesses, policy.keys, policy.threshold, now)? do
      return Err("transparency_stale")
    end
    backup_witness_deadline(current, witnesses, policy.keys, now, 0, checkpoint_deadline)?
  end
  Ok(BackupCapturedTransparencyCheck { verified: cached, fresh_through: deadline })
end
