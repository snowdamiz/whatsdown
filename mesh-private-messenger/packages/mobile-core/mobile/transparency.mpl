from Binary.Reader import BinaryReader, finish, reader
from Mobile.Codec import (
  current_time,
  encode_output_list,
  mobile_byte,
  mobile_join,
  mobile_read_byte,
  mobile_utf8,
  mobile_vector,
  mobile_wide,
  mobile_write_u16,
  take_fixed,
  take_vector
)
from Mobile.DeviceSet import account_device_profiles, verified_device_set
from Mobile.LookupProofs import (
  LookupProof,
  lookup_proofs_blob,
  lookup_proofs_label,
  lookup_proofs_load
)
from Mobile.TrustAlarm import trust_alarm_gate
from Mobile.Platform import native_security_config
from Mobile.Profile import load_profile
from Mobile.Types import (
  MobilePayloadRequest,
  MobileReadBytes,
  MobileSecurityConfig,
  MobileTransparencyRequest,
  MobileTransparencyStorage,
  MobileTransparencyView,
  MobileTriplePayloadRequest,
  MobileVerifiedDeviceSet,
  MobileVerifiedTransparencySet
)
from Protocol.DirectoryWire import decode_device_set
from Protocol.V1 import AccountIdentity, DeviceCredential, DeviceSet, DirectoryEntry, PrekeyBundle
from Security.Config import SecurityConfig, SecurityWitness, security_config_witness_keys
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.Records import store_record_changes, store_updated_blobs
from Transparency.Client import checkpoint_fresh_at, transparency_verify_evidence_v2
from Transparency.CompactWire import (
  CompactConsistency,
  TransparencyEvidenceV2,
  TransparencyTreeQueryV2,
  transparency_decode_consistency_v2,
  transparency_decode_evidence_v2,
  transparency_decode_tree_query_v2,
  transparency_encode_lookup_v2,
  transparency_encode_tree_query_v2
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  checkpoint_hash,
  leaf_hash,
  verify_checkpoint,
  verify_witnesses
)
from Transparency.Tree import tlog_empty_root, tlog_verify_consistency
from Transparency.Wire import (
  TransparencyLookup,
  account_lookup_id,
  decode_checkpoint,
  encode_checkpoint
)
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.Transparency: what this device has verified of the key log.
##!
##! The view is the newest checkpoint verified under the pinned witness set,
##! plus the hashes of older checkpoints known to be prefixes of it: every
##! checkpoint this device verified (each was proven consistent with the one
##! before), and every anchor whose consistency proof it fetched and verified.
##! An older checkpoint outside that list (a group baseline, another device's
##! key package) is proven once: the core records what to fetch, returns
##! `transparency_anchor_proof_needed`, and the app hands the fetched `KTC` v2
##! to `accept_transparency_anchor_proof`.

# Older checkpoints remembered as prefixes of the view, oldest dropped first.
# A dropped anchor is proven again the next time something needs it.

fn known_limit() -> Int do
  512
end

fn view_label() -> String do
  "transparency-view/v2"
end

# Version 1 views carried every leaf hash; they are dropped, not read.

fn legacy_view_labels() -> List<String> do
  [
    "transparency-view/v1",
    "transparency-view-chunk/v1/0",
    "transparency-view-chunk/v1/1",
    "transparency-view-chunk/v1/2"
  ]
end

fn anchor_requests_label() -> String do
  "transparency-anchor-requests/v1"
end

fn witness_sets_label() -> String do
  "transparency-witness-sets/v1"
end

# A device that last verified its own account more than 90 days ago may have
# missed transitions whose bytes the directory has pruned since.

fn away_ms() -> Int do
  7_776_000_000
end

fn same_bytes(left :: Bytes, right :: Bytes) -> Bool do
  Bytes.secure_equals(left, right)
end

fn u16_value(value :: Bytes) -> Int do
  let bytes = Bytes.to_list(value)
  List.get(bytes, 0) * 256 + List.get(bytes, 1)
end

# Local list frames: u8 1 || tag || u8 count || count x fixed-size entries.

fn list_header(tag :: String, count :: Int) -> Bytes!String do
  mobile_join([mobile_byte(1)?, Bytes.from_utf8(tag), mobile_byte(count)?], 0, Bytes.empty())
end

fn decode_list(input :: Bytes, tag :: String, width :: Int, limit :: Int) -> List<Bytes>!String do
  if Bytes.length(input) == 0 do
    Ok(List.new())
  else if Bytes.length(input) < 5 do
    Err("invalid_transparency_cache")
  else
    let count = mobile_read_byte(Bytes.slice(input, 4, 1)?)?
    if count > limit
      || Bytes.length(input) != 5 + count * width
      || !same_bytes(Bytes.slice(input, 0, 5)?, list_header(tag, count)?) do
      Err("invalid_transparency_cache")
    else
      Ok(for index in 0..count do
        Bytes.slice(input, 5 + index * width, width)?
      end)
    end
  end
end

fn encode_list(values :: List<Bytes>, tag :: String, limit :: Int) -> Bytes!String do
  let kept = List.drop(values, List.length(values) - limit)
  mobile_join([list_header(tag, List.length(kept))?] ++ kept, 0, Bytes.empty())
end

fn load_optional(database_path :: String,
  wrapping_key :: borrow StorageKey,
  label :: String) -> Bytes!String do
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_local(blob, wrapping_key, local_context(label)?)
  end
end

pub fn transparency_checkpoint_bytes(database_path :: String,
  wrapping_key :: borrow StorageKey) -> Bytes!String do
  load_optional(database_path, wrapping_key, "transparency-checkpoint/v1")
end

pub fn transparency_device_set_label(account_id :: Bytes) -> String do
  "transparency-device-set/v1/#{Bytes.to_hex(account_id)}"
end

pub fn canonical_transparency_checkpoint(input :: Bytes) -> TransparencyCheckpoint!String do
  if Bytes.length(input) != 188 do
    Err("invalid_transparency_checkpoint")
  else
    let checkpoint = decode_checkpoint(input)?
    if same_bytes(encode_checkpoint(checkpoint)?, input) do
      Ok(checkpoint)
    else
      Err("invalid_transparency_checkpoint")
    end
  end
end

# Cached device set: u8 2 || "KTS" || set_id32 || vector32(KTK) || vector32(set).
# Version 1 entries have no set_id; they are read only to learn where this
# device last saw its own account.

pub fn encode_verified_transparency_set(value :: MobileVerifiedTransparencySet) -> Bytes!String do
  if Bytes.length(value.checkpoint) != 188
    || Bytes.length(value.set_id) != 32
    || Bytes.length(value.device_set) == 0
    || Bytes.length(value.device_set) > 305260 do
    Err("invalid_transparency_cache")
  else
    canonical_transparency_checkpoint(value.checkpoint)?
    mobile_join([
        mobile_byte(2)?,
        Bytes.from_utf8("KTS"),
        value.set_id,
        mobile_vector(value.checkpoint)?,
        mobile_vector(value.device_set)?
      ],
      0,
      Bytes.empty())
  end
end

fn read_transparency_set(input :: Bytes) -> (Int, MobileVerifiedTransparencySet)!String do
  let state = case reader(input, 305492) do
    Err(_) -> Err("invalid_transparency_cache")
    Ok(value)
  end?
  let version = take_fixed(state, 1)?
  let magic = take_fixed(version.state, 3)?
  let number = mobile_read_byte(version.value)?
  let set_id = take_fixed(magic.state,
    if number == 2 do
      32
    else
      0
    end)?
  let checkpoint = take_vector(set_id.state, 188)?
  let device_set = take_vector(checkpoint.state, 305260)?
  case finish(device_set.state) do
    Err(_) -> Err("invalid_transparency_cache")
    Ok(_) -> if (number != 1 && number != 2)
      || !same_bytes(magic.value, Bytes.from_utf8("KTS"))
      || Bytes.length(checkpoint.value) != 188
      || Bytes.length(device_set.value) == 0 do
      Err("invalid_transparency_cache")
    else
      Ok((number,
        MobileVerifiedTransparencySet {
          checkpoint: checkpoint.value,
          device_set: device_set.value,
          set_id: set_id.value
        }))
    end
  end
end

fn decode_verified_transparency_set(input :: Bytes) -> MobileVerifiedTransparencySet!String do
  let (version, value) = read_transparency_set(input)?
  if version != 2 do
    Err("device_set_transparency_unverified")
  else if !same_bytes(encode_verified_transparency_set(value)?, input) do
    Err("invalid_transparency_cache")
  else
    Ok(value)
  end
end

# View: u8 2 || "KTV" || service_key32 || set_id32 || KTK || u16 n || n x hash32.

fn encode_transparency_view(value :: MobileTransparencyView) -> Bytes!String do
  if Bytes.length(value.service_public_key) != 32
    || Bytes.length(value.set_id) != 32
    || List.length(value.known) > known_limit()
    || !List.all(value.known, fn hash -> Bytes.length(hash) == 32 end) do
    Err("invalid_transparency_view")
  else
    canonical_transparency_checkpoint(value.checkpoint)?
    mobile_join([
        mobile_byte(2)?,
        Bytes.from_utf8("KTV"),
        value.service_public_key,
        value.set_id,
        value.checkpoint,
        mobile_write_u16(List.length(value.known))?
      ]
        ++ value.known,
      0,
      Bytes.empty())
  end
end

fn take_hashes(state :: BinaryReader,
  count :: Int,
  output :: List<Bytes>) -> (BinaryReader, List<Bytes>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let hash = take_fixed(state, 32)?
    take_hashes(hash.state, count, List.append(output, hash.value))
  end
end

fn decode_transparency_view(input :: Bytes) -> MobileTransparencyView!String do
  case read_transparency_view(input) do
    Err(_) -> Err("invalid_transparency_view")
    Ok(value)
  end
end

fn read_transparency_view(input :: Bytes) -> MobileTransparencyView!String do
  let state = case reader(input, 260 + known_limit() * 32) do
    Err(_) -> Err("invalid_transparency_view")
    Ok(value)
  end?
  let version = take_fixed(state, 1)?
  let magic = take_fixed(version.state, 3)?
  let service_key = take_fixed(magic.state, 32)?
  let set_id = take_fixed(service_key.state, 32)?
  let checkpoint = take_fixed(set_id.state, 188)?
  let count = take_fixed(checkpoint.state, 2)?
  let (rest, known) = take_hashes(count.state, u16_value(count.value), List.new())?
  case finish(rest) do
    Err(_) -> Err("invalid_transparency_view")
    Ok(_) -> do
      let value = MobileTransparencyView {
        checkpoint: checkpoint.value,
        service_public_key: service_key.value,
        set_id: set_id.value,
        known: known
      }
      if mobile_read_byte(version.value)? != 2
        || !same_bytes(magic.value, Bytes.from_utf8("KTV"))
        || !same_bytes(encode_transparency_view(value)?, input) do
        Err("invalid_transparency_view")
      else
        Ok(value)
      end
    end
  end
end

pub fn transparency_view_storage(value :: MobileTransparencyView,
  wrapping_key :: borrow StorageKey) -> MobileTransparencyStorage!String do
  let label = view_label()
  let blob = seal_local(encode_transparency_view(value)?, wrapping_key, local_context(label)?)?
  Ok(MobileTransparencyStorage { labels: [label], blobs: [blob] })
end

fn transparency_view_bytes(database_path :: String,
  wrapping_key :: borrow StorageKey) -> Bytes!String do
  load_optional(database_path, wrapping_key, view_label())
end

pub fn load_transparency_view(database_path :: String,
  wrapping_key :: borrow StorageKey) -> MobileTransparencyView!String do
  let encoded = transparency_view_bytes(database_path, wrapping_key)?
  let checkpoint = transparency_checkpoint_bytes(database_path, wrapping_key)?
  if Bytes.length(encoded) == 0 || Bytes.length(checkpoint) == 0 do
    Err("group_transparency_unverified")
  else
    let view = decode_transparency_view(encoded)?
    if same_bytes(view.checkpoint, checkpoint) do
      Ok(view)
    else
      Err("invalid_transparency_view")
    end
  end
end

# The newest hashes win: `added` is appended (without repeats) and the oldest
# entries past the limit are dropped.

fn remember(known :: List<Bytes>, added :: List<Bytes>) -> List<Bytes> do
  let kept = List.filter(known,
    fn hash -> !List.any(added, fn value -> same_bytes(value, hash) end) end)
  let fresh = List.filter(added, fn hash -> Bytes.length(hash) == 32 end)
  let combined = kept ++ fresh
  List.drop(combined, List.length(combined) - known_limit())
end

# 0: this checkpoint cannot be a prefix of the view (newer, a different
# checkpoint at the same position, badly signed, or a different root at the
# same size). 1: it is known to be a prefix. 2: a consistency proof would
# settle it.

fn anchor_state(encoded :: Bytes, view :: MobileTransparencyView) -> Int!String do
  let anchor = canonical_transparency_checkpoint(encoded)?
  let current = canonical_transparency_checkpoint(view.checkpoint)?
  let size_order = U64.compare(anchor.tree_size, current.tree_size)
  let sequence_order = U64.compare(anchor.sequence, current.sequence)
  let current_bytes = same_bytes(encoded, view.checkpoint)
  if size_order > 0
    || sequence_order > 0
    || (sequence_order == 0 && !current_bytes)
    || !verify_checkpoint(anchor, SigningPublicKey { bytes: view.service_public_key })? do
    Ok(0)
  else if current_bytes do
    Ok(1)
  else
    let hash = checkpoint_hash(anchor)?
    if List.any(view.known, fn value -> same_bytes(value, hash) end) do
      Ok(1)
    else if size_order == 0 do
      Ok(if same_bytes(anchor.tree_root, current.tree_root) do
        1
      else
        0
      end)
    else if U64.to_int(anchor.tree_size)? == 0 do
      Ok(if same_bytes(anchor.tree_root, tlog_empty_root(1)?) do
        1
      else
        0
      end)
    else
      Ok(2)
    end
  end
end

pub fn transparency_checkpoint_known(encoded :: Bytes,
  view :: MobileTransparencyView) -> Bool!String do
  Ok(anchor_state(encoded, view)? == 1)
end

# Anchor proof request (397 bytes): the KTS v2 query to POST to
# /v1/transparency/consistency (21 bytes), then the anchor KTK and the view
# KTK the proof must connect.

fn anchor_request(encoded :: Bytes, view :: MobileTransparencyView) -> Bytes!String do
  let anchor = canonical_transparency_checkpoint(encoded)?
  let current = canonical_transparency_checkpoint(view.checkpoint)?
  let query = transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
    old_size: U64.to_int(anchor.tree_size)?,
    new_size: U64.to_int(current.tree_size)?,
    tree: 1
  })?
  mobile_join([query, encoded, view.checkpoint], 0, Bytes.empty())
end

fn request_anchor(value :: Bytes) -> Bytes!String do
  if Bytes.length(value) != 397 do
    Err("invalid_transparency_anchor_request")
  else
    Bytes.slice(value, 21, 188)
  end
end

# Pending requests, at most 16, oldest dropped first.

fn load_anchor_requests(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
  decode_list(load_optional(database_path, wrapping_key, anchor_requests_label())?, "KAQ", 397, 16)
end

fn anchor_requests_blob(values :: List<Bytes>, wrapping_key :: borrow StorageKey) -> Bytes!String do
  seal_local(encode_list(values, "KAQ", 16)?, wrapping_key, local_context(anchor_requests_label())?)
end

fn without_anchors(values :: List<Bytes>, anchors :: List<Bytes>) -> List<Bytes> do
  List.filter(values,
    fn value -> case request_anchor(value) do
      Ok(existing) -> !List.any(anchors, fn anchor -> same_bytes(existing, anchor) end)
      Err(_) -> false
    end end)
end

# Records what the app must fetch for each anchor and says so. The error
# carries the first KTS v2 query in hex; the full requests are listed by
# `transparency_anchor_requests`.

fn anchor_proof_needed(database_path :: String,
  anchors :: List<Bytes>,
  view :: MobileTransparencyView) -> String!String do
  let wrapping_key = platform_key()?
  let requests = for anchor in anchors do
    anchor_request(anchor, view)?
  end
  let pending = without_anchors(load_anchor_requests(database_path, wrapping_key)?, anchors)
    ++ requests
  store_updated_blobs(database_path,
    [anchor_requests_label()],
    [anchor_requests_blob(pending, wrapping_key)?])?
  Ok("transparency_anchor_proof_needed:" <> Bytes.to_hex(Bytes.slice(List.head(requests), 0, 21)?))
end

# True when every anchor is a prefix of the view, false when one cannot be;
# otherwise the anchors a proof would settle are requested together.

fn anchors_in_view(database_path :: String,
  anchors :: List<Bytes>,
  view :: MobileTransparencyView) -> Bool!String do
  let states = for anchor in anchors do
    anchor_state(anchor, view)?
  end
  let needed = for index in 0..List.length(anchors) when List.get(states, index) == 2 do
    List.get(anchors, index)
  end
  if List.any(states, fn state -> state == 0 end) do
    Ok(false)
  else if List.length(needed) == 0 do
    Ok(true)
  else
    Err(anchor_proof_needed(database_path, needed, view)?)
  end
end

pub fn transparency_checkpoint_in_view(database_path :: String,
  encoded_checkpoint :: Bytes,
  view :: MobileTransparencyView) -> Bool!String do
  anchors_in_view(database_path, [encoded_checkpoint], view)
end

pub fn transparency_checkpoint_precedes(database_path :: String,
  first :: Bytes,
  second :: Bytes,
  view :: MobileTransparencyView) -> Bool!String do
  let first_checkpoint = canonical_transparency_checkpoint(first)?
  let second_checkpoint = canonical_transparency_checkpoint(second)?
  let sequence_order = U64.compare(first_checkpoint.sequence, second_checkpoint.sequence)
  let tree_order = U64.compare(first_checkpoint.tree_size, second_checkpoint.tree_size)
  if sequence_order > 0 || tree_order > 0 || (sequence_order == 0 && !same_bytes(first, second)) do
    Ok(false)
  else
    anchors_in_view(database_path, [first, second], view)
  end
end

pub fn transparency_anchor_requests(database_path :: String) -> Bytes!String do
  ensure_schema(database_path)?
  encode_output_list(load_anchor_requests(database_path, platform_key()?)?)
end

fn anchor_proof_valid(request :: Bytes,
  response :: Bytes,
  view :: MobileTransparencyView) -> Bool!String do
  let query = transparency_decode_tree_query_v2(Bytes.slice(request, 0, 21)?)?
  let anchor = canonical_transparency_checkpoint(Bytes.slice(request, 21, 188)?)?
  let target_bytes = Bytes.slice(request, 209, 188)?
  let target = canonical_transparency_checkpoint(target_bytes)?
  let proof = transparency_decode_consistency_v2(response)?
  let old_size = U64.to_int(anchor.tree_size)?
  let new_size = U64.to_int(target.tree_size)?
  Ok(query.tree == 1
    && query.old_size == old_size
    && query.new_size == new_size
    && proof.old_size == old_size
    && proof.new_size == new_size
    && anchor_state(target_bytes, view)? == 1
    && verify_checkpoint(anchor, SigningPublicKey { bytes: view.service_public_key })?
    && tlog_verify_consistency(1,
      old_size,
      new_size,
      proof.path,
      anchor.tree_root,
      target.tree_root))
end

# Accepts the KTC v2 the directory answered for one request. A proof that
# does not connect the anchor to a checkpoint this device verified is
# refused; either way the request is settled.

pub fn accept_transparency_anchor_proof(request :: MobileTriplePayloadRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let wrapping_key = platform_key()?
  let anchor = request_anchor(request.first)?
  let view = load_transparency_view(request.database_path, wrapping_key)?
  let pending = without_anchors(load_anchor_requests(request.database_path, wrapping_key)?,
    [anchor])
  let pending_blob = anchor_requests_blob(pending, wrapping_key)?
  let valid = case anchor_proof_valid(request.first, request.second, view) do
    Err(_) -> false
    Ok(value) -> value
  end
  if !valid do
    store_updated_blobs(request.database_path, [anchor_requests_label()], [pending_blob])?
    Err("transparency_anchor_proof_invalid")
  else
    let hash = checkpoint_hash(canonical_transparency_checkpoint(anchor)?)?
    let storage = transparency_view_storage(%{view | known: remember(view.known, [hash])},
      wrapping_key)?
    store_updated_blobs(request.database_path,
      storage.labels ++ [anchor_requests_label()],
      storage.blobs ++ [pending_blob])?
    Ok(hash)
  end
end

# Witness sets this device has verified under (set_id32 || u8 k), newest last.

pub fn transparency_witness_sets(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
  decode_list(load_optional(database_path, wrapping_key, witness_sets_label())?, "KWS", 33, 16)
end

fn witness_sets_blob(values :: List<Bytes>,
  current :: Bytes,
  wrapping_key :: borrow StorageKey) -> Bytes!String do
  let others = List.filter(values, fn value -> !same_bytes(value, current) end)
  seal_local(encode_list(others ++ [current], "KWS", 16)?,
    wrapping_key,
    local_context(witness_sets_label())?)
end

pub fn require_transparency_device_set(database_path :: String,
  wrapping_key :: borrow StorageKey,
  devices :: MobileVerifiedDeviceSet) -> Bytes!String do
  let label = transparency_device_set_label(devices.account.account_id)
  let encoded = load_optional(database_path, wrapping_key, label)?
  if Bytes.length(encoded) == 0 do
    return Err("device_set_transparency_unverified")
  end
  let cached = decode_verified_transparency_set(encoded)?
  let view = case load_transparency_view(database_path, wrapping_key) do
    Err(error) -> if error == "group_transparency_unverified" do
      Err("device_set_transparency_unverified")
    else
      Err(error)
    end
    Ok(loaded)
  end?
  # A set verified under another witness set is looked up again.
  let config = native_security_config()?
  if same_bytes(cached.device_set, devices.wire)
    && same_bytes(cached.set_id, config.config.set_id)
    && transparency_checkpoint_known(cached.checkpoint, view)? do
    if checkpoint_fresh_at(decode_checkpoint(cached.checkpoint)?.timestamp, current_time()?) do
      Ok(cached.checkpoint)
    else
      Err("transparency_stale")
    end
  else
    Err("device_set_transparency_unverified")
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
  if transparency_checkpoint_precedes(database_path, baseline_checkpoint, cached_checkpoint, view)?
    && transparency_checkpoint_precedes(database_path, cached_checkpoint, view.checkpoint, view)? do
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
  case transparency_encode_lookup_v2(TransparencyLookup {
    username: username,
    previous_tree_size: previous_tree_size
  }) do
    Err(_) -> Err("invalid_username")
    Ok(encoded)
  end
end

fn local_account_id(database_path :: String) -> Bytes do
  case load_profile(database_path) do
    Err(_) -> Bytes.empty()
    Ok(profile) -> case decode_client_profile(profile) do
      Err(_) -> Bytes.empty()
      Ok(value) -> value.account_id
    end
  end
end

# Plan section 6.15: the directory keeps superseded entries for 90 days. When
# this device's own account moved more than one step since it last looked,
# and that look is older than the pruning window, some transitions it never
# saw may be gone, so it says so rather than accepting quietly.

fn changed_while_away(database_path :: String,
  wrapping_key :: borrow StorageKey,
  devices :: MobileVerifiedDeviceSet,
  checkpoint :: TransparencyCheckpoint) -> Bool!String do
  let label = transparency_device_set_label(devices.account.account_id)
  let local = local_account_id(database_path)
  let previous = if same_bytes(local, devices.account.account_id) do
    load_optional(database_path, wrapping_key, label)?
  else
    Bytes.empty()
  end
  if Bytes.length(previous) == 0 do
    Ok(false)
  else
    let (_, cached) = read_transparency_set(previous)?
    let seen = case decode_device_set(cached.device_set) do
      Err(_) -> Err("invalid_transparency_cache")
      Ok(value)
    end?
    let seen_at = U64.to_int(decode_checkpoint(cached.checkpoint)?.timestamp)?
    let skipped = U64.compare(devices.value.sequence,
      U64.add(seen.sequence, mobile_wide("1")?)?) > 0
    Ok(skipped && U64.to_int(checkpoint.timestamp)? - seen_at > away_ms())
  end
end

# What a fork proof would need from this lookup (Mobile.LookupProofs): the
# checkpoint, the Morse attestations on it that verify under the pinned keys,
# and the looked-up leaf with its audit path.

fn lookup_proof(config :: MobileSecurityConfig,
  evidence :: TransparencyEvidenceV2,
  encoded_checkpoint :: Bytes) -> LookupProof!String do
  let digest = checkpoint_hash(evidence.checkpoint)?
  let keys = security_config_witness_keys(config.config)
  let candidates = for value in evidence.witnesses when value.kind == 1
    && same_bytes(value.checkpoint_hash, digest) do
    WitnessAttestation {
      witness_id: value.witness_id,
      checkpoint_hash: value.checkpoint_hash,
      signature: value.signature
    }
  end
  let verified = List.filter(candidates,
    fn value -> case verify_witnesses(evidence.checkpoint, [value], keys, 1) do
      Ok(valid) -> valid
      Err(_) -> false
    end end)
  Ok(LookupProof {
    checkpoint: encoded_checkpoint,
    attestations: List.take(verified, 16),
    leaf_index: evidence.inclusion.leaf_index,
    leaf: leaf_hash(evidence.entry_bytes)?,
    path: evidence.inclusion.path
  })
end

# While a trust alarm is active (Mobile.TrustAlarm) this device takes on no new
# keys: an account it has never verified, a new account identity, or a device
# it has not seen in the account is refused. A set it already holds is still
# refreshed, including renewals and removals the account signed for devices it
# knows, so existing chats keep working.

fn device_seen(seen :: List<ClientProfile>, profile :: ClientProfile) -> Bool do
  List.any(seen, fn old -> same_bytes(old.device_id, profile.device_id) end)
end

fn known_devices(cached :: Bytes, devices :: MobileVerifiedDeviceSet) -> Bool do
  case read_transparency_set(cached) do
    Err(_) -> false
    Ok((_, value)) -> if same_bytes(value.device_set, devices.wire) do
      true
    else
      case verified_device_set(value.device_set) do
        Err(_) -> false
        Ok(previous) -> same_bytes(previous.value.account_identity, devices.value.account_identity)
          && List.all(account_device_profiles(devices),
            fn profile -> device_seen(account_device_profiles(previous), profile) end)
      end
    end
  end
end

fn require_known_keys(database_path :: String,
  wrapping_key :: borrow StorageKey,
  devices :: MobileVerifiedDeviceSet) -> ()!String do
  let cached = load_optional(database_path,
    wrapping_key,
    transparency_device_set_label(devices.account.account_id))?
  if Bytes.length(cached) > 0 && known_devices(cached, devices) do
    Ok(nil)
  else
    trust_alarm_gate(database_path)
  end
end

fn store_verified(request :: MobileTransparencyRequest,
  config :: MobileSecurityConfig,
  evidence :: TransparencyEvidenceV2,
  previous :: Bytes,
  known :: List<Bytes>,
  devices :: MobileVerifiedDeviceSet) -> Bytes!String do
  let wrapping_key = platform_key()?
  let checkpoint_label = "transparency-checkpoint/v1"
  let encoded_checkpoint = encode_checkpoint(evidence.checkpoint)?
  let previous_hash = if Bytes.length(previous) == 0 do
    Bytes.empty()
  else
    checkpoint_hash(decode_checkpoint(previous)?)?
  end
  let view_storage = transparency_view_storage(MobileTransparencyView {
      checkpoint: encoded_checkpoint,
      service_public_key: config.transparency_service_public_key,
      set_id: config.config.set_id,
      known: remember(known, [previous_hash, checkpoint_hash(evidence.checkpoint)?])
    },
    wrapping_key)?
  let checkpoint_blob = seal_local(encoded_checkpoint,
    wrapping_key,
    local_context(checkpoint_label)?)?
  let device_set_label = transparency_device_set_label(devices.account.account_id)
  let device_set_blob = seal_local(encode_verified_transparency_set(MobileVerifiedTransparencySet {
      checkpoint: encoded_checkpoint,
      device_set: devices.wire,
      set_id: config.config.set_id
    })?,
    wrapping_key,
    local_context(device_set_label)?)?
  let current_set = mobile_join([config.config.set_id, mobile_byte(config.config.threshold)?],
    0,
    Bytes.empty())?
  let sets_blob = witness_sets_blob(transparency_witness_sets(request.database_path, wrapping_key)?,
    current_set,
    wrapping_key)?
  let away = changed_while_away(request.database_path, wrapping_key, devices, evidence.checkpoint)?
  let proofs_blob = lookup_proofs_blob(lookup_proofs_load(request.database_path, wrapping_key)?,
    lookup_proof(config, evidence, encoded_checkpoint)?,
    wrapping_key)?
  store_record_changes(request.database_path,
    view_storage.labels
      ++ [checkpoint_label, device_set_label, witness_sets_label(), lookup_proofs_label()],
    view_storage.blobs ++ [checkpoint_blob, device_set_blob, sets_blob, proofs_blob],
    legacy_view_labels())?
  if away do
    Err("account_changed_while_away")
  else
    Ok(evidence.entry_bytes)
  end
end

# A set change keeps continuity: the previous checkpoint still anchors the
# consistency proof, so a new set can never roll the log back. What was
# verified under the old set (cached device sets) is looked up again. A
# service key change is a different log and stays refused.

pub fn verify_transparency_response(request :: MobileTransparencyRequest) -> Bytes!String do
  let config = native_security_config()?
  ensure_schema(request.database_path)?
  let evidence = case transparency_decode_evidence_v2(request.evidence) do
    Err(_) -> Err("invalid_transparency_evidence")
    Ok(value)
  end?
  let wrapping_key = platform_key()?
  let previous = transparency_checkpoint_bytes(request.database_path, wrapping_key)?
  let existing = transparency_view_bytes(request.database_path, wrapping_key)?
  let (trust_matches, known) = if Bytes.length(existing) == 0 do
    (true, List.new())
  else
    let view = decode_transparency_view(existing)?
    (same_bytes(view.checkpoint, previous)
        && same_bytes(view.service_public_key, config.transparency_service_public_key),
      view.known)
  end
  let now = current_time()?
  if !trust_matches do
    Err("transparency_trust_mismatch")
  else if !transparency_verify_evidence_v2(evidence,
    SigningPublicKey { bytes: config.transparency_service_public_key },
    security_config_witness_keys(config.config),
    config.config.threshold,
    config.config.c2sp_origin,
    previous,
    now)? do
    Err("transparency_verification_failed")
  else if !checkpoint_fresh_at(evidence.checkpoint.timestamp, now) do
    Err("transparency_stale")
  else
    let devices = verified_device_set(evidence.entry_bytes)?
    let expected_account = account_lookup_id(request.username)?
    let matches_recipient = if Bytes.length(expected_account) == 0 do
      devices.value.username == request.username
    else
      same_bytes(expected_account, devices.account.account_id)
    end
    if !matches_recipient do
      Err("transparency_username_mismatch")
    else
      require_known_keys(request.database_path, wrapping_key, devices)?
      store_verified(request, config, evidence, previous, known, devices)
    end
  end
end

pub fn fresh_account_device_set(database_path :: String,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes) -> MobileVerifiedDeviceSet!String do
  let label = transparency_device_set_label(account_id)
  let encoded = load_optional(database_path, wrapping_key, label)?
  if Bytes.length(encoded) == 0 do
    return Err("device_set_transparency_unverified")
  end
  let cached = decode_verified_transparency_set(encoded)?
  let devices = verified_device_set(cached.device_set)?
  if !same_bytes(devices.account.account_id, account_id) do
    Err("transparency_account_mismatch")
  else
    require_transparency_device_set(database_path, wrapping_key, devices)?
    Ok(devices)
  end
end
