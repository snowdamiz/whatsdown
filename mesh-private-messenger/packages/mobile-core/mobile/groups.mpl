from Protocol.Capabilities import supports_group_expiry
from Mobile.Expiry import message_unexpired
from Mobile.GroupExpiryPolicy import group_timer
from Mobile.GroupPolicyWire import group_policy_label
from Groups.Expiry import TimedGroupPayload, decode_timed_group_payload
from Mobile.TransparencySafety import require_log_changes_allowed
from Mobile.Gossip import outgoing_gossip_hint, observe_group_gossip
from Groups.GroupPayload import GroupPayload, decode_group_payload
from Transport.GroupRecipient import is_group_transport, open_group_transport
from Mobile.Transport import MobileOpenedPacket, open_outer_packet, opened_packet_kind
from Mobile.Transparency import fresh_account_device_set
from Mobile.Attachments import encode_group_attachment
from Mobile.GroupState import group_attachment_recipients, group_profile
from Mobile.Presentation import (
  community_change_allowed,
  community_group,
  group_record_labels,
  load_presentation_record,
  present_message,
  present_message_with_attachment,
  presented_body,
  presentation_fields,
  record_change_allowed,
  save_presentation,
  store_group_anchor
)
from Groups.CommitWire import encode_group_commit
from Groups.GroupCodec import delivery_targets
from Groups.GroupMessages import (
  decrypt_group_message,
  encode_group_message,
  encrypt_group_payload_for_transport,
  encrypt_timed_group_payload_for_transport
)
from Groups.Membership import (
  apply_commit,
  commit_add,
  commit_remove,
  commit_update,
  commit_witness_policy,
  create_group,
  join_from_welcome
)
from Groups.Mls import (
  CommitApplyOutcome,
  GroupAddOutcome,
  GroupCommit,
  GroupDecryptOutcome,
  GroupDeliveryTarget,
  GroupEncryptOutcome,
  GroupError,
  GroupMessage,
  GroupProposal,
  GroupRemoveOutcome,
  GroupState,
  GroupTransparencyPolicy,
  GroupWelcome
)
from Groups.WelcomeWire import encode_group_welcome
from Groups.Tree import (
  indexed_members,
  GroupTree,
  GroupMember,
  IndexedGroupMember,
  find_member_index,
  member_at
)
from Identity.Device import DeviceKeys
from Mobile.Codec import canonical_outer, current_time, encode_output_list
from Mobile.DeviceSet import local_device_set, verified_device_set, device_set_label
from Mobile.GroupInvitesState import accepted_invitation_scope
from Mobile.GroupState import (
  canonical_group_commit,
  canonical_group_message,
  canonical_group_welcome,
  consume_group_private,
  consume_group_state,
  decode_group_ids,
  decode_group_key_package,
  decode_group_packet,
  decode_group_welcome_packet,
  encode_group_packet,
  encode_group_welcome_packet,
  group_add_envelopes,
  group_baseline_blob,
  group_baseline_label,
  group_checkpoint,
  group_trust_matches,
  group_wire_set,
  group_history_label,
  group_join_label,
  group_join_scoped_label,
  group_key_package_unsigned,
  group_member,
  group_snapshot_blob,
  group_state_label,
  group_target_envelopes,
  load_group,
  load_group_baseline,
  updated_group_history_blob,
  updated_group_index_blob,
  verified_group_member
)
from Mobile.Outbox import load_outbox_ids, prepare_outbox_writes
from Mobile.Profile import load_profile, open_device
from Mobile.Transparency import (
  canonical_transparency_checkpoint,
  load_transparency_view,
  transparency_checkpoint_precedes,
  verified_transparency_device_set
)
from Mobile.Types import (
  MobileTriplePayloadRequest,
  MobileGroupAddRequest,
  MobileGroupHistoryEntry,
  MobileGroupKeyPackage,
  MobileGroupPacket,
  MobileGroupReceiveOutcome,
  MobileGroupRemoveRequest,
  MobileGroupSendRequest,
  MobileGroupWelcomePacket,
  MobileReceiveRequest,
  MobileTransparencyView,
  MobileVerifiedDeviceSet
)
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DeviceSet,
  DirectoryEntry,
  OuterEnvelope,
  InnerEnvelope,
  ProtocolExtension,
  PrekeyBundle,
  protocol_sealed_outer_suite
)
from Storage.Blobs import ensure_schema, load_blob
from Storage.GroupRecords import (
  store_group_join,
  store_group_message_outbound,
  store_group_message_outbound_guarded,
  store_group_outbound,
  store_group_state_history_guarded,
  store_new_group
)
from Storage.AccountGuard import account_basis_current
from Storage.FanoutCommit import (
  FanoutSnapshot,
  capture_fanout_snapshot,
  combine_fanout_snapshots
)
from Storage.Keys import context, local_context, open_local, open_x25519, platform_key
from Storage.Records import store_updated_session
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.Groups implementation.

pub fn create_mobile_group(database_path :: String) -> Bytes!String do
  ensure_schema(database_path)?
  let profile = decode_client_profile(load_profile(database_path)?)?
  let wrapping_key = platform_key()?
  require_log_changes_allowed(database_path, wrapping_key)?
  if !local_device_set(profile,
    fresh_account_device_set(database_path, wrapping_key, profile.account_id)?) do
    return Err("local_device_set_mismatch")
  end
  let checkpoint = group_checkpoint(database_path, wrapping_key)?
  let view = load_transparency_view(database_path, wrapping_key)?
  let checkpoint_hash_value = checkpoint_hash(canonical_transparency_checkpoint(checkpoint)?)?
  let leaf_keys = case Crypto.x25519_generate() do
    Err(_) -> Err("group_key_generation_failed")
    Ok(value)
  end?
  let creator = group_member(profile,
    X25519PublicKey { bytes: profile.credential.dh_public_key },
    leaf_keys.public_key,
    profile.account.directory_sequence,
    checkpoint_hash_value,
    view.witness_threshold)
  let state = case create_group(creator,
    leaf_keys.private_key,
    [1],
    GroupTransparencyPolicy {
      minimum_directory_sequence: profile.account.directory_sequence,
      checkpoint_hash: checkpoint_hash_value,
      witness_threshold: view.witness_threshold,
      set_id: group_wire_set(view)?
    }) do
    Err(_) -> Err("group_create_failed")
    Ok(value)
  end?
  let group_id = state.group_id
  let (label, blob) = group_snapshot_blob(state, profile, wrapping_key)?
  let index_blob = updated_group_index_blob(database_path, wrapping_key, group_id)?
  let baseline_label = group_baseline_label(group_id)?
  let baseline_blob = group_baseline_blob(checkpoint, wrapping_key, group_id)?
  store_new_group(database_path, label, blob, index_blob, baseline_label, baseline_blob)?
  Ok(group_id)
end

pub fn add_mobile_group_member(request :: MobileGroupAddRequest) -> Bytes!String do
  add_mobile_group_member_with_updates(request, [], [])
end

pub fn add_mobile_group_member_with_updates(request :: MobileGroupAddRequest,
  extra_labels :: List<String>,
  extra_blobs :: List<Bytes>) -> Bytes!String do
  ensure_schema(request.database_path)?
  let profile = decode_client_profile(load_profile(request.database_path)?)?
  let wrapping_key = platform_key()?
  require_log_changes_allowed(request.database_path, wrapping_key)?
  if !community_change_allowed(request.database_path,
    wrapping_key,
    request.group_id,
    profile.account_id,
    Bytes.empty())? do
    return Err("community_admin_required")
  end
  let state = load_group(request.database_path, profile, wrapping_key, request.group_id)?
  require_group_authorizations(request.database_path, wrapping_key, indexed_members(state.tree), 0)?
  let baseline = load_group_baseline(request.database_path, wrapping_key, request.group_id)?
  let baseline_hash = checkpoint_hash(canonical_transparency_checkpoint(baseline)?)?
  if !Bytes.secure_equals(baseline_hash, state.policy.checkpoint_hash) do
    consume_group_state(state)
    Err("group_state_invalid")
  else
    let view = load_transparency_view(request.database_path, wrapping_key)?
    let devices = verified_device_set(request.device_set)?
    let proof_checkpoint = verified_transparency_device_set(request.database_path,
      wrapping_key,
      devices,
      baseline)?
    let member = verified_group_member(devices,
      request.key_package,
      proof_checkpoint,
      baseline,
      view,
      request.database_path,
      wrapping_key)?
    let pending_ids = load_outbox_ids(request.database_path, wrapping_key)?
    let device = open_device(profile, wrapping_key, request.database_path)?
    let prior_targets = case delivery_targets(state.tree, state.local_leaf) do
      Err(_) -> Err("group_delivery_failed")
      Ok(value)
    end?
    let now = current_time()?
    let (state, refresh_envelopes) = refresh_for_send(request.database_path,
      wrapping_key,
      state,
      device.signing_private_key,
      prior_targets,
      now,
      false)?
    case commit_add(state, device.signing_private_key, member) do
      GroupAddRejected(rejected, _) -> do
        consume_group_state(rejected)
        Err("group_add_rejected")
      end
      GroupMemberAdded(next, commit, welcome) -> do
        let commit_wire = case encode_group_commit(commit) do
          Err(_) -> Err("group_commit_encoding_failed")
          Ok(value)
        end?
        let welcome_wire = case encode_group_welcome(welcome) do
          Err(_) -> Err("group_welcome_encoding_failed")
          Ok(value)
        end?
        let welcome_packet = encode_group_welcome_packet(MobileGroupWelcomePacket {
          baseline_checkpoint: baseline,
          welcome: welcome_wire
        })?
        let targets = case delivery_targets(next.tree, next.local_leaf) do
          Err(_) -> Err("group_delivery_failed")
          Ok(value)
        end?
        let envelopes = group_add_envelopes(request.database_path,
          wrapping_key,
          targets,
          welcome.recipient_leaf,
          encode_group_packet(2, commit_wire)?,
          encode_group_packet(1, welcome_packet)?,
          now,
          0,
          refresh_envelopes)?
        let (outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
          pending_ids,
          envelopes,
          request.database_path,
          Bytes.empty(),
          0,
          0,
          profile)?
        let (state_label, state_blob) = group_snapshot_blob(next, profile, wrapping_key)?
        store_group_outbound(request.database_path,
          state_label,
          state_blob,
          outbox_labels,
          outbox_blobs,
          outbox_index_blob,
          extra_labels,
          extra_blobs)?
        encode_output_list(envelopes)
      end
    end
  end
end

pub fn remove_mobile_group_member(request :: MobileGroupRemoveRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let profile = decode_client_profile(load_profile(request.database_path)?)?
  let wrapping_key = platform_key()?
  if !community_change_allowed(request.database_path,
    wrapping_key,
    request.group_id,
    profile.account_id,
    request.account_id)? do
    return Err("community_admin_required")
  end
  let community = community_group(request.database_path, wrapping_key, request.group_id)?
  let state = load_group(request.database_path, profile, wrapping_key, request.group_id)?
  let leaf_index = find_member_index(state.tree, request.account_id, request.device_id)
  let creator_id = creator_account(state.tree)
  if leaf_index == 0 && !community do
    consume_group_state(state)
    Err("group_creator_cannot_be_removed")
  else if leaf_index < 0 do
    consume_group_state(state)
    Err("group_member_not_found")
  else
    let remaining = List.filter(indexed_members(state.tree),
      fn(member) -> member.leaf_index != leaf_index end)
    require_group_authorizations(request.database_path, wrapping_key, remaining, 0)?
    let pending_ids = load_outbox_ids(request.database_path, wrapping_key)?
    let device = open_device(profile, wrapping_key, request.database_path)?
    case commit_remove(state, device.signing_private_key, leaf_index) do
      GroupRemoveRejected(rejected, _) -> do
        consume_group_state(rejected)
        Err("group_remove_rejected")
      end
      GroupMemberRemoved(next, commit) -> do
        let commit_wire = case encode_group_commit(commit) do
          Err(_) -> Err("group_commit_encoding_failed")
          Ok(value)
        end?
        let targets = case delivery_targets(next.tree, next.local_leaf) do
          Err(_) -> Err("group_delivery_failed")
          Ok(value)
        end?
        let envelopes = group_target_envelopes(request.database_path,
          wrapping_key,
          targets,
          encode_group_packet(2, commit_wire)?,
          current_time()?,
          0,
          List.new())?
        let (outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
          pending_ids,
          envelopes,
          request.database_path,
          Bytes.empty(),
          0,
          0,
          profile)?
        let (state_label, state_blob) = group_snapshot_blob(next, profile, wrapping_key)?
        store_group_outbound(request.database_path,
          state_label,
          state_blob,
          outbox_labels,
          outbox_blobs,
          outbox_index_blob,
          [],
          [])?
        encode_output_list(envelopes)
      end
    end
  end
end

fn refresh_for_send(path :: String,
  key :: borrow StorageKey,
  state :: consume GroupState,
  signing :: borrow SigningPrivateKey,
  targets :: List<GroupDeliveryTarget>,
  now :: U64,
  periodic :: Bool) -> Result<(GroupState, List<Bytes>), String> do
  let view = load_transparency_view(path, key)?
  let matches = group_trust_matches(state.policy.set_id, state.policy.witness_threshold, view)?
  if matches && (!periodic || (state.version == 2 && state.next_generation < 256)) do
    Ok((state, List.new()))
  else
    # Callers have freshly authorized the entire roster under this view. The
    # signed transition changes its policy and keys together, before any add
    # or application message; the state and all envelopes commit atomically.
    if !matches do
      require_log_changes_allowed(path, key)?
    end
    let outcome = if matches do
      commit_update(state, signing)
    else
      let policy = %{state.policy | set_id: view.set_id, witness_threshold: view.witness_threshold}
      commit_witness_policy(state, signing, policy)
    end
    case outcome do
      GroupRemoveRejected(rejected, _) -> do
        consume_group_state(rejected)
        Err("group_refresh_rejected")
      end
      GroupMemberRemoved(next, commit) -> do
        let wire = case encode_group_commit(commit) do
          Err(_) -> Err("group_commit_encoding_failed")
          Ok(value)
        end?
        let envelopes = group_target_envelopes(path,
          key,
          targets,
          encode_group_packet(2, wire)?,
          now,
          0,
          List.new())?
        Ok((next, envelopes))
      end
    end
  end
end

fn require_group_authorizations(path :: String,
  key :: borrow StorageKey,
  members :: List<IndexedGroupMember>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(members) do
    Ok(nil)
  else
    let member = List.get(members, index).member
    let devices = fresh_account_device_set(path, key, member.account_id)?
    let profile = case group_profile(devices.profiles, member.account_id, member.device_id, 0) do
      Ok(value)
      Err(_) -> Err("group_membership_changed")
    end?
    if !Bytes.secure_equals(profile.credential.signing_public_key,
      member.signing_public_key.bytes) do
      Err("group_membership_changed")
    else
      require_group_authorizations(path, key, members, index + 1)
    end
  end
end

fn require_group_expiry_readers(path :: String,
  key :: borrow StorageKey,
  members :: List<IndexedGroupMember>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(members) do
    Ok(nil)
  else
    let member = List.get(members, index).member
    let devices = fresh_account_device_set(path, key, member.account_id)?
    let profile = case group_profile(devices.profiles, member.account_id, member.device_id, 0) do
      Err(_) -> return Err("group_membership_changed")
      Ok(value) -> value
    end
    if !Bytes.secure_equals(profile.credential.signing_public_key,
      member.signing_public_key.bytes) do
      Err("group_membership_changed")
    else if !supports_group_expiry(profile.credential.capabilities) do
      Err("group_expiry_upgrade_required")
    else
      require_group_expiry_readers(path, key, members, index + 1)
    end
  end
end

fn add_group_source(labels :: List<String>, value :: String) -> List<String> do
  if List.contains(labels, value) do
    labels
  else
    List.append(labels, value)
  end
end

# Capture before reading credentials, presentation or the group ratchet. The
# first snapshot pins the roster used to discover every later account source;
# the final write validates both snapshots under the same SQLite write lock.
pub fn capture_group_attachment_send(path :: String, group_id :: Bytes) -> FanoutSnapshot!String do
  capture_group_message_sources(path, group_id, load_blob(path, "profile/v1")?)
end

fn capture_group_message_sources(path :: String,
  group_id :: Bytes,
  sealed_profile :: Bytes) -> FanoutSnapshot!String do
  let key = platform_key()?
  let profile = decode_client_profile(load_profile(path)?)?
  let initial = capture_fanout_snapshot(path,
    sealed_profile,
    [
      "groups/v1",
      group_state_label(group_id)?,
      group_baseline_label(group_id)?,
      group_history_label(group_id),
      group_policy_label(group_id)?,
      "outbox/v1",
      "delivery/v1",
      "postage-queue/v1",
      "transparency-checkpoint/v1",
      "transparency-witnesses/v2",
      "transparency-fork/v1",
      "anchor-schedule/v1",
      "anchor-observation/v1",
      "contact-address/v1",
      "presentation/v1/user/#{Bytes.to_hex(profile.account_id)}"
    ]
      ++ group_record_labels(group_id))?
  # Require membership in the exact original index before selecting state or
  # policy. A retained orphan must not recreate history/outbox after forget.
  let index_blob = List.head(List.head(initial.bases).records)
  if Bytes.length(index_blob) == 0 do
    return Err("group_not_found")
  end
  let indexed = decode_group_ids(open_local(index_blob, key, local_context("groups/v1")?)?)?
  if !List.any(indexed, fn(id) -> Bytes.secure_equals(id, group_id) end) do
    return Err("group_not_found")
  end
  let state = load_group(path, profile, key, group_id)?
  let members = indexed_members(state.tree)
  consume_group_state(state)
  let labels = List.reduce(members,
    [],
    fn(labels, entry) do
      let account = entry.member.account_id
      add_group_source(add_group_source(labels, device_set_label(account)),
        "transparency-device-set/v1/#{Bytes.to_hex(account)}")
    end)
  let authorization = capture_fanout_snapshot(path, sealed_profile, labels)?
  let before = combine_fanout_snapshots(initial, authorization)?
  if !List.all(before.bases, fn(basis) -> account_basis_current(path, basis) end) do
    return Err("account_state_changed")
  end
  Ok(before)
end

pub fn send_mobile_group_message(input :: MobileGroupSendRequest) -> Bytes!String do
  # Capture before presentation is read. Defer observing capture failure until
  # its original point so presentation validation keeps its existing priority.
  let captured = capture_group_attachment_send(input.database_path, input.group_id)
  let presented = present_message(input.database_path, input.group_id, input.body)?
  let text_only = %{input | body: presented}
  if Bytes.length(input.attachment) == 0 && Bytes.length(text_only.body) > 65237 do
    Err("group_message_too_large")
  else
    ensure_schema(input.database_path)?
    let guarded = Some(captured?)
    let profile = decode_client_profile(load_profile(input.database_path)?)?
    let wrapping_key = platform_key()?
    let seconds = group_timer(input.database_path, wrapping_key, input.group_id)?
    let state = load_group(input.database_path, profile, wrapping_key, input.group_id)?
    if seconds > 0 do
      require_group_expiry_readers(input.database_path,
        wrapping_key,
        indexed_members(state.tree),
        0)?
    end
    require_group_authorizations(input.database_path, wrapping_key, indexed_members(state.tree), 0)?
    let targets = case delivery_targets(state.tree, state.local_leaf) do
      Err(_) -> Err("group_delivery_failed")
      Ok(value)
    end?
    if List.length(targets) == 0 do
      consume_group_state(state)
      Err("group_has_no_recipients")
    else
      let pending_ids = load_outbox_ids(input.database_path, wrapping_key)?
      let device = open_device(profile, wrapping_key, input.database_path)?
      # The attachment key is wrapped once per recipient device inside the presented body.
      let request = if Bytes.length(input.attachment) == 0 do
        Ok(text_only)
      else
        let recipients = group_attachment_recipients(input.database_path,
          wrapping_key,
          targets,
          input.attachment,
          0,
          List.new())?
        let envelope = encode_group_attachment(device, input.attachment, recipients)?
        let framed = present_message_with_attachment(input.database_path,
          input.group_id,
          input.body,
          envelope)?
        if Bytes.length(framed) > 65237 do
          Err("group_message_too_large")
        else
          Ok(%{input | body: framed})
        end
      end?
      if seconds > 0 && Bytes.length(request.body) > 65225 do
        consume_group_state(state)
        return Err("group_message_too_large")
      end
      let now = current_time()?
      let (state, refresh_envelopes) = refresh_for_send(request.database_path,
        wrapping_key,
        state,
        device.signing_private_key,
        targets,
        now,
        true)?
      let sender = case member_at(state.tree, state.local_leaf) do
        Err(_) -> Err("group_message_rejected")
        Ok(value)
      end?
      let creator_id = creator_account(state.tree)
      let epoch = state.epoch
      let payload = GroupPayload {
        kind: 1,
        body: request.body,
        hint: outgoing_gossip_hint(request.database_path, wrapping_key)?,
        recipient_account: Bytes.empty(),
        recipient_device: Bytes.empty()
      }
      let encrypted = if seconds > 0 do
        encrypt_timed_group_payload_for_transport(state,
          device.signing_private_key,
          TimedGroupPayload { timestamp: now, disappearing_seconds: seconds, payload: payload },
          Bytes.from_utf8("mesh-mobile-group/v1"))
      else
        encrypt_group_payload_for_transport(state,
          device.signing_private_key,
          payload,
          Bytes.from_utf8("mesh-mobile-group/v1"))
      end
      case encrypted do
        GroupEncryptRejected(rejected, _) -> do
          consume_group_state(rejected)
          Err("group_message_rejected")
        end
        GroupMessageEncrypted(next, message) -> do
          let message_wire = case encode_group_message(message) do
            Err(_) -> Err("group_message_encoding_failed")
            Ok(value)
          end?
          let envelopes = group_target_envelopes(request.database_path,
            wrapping_key,
            targets,
            encode_group_packet(3, message_wire)?,
            now,
            0,
            refresh_envelopes)?
          # Membership refreshes lead the list; the message's own envelopes follow.
          let (outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
            pending_ids,
            envelopes,
            request.database_path,
            Crypto.sha256(message_wire),
            List.length(refresh_envelopes),
            List.length(envelopes) - List.length(refresh_envelopes),
            profile)?
          let (state_label, state_blob) = group_snapshot_blob(next, profile, wrapping_key)?
          let (history_labels, history_blobs) = updated_group_history_blob(request.database_path,
            wrapping_key,
            request.group_id,
            creator_id,
            MobileGroupHistoryEntry {
              disappearing_seconds: seconds,
              message_id: Crypto.sha256(message_wire),
              direction: 1,
              epoch: epoch,
              sender_account_id: sender.account_id,
              sender_device_id: sender.device_id,
              timestamp: now,
              body: request.body,
              attachment: input.attachment
            })?
          case guarded do
            None -> store_group_message_outbound(request.database_path,
              state_label,
              state_blob,
              history_labels,
              history_blobs,
              outbox_labels,
              outbox_blobs,
              outbox_index_blob)?
            Some(before) -> store_group_message_outbound_guarded(request.database_path,
              state_label,
              state_blob,
              history_labels,
              history_blobs,
              outbox_labels,
              outbox_blobs,
              outbox_index_blob,
              before)?
          end
          encode_output_list(envelopes)
        end
      end
    end
  end
end

fn welcome_member(value :: GroupWelcome) -> GroupMember!String do
  case value.commit.proposal do
    AddMember(leaf_index, member) -> if leaf_index == value.recipient_leaf do
      Ok(member)
    else
      Err("invalid_group_welcome")
    end
    RemoveMember(_) -> Err("invalid_group_welcome")
    UpdateKeys -> Err("invalid_group_welcome")
    UpdateWitnessPolicy(_) -> Err("invalid_group_welcome")
  end
end

fn local_welcome_member(profile :: ClientProfile,
  member :: GroupMember,
  welcome :: GroupWelcome) -> Bool do
  Bytes.secure_equals(member.account_id, profile.account_id)
    && Bytes.secure_equals(member.device_id, profile.device_id)
    && Bytes.secure_equals(member.signing_public_key.bytes, profile.credential.signing_public_key)
    && Bytes.secure_equals(member.mailbox_token, profile.entry.mailbox_token)
    && Bytes.secure_equals(member.transparency_checkpoint_hash, welcome.policy.checkpoint_hash)
    && member.witness_count >= welcome.policy.witness_threshold
end

# Whoever added this device is the first member it trusts to say what a community is.

fn store_welcome_anchor(database_path :: String,
  wrapping_key :: borrow StorageKey,
  welcome :: GroupWelcome) -> Result<(), String> do
  case List.find(welcome.members,
    fn(value) do value.leaf_index == welcome.commit.committer_leaf end) do
    Some(committer) -> store_group_anchor(database_path,
      wrapping_key,
      welcome.commit.group_id,
      committer.member.account_id)
    None -> Ok(nil)
  end
end

fn join_mobile_group(database_path :: String,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  welcome :: GroupWelcome,
  baseline_checkpoint :: Bytes) -> Bytes!String do
  let group_id = welcome.commit.group_id
  let state_label = group_state_label(group_id)?
  let member = welcome_member(welcome)?
  let baseline = canonical_transparency_checkpoint(baseline_checkpoint)?
  let baseline_hash = checkpoint_hash(baseline)?
  let current_checkpoint = group_checkpoint(database_path, wrapping_key)?
  let view = load_transparency_view(database_path, wrapping_key)?
  if !(group_trust_matches(welcome.policy.set_id, welcome.policy.witness_threshold, view)?)
    || !Bytes.secure_equals(baseline_hash, welcome.policy.checkpoint_hash)
    || !local_welcome_member(profile, member, welcome)
    || !(transparency_checkpoint_precedes(baseline_checkpoint,
      current_checkpoint,
      view,
      database_path,
      wrapping_key)?) do
    return Err("group_welcome_rejected")
  end
  case load_blob(database_path, state_label) do
    Ok(_) -> do
      let stored_baseline = load_group_baseline(database_path, wrapping_key, group_id)?
      let existing = load_group(database_path, profile, wrapping_key, group_id)?
      let existing_valid = Bytes.secure_equals(stored_baseline, baseline_checkpoint)
        && Bytes.secure_equals(existing.policy.checkpoint_hash, baseline_hash)
      consume_group_state(existing)
      if !existing_valid do
        Err("group_welcome_rejected")
      else
        store_updated_session(database_path,
          "groups/v1",
          updated_group_index_blob(database_path, wrapping_key, group_id)?)?
        Ok(group_id)
      end
    end
    Err(error) -> if error != "local_state_not_found" do
      Err(error)
    else
      let scope = accepted_invitation_scope(database_path,
        wrapping_key,
        welcome,
        baseline_checkpoint)?
      let package_label = group_join_scoped_label(scope, "package")
      let init_label = group_join_scoped_label(scope, "init")
      let leaf_label = group_join_scoped_label(scope, "leaf")
      let stored_package = decode_group_key_package(open_local(load_blob(database_path,
          package_label)?,
        wrapping_key,
        local_context(package_label)?)?)?
      let package_signature_valid = case Crypto.verify(SigningPublicKey {
          bytes: profile.credential.signing_public_key
        },
        group_key_package_unsigned(stored_package)?,
        stored_package.signature) do
        Err(_) -> false
        Ok(value) -> value
      end
      if !package_signature_valid
        || !(group_trust_matches(stored_package.set_id, stored_package.witness_count, view)?)
        || !Bytes.secure_equals(stored_package.account_id, profile.account_id)
        || !Bytes.secure_equals(stored_package.device_id, profile.device_id)
        || !Bytes.secure_equals(stored_package.init_public_key.bytes, member.init_public_key.bytes)
        || !Bytes.secure_equals(stored_package.leaf_public_key.bytes, member.leaf_public_key.bytes)
        || !(transparency_checkpoint_precedes(baseline_checkpoint,
          stored_package.checkpoint,
          view,
          database_path,
          wrapping_key)?)
        || !(transparency_checkpoint_precedes(stored_package.checkpoint,
          current_checkpoint,
          view,
          database_path,
          wrapping_key)?) do
        Err("group_welcome_rejected")
      else
        let init_private = open_x25519(load_blob(database_path, init_label)?,
          wrapping_key,
          context(profile.account_id, profile.device_id, init_label, 17)?)?
        let leaf_private = open_x25519(load_blob(database_path, leaf_label)?,
          wrapping_key,
          context(profile.account_id, profile.device_id, leaf_label, 17)?)?
        let state = case join_from_welcome(welcome, init_private, leaf_private) do
          Err(_) -> Err("group_welcome_rejected")
          Ok(value)
        end?
        consume_group_private(init_private)
        let (label, blob) = group_snapshot_blob(state, profile, wrapping_key)?
        let index_blob = updated_group_index_blob(database_path, wrapping_key, group_id)?
        let baseline_label = group_baseline_label(group_id)?
        let baseline_blob = group_baseline_blob(baseline_checkpoint, wrapping_key, group_id)?
        store_group_join(database_path,
          label,
          blob,
          index_blob,
          baseline_label,
          baseline_blob,
          package_label,
          init_label,
          leaf_label)?
        store_welcome_anchor(database_path, wrapping_key, welcome)?
        Ok(group_id)
      end
    end
  end
end

fn apply_mobile_group_commit(database_path :: String,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  commit :: GroupCommit) -> Bytes!String do
  case commit.proposal do
    AddMember(_, _) -> require_log_changes_allowed(database_path, wrapping_key)?
    UpdateWitnessPolicy(_) -> require_log_changes_allowed(database_path, wrapping_key)?
    _ -> nil
  end
  let group_id = commit.group_id
  # A community protects its owner, which the role check below enforces, rather than its creator.
  let community = community_group(database_path, wrapping_key, group_id)?
  let state = load_group(database_path, profile, wrapping_key, group_id)?
  let epoch_order = U64.compare(commit.prior_epoch, state.epoch)
  let removes_creator = case commit.proposal do
    RemoveMember(leaf) -> leaf == 0 && !community
    _ -> false
  end
  if removes_creator do
    consume_group_state(state)
    Err("group_commit_rejected")
  else if epoch_order > 0 do
    consume_group_state(state)
    Err("group_future_epoch")
  else if epoch_order < 0 do
    consume_group_state(state)
    Err("group_stale_epoch")
  else if !community_commit_allowed(database_path, wrapping_key, state.tree, commit)? do
    consume_group_state(state)
    Err("group_commit_rejected")
  else
    case commit.proposal do
      UpdateWitnessPolicy(policy) -> do
        let view = load_transparency_view(database_path, wrapping_key)?
        if !(group_trust_matches(policy.set_id, policy.witness_threshold, view)?) do
          consume_group_state(state)
          return Err("group_commit_rejected")
        end
        require_group_authorizations(database_path, wrapping_key, indexed_members(state.tree), 0)?
      end
      _ -> nil
    end
    case apply_commit(state, commit) do
      CommitRejected(rejected, error) -> do
        consume_group_state(rejected)
        case error do
          FutureEpoch -> Err("group_future_epoch")
          StaleEpoch -> Err("group_stale_epoch")
          _ -> Err("group_commit_rejected")
        end
      end
      CommitApplied(next) -> do
        let (label, blob) = group_snapshot_blob(next, profile, wrapping_key)?
        store_updated_session(database_path, label, blob)?
        Ok(group_id)
      end
    end
  end
end

fn community_commit_allowed(database_path :: String,
  wrapping_key :: borrow StorageKey,
  tree :: GroupTree,
  commit :: GroupCommit) -> Bool!String do
  let committer = case member_at(tree, commit.committer_leaf) do
    Err(_) -> return Ok(false)
    Ok(member) -> member.account_id
  end
  case commit.proposal do
    UpdateKeys -> Ok(true)
    UpdateWitnessPolicy(_) -> Ok(true)
    AddMember(_, _) -> community_change_allowed(database_path,
      wrapping_key,
      commit.group_id,
      committer,
      Bytes.empty())
    RemoveMember(leaf) -> case member_at(tree, leaf) do
      Err(_) -> Ok(false)
      Ok(target) -> community_change_allowed(database_path,
        wrapping_key,
        commit.group_id,
        committer,
        target.account_id)
    end
  end
end

fn opened_group_payload(version :: Int,
  plaintext :: Bytes,
  now :: U64) -> TimedGroupPayload!String do
  if version == 6 do
    case decode_timed_group_payload(plaintext) do
      Err(_) -> Err("group_message_rejected")
      Ok(value)
    end
  else
    let payload = if version == 5 do
      case decode_group_payload(plaintext) do
        Err(_) -> return Err("group_message_rejected")
        Ok(value) -> value
      end
    else
      GroupPayload {
        kind: 1,
        body: plaintext,
        hint: Bytes.empty(),
        recipient_account: Bytes.empty(),
        recipient_device: Bytes.empty()
      }
    end
    Ok(TimedGroupPayload { timestamp: now, disappearing_seconds: 0, payload: payload })
  end
end

fn open_mobile_group_message(database_path :: String,
  profile :: ClientProfile,
  sealed_profile :: Bytes,
  wrapping_key :: borrow StorageKey,
  message :: GroupMessage) -> Bytes!String do
  # Pin exact custody, membership, ratchet and history (including absence)
  # before opening the state. Gossip's independent public-evidence writes are
  # intentionally outside this basis; they cannot authorize a history write.
  let sources = capture_fanout_snapshot(database_path,
    sealed_profile,
    [
      "groups/v1",
      group_state_label(message.group_id)?,
      group_history_label(message.group_id),
      group_baseline_label(message.group_id)?
    ]
      ++ group_record_labels(message.group_id))?
  # A state row alone is not current membership: an old stale writer may have
  # left an orphan after forget. Validate the exact captured index, not a later
  # independent read, so every accepted message remains in the expiry sweep.
  let index_blob = List.head(List.head(sources.bases).records)
  if Bytes.length(index_blob) == 0 do
    return Err("group_message_rejected")
  end
  let indexed = decode_group_ids(open_local(index_blob,
    wrapping_key,
    local_context("groups/v1")?)?)?
  if !List.any(indexed, fn(id) -> Bytes.secure_equals(id, message.group_id) end) do
    return Err("group_message_rejected")
  end
  let state = load_group(database_path, profile, wrapping_key, message.group_id)?
  let epoch_order = U64.compare(message.epoch, state.epoch)
  if epoch_order > 0 do
    consume_group_state(state)
    Err("group_future_epoch")
  else if epoch_order < 0 do
    consume_group_state(state)
    Err("group_stale_epoch")
  else
    let sender = case member_at(state.tree, message.sender_leaf) do
      Err(_) -> Err("group_message_rejected")
      Ok(value)
    end?
    let sender_presentation = capture_fanout_snapshot(database_path,
      sealed_profile,
      ["presentation/v1/user/#{Bytes.to_hex(sender.account_id)}"])?
    let before = combine_fanout_snapshots(sources, sender_presentation)?
    let creator_id = creator_account(state.tree)
    case decrypt_group_message(state, message, Bytes.from_utf8("mesh-mobile-group/v1")) do
      MessageRejected(rejected, error) -> do
        consume_group_state(rejected)
        case error do
          FutureEpoch -> Err("group_future_epoch")
          StaleEpoch -> Err("group_stale_epoch")
          _ -> Err("group_message_rejected")
        end
      end
      MessageOpened(next, plaintext) -> do
        let (label, blob) = group_snapshot_blob(next, profile, wrapping_key)?
        let now = current_time()?
        let timed = opened_group_payload(message.version, plaintext, now)?
        let payload = timed.payload
        let timestamp = timed.timestamp
        let seconds = timed.disappearing_seconds
        let visible = message_unexpired(timestamp, seconds, now)?
        let addressed = payload.kind == 1
          || (Bytes.secure_equals(payload.recipient_account, profile.account_id)
            && Bytes.secure_equals(payload.recipient_device, profile.device_id))
        if addressed do
          observe_group_gossip(database_path,
            wrapping_key,
            InnerEnvelope {
              version: 1,
              sender_account_id: sender.account_id,
              sender_device_id: sender.device_id,
              recipient_device_id: profile.device_id,
              conversation_id: message.group_id,
              client_message_id: Bytes.slice(Crypto.sha256(message.ciphertext), 0, 16)?,
              client_timestamp: timestamp,
              message_type: payload.kind,
              body: if visible || payload.kind == 5 do
                payload.body
              else
                Bytes.empty()
              end,
              reply_reference: Bytes.empty(),
              attachment_manifest: Bytes.empty(),
              receipt_policy: 0,
              disappearing_seconds: 0,
              extensions: if Bytes.length(payload.hint) == 0 do
                []
              else
                [ProtocolExtension { id: 2, mandatory: false, value: payload.hint }]
              end
            },
            now)?
        end
        if payload.kind == 5 || !visible do
          store_group_state_history_guarded(database_path, label, blob, [], [], before)?
          return Ok(Bytes.empty())
        end
        let plaintext = payload.body
        let (history_labels, history_blobs) = updated_group_history_blob(database_path,
          wrapping_key,
          message.group_id,
          creator_id,
          MobileGroupHistoryEntry {
            disappearing_seconds: seconds,
            message_id: Crypto.sha256(case encode_group_message(message) do
              Err(_) -> Err("group_message_encoding_failed")
              Ok(value)
            end?),
            direction: 2,
            epoch: message.epoch,
            sender_account_id: sender.account_id,
            sender_device_id: sender.device_id,
            timestamp: timestamp,
            body: plaintext,
            attachment: Bytes.empty()
          })?
        store_group_state_history_guarded(database_path,
          label,
          blob,
          history_labels,
          history_blobs,
          before)?
        Ok(presented_body(plaintext))
      end
    end
  end
end

fn receive_mobile_group_result(request :: MobileReceiveRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let sealed_profile = load_blob(request.database_path, "profile/v1")?
  let profile = decode_client_profile(load_profile(request.database_path)?)?
  let outer = canonical_outer(request.outer)?
  let sealed_suite = outer.suite == protocol_sealed_outer_suite()
  if !(outer.suite == 3 || sealed_suite)
    || !Bytes.secure_equals(outer.mailbox_token, profile.entry.mailbox_token) do
    Err("wrong_group_delivery")
  else
    let wrapping_key = platform_key()?
    let encoded_packet = if sealed_suite do
      let device = open_device(profile, wrapping_key, request.database_path)?
      let opened = open_outer_packet(outer, device.identity_private_key)?
      if opened_packet_kind(opened) == 3 do
        Ok(opened.packet)
      else
        Err("invalid_group_packet")
      end
    else if is_group_transport(outer.ciphertext) do
      # Legacy queued packets remain readable under their original format.
      let device = open_device(profile, wrapping_key, request.database_path)?
      open_group_transport(outer.ciphertext, device.identity_private_key)
    else
      Ok(outer.ciphertext)
    end?
    let packet = decode_group_packet(encoded_packet)?
    if packet.kind == 1 do
      require_log_changes_allowed(request.database_path, wrapping_key)?
      let welcome_packet = decode_group_welcome_packet(packet.payload)?
      join_mobile_group(request.database_path,
        profile,
        wrapping_key,
        canonical_group_welcome(welcome_packet.welcome)?,
        welcome_packet.baseline_checkpoint)
    else if packet.kind == 2 do
      apply_mobile_group_commit(request.database_path,
        profile,
        wrapping_key,
        canonical_group_commit(packet.payload)?)
    else
      open_mobile_group_message(request.database_path,
        profile,
        sealed_profile,
        wrapping_key,
        canonical_group_message(packet.payload)?)
    end
  end
end

fn permanent_group_delivery_error(error :: String) -> Bool do
  error == "wrong_group_delivery"
    || error == "invalid_recipient_packet"
    || error == "invalid_outer_envelope"
    || error == "noncanonical_outer_envelope"
    || error == "invalid_group_packet"
    || error == "invalid_group_welcome"
    || error == "group_welcome_rejected"
    || error == "invalid_group_commit"
    || error == "group_commit_rejected"
    || error == "group_stale_epoch"
    || error == "invalid_group_message"
    || error == "group_message_rejected"
    || error == "group_limit_reached"
end

pub fn receive_mobile_group_classified(request :: MobileReceiveRequest) -> MobileGroupReceiveOutcome do
  case receive_mobile_group_result(request) do
    Ok(output) -> GroupReceiveApplied(output)
    Err(error) -> if permanent_group_delivery_error(error) do
      GroupReceiveRejected(error)
    else
      GroupReceiveRetry(error)
    end
  end
end

pub fn receive_mobile_group(request :: MobileReceiveRequest) -> Bytes!String do
  case receive_mobile_group_classified(request) do
    GroupReceiveApplied(output) -> Ok(output)
    GroupReceiveRetry(error) -> Err(error)
    GroupReceiveRejected(error) -> Err(error)
  end
end

pub fn save_owned_presentation(request :: MobileTriplePayloadRequest) -> Bytes!String do
  let local = decode_client_profile(load_profile(request.database_path)?)?
  let key = Bytes.to_utf8(request.first)?
  if key == "user/" <> Bytes.to_hex(local.account_id) || String.starts_with(key, "nickname/") do
    save_presentation(request)
  else if String.starts_with(key, "group/") do
    let parts = String.split(key, "/")
    if List.length(parts) != 2 do
      Err("invalid_presentation_key")
    else
      let group_id = Bytes.from_hex(List.get(parts, 1))?
      let wrapping_key = platform_key()?
      let state = load_group(request.database_path, local, wrapping_key, group_id)?
      let creator = creator_account(state.tree)
      consume_group_state(state)
      let stored = load_presentation_record(request.database_path, wrapping_key, request.first)?
      if record_change_allowed(stored, request.second, local.account_id, creator, Bytes.empty())? do
        save_presentation(request)
      else if Bytes.length(presentation_fields(request.second)?.community) > 0
        || Bytes.length(stored) > 0 && Bytes.length(presentation_fields(stored)?.community) > 0 do
        Err("community_admin_required")
      else
        Err("group_creator_required")
      end
    end
  else
    Err("invalid_presentation_key")
  end
end

fn creator_account(tree :: GroupTree) -> Bytes do
  case member_at(tree, 0) do
    Ok(member) -> member.account_id
    Err(_) -> Bytes.empty()
  end
end
