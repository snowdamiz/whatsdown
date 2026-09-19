from Mobile.Presentation import present_message, presented_body
from Groups.CommitWire import encode_group_commit
from Groups.GroupCodec import delivery_targets
from Groups.GroupMessages import decrypt_group_message, encode_group_message, encrypt_group_message
from Groups.Membership import apply_commit, commit_add, commit_remove, create_group, join_from_welcome
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
from Groups.Tree import GroupMember, IndexedGroupMember, find_member_index, member_at
from Identity.Device import DeviceKeys
from Mobile.Codec import canonical_outer, current_time, encode_output_list
from Mobile.DeviceSet import verified_device_set
from Mobile.GroupInvitesState import accepted_invitation_scope
from Mobile.GroupState import (
  canonical_group_commit,
  canonical_group_message,
  canonical_group_welcome,
  consume_group_private,
  consume_group_state,
  decode_group_key_package,
  decode_group_packet,
  decode_group_welcome_packet,
  encode_group_packet,
  encode_group_welcome_packet,
  group_add_envelopes,
  group_baseline_blob,
  group_baseline_label,
  group_checkpoint,
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
  PrekeyBundle
)
from Storage.Blobs import ensure_schema, load_blob
from Storage.GroupRecords import (
  store_group_join,
  store_group_message_outbound,
  store_group_outbound,
  store_group_state_history,
  store_new_group
)
from Storage.Keys import context, local_context, open_local, open_x25519, platform_key
from Storage.Records import store_updated_session
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.Groups implementation.

pub fn create_mobile_group(database_path :: String) -> Bytes ! String do
  ensure_schema(database_path) ?
  let profile = decode_client_profile(load_profile(database_path) ?) ?
  let wrapping_key = platform_key() ?
  let checkpoint = group_checkpoint(database_path, wrapping_key) ?
  let checkpoint_hash_value = checkpoint_hash(canonical_transparency_checkpoint(checkpoint) ?) ?
  let leaf_keys = case Crypto.x25519_generate() do
    Err( _) -> Err("group_key_generation_failed")
    Ok( value) -> Ok(value)
  end ?
  let creator = group_member(profile,
  X25519PublicKey { bytes : profile.credential.dh_public_key },
  leaf_keys.public_key,
  profile.account.directory_sequence,
  checkpoint_hash_value,
  2)
  let state = case create_group(creator,
  leaf_keys.private_key,
  [1],
  GroupTransparencyPolicy {
    minimum_directory_sequence : profile.account.directory_sequence,
    checkpoint_hash : checkpoint_hash_value,
    witness_threshold : 2
  }) do
    Err( _) -> Err("group_create_failed")
    Ok( value) -> Ok(value)
  end ?
  let group_id = state.group_id
  let ( label, blob) = group_snapshot_blob(state, profile, wrapping_key) ?
  let index_blob = updated_group_index_blob(database_path, wrapping_key, group_id) ?
  let baseline_label = group_baseline_label(group_id) ?
  let baseline_blob = group_baseline_blob(checkpoint, wrapping_key, group_id) ?
  store_new_group(database_path, label, blob, index_blob, baseline_label, baseline_blob) ?
  Ok(group_id)
end

pub fn add_mobile_group_member(request :: MobileGroupAddRequest) -> Bytes ! String do
  add_mobile_group_member_with_updates(request, [], [])
end

pub fn add_mobile_group_member_with_updates(request :: MobileGroupAddRequest,
extra_labels :: List<String>, extra_blobs :: List<Bytes>) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_group(request.database_path, profile, wrapping_key, request.group_id) ?
  let baseline = load_group_baseline(request.database_path, wrapping_key, request.group_id) ?
  let baseline_hash = checkpoint_hash(canonical_transparency_checkpoint(baseline) ?) ?
  if !Bytes.secure_equals(baseline_hash, state.policy.checkpoint_hash) do
    consume_group_state(state)
    Err("group_state_invalid")
  else
    let view = load_transparency_view(request.database_path, wrapping_key) ?
    let devices = verified_device_set(request.device_set) ?
    let proof_checkpoint = verified_transparency_device_set(request.database_path,
    wrapping_key,
    devices,
    baseline) ?
    let member = verified_group_member(devices,
    request.key_package,
    proof_checkpoint,
    baseline,
    view) ?
    let pending_ids = load_outbox_ids(request.database_path, wrapping_key) ?
    let device = open_device(profile, wrapping_key, request.database_path) ?
    case commit_add(state, device.signing_private_key, member) do
      GroupAddRejected( rejected, _) -> do
        consume_group_state(rejected)
        Err("group_add_rejected")
      end
      GroupMemberAdded( next, commit, welcome) -> do
        let commit_wire = case encode_group_commit(commit) do
          Err( _) -> Err("group_commit_encoding_failed")
          Ok( value) -> Ok(value)
        end ?
        let welcome_wire = case encode_group_welcome(welcome) do
          Err( _) -> Err("group_welcome_encoding_failed")
          Ok( value) -> Ok(value)
        end ?
        let welcome_packet = encode_group_welcome_packet(MobileGroupWelcomePacket {
          baseline_checkpoint : baseline,
          welcome : welcome_wire
        }) ?
        let targets = case delivery_targets(next.tree, next.local_leaf) do
          Err( _) -> Err("group_delivery_failed")
          Ok( value) -> Ok(value)
        end ?
        let now = current_time() ?
        let envelopes = group_add_envelopes(targets,
        welcome.recipient_leaf,
        encode_group_packet(2, commit_wire) ?,
        encode_group_packet(1, welcome_packet) ?,
        now,
        0,
        List.new()) ?
        let ( outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
        pending_ids,
        envelopes) ?
        let ( state_label, state_blob) = group_snapshot_blob(next, profile, wrapping_key) ?
        store_group_outbound(request.database_path,
        state_label,
        state_blob,
        outbox_labels,
        outbox_blobs,
        outbox_index_blob, extra_labels, extra_blobs) ?
        encode_output_list(envelopes)
      end
    end
  end
end

pub fn remove_mobile_group_member(request :: MobileGroupRemoveRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_group(request.database_path, profile, wrapping_key, request.group_id) ?
  let leaf_index = find_member_index(state.tree, request.account_id, request.device_id)
  if leaf_index < 0 do
    consume_group_state(state)
    Err("group_member_not_found")
  else
    let pending_ids = load_outbox_ids(request.database_path, wrapping_key) ?
    let device = open_device(profile, wrapping_key, request.database_path) ?
    case commit_remove(state, device.signing_private_key, leaf_index) do
      GroupRemoveRejected( rejected, _) -> do
        consume_group_state(rejected)
        Err("group_remove_rejected")
      end
      GroupMemberRemoved( next, commit) -> do
        let commit_wire = case encode_group_commit(commit) do
          Err( _) -> Err("group_commit_encoding_failed")
          Ok( value) -> Ok(value)
        end ?
        let targets = case delivery_targets(next.tree, next.local_leaf) do
          Err( _) -> Err("group_delivery_failed")
          Ok( value) -> Ok(value)
        end ?
        let envelopes = group_target_envelopes(targets,
        encode_group_packet(2, commit_wire) ?,
        current_time() ?,
        0,
        List.new()) ?
        let ( outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
        pending_ids,
        envelopes) ?
        let ( state_label, state_blob) = group_snapshot_blob(next, profile, wrapping_key) ?
        store_group_outbound(request.database_path,
        state_label,
        state_blob,
        outbox_labels,
        outbox_blobs,
        outbox_index_blob, [], []) ?
        encode_output_list(envelopes)
      end
    end
  end
end

pub fn send_mobile_group_message(input :: MobileGroupSendRequest) -> Bytes ! String do
  let request = % { input | body : present_message(input.database_path, input.group_id, input.body) ? }
  if Bytes.length(request.body) > 65342 do
    Err("group_message_too_large")
  else
    ensure_schema(request.database_path) ?
    let profile = decode_client_profile(load_profile(request.database_path) ?) ?
    let wrapping_key = platform_key() ?
    let state = load_group(request.database_path, profile, wrapping_key, request.group_id) ?
    let targets = case delivery_targets(state.tree, state.local_leaf) do
      Err( _) -> Err("group_delivery_failed")
      Ok( value) -> Ok(value)
    end ?
    if List.length(targets) == 0 do
      consume_group_state(state)
      Err("group_has_no_recipients")
    else
      let pending_ids = load_outbox_ids(request.database_path, wrapping_key) ?
      let device = open_device(profile, wrapping_key, request.database_path) ?
      let sender = case member_at(state.tree, state.local_leaf) do
        Err( _) -> Err("group_message_rejected")
        Ok( value) -> Ok(value)
      end ?
      let epoch = state.epoch
      case encrypt_group_message(state,
      device.signing_private_key,
      request.body,
      Bytes.from_utf8("mesh-mobile-group/v1")) do
        GroupEncryptRejected( rejected, _) -> do
          consume_group_state(rejected)
          Err("group_message_rejected")
        end
        GroupMessageEncrypted( next, message) -> do
          let message_wire = case encode_group_message(message) do
            Err( _) -> Err("group_message_encoding_failed")
            Ok( value) -> Ok(value)
          end ?
          let now = current_time() ?
          let envelopes = group_target_envelopes(targets,
          encode_group_packet(3, message_wire) ?,
          now,
          0,
          List.new()) ?
          let ( outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
          pending_ids,
          envelopes) ?
          let ( state_label, state_blob) = group_snapshot_blob(next, profile, wrapping_key) ?
          let history_label = group_history_label(request.group_id)
          let history_blob = updated_group_history_blob(request.database_path,
          wrapping_key,
          request.group_id,
          MobileGroupHistoryEntry {
            direction : 1,
            epoch : epoch,
            sender_account_id : sender.account_id,
            sender_device_id : sender.device_id,
            timestamp : now,
            body : request.body
          }) ?
          store_group_message_outbound(request.database_path,
          state_label,
          state_blob,
          history_label,
          history_blob,
          outbox_labels,
          outbox_blobs,
          outbox_index_blob) ?
          encode_output_list(envelopes)
        end
      end
    end
  end
end

fn welcome_member(value :: GroupWelcome) -> GroupMember ! String do
  case value.commit.proposal do
    AddMember( leaf_index, member) -> if leaf_index == value.recipient_leaf do
      Ok(member)
    else
      Err("invalid_group_welcome")
    end
    RemoveMember( _) -> Err("invalid_group_welcome")
  end
end

fn local_welcome_member(profile :: ClientProfile, member :: GroupMember, welcome :: GroupWelcome) -> Bool do
  Bytes.secure_equals(member.account_id, profile.account_id) && Bytes.secure_equals(member.device_id,
  profile.device_id) && Bytes.secure_equals(member.signing_public_key.bytes,
  profile.credential.signing_public_key) && Bytes.secure_equals(member.mailbox_token,
  profile.entry.mailbox_token) && Bytes.secure_equals(member.transparency_checkpoint_hash,
  welcome.policy.checkpoint_hash) && member.witness_count == 2 && welcome.policy.witness_threshold == 2
end

fn join_mobile_group(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
welcome :: GroupWelcome,
baseline_checkpoint :: Bytes) -> Bytes ! String do
  let group_id = welcome.commit.group_id
  let state_label = group_state_label(group_id) ?
  let member = welcome_member(welcome) ?
  let baseline = canonical_transparency_checkpoint(baseline_checkpoint) ?
  let baseline_hash = checkpoint_hash(baseline) ?
  let current_checkpoint = group_checkpoint(database_path, wrapping_key) ?
  let view = load_transparency_view(database_path, wrapping_key) ?
  if !Bytes.secure_equals(baseline_hash, welcome.policy.checkpoint_hash) || !local_welcome_member(profile,
  member,
  welcome) || !(transparency_checkpoint_precedes(baseline_checkpoint, current_checkpoint, view) ?) do
    Err("group_welcome_rejected")
  else
    case load_blob(database_path, state_label) do
      Ok( _) -> do
        let stored_baseline = load_group_baseline(database_path, wrapping_key, group_id) ?
        let existing = load_group(database_path, profile, wrapping_key, group_id) ?
        let existing_valid = Bytes.secure_equals(stored_baseline, baseline_checkpoint) && Bytes.secure_equals(existing.policy.checkpoint_hash,
        baseline_hash)
        consume_group_state(existing)
        if !existing_valid do
          Err("group_welcome_rejected")
        else
          store_updated_session(database_path,
          "groups/v1",
          updated_group_index_blob(database_path, wrapping_key, group_id) ?) ?
          Ok(group_id)
        end
      end
      Err( error) -> if error != "local_state_not_found" do
        Err(error)
      else
        let scope = accepted_invitation_scope(database_path, wrapping_key, welcome, baseline_checkpoint) ?
        let package_label = group_join_scoped_label(scope, "package")
        let init_label = group_join_scoped_label(scope, "init")
        let leaf_label = group_join_scoped_label(scope, "leaf")
        let stored_package = decode_group_key_package(open_local(load_blob(database_path,
        package_label) ?,
        wrapping_key,
        local_context(package_label) ?) ?) ?
        let package_signature_valid = case Crypto.verify(SigningPublicKey { bytes : profile.credential.signing_public_key },
        group_key_package_unsigned(stored_package) ?,
        stored_package.signature) do
          Err( _) -> false
          Ok( value) -> value
        end
        if !package_signature_valid || !Bytes.secure_equals(stored_package.account_id,
        profile.account_id) || !Bytes.secure_equals(stored_package.device_id, profile.device_id) || !Bytes.secure_equals(stored_package.init_public_key.bytes,
        member.init_public_key.bytes) || !Bytes.secure_equals(stored_package.leaf_public_key.bytes,
        member.leaf_public_key.bytes) || !(transparency_checkpoint_precedes(baseline_checkpoint,
        stored_package.checkpoint,
        view) ?) || !(transparency_checkpoint_precedes(stored_package.checkpoint,
        current_checkpoint,
        view) ?) do
          Err("group_welcome_rejected")
        else
          let init_private = open_x25519(load_blob(database_path, init_label) ?,
          wrapping_key,
          context(profile.account_id, profile.device_id, init_label, 17) ?) ?
          let leaf_private = open_x25519(load_blob(database_path, leaf_label) ?,
          wrapping_key,
          context(profile.account_id, profile.device_id, leaf_label, 17) ?) ?
          let state = case join_from_welcome(welcome, init_private, leaf_private) do
            Err( _) -> Err("group_welcome_rejected")
            Ok( value) -> Ok(value)
          end ?
          consume_group_private(init_private)
          let ( label, blob) = group_snapshot_blob(state, profile, wrapping_key) ?
          let index_blob = updated_group_index_blob(database_path, wrapping_key, group_id) ?
          let baseline_label = group_baseline_label(group_id) ?
          let baseline_blob = group_baseline_blob(baseline_checkpoint, wrapping_key, group_id) ?
          store_group_join(database_path,
          label,
          blob,
          index_blob,
          baseline_label,
          baseline_blob,
          package_label,
          init_label,
          leaf_label) ?
          Ok(group_id)
        end
      end
    end
  end
end

fn apply_mobile_group_commit(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
commit :: GroupCommit) -> Bytes ! String do
  let group_id = commit.group_id
  let state = load_group(database_path, profile, wrapping_key, group_id) ?
  let epoch_order = U64.compare(commit.prior_epoch, state.epoch)
  if epoch_order > 0 do
    consume_group_state(state)
    Err("group_future_epoch")
  else if epoch_order < 0 do
    consume_group_state(state)
    Err("group_stale_epoch")
  else
    case apply_commit(state, commit) do
      CommitRejected( rejected, error) -> do
        consume_group_state(rejected)
        case error do
          FutureEpoch -> Err("group_future_epoch")
          StaleEpoch -> Err("group_stale_epoch")
          _ -> Err("group_commit_rejected")
        end
      end
      CommitApplied( next) -> do
        let ( label, blob) = group_snapshot_blob(next, profile, wrapping_key) ?
        store_updated_session(database_path, label, blob) ?
        Ok(group_id)
      end
    end
  end
end

fn open_mobile_group_message(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
message :: GroupMessage) -> Bytes ! String do
  let state = load_group(database_path, profile, wrapping_key, message.group_id) ?
  let epoch_order = U64.compare(message.epoch, state.epoch)
  if epoch_order > 0 do
    consume_group_state(state)
    Err("group_future_epoch")
  else if epoch_order < 0 do
    consume_group_state(state)
    Err("group_stale_epoch")
  else
    let sender = case member_at(state.tree, message.sender_leaf) do
      Err( _) -> Err("group_message_rejected")
      Ok( value) -> Ok(value)
    end ?
    case decrypt_group_message(state, message, Bytes.from_utf8("mesh-mobile-group/v1")) do
      MessageRejected( rejected, error) -> do
        consume_group_state(rejected)
        case error do
          FutureEpoch -> Err("group_future_epoch")
          StaleEpoch -> Err("group_stale_epoch")
          _ -> Err("group_message_rejected")
        end
      end
      MessageOpened( next, plaintext) -> do
        let ( label, blob) = group_snapshot_blob(next, profile, wrapping_key) ?
        let history_label = group_history_label(message.group_id)
        let history_blob = updated_group_history_blob(database_path,
        wrapping_key,
        message.group_id,
        MobileGroupHistoryEntry {
          direction : 2,
          epoch : message.epoch,
          sender_account_id : sender.account_id,
          sender_device_id : sender.device_id,
          timestamp : current_time() ?,
          body : plaintext
        }) ?
        store_group_state_history(database_path, label, blob, history_label, history_blob) ?
        Ok(presented_body(plaintext))
      end
    end
  end
end

fn receive_mobile_group_result(request :: MobileReceiveRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let outer = canonical_outer(request.outer) ?
  if outer.suite != 3 || !Bytes.secure_equals(outer.mailbox_token, profile.entry.mailbox_token) do
    Err("wrong_group_delivery")
  else
    let packet = decode_group_packet(outer.ciphertext) ?
    let wrapping_key = platform_key() ?
    if packet.kind == 1 do
      let welcome_packet = decode_group_welcome_packet(packet.payload) ?
      join_mobile_group(request.database_path,
      profile,
      wrapping_key,
      canonical_group_welcome(welcome_packet.welcome) ?,
      welcome_packet.baseline_checkpoint)
    else if packet.kind == 2 do
      apply_mobile_group_commit(request.database_path,
      profile,
      wrapping_key,
      canonical_group_commit(packet.payload) ?)
    else
      open_mobile_group_message(request.database_path,
      profile,
      wrapping_key,
      canonical_group_message(packet.payload) ?)
    end
  end
end

fn permanent_group_delivery_error(error :: String) -> Bool do
  error == "wrong_group_delivery" || error == "invalid_outer_envelope" || error == "noncanonical_outer_envelope" || error == "invalid_group_packet" || error == "invalid_group_welcome" || error == "group_welcome_rejected" || error == "invalid_group_commit" || error == "group_commit_rejected" || error == "group_stale_epoch" || error == "invalid_group_message" || error == "group_message_rejected" || error == "group_limit_reached"
end

pub fn receive_mobile_group_classified(request :: MobileReceiveRequest) -> MobileGroupReceiveOutcome do
  case receive_mobile_group_result(request) do
    Ok( output) -> GroupReceiveApplied(output)
    Err( error) -> if permanent_group_delivery_error(error) do
      GroupReceiveRejected(error)
    else
      GroupReceiveRetry(error)
    end
  end
end

pub fn receive_mobile_group(request :: MobileReceiveRequest) -> Bytes ! String do
  case receive_mobile_group_classified(request) do
    GroupReceiveApplied( output) -> Ok(output)
    GroupReceiveRetry( error) -> Err(error)
    GroupReceiveRejected( error) -> Err(error)
  end
end
