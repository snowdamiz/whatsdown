from Mobile.Account import (
  account_deletion,
  authorize_link,
  authorize_link_for_set,
  complete_link,
  create_account,
  create_device_link_request,
  create_device_revocation,
  device_departure,
  device_link_sas,
  directory_entry_for,
  erase_account,
  forget_on_proof,
  directory_lookup,
  import_contact,
  inspect_device_set,
  mailbox_fetch
)
from Mobile.Attachments import open_attachment_chunk, prepare_attachment, seal_attachment_chunk
from Mobile.Codec import canonical_outer, mobile_utf8
from Mobile.Fanout import send_fanout
from Mobile.GroupInvites import (
  invite_to_group,
  accept_group_invitation,
  complete_group_invitation,
  decline_group_invitation,
  list_group_invitations
)
from Mobile.FanoutPrekeys import fanout_prekey_claims, prepare_fanout_prekeys, reserve_fanout_prekey
from Mobile.GroupState import (
  create_group_key_package,
  inspect_mobile_group,
  list_mobile_groups,
  mobile_group_history
)
from Mobile.Groups import (
  save_owned_presentation,
  add_mobile_group_member,
  create_mobile_group,
  receive_mobile_group,
  remove_mobile_group_member,
  send_mobile_group_message
)
from Mobile.History import (
  conversation_safety,
  list_conversations,
  load_visible_history,
  update_conversation
)
from Mobile.Inbox import process_delivery_batch
from Mobile.Messages import receive_initial_message, receive_message, send_message, start_conversation
from Mobile.Outbox import acknowledge_outbox, fail_outbox, list_outbox, page_outbox
from Mobile.Platform import privacy_submission, stamped_request
from Mobile.Prekeys import reconcile_prekeys, replenish_prekeys
from Mobile.Journal import load_journal, save_journal
from Mobile.Presentation import load_presentation
from Mobile.Profile import load_profile
from Mobile.Push import complete_push_action, push_action, push_intent, push_status
from Mobile.Requests import (
  parse_account_request,
  parse_attachment_chunk_request,
  parse_attachment_prepare_request,
  parse_batch_request,
  parse_fanout_prekey_reservation_request,
  parse_fanout_prepare_request,
  parse_fanout_request,
  parse_fanout_targets_request,
  parse_group_add_request,
  parse_group_reference_request,
  parse_group_remove_request,
  parse_group_send_request,
  parse_payload_request,
  parse_peer_request,
  parse_policy_request,
  parse_prekey_reconcile_request,
  parse_prekey_request,
  parse_push_action_completion,
  parse_push_intent_request,
  parse_receive_request,
  parse_start_request,
  parse_store_request,
  parse_transparency_request,
  parse_triple_payload_request
)
from Mobile.Transparency import transparency_lookup, verify_transparency_response
from Mobile.Types import (
  MobileAccountRequest,
  MobileAttachmentChunkRequest,
  MobileAttachmentPrepareRequest,
  MobileBatchRequest,
  MobileFanoutPrekeyReservationRequest,
  MobileFanoutPrepareRequest,
  MobileFanoutRequest,
  MobileFanoutTargetsRequest,
  MobileGroupAddRequest,
  MobileGroupReferenceRequest,
  MobileGroupRemoveRequest,
  MobileGroupSendRequest,
  MobilePayloadRequest,
  MobilePeerRequest,
  MobilePolicyRequest,
  MobilePrekeyReconcileRequest,
  MobilePrekeyRequest,
  MobilePushActionCompletion,
  MobilePushIntentRequest,
  MobileReceiveRequest,
  MobileStartRequest,
  MobileStoreRequest,
  MobileTransparencyRequest,
  MobileTriplePayloadRequest
)
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import OuterEnvelope
from Storage.Blobs import ensure_schema
from Storage.Records import store_envelope

##! Native messenger entrypoints; implementation is organized under Mobile and Storage.

@ export("mesh_messenger_initialize")pub fn initialize(request :: Bytes) -> Bytes ! String do
  case Bytes.to_utf8(request) do
    Err(_) -> Err("invalid_database_path")
    Ok(database_path) -> if String.length(database_path) == 0 || String.length(database_path) > 4096 do
      Err("invalid_database_path")
    else
      ensure_schema(database_path) ?
      Ok(Bytes.from_utf8("mesh-messenger-mobile-v1"))
    end
  end
end

@ export("mesh_messenger_validate_outer")pub fn validate_outer(request :: Bytes) -> Bytes ! String do
  let value = canonical_outer(request) ?
  case encode_outer_envelope(value) do
    Err(_) -> Err("invalid_outer_envelope")
    Ok(encoded) -> Ok(encoded)
  end
end

@ export("mesh_messenger_store_envelope")pub fn persist_envelope(request :: Bytes) -> Bytes ! String do
  store_envelope(parse_store_request(request) ?)
end

@ export("mesh_messenger_create_account")pub fn create_account_export(request :: Bytes) -> Bytes ! String do
  case parse_account_request(request) do
    Err(error) -> Err(error)
    Ok(parsed) -> create_account(parsed)
  end
end

@ export("mesh_messenger_load_profile")pub fn load_profile_export(request :: Bytes) -> Bytes ! String do
  load_profile(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_replenish_prekeys")pub fn replenish_prekeys_export(request :: Bytes) -> Bytes ! String do
  replenish_prekeys(parse_prekey_request(request) ?)
end

@ export("mesh_messenger_reconcile_prekeys")pub fn reconcile_prekeys_export(request :: Bytes) -> Bytes ! String do
  reconcile_prekeys(parse_prekey_reconcile_request(request) ?)
end

@ export("mesh_messenger_create_link_request")pub fn create_link_request_export(request :: Bytes) -> Bytes ! String do
  create_device_link_request(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_device_link_sas")pub fn device_link_sas_export(request :: Bytes) -> Bytes ! String do
  device_link_sas(request)
end

pub fn authorize_device_link_export(request :: Bytes) -> Bytes ! String do
  authorize_link(parse_payload_request(request) ?)
end

@ export("mesh_messenger_authorize_device_link_for_set")pub fn authorize_device_link_for_set_export(request :: Bytes) -> Bytes ! String do
  authorize_link_for_set(parse_triple_payload_request(request) ?)
end

@ export("mesh_messenger_complete_device_link")pub fn complete_device_link_export(request :: Bytes) -> Bytes ! String do
  complete_link(parse_payload_request(request) ?)
end

@ export("mesh_messenger_inspect_device_set")pub fn inspect_device_set_export(request :: Bytes) -> Bytes ! String do
  inspect_device_set(parse_payload_request(request) ?)
end

@ export("mesh_messenger_create_device_revocation")pub fn create_device_revocation_export(request :: Bytes) -> Bytes ! String do
  create_device_revocation(parse_triple_payload_request(request) ?)
end

@ export("mesh_messenger_account_deletion")pub fn account_deletion_export(request :: Bytes) -> Bytes ! String do
  account_deletion(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_erase_account")pub fn erase_account_export(request :: Bytes) -> Bytes ! String do
  erase_account(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_device_departure")pub fn device_departure_export(request :: Bytes) -> Bytes ! String do
  device_departure(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_forget_on_proof")pub fn forget_on_proof_export(request :: Bytes) -> Bytes ! String do
  forget_on_proof(parse_payload_request(request) ?)
end

pub fn start_conversation_export(request :: Bytes) -> Bytes ! String do
  start_conversation(parse_start_request(request) ?)
end

@ export("mesh_messenger_receive_initial")pub fn receive_initial_export(request :: Bytes) -> Bytes ! String do
  receive_initial_message(parse_receive_request(request) ?)
end

pub fn fanout_prekey_claims_export(request :: Bytes) -> Bytes ! String do
  fanout_prekey_claims(parse_fanout_targets_request(request) ?)
end

pub fn reserve_fanout_prekey_export(request :: Bytes) -> Bytes ! String do
  reserve_fanout_prekey(parse_fanout_prekey_reservation_request(request) ?)
end

@ export("mesh_messenger_prepare_fanout_prekeys")pub fn prepare_fanout_prekeys_export(request :: Bytes) -> Bytes ! String do
  prepare_fanout_prekeys(parse_fanout_prepare_request(request) ?)
end

@ export("mesh_messenger_send_fanout")pub fn send_fanout_export(request :: Bytes) -> Bytes ! String do
  send_fanout(parse_fanout_request(request) ?)
end

pub fn send_message_export(request :: Bytes) -> Bytes ! String do
  send_message(parse_start_request(request) ?)
end

@ export("mesh_messenger_group_key_package")pub fn group_key_package_export(request :: Bytes) -> Bytes ! String do
  let database_path = mobile_utf8(request, "invalid_database_path") ?
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    create_group_key_package(database_path)
  end
end

@ export("mesh_messenger_group_invite")pub fn group_invite_export(request :: Bytes) -> Bytes ! String do
  invite_to_group(parse_fanout_request(request) ?)
end

@ export("mesh_messenger_group_invitation_accept")pub fn group_invitation_accept_export(request :: Bytes) -> Bytes ! String do
  accept_group_invitation(parse_fanout_request(request) ?)
end

@ export("mesh_messenger_group_invitation_complete")pub fn group_invitation_complete_export(request :: Bytes) -> Bytes ! String do
  complete_group_invitation(parse_triple_payload_request(request) ?)
end

@ export("mesh_messenger_group_invitation_decline")pub fn group_invitation_decline_export(request :: Bytes) -> Bytes ! String do
  decline_group_invitation(parse_payload_request(request) ?)
end

@ export("mesh_messenger_group_invitations")pub fn group_invitations_export(request :: Bytes) -> Bytes ! String do
  list_group_invitations(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_group_create")pub fn group_create_export(request :: Bytes) -> Bytes ! String do
  let database_path = mobile_utf8(request, "invalid_database_path") ?
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    create_mobile_group(database_path)
  end
end

@ export("mesh_messenger_group_add")pub fn group_add_export(request :: Bytes) -> Bytes ! String do
  add_mobile_group_member(parse_group_add_request(request) ?)
end

@ export("mesh_messenger_group_remove")pub fn group_remove_export(request :: Bytes) -> Bytes ! String do
  remove_mobile_group_member(parse_group_remove_request(request) ?)
end

@ export("mesh_messenger_group_send")pub fn group_send_export(request :: Bytes) -> Bytes ! String do
  send_mobile_group_message(parse_group_send_request(request) ?)
end

@ export("mesh_messenger_group_receive")pub fn group_receive_export(request :: Bytes) -> Bytes ! String do
  receive_mobile_group(parse_receive_request(request) ?)
end

@ export("mesh_messenger_group_list")pub fn group_list_export(request :: Bytes) -> Bytes ! String do
  list_mobile_groups(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_group_inspect")pub fn group_inspect_export(request :: Bytes) -> Bytes ! String do
  inspect_mobile_group(parse_group_reference_request(request) ?)
end

@ export("mesh_messenger_group_history")pub fn group_history_export(request :: Bytes) -> Bytes ! String do
  mobile_group_history(parse_group_reference_request(request) ?)
end

@ export("mesh_messenger_receive_message")pub fn receive_message_export(request :: Bytes) -> Bytes ! String do
  receive_message(parse_receive_request(request) ?)
end

@ export("mesh_messenger_update_conversation")pub fn update_conversation_export(request :: Bytes) -> Bytes ! String do
  update_conversation(parse_policy_request(request) ?)
end

@ export("mesh_messenger_push_intent")pub fn push_intent_export(request :: Bytes) -> Bytes ! String do
  push_intent(parse_push_intent_request(request) ?)
end

pub fn push_action_export(request :: Bytes) -> Bytes ! String do
  push_action(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_push_action_complete")pub fn push_action_complete_export(request :: Bytes) -> Bytes ! String do
  complete_push_action(parse_push_action_completion(request) ?)
end

@ export("mesh_messenger_push_status")pub fn push_status_export(request :: Bytes) -> Bytes ! String do
  push_status(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_list_conversations")pub fn list_conversations_export(request :: Bytes) -> Bytes ! String do
  list_conversations(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_load_history")pub fn load_history_export(request :: Bytes) -> Bytes ! String do
  load_visible_history(parse_peer_request(request) ?)
end

@ export("mesh_messenger_safety_number")pub fn safety_number_export(request :: Bytes) -> Bytes ! String do
  conversation_safety(parse_peer_request(request) ?)
end

@ export("mesh_messenger_import_contact")pub fn import_contact_export(request :: Bytes) -> Bytes ! String do
  import_contact(request)
end

@ export("mesh_messenger_directory_entry")pub fn directory_entry_export(request :: Bytes) -> Bytes ! String do
  directory_entry_for(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_directory_lookup")pub fn directory_lookup_export(request :: Bytes) -> Bytes ! String do
  directory_lookup(request)
end

@ export("mesh_messenger_transparency_lookup")pub fn transparency_lookup_export(request :: Bytes) -> Bytes ! String do
  transparency_lookup(parse_payload_request(request) ?)
end

# What the app sends to the two anonymous directory endpoints it calls itself:
# the same bytes as the exports above, wrapped in proof of work for that
# endpoint. The label never leaves Mesh.

@ export("mesh_messenger_register_request")pub fn register_request_export(request :: Bytes) -> Bytes ! String do
  stamped_request("mesh-msg/v1/work/register",
  directory_entry_for(mobile_utf8(request, "invalid_database_path") ?) ?)
end

@ export("mesh_messenger_resolve_request")pub fn resolve_request_export(request :: Bytes) -> Bytes ! String do
  stamped_request("mesh-msg/v1/work/resolve",
  transparency_lookup(parse_payload_request(request) ?) ?)
end

@ export("mesh_messenger_verify_transparency")pub fn verify_transparency_export(request :: Bytes) -> Bytes ! String do
  verify_transparency_response(parse_transparency_request(request) ?)
end

@ export("mesh_messenger_privacy_submission")pub fn privacy_submission_export(request :: Bytes) -> Bytes ! String do
  privacy_submission(request)
end

@ export("mesh_messenger_mailbox_fetch")pub fn mailbox_fetch_export(request :: Bytes) -> Bytes ! String do
  mailbox_fetch(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_process_delivery_batch")pub fn process_delivery_batch_export(request :: Bytes) -> Bytes ! String do
  process_delivery_batch(parse_batch_request(request) ?)
end

@ export("mesh_messenger_outbox_list")pub fn outbox_list_export(request :: Bytes) -> Bytes ! String do
  let database_path = mobile_utf8(request, "invalid_database_path") ?
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    list_outbox(database_path)
  end
end

@ export("mesh_messenger_outbox_ack")pub fn outbox_ack_export(request :: Bytes) -> Bytes ! String do
  acknowledge_outbox(parse_payload_request(request) ?)
end

# The service refused this envelope for good. It leaves the outbox, and counts
# against its message rather than for it.

@ export("mesh_messenger_outbox_fail")pub fn outbox_fail_export(request :: Bytes) -> Bytes ! String do
  fail_outbox(parse_payload_request(request) ?)
end

# Up to eight queued envelopes starting at a four-byte offset, so a sender can
# pass by envelopes it is leaving queued.

@ export("mesh_messenger_outbox_page")pub fn outbox_page_export(request :: Bytes) -> Bytes ! String do
  page_outbox(parse_payload_request(request) ?)
end

# The app's read, notification and receipt journals, sealed like everything else
# it keeps; see `Mobile.Journal` for what may be named.

@ export("mesh_messenger_journal_load")pub fn journal_load_export(request :: Bytes) -> Bytes ! String do
  load_journal(parse_payload_request(request) ?)
end

@ export("mesh_messenger_journal_save")pub fn journal_save_export(request :: Bytes) -> Bytes ! String do
  save_journal(parse_triple_payload_request(request) ?)
end

@ export("mesh_messenger_presentation_load")pub fn presentation_load_export(request :: Bytes) -> Bytes ! String do
  load_presentation(parse_payload_request(request) ?)
end

@ export("mesh_messenger_presentation_save")pub fn presentation_save_export(request :: Bytes) -> Bytes ! String do
  save_owned_presentation(parse_triple_payload_request(request) ?)
end

@ export("mesh_messenger_attachment_prepare")pub fn attachment_prepare_export(request :: Bytes) -> Bytes ! String do
  prepare_attachment(parse_attachment_prepare_request(request) ?)
end

@ export("mesh_messenger_attachment_seal_chunk")pub fn attachment_seal_chunk_export(request :: Bytes) -> Bytes ! String do
  seal_attachment_chunk(parse_attachment_chunk_request(request) ?)
end

@ export("mesh_messenger_attachment_open_chunk")pub fn attachment_open_chunk_export(request :: Bytes) -> Bytes ! String do
  open_attachment_chunk(parse_attachment_chunk_request(request) ?)
end
