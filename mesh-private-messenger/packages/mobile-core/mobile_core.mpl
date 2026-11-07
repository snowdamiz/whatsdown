from Mobile.GroupExpiryPolicy import native_group_policy
from Mobile.GroupHistoryExpiry import expire_group_history_for
from Mobile.Codec import current_time
from Mobile.NetworkCounter import native_network_counter
from Mobile.FanoutNetwork import native_fanout_send
from Mobile.JournalBound import native_journal_load, native_journal_save
from Mobile.AccountNetwork import (
  native_account_delete,
  native_account_discard,
  native_account_capabilities
)
from Mobile.DeviceNetwork import native_devices_renew, native_device_revoke
from Mobile.PushNetwork import (
  native_push_intent,
  native_push_complete,
  native_push_send,
  native_push_begin,
  native_push_validate
)
from Mobile.AttachmentUpload import native_attachment_upload, native_attachment_discard
from Mobile.DirectoryResolve import native_directory_resolve
from Mobile.OutboxNetwork import native_outbox_drain
from Mobile.DirectoryNetwork import native_directory_register, native_prekeys_synchronize
from Mobile.Credits import native_credit_wallet_quote
from Mobile.Credits import (
  native_credit_discover_online,
  native_credit_purchase_continue,
  native_credit_action_continue,
  native_credit_signup_policy_online,
  native_credit_payment_handoff
)
from Mobile.BountyTransferNative import (
  native_bounty_transfer_status,
  native_bounty_transfer_prepare,
  native_bounty_transfer_commit,
  native_bounty_transfer_submit,
  native_bounty_transfer_recover,
  native_bounty_transfer_cancel
)
from Mobile.CreditAttachmentNative import (
  native_credit_attachment_grant,
  native_credit_attachment_upload,
  native_credit_attachment_complete,
  native_credit_attachment_delete,
  native_attachment_fetch_chunk,
  native_credit_attachment_prepare,
  native_credit_attachment_recover,
  native_credit_attachment_receipt,
  native_credit_attachment_part,
  native_credit_attachment_part_recover,
  native_credit_attachment_prune,
  native_credit_attachment_preview,
  native_credit_attachments,
  native_attachment_download_plan
)
from Mobile.Credits import (
  native_credit_action_recovery,
  native_credit_signup_policy,
  native_credit_signup_policy_view,
  require_credit_signup_enabled,
  native_signup_draft_rename,
  native_signup_draft_free,
  native_signup_draft_free_complete,
  native_credit_signup,
  native_credit_signup_recover,
  native_register_signup_policy
)
from Mobile.SignupDraft import signup_draft_state, require_free_registration_allowed
from Mobile.Credits import (
  native_credit_wallet_prepare,
  native_credit_wallet_commit,
  native_credit_wallet_submit
)
from Mobile.Credits import native_credit_payment_url, native_credit_payment_signature
from Mobile.Credits import (
  native_credit_retention,
  native_credit_retention_recover,
  native_credit_receipt
)
from Mobile.Credits import (
  native_credit_discovery,
  native_credit_admit,
  native_credit_prepare,
  native_credit_prepare_again,
  native_credit_quote,
  native_credit_payment,
  native_credit_finalize,
  native_credit_recover,
  native_credit_purchases,
  native_credit_balance,
  native_credit_reserve,
  native_credit_reservation
)
from Mobile.Account import (
  account_deletion,
  authorize_link,
  authorize_link_for_set,
  complete_link,
  create_account,
  create_account_with_presentation,
  create_signup_draft_account,
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
from Mobile.Codec import canonical_outer, mobile_utf8, mobile_byte
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
  forget_mobile_group,
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
from Mobile.Messages import (
  receive_initial_message,
  receive_message,
  send_message,
  start_conversation
)
from Mobile.Outbox import acknowledge_outbox, fail_outbox, list_outbox, page_outbox
from Mobile.GossipSend import flush_gossip
from Mobile.AnchorCheck import AnchorObservation, check_native_anchor, anchor_observation_output
from Mobile.Bounty import disclosable_fork
from Mobile.CreditPostageNative import (
  native_credit_postage_candidate,
  native_credit_postage_preview,
  native_credit_postage_prepare,
  native_credit_postage_recover,
  native_credit_postage_receipt,
  native_credit_postage_continue,
  native_credit_postage_inventory,
  native_postage_policy_view,
  native_postage_policy_prepare,
  native_postage_policy_publish
)
from Mobile.BountyNative import (
  native_bounty_status,
  native_bounty_set_enabled,
  native_bounty_commit,
  native_bounty_unavailable
)
from Mobile.ForkFiling import check_native_filing
from Mobile.Platform import privacy_submission, stamped_request
from Mobile.Resolve import resolution_plan
from Mobile.Prekeys import reconcile_prekeys, replenish_prekeys
from Mobile.Journal import load_journal, save_journal
from Mobile.Presentation import load_presentation
from Mobile.Profile import load_profile
from Mobile.Renewal import renew_devices
from Mobile.Push import complete_push_action, push_action, push_intent, push_status
from Mobile.Requests import (
  parse_account_request,
  parse_create_account_request,
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
from Storage.Keys import platform_key
from Storage.Blobs import ensure_schema
from Storage.Records import store_envelope
from Mobile.MailboxNative import native_mailbox_open, native_mailbox_poll, native_mailbox_close
from Mobile.MailboxSync import native_mailbox_synchronize

##! Native messenger entrypoints; implementation is organized under Mobile and Storage.

@export("mesh_messenger_initialize") pub fn initialize(request :: Bytes) -> Bytes!String do
  case Bytes.to_utf8(request) do
    Err(_) -> Err("invalid_database_path")
    Ok(database_path) -> if String.length(database_path) == 0
      || String.length(database_path) > 4096 do
      Err("invalid_database_path")
    else
      ensure_schema(database_path)?
      Ok(Bytes.from_utf8("mesh-messenger-mobile-v1"))
    end
  end
end

@export("mesh_messenger_validate_outer") pub fn validate_outer(request :: Bytes) -> Bytes!String do
  let value = canonical_outer(request)?
  case encode_outer_envelope(value) do
    Err(_) -> Err("invalid_outer_envelope")
    Ok(encoded)
  end
end

@export("mesh_messenger_store_envelope") pub fn persist_envelope(request :: Bytes) -> Bytes!String do
  store_envelope(parse_store_request(request)?)
end

@export("mesh_messenger_create_account") pub fn create_account_export(request :: Bytes) -> Bytes!String do
  case parse_create_account_request(request) do
    Err(error)
    Ok(parsed) -> do
      let (account, presentation) = parsed
      create_account_with_presentation(account, presentation)
    end
  end
end

@export("mesh_messenger_load_profile") pub fn load_profile_export(request :: Bytes) -> Bytes!String do
  load_profile(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_create_signup_draft") pub fn create_signup_draft_export(request :: Bytes) -> Bytes!String do
  require_credit_signup_enabled()?
  create_signup_draft_account(parse_account_request(request)?)
end

@export("mesh_messenger_signup_draft_state") pub fn signup_draft_state_export(request :: Bytes) -> Bytes!String do
  mobile_byte(signup_draft_state(mobile_utf8(request, "invalid_database_path")?)?)
end

@export("mesh_messenger_credit_action_recovery") pub fn credit_action_recovery_export(request :: Bytes) -> Bytes!String do
  native_credit_action_recovery(request)
end

@export("mesh_messenger_credit_signup_policy") pub fn credit_signup_policy_export(request :: Bytes) -> Bytes!String do
  native_credit_signup_policy(request)
end

@export("mesh_messenger_credit_signup_policy_view") pub fn credit_signup_policy_view_export(request :: Bytes) -> Bytes!String do
  native_credit_signup_policy_view(request)
end

@export("mesh_messenger_signup_draft_rename") pub fn signup_draft_rename_export(request :: Bytes) -> Bytes!String do
  native_signup_draft_rename(request)
end

@export("mesh_messenger_signup_draft_free") pub fn signup_draft_free_export(request :: Bytes) -> Bytes!String do
  native_signup_draft_free(request)
end

@export("mesh_messenger_signup_draft_free_complete") pub fn signup_draft_free_complete_export(request :: Bytes) -> Bytes!String do
  native_signup_draft_free_complete(request)
end

@export("mesh_messenger_credit_signup") pub fn credit_signup_export(request :: Bytes) -> Bytes!String do
  native_credit_signup(request)
end

@export("mesh_messenger_credit_signup_recover") pub fn credit_signup_recover_export(request :: Bytes) -> Bytes!String do
  native_credit_signup_recover(request)
end

@export("mesh_messenger_register_signup_policy") pub fn register_signup_policy_export(request :: Bytes) -> Bytes!String do
  native_register_signup_policy(request)
end

@export("mesh_messenger_credit_attachment_prepare") pub fn credit_attachment_prepare_export(request :: Bytes) -> Bytes!String do
  native_credit_attachment_prepare(request)
end

@export("mesh_messenger_credit_attachment_recover") pub fn credit_attachment_recover_export(request :: Bytes) -> Bytes!String do
  native_credit_attachment_recover(request)
end

@export("mesh_messenger_credit_attachment_receipt") pub fn credit_attachment_receipt_export(request :: Bytes) -> Bytes!String do
  native_credit_attachment_receipt(request)
end

@export("mesh_messenger_credit_attachment_part") pub fn credit_attachment_part_export(request :: Bytes) -> Bytes!String do
  native_credit_attachment_part(request)
end

@export("mesh_messenger_credit_attachment_part_recover") pub fn credit_attachment_part_recover_export(request :: Bytes) -> Bytes!String do
  native_credit_attachment_part_recover(request)
end

@export("mesh_messenger_credit_attachment_prune") pub fn credit_attachment_prune_export(request :: Bytes) -> Bytes!String do
  native_credit_attachment_prune(request)
end

@export("mesh_messenger_credit_attachment_preview") pub fn credit_attachment_preview_export(request :: Bytes) -> Bytes!String do
  native_credit_attachment_preview(request)
end

@display("Paid attachment names, MIME types and journal status are returned to the reviewed React Native paid-attachment inventory for display and explicit resume/cancel controls; content remains private elsewhere.")
@export("mesh_messenger_credit_attachments") pub fn credit_attachments_export(request :: Bytes) -> Bytes!String do
  native_credit_attachments(request)
end

@display("Authenticated attachment names, MIME types and bounded download metadata are returned to the reviewed React Native attachment display/save adapter; object fetching remains in Mesh.")
@export("mesh_messenger_attachment_download_plan") pub fn attachment_download_plan_export(request :: Bytes) -> Bytes!String do
  native_attachment_download_plan(request)
end

@export("mesh_messenger_replenish_prekeys") pub fn replenish_prekeys_export(request :: Bytes) -> Bytes!String do
  replenish_prekeys(parse_prekey_request(request)?)
end

@export("mesh_messenger_reconcile_prekeys") pub fn reconcile_prekeys_export(request :: Bytes) -> Bytes!String do
  reconcile_prekeys(parse_prekey_reconcile_request(request)?)
end

@export("mesh_messenger_create_link_request") pub fn create_link_request_export(request :: Bytes) -> Bytes!String do
  create_device_link_request(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_device_link_sas") pub fn device_link_sas_export(request :: Bytes) -> Bytes!String do
  device_link_sas(request)
end

pub fn authorize_device_link_export(request :: Bytes) -> Bytes!String do
  authorize_link(parse_payload_request(request)?)
end

@export("mesh_messenger_authorize_device_link_for_set") pub fn authorize_device_link_for_set_export(request :: Bytes) -> Bytes!String do
  authorize_link_for_set(parse_triple_payload_request(request)?)
end

@export("mesh_messenger_complete_device_link") pub fn complete_device_link_export(request :: Bytes) -> Bytes!String do
  complete_link(parse_payload_request(request)?)
end

@export("mesh_messenger_inspect_device_set") pub fn inspect_device_set_export(request :: Bytes) -> Bytes!String do
  inspect_device_set(parse_payload_request(request)?)
end

@export("mesh_messenger_create_device_revocation") pub fn create_device_revocation_export(request :: Bytes) -> Bytes!String do
  create_device_revocation(parse_triple_payload_request(request)?)
end

@export("mesh_messenger_account_deletion") pub fn account_deletion_export(request :: Bytes) -> Bytes!String do
  account_deletion(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_erase_account") pub fn erase_account_export(request :: Bytes) -> Bytes!String do
  erase_account(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_device_departure") pub fn device_departure_export(request :: Bytes) -> Bytes!String do
  device_departure(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_forget_on_proof") pub fn forget_on_proof_export(request :: Bytes) -> Bytes!String do
  forget_on_proof(parse_payload_request(request)?)
end

pub fn start_conversation_export(request :: Bytes) -> Bytes!String do
  start_conversation(parse_start_request(request)?)
end

@display("The legacy native initial-receive response returns the authenticated message body to the app-owned UI boundary; calls from Mesh retain private results and internal mailbox processing grants no display permission.")
@export("mesh_messenger_receive_initial") pub fn receive_initial_export(request :: Bytes) -> Plaintext<Bytes>!String do
  receive_initial_message(parse_receive_request(request)?)
end

pub fn fanout_prekey_claims_export(request :: Bytes) -> Bytes!String do
  fanout_prekey_claims(parse_fanout_targets_request(request)?)
end

pub fn reserve_fanout_prekey_export(request :: Bytes) -> Bytes!String do
  reserve_fanout_prekey(parse_fanout_prekey_reservation_request(request)?)
end

@export("mesh_messenger_prepare_fanout_prekeys") pub fn prepare_fanout_prekeys_export(request :: Bytes) -> Bytes!String do
  prepare_fanout_prekeys(parse_fanout_prepare_request(request)?)
end

@export("mesh_messenger_send_fanout") pub fn send_fanout_export(request :: Bytes) -> Bytes!String do
  send_fanout(parse_fanout_request(request)?)
end

pub fn send_message_export(request :: Bytes) -> Bytes!String do
  send_message(parse_start_request(request)?)
end

@export("mesh_messenger_group_key_package") pub fn group_key_package_export(request :: Bytes) -> Bytes!String do
  let database_path = mobile_utf8(request, "invalid_database_path")?
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    create_group_key_package(database_path)
  end
end

@export("mesh_messenger_group_invite") pub fn group_invite_export(request :: Bytes) -> Bytes!String do
  invite_to_group(request)
end

@export("mesh_messenger_group_invitation_accept") pub fn group_invitation_accept_export(request :: Bytes) -> Bytes!String do
  accept_group_invitation(request)
end

@export("mesh_messenger_group_invitation_complete") pub fn group_invitation_complete_export(request :: Bytes) -> Bytes!String do
  complete_group_invitation(parse_triple_payload_request(request)?)
end

@export("mesh_messenger_group_invitation_decline") pub fn group_invitation_decline_export(request :: Bytes) -> Bytes!String do
  decline_group_invitation(parse_payload_request(request)?)
end

@export("mesh_messenger_group_invitations") pub fn group_invitations_export(request :: Bytes) -> Bytes!String do
  list_group_invitations(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_group_create") pub fn group_create_export(request :: Bytes) -> Bytes!String do
  let database_path = mobile_utf8(request, "invalid_database_path")?
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    create_mobile_group(database_path)
  end
end

@export("mesh_messenger_group_add") pub fn group_add_export(request :: Bytes) -> Bytes!String do
  add_mobile_group_member(parse_group_add_request(request)?)
end

@export("mesh_messenger_group_remove") pub fn group_remove_export(request :: Bytes) -> Bytes!String do
  remove_mobile_group_member(parse_group_remove_request(request)?)
end

@export("mesh_messenger_group_send") pub fn group_send_export(request :: Bytes) -> Bytes!String do
  send_mobile_group_message(parse_group_send_request(request)?)
end

@display("The legacy native group-receive response returns the authenticated message body to the app-owned UI boundary; calls from Mesh retain private results and internal mailbox processing grants no display permission.")
@export("mesh_messenger_group_receive") pub fn group_receive_export(request :: Bytes) -> Plaintext<Bytes>!String do
  receive_mobile_group(parse_receive_request(request)?)
end

@export("mesh_messenger_group_list") pub fn group_list_export(request :: Bytes) -> Bytes!String do
  list_mobile_groups(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_group_inspect") pub fn group_inspect_export(request :: Bytes) -> Bytes!String do
  inspect_mobile_group(parse_group_reference_request(request)?)
end

@display("Group history bodies and attachment presentation are returned to the reviewed React Native chat and local notification adapters; notification redaction and receipt timestamps are computed there, and receipt transport is natively re-sealed.")
@export("mesh_messenger_group_history") pub fn group_history_export(request :: Bytes) -> Bytes!String do
  let parsed = parse_group_reference_request(request)?
  expire_group_history_for(parsed.database_path, parsed.group_id, current_time()?)?
  mobile_group_history(parsed)
end

@export("mesh_messenger_group_forget") pub fn group_forget_export(request :: Bytes) -> Bytes!String do
  forget_mobile_group(parse_group_reference_request(request)?)
end

@display("The legacy native direct-receive response returns the authenticated message body to the app-owned UI boundary; calls from Mesh retain private results and internal mailbox processing grants no display permission.")
@export("mesh_messenger_receive_message") pub fn receive_message_export(request :: Bytes) -> Plaintext<Bytes>!String do
  receive_message(parse_receive_request(request)?)
end

@export("mesh_messenger_update_conversation") pub fn update_conversation_export(request :: Bytes) -> Bytes!String do
  update_conversation(parse_policy_request(request)?)
end

@export("mesh_messenger_push_intent") pub fn push_intent_export(request :: Bytes) -> Bytes!String do
  push_intent(parse_push_intent_request(request)?)
end

pub fn push_action_export(request :: Bytes) -> Bytes!String do
  push_action(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_push_action_complete") pub fn push_action_complete_export(request :: Bytes) -> Bytes!String do
  complete_push_action(parse_push_action_completion(request)?)
end

@export("mesh_messenger_push_status") pub fn push_status_export(request :: Bytes) -> Bytes!String do
  push_status(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_list_conversations") pub fn list_conversations_export(request :: Bytes) -> Bytes!String do
  list_conversations(mobile_utf8(request, "invalid_database_path")?)
end

@display("Direct history bodies, attachment presentation and finite view-once placeholder statuses are returned to the reviewed React Native chat and local notification adapters; notification redaction and receipt timestamps are computed there, and receipt transport is natively re-sealed. View-once references, capabilities, keys and image bytes remain private.")
@export("mesh_messenger_load_history", max_output: 16_794_632) pub fn load_history_export(request :: Bytes) -> Bytes!String do
  load_visible_history(parse_peer_request(request)?)
end

@export("mesh_messenger_safety_number") pub fn safety_number_export(request :: Bytes) -> Bytes!String do
  conversation_safety(parse_peer_request(request)?)
end

@export("mesh_messenger_import_contact") pub fn import_contact_export(request :: Bytes) -> Bytes!String do
  import_contact(request)
end

@export("mesh_messenger_directory_entry") pub fn directory_entry_export(request :: Bytes) -> Bytes!String do
  directory_entry_for(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_directory_lookup") pub fn directory_lookup_export(request :: Bytes) -> Bytes!String do
  directory_lookup(request)
end

@export("mesh_messenger_transparency_lookup") pub fn transparency_lookup_export(request :: Bytes) -> Bytes!String do
  transparency_lookup(parse_payload_request(request)?)
end

# What the app sends to the two anonymous directory endpoints it calls itself:
# the same bytes as the exports above, wrapped in proof of work for that
# endpoint. The label never leaves Mesh.

@export("mesh_messenger_register_request") pub fn register_request_export(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_database_path")?
  require_free_registration_allowed(path)?
  stamped_request("mesh-msg/v1/work/register", directory_entry_for(path)?)
end

# The registrations that renew this device (and, on the device holding the
# account key, the linked devices that asked), for its account's verified
# device set. Each is already wrapped in proof of work for the register
# endpoint; send them in order and stop at the first refusal.

@export("mesh_messenger_renew_devices") pub fn renew_devices_export(request :: Bytes) -> Bytes!String do
  renew_devices(parse_payload_request(request)?)
end

@export("mesh_messenger_resolve_request") pub fn resolve_request_export(request :: Bytes) -> Bytes!String do
  stamped_request("mesh-msg/v1/work/resolve", transparency_lookup(parse_payload_request(request)?)?)
end

@export("mesh_messenger_resolve_plan") pub fn resolve_plan_export(request :: Bytes) -> Bytes!String do
  resolution_plan(parse_payload_request(request)?)
end

@export("mesh_messenger_verify_transparency") pub fn verify_transparency_export(request :: Bytes) -> Bytes!String do
  verify_transparency_response(parse_transparency_request(request)?)
end

# Public, already-verified evidence for the persistent banner and Details.
@export("mesh_messenger_transparency_fork") pub fn transparency_fork_export(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_database_path")?
  ensure_schema(path)?
  let key = platform_key()?
  disclosable_fork(path, key)
end

@export("mesh_messenger_bounty_status") pub fn bounty_status_export(request :: Bytes) -> Bytes!String do
  native_bounty_status(request)
end

# Host-private: these three exports must never enter generic JS dispatch.
@export("mesh_messenger_bounty_set_enabled") pub fn bounty_set_enabled_export(request :: Bytes) -> Bytes!String do
  native_bounty_set_enabled(request)
end

@export("mesh_messenger_bounty_commit") pub fn bounty_commit_export(request :: Bytes) -> Bytes!String do
  native_bounty_commit(request)
end

@export("mesh_messenger_bounty_unavailable") pub fn bounty_unavailable_export(request :: Bytes) -> Bytes!String do
  native_bounty_unavailable(request)
end

@export("mesh_messenger_bounty_transfer_status") pub fn bounty_transfer_status_export(request :: Bytes) -> Bytes!String do
  native_bounty_transfer_status(request)
end

@export("mesh_messenger_bounty_transfer_recover") pub fn bounty_transfer_recover_export(request :: Bytes) -> Bytes!String do
  native_bounty_transfer_recover(request)
end

@export("mesh_messenger_bounty_transfer_cancel") pub fn bounty_transfer_cancel_export(request :: Bytes) -> Bytes!String do
  native_bounty_transfer_cancel(request)
end

# Host-private transfer preparation/signature commit/submission. These exports
# are excluded from generic JS dispatch, like native wallet purchase signing.
@export("mesh_messenger_bounty_transfer_prepare") pub fn bounty_transfer_prepare_export(request :: Bytes) -> Bytes!String do
  native_bounty_transfer_prepare(request)
end

@export("mesh_messenger_bounty_transfer_commit") pub fn bounty_transfer_commit_export(request :: Bytes) -> Bytes!String do
  native_bounty_transfer_commit(request)
end

@export("mesh_messenger_bounty_transfer_submit") pub fn bounty_transfer_submit_export(request :: Bytes) -> Bytes!String do
  native_bounty_transfer_submit(request)
end

# A foreground/background wake only asks Mesh to check whether work is due.
# Native release pins, the clock, persisted limits and all RPCs stay in Mesh.
@export("mesh_messenger_anchor_check") pub fn anchor_check_export(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_database_path")?
  if String.length(path) == 0 || String.length(path) > 4096 do
    return Err("invalid_database_path")
  end
  anchor_observation_output(check_native_anchor(path, false)?)
end

# Independently scheduled from message sync: all evidence, destinations,
# durable retry limits and finalized receipt checks remain inside Mesh.
@export("mesh_messenger_fork_filing") pub fn fork_filing_export(request :: Bytes) -> Bytes!String do
  check_native_filing(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_privacy_submission") pub fn privacy_submission_export(request :: Bytes) -> Bytes!String do
  privacy_submission(request)
end

@export("mesh_messenger_mailbox_fetch") pub fn mailbox_fetch_export(request :: Bytes) -> Bytes!String do
  mailbox_fetch(mobile_utf8(request, "invalid_database_path")?)
end

@export("mesh_messenger_mailbox_synchronize") pub fn mailbox_synchronize_export(request :: Bytes) -> Bytes!String do
  native_mailbox_synchronize(request)
end

@export("mesh_messenger_mailbox_stream_open") pub fn mailbox_stream_open_export(request :: Bytes) -> Bytes!String do
  native_mailbox_open(request)
end

@export("mesh_messenger_mailbox_stream_poll") pub fn mailbox_stream_poll_export(request :: Bytes) -> Bytes!String do
  native_mailbox_poll(request)
end

@export("mesh_messenger_mailbox_stream_close") pub fn mailbox_stream_close_export(request :: Bytes) -> Bytes!String do
  native_mailbox_close(request)
end

@export("mesh_messenger_process_delivery_batch") pub fn process_delivery_batch_export(request :: Bytes) -> Bytes!String do
  process_delivery_batch(parse_batch_request(request)?)
end

@export("mesh_messenger_outbox_list") pub fn outbox_list_export(request :: Bytes) -> Bytes!String do
  let database_path = mobile_utf8(request, "invalid_database_path")?
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    flush_gossip(database_path)?
    list_outbox(database_path)
  end
end

@export("mesh_messenger_outbox_drain") pub fn outbox_drain_export(request :: Bytes) -> Bytes!String do
  native_outbox_drain(request)
end

@export("mesh_messenger_outbox_ack") pub fn outbox_ack_export(request :: Bytes) -> Bytes!String do
  acknowledge_outbox(parse_payload_request(request)?)
end

# The service refused this envelope for good. It leaves the outbox, and counts
# against its message rather than for it.

@export("mesh_messenger_outbox_fail") pub fn outbox_fail_export(request :: Bytes) -> Bytes!String do
  fail_outbox(parse_payload_request(request)?)
end

# Up to eight queued envelopes starting at a four-byte offset, so a sender can
# pass by envelopes it is leaving queued.

@export("mesh_messenger_outbox_page") pub fn outbox_page_export(request :: Bytes) -> Bytes!String do
  let parsed = parse_payload_request(request)?
  flush_gossip(parsed.database_path)?
  page_outbox(parsed)
end

# The app's read, notification and receipt journals, sealed like everything else
# it keeps; see `Mobile.Journal` for what may be named.

@export("mesh_messenger_journal_load") pub fn journal_load_export(request :: Bytes) -> Bytes!String do
  load_journal(parse_payload_request(request)?)
end

@export("mesh_messenger_journal_save") pub fn journal_save_export(request :: Bytes) -> Bytes!String do
  save_journal(parse_triple_payload_request(request)?)
end

@display("Profile, contact nickname, group and community name/avatar/text records are returned to the reviewed React Native presentation store for chat, contact/profile/community screens and local group notification presentation; raw content remains private elsewhere.")
@export("mesh_messenger_presentation_load") pub fn presentation_load_export(request :: Bytes) -> Bytes!String do
  load_presentation(parse_payload_request(request)?)
end

@display("The confirmed selected profile, local nickname, group or community presentation record is returned to the reviewed React Native edit and community-state adapters after an authenticated local update; raw content remains private elsewhere.")
@export("mesh_messenger_presentation_save") pub fn presentation_save_export(request :: Bytes) -> Bytes!String do
  save_owned_presentation(parse_triple_payload_request(request)?)
end

@export("mesh_messenger_attachment_prepare") pub fn attachment_prepare_export(request :: Bytes) -> Bytes!String do
  prepare_attachment(parse_attachment_prepare_request(request)?)
end

@export("mesh_messenger_attachment_seal_chunk") pub fn attachment_seal_chunk_export(request :: Bytes) -> Bytes!String do
  seal_attachment_chunk(parse_attachment_chunk_request(request)?)
end

pub fn attachment_open_chunk_export(request :: Bytes) -> Bytes!String do
  open_attachment_chunk(parse_attachment_chunk_request(request)?)
end

# Anonymous credit custody uses counted-vector packets and native trust pins.

@export("mesh_messenger_credit_discover_online")
pub fn credit_discover_online_export(request :: Bytes) -> Bytes!String do
  native_credit_discover_online(request)
end

@export("mesh_messenger_credit_purchase_continue")
pub fn credit_purchase_continue_export(request :: Bytes) -> Bytes!String do
  native_credit_purchase_continue(request)
end

@export("mesh_messenger_credit_payment_handoff")
pub fn credit_payment_handoff_export(request :: Bytes) -> Bytes!String do
  native_credit_payment_handoff(request)
end

@export("mesh_messenger_credit_action_continue")
pub fn credit_action_continue_export(request :: Bytes) -> Bytes!String do
  native_credit_action_continue(request)
end

@export("mesh_messenger_credit_signup_policy_online")
pub fn credit_signup_policy_online_export(request :: Bytes) -> Bytes!String do
  native_credit_signup_policy_online(request)
end

@export("mesh_messenger_credit_discovery")
pub fn credit_discovery_export(request :: Bytes) -> Bytes!String do
  native_credit_discovery(request)
end

@export("mesh_messenger_credit_admit")
pub fn credit_admit_export(request :: Bytes) -> Bytes!String do
  native_credit_admit(request)
end

@export("mesh_messenger_credit_prepare")
pub fn credit_prepare_export(request :: Bytes) -> Bytes!String do
  native_credit_prepare(request)
end

@export("mesh_messenger_credit_prepare_again")
pub fn credit_prepare_again_export(request :: Bytes) -> Bytes!String do
  native_credit_prepare_again(request)
end

@export("mesh_messenger_credit_quote")
pub fn credit_quote_export(request :: Bytes) -> Bytes!String do
  native_credit_quote(request)
end

@export("mesh_messenger_credit_payment")
pub fn credit_payment_export(request :: Bytes) -> Bytes!String do
  native_credit_payment(request)
end

@export("mesh_messenger_credit_finalize")
pub fn credit_finalize_export(request :: Bytes) -> Bytes!String do
  native_credit_finalize(request)
end

@export("mesh_messenger_credit_recover")
pub fn credit_recover_export(request :: Bytes) -> Bytes!String do
  native_credit_recover(request)
end

@export("mesh_messenger_credit_purchases")
pub fn credit_purchases_export(request :: Bytes) -> Bytes!String do
  native_credit_purchases(request)
end

@export("mesh_messenger_credit_balance")
pub fn credit_balance_export(request :: Bytes) -> Bytes!String do
  native_credit_balance(request)
end

@export("mesh_messenger_credit_reserve")
pub fn credit_reserve_export(request :: Bytes) -> Bytes!String do
  native_credit_reserve(request)
end

@export("mesh_messenger_credit_reservation")
pub fn credit_reservation_export(request :: Bytes) -> Bytes!String do
  native_credit_reservation(request)
end

@export("mesh_messenger_credit_retention")
pub fn credit_retention_export(request :: Bytes) -> Bytes!String do
  native_credit_retention(request)
end

@export("mesh_messenger_credit_retention_recover")
pub fn credit_retention_recover_export(request :: Bytes) -> Bytes!String do
  native_credit_retention_recover(request)
end

@export("mesh_messenger_credit_receipt")
pub fn credit_receipt_export(request :: Bytes) -> Bytes!String do
  native_credit_receipt(request)
end

@export("mesh_messenger_credit_payment_url")
pub fn credit_payment_url_export(request :: Bytes) -> Bytes!String do
  native_credit_payment_url(request)
end

@export("mesh_messenger_credit_payment_signature")
pub fn credit_payment_signature_export(request :: Bytes) -> Bytes!String do
  native_credit_payment_signature(request)
end

@export("mesh_messenger_credit_wallet_quote")
pub fn credit_wallet_quote_export(request :: Bytes) -> Bytes!String do
  native_credit_wallet_quote(request)
end

@export("mesh_messenger_credit_wallet_prepare")
pub fn credit_wallet_prepare_export(request :: Bytes) -> Bytes!String do
  native_credit_wallet_prepare(request)
end

@export("mesh_messenger_credit_wallet_commit")
pub fn credit_wallet_commit_export(request :: Bytes) -> Bytes!String do
  native_credit_wallet_commit(request)
end

@export("mesh_messenger_credit_wallet_submit")
pub fn credit_wallet_submit_export(request :: Bytes) -> Bytes!String do
  native_credit_wallet_submit(request)
end

@export("mesh_messenger_credit_postage_candidate")
pub fn credit_postage_candidate_export(request :: Bytes) -> Bytes!String do
  native_credit_postage_candidate(request)
end

@export("mesh_messenger_credit_postage_preview")
pub fn credit_postage_preview_export(request :: Bytes) -> Bytes!String do
  native_credit_postage_preview(request)
end

@export("mesh_messenger_credit_postage_prepare")
pub fn credit_postage_prepare_export(request :: Bytes) -> Bytes!String do
  native_credit_postage_prepare(request)
end

@export("mesh_messenger_credit_postage_recover")
pub fn credit_postage_recover_export(request :: Bytes) -> Bytes!String do
  native_credit_postage_recover(request)
end

@export("mesh_messenger_credit_postage_receipt")
pub fn credit_postage_receipt_export(request :: Bytes) -> Bytes!String do
  native_credit_postage_receipt(request)
end

@export("mesh_messenger_credit_postage_inventory")
pub fn credit_postage_inventory_export(request :: Bytes) -> Bytes!String do
  native_credit_postage_inventory(request)
end

@export("mesh_messenger_postage_policy_view")
pub fn postage_policy_view_export(request :: Bytes) -> Bytes!String do
  native_postage_policy_view(request)
end

@export("mesh_messenger_postage_policy_prepare")
pub fn postage_policy_prepare_export(request :: Bytes) -> Bytes!String do
  native_postage_policy_prepare(request)
end

@export("mesh_messenger_credit_postage_continue")
pub fn credit_postage_continue_export(request :: Bytes) -> Bytes!String do
  native_credit_postage_continue(request)
end

@export("mesh_messenger_postage_policy_publish")
pub fn postage_policy_publish_export(request :: Bytes) -> Bytes!String do
  native_postage_policy_publish(request)
end

@export("mesh_messenger_directory_register") pub fn directory_register_export(request :: Bytes) -> Bytes!String do
  native_directory_register(request)
end

@export("mesh_messenger_prekeys_synchronize") pub fn prekeys_synchronize_export(request :: Bytes) -> Bytes!String do
  native_prekeys_synchronize(request)
end

@export("mesh_messenger_credit_attachment_grant") pub fn credit_attachment_grant_export(request :: Bytes) -> Bytes!String do
  native_credit_attachment_grant(request)
end

@export("mesh_messenger_credit_attachment_upload") pub fn credit_attachment_upload_export(request :: Bytes) -> Bytes!String do
  native_credit_attachment_upload(request)
end

@export("mesh_messenger_credit_attachment_complete") pub fn credit_attachment_complete_export(request :: Bytes) -> Bytes!String do
  native_credit_attachment_complete(request)
end

@export("mesh_messenger_credit_attachment_delete") pub fn credit_attachment_delete_export(request :: Bytes) -> Bytes!String do
  native_credit_attachment_delete(request)
end

@display("User-requested attachment plaintext is returned to the native display/save boundary after authenticated chunk opening; HTTP transport remains in Mesh.")
@export("mesh_messenger_attachment_fetch_chunk") pub fn attachment_fetch_chunk_export(request :: Bytes) -> Bytes!String do
  native_attachment_fetch_chunk(request)
end

@export("mesh_messenger_attachment_upload", max_input: 16_830_000) pub fn attachment_upload_export(request :: Bytes) -> Bytes!String do
  native_attachment_upload(request)
end

@export("mesh_messenger_attachment_discard") pub fn attachment_discard_export(request :: Bytes) -> Bytes!String do
  native_attachment_discard(request)
end

@export("mesh_messenger_directory_resolve") pub fn directory_resolve_export(request :: Bytes) -> Bytes!String do
  native_directory_resolve(request)
end

@export("mesh_messenger_push_flow_intent") pub fn push_flow_intent_export(request :: Bytes) -> Bytes!String do
  native_push_intent(request)
end

@export("mesh_messenger_push_flow_complete") pub fn push_flow_complete_export(request :: Bytes) -> Bytes!String do
  native_push_complete(request)
end

@export("mesh_messenger_push_flow_send") pub fn push_flow_send_export(request :: Bytes) -> Bytes!String do
  native_push_send(request)
end

@export("mesh_messenger_push_flow_begin", max_input: 40_243, max_output: 4_096)
pub fn push_flow_begin_export(request :: Bytes) -> Bytes!String do
  native_push_begin(request)
end

@export("mesh_messenger_push_flow_validate", max_input: 4_154, max_output: 4_096)
pub fn push_flow_validate_export(request :: Bytes) -> Bytes!String do
  native_push_validate(request)
end

@export("mesh_messenger_account_delete", max_input: 40_238, max_output: 4_096)
pub fn account_delete_export(request :: Bytes) -> Bytes!String do
  native_account_delete(request)
end

@export("mesh_messenger_account_discard", max_input: 40_238, max_output: 4_096)
pub fn account_discard_export(request :: Bytes) -> Bytes!String do
  native_account_discard(request)
end

@export("mesh_messenger_account_capabilities", max_input: 40_238, max_output: 4_096)
pub fn account_capabilities_export(request :: Bytes) -> Bytes!String do
  native_account_capabilities(request)
end

@export("mesh_messenger_devices_renew", max_input: 309_364, max_output: 4_096)
pub fn devices_renew_export(request :: Bytes) -> Bytes!String do
  native_devices_renew(request)
end

@export("mesh_messenger_device_revoke", max_input: 309_384, max_output: 4_096)
pub fn device_revoke_export(request :: Bytes) -> Bytes!String do
  native_device_revoke(request)
end

@export("mesh_messenger_journal_load_bound", max_input: 40_498, max_output: 262_144)
pub fn journal_load_bound_export(request :: Bytes) -> Bytes!String do
  native_journal_load(request)
end

@export("mesh_messenger_journal_save_bound", max_input: 302_646, max_output: 4_096)
pub fn journal_save_bound_export(request :: Bytes) -> Bytes!String do
  native_journal_save(request)
end

@export("mesh_messenger_fanout_send", max_input: 88_740, max_output: 4_096)
pub fn fanout_send_export(request :: Bytes) -> Bytes!String do
  native_fanout_send(request)
end

# Optional public chain telemetry. Its failure never changes AnchorCheck/session state.
@export("mesh_messenger_network_counter") pub fn network_counter_export(request :: Bytes) -> Bytes!String do
  let path = mobile_utf8(request, "invalid_database_path")?
  if String.length(path) == 0 || String.length(path) > 4096 do
    return Err("invalid_database_path")
  end
  native_network_counter(path)
end

@export("mesh_messenger_group_policy") pub fn group_policy_export(request :: Bytes) -> Bytes!String do
  native_group_policy(request)
end

from Mobile.BackupNative import (
  native_backup_create,
  native_backup_preview,
  native_backup_import,
  native_backup_list,
  native_backup_remove,
  native_backup_overview,
  native_backup_page
)

@export("mesh_messenger_backup_create", max_input: 42004, max_output: 16801001)
pub fn backup_create_export(request :: Bytes) -> Bytes!String do
  native_backup_create(request)
end

@display("Authenticated portable backup overview metadata including finite schema attachment policy and separate file omission counts is returned only to the account-bound native import confirmation screen after complete restore canonical schema and current owner checks; message bodies attachment names MIME types file contents equality tokens authorization keys service realms recovery codes and raw errors remain private.")
@export("mesh_messenger_backup_preview", max_input: 16841207, max_output: 8192)
pub fn backup_preview_export(request :: Bytes) -> Bytes!String do
  native_backup_preview(request)
end

@export("mesh_messenger_backup_import", max_input: 16841239, max_output: 4096)
pub fn backup_import_export(request :: Bytes) -> Bytes!String do
  native_backup_import(request)
end

@display("Authenticated local archive identifiers and creation timestamps are returned only to the account-bound native backup inventory for selecting a read-only archive or explicit removal; message bodies archive digests authorization keys service realms recovery codes and raw errors remain private.")
@export("mesh_messenger_backup_list", max_input: 40239, max_output: 4096)
pub fn backup_list_export(request :: Bytes) -> Bytes!String do
  native_backup_list(request)
end

@export("mesh_messenger_backup_remove", max_input: 40271, max_output: 4096)
pub fn backup_remove_export(request :: Bytes) -> Bytes!String do
  native_backup_remove(request)
end

@display("Authenticated stored archive historical conversation identifiers labels creation time bounded message counts finite attachment policy and separate file omission counts are returned only to the account-bound native read-only archive overview after current owner and snapshot checks; message bodies attachment names MIME types file contents equality tokens authorization keys service realms recovery codes and raw errors remain private.")
@export("mesh_messenger_backup_overview", max_input: 40271, max_output: 8192)
pub fn backup_overview_export(request :: Bytes) -> Bytes!String do
  native_backup_overview(request)
end

@display("Authenticated bounded archive page text historical record metadata included-file display metadata explicit omission reasons revision-bound equality tokens and explicitly selected archive-file chunks are returned only to the current account-bound native read-only archive viewer after canonical owner selected-slot original snapshot and current authority checks; raw canonical archives archive and index digests revision tags authorization keys service realms recovery codes object capabilities keys and raw errors remain private.")
@export("mesh_messenger_backup_page", max_input: 40313, max_output: 135168)
pub fn backup_page_export(request :: Bytes) -> Bytes!String do
  native_backup_page(request)
end

from Mobile.BackupNative import (
  native_backup_pending_state,
  native_backup_pending_resume,
  native_backup_pending_discard,
  native_backup_pending_repair
)

@display("Current custody checked pending backup export state is returned only to the account bound native continuation screen as empty repair required or an authenticated bounded draft identifier creation timestamp and ciphertext byte count; recovery codes plaintext history payloads descriptor digests authorization keys service realms raw errors and prior caller control remain private.")
@export("mesh_messenger_backup_pending_state", max_input: 40239, max_output: 46)
pub fn backup_pending_state_export(request :: Bytes) -> Bytes!String do
  native_backup_pending_state(request)
end

@export("mesh_messenger_backup_pending_resume", max_input: 44371, max_output: 16796869)
pub fn backup_pending_resume_export(request :: Bytes) -> Bytes!String do
  native_backup_pending_resume(request)
end

@export("mesh_messenger_backup_pending_discard", max_input: 40271, max_output: 34)
pub fn backup_pending_discard_export(request :: Bytes) -> Bytes!String do
  native_backup_pending_discard(request)
end

@export("mesh_messenger_backup_pending_repair", max_input: 40239, max_output: 32)
pub fn backup_pending_repair_export(request :: Bytes) -> Bytes!String do
  native_backup_pending_repair(request)
end

from Mobile.ViewOnceNative import native_view_once_consume

@display("User explicitly opens this selected per-device view-once image; authenticated image format and bytes are returned only after durable local consumption to the current native-only one-shot viewer. Generic JavaScript invoke, save, sharing, backup, network and detailed errors remain excluded.")
@export("mesh_messenger_view_once_consume", max_input: 40271, max_output: 16777225, bindings: "native")
pub fn view_once_consume_native_export(request :: Bytes) -> Plaintext<Bytes>!String do
  native_view_once_consume(request)
end
