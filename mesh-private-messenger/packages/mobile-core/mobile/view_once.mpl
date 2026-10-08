from Mobile.Delivery import load_delivery
from Mobile.Fanout import send_fanout_control
from Mobile.GroupState import (
  encode_group_history_summary,
  group_history_entries,
  group_history_sealed
)
from Mobile.GroupTimer import group_view_once_flag
from Mobile.Groups import send_mobile_group_message_with
from Mobile.History import (
  history_entries_for,
  history_sealed_for,
  history_summary,
  history_view_once_type
)
from Mobile.Presentation import present_message
from Mobile.Profile import load_profile, open_device, peer_account_id
from Mobile.Sessions import find_peer_session, load_session_ids
from Mobile.Types import (
  MobileFanoutRequest,
  MobileGroupHistoryEntry,
  MobileGroupSendRequest,
  MobileHistoryEntry,
  MobileTriplePayloadRequest
)
from Protocol.V1 import InnerEnvelope
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Storage.Records import store_updated_blobs
from Transport.Packet import decode_client_profile

##! View-once messages (`protocol/privacy-contract.md`, "View-once messages").
##!
##! A direct one is inner message type 8; a group one is a version 5 group
##! message with `GOP` flag 1 (`Mobile.GroupTimer`). No device of the sender's
##! account keeps its content, only a stub that says one was sent. A recipient
##! device keeps the content sealed like any other message but never lists it:
##! it hands it out once, through `open`, and deletes it in the same call.
##! Builds from before view-once drop both kinds unread.

pub fn send_view_once(request :: MobileFanoutRequest) -> Bytes!String do
  send_fanout_control(%{request |
      body: present_message(request.database_path, Bytes.empty(), request.body)?
    },
    history_view_once_type(),
    [],
    [])
end

pub fn send_group_view_once(request :: MobileGroupSendRequest) -> Bytes!String do
  if Bytes.length(request.body) == 0 && Bytes.length(request.attachment) == 0 do
    Err("invalid_view_once")
  else
    send_mobile_group_message_with(request, group_view_once_flag(), -1)
  end
end

fn unopened_direct(entry :: MobileHistoryEntry, message_id :: Bytes) -> Bool do
  entry.direction == 2
    && entry.inner.message_type == history_view_once_type()
    && Bytes.secure_equals(entry.inner.client_message_id, message_id)
    && (Bytes.length(entry.inner.body) > 0 || Bytes.length(entry.inner.attachment_manifest) > 0)
end

## The content of a view-once message received in the chat with `first` (a
## peer profile or account ID) whose message ID is `second`, as one history
## summary; the content leaves this device's history in the same call.
## `view_once_unavailable` once it has been opened, or if there is no such message.

pub fn open_view_once(request :: MobileTriplePayloadRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let path = request.database_path
  let wrapping_key = platform_key()?
  let local = decode_client_profile(load_profile(path)?)?
  let loaded = find_peer_session(path,
    wrapping_key,
    peer_account_id(request.first)?,
    load_session_ids(path, wrapping_key)?,
    0)?
  let conversation_id = loaded.record.conversation_id
  let entries = history_entries_for(path, wrapping_key, conversation_id)?
  let found = List.find(entries, fn(entry) do unopened_direct(entry, request.second) end)
  let entry = case found do
    None -> Err("view_once_unavailable")
    Some(value) -> Ok(value)
  end?
  let device = open_device(local, wrapping_key, path)?
  let summary = history_summary(device, entry, load_delivery(path, wrapping_key)?, true)?
  let emptied = for value in entries do
    if unopened_direct(value, request.second) do
      %{value | inner: %{value.inner | body: Bytes.empty(), attachment_manifest: Bytes.empty()}}
    else
      value
    end
  end
  let (label, blob) = history_sealed_for(emptied, wrapping_key, conversation_id)?
  store_updated_blobs(path, [label], [blob])?
  Ok(summary)
end

fn unopened_group(entry :: MobileGroupHistoryEntry, message_id :: Bytes) -> Bool do
  entry.kind == 1
    && Bytes.secure_equals(entry.message_id, message_id)
    && (Bytes.length(entry.body) > 0 || Bytes.length(entry.attachment) > 0)
end

## The same for a group: `first` is the group ID and `second` the message ID.

pub fn open_group_view_once(request :: MobileTriplePayloadRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let path = request.database_path
  let wrapping_key = platform_key()?
  let local = decode_client_profile(load_profile(path)?)?
  let entries = group_history_entries(path, wrapping_key, request.first)?
  let found = List.find(entries, fn(entry) do unopened_group(entry, request.second) end)
  let entry = case found do
    None -> Err("view_once_unavailable")
    Some(value) -> Ok(value)
  end?
  let device = open_device(local, wrapping_key, path)?
  let summary = encode_group_history_summary(device,
    entry,
    load_delivery(path, wrapping_key)?,
    true)?
  let emptied = for value in entries do
    if unopened_group(value, request.second) do
      %{value | body: Bytes.empty(), attachment: Bytes.empty()}
    else
      value
    end
  end
  let (label, blob) = group_history_sealed(emptied, wrapping_key, request.first)?
  store_updated_blobs(path, [label], [blob])?
  Ok(summary)
end
