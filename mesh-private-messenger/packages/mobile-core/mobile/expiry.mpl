from Mobile.Attachments import attachment_object_ids
from Mobile.Codec import current_time, encode_output_list, mobile_wide, mobile_write_u64
from Mobile.ExpiredObjects import (
  expired_objects_added,
  expired_objects_label,
  expired_objects_load,
  expired_objects_sealed
)
from Mobile.GroupState import (
  group_entry_expired,
  group_history_entries,
  group_history_sealed,
  group_index_ids
)
from Mobile.History import history_entries_for, history_expires_at, history_sealed_for
from Mobile.Sessions import load_session_ids, load_session_record
from Mobile.Types import MobileGroupHistoryEntry, MobileHistoryEntry
from Protocol.V1 import InnerEnvelope
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Storage.Records import store_updated_blobs

##! Disappearing messages leave this device's storage once their time is up:
##! at every mailbox sync (`Mobile.Inbox`), whenever the app asks
##! (`mesh_messenger_expiry_purge`, which it calls on a timer while it runs),
##! and when their chat's history loads. Removing one rewrites the sealed
##! history without it; the objects its attachments named are remembered
##! until the app collects them, so it can delete what it cached of them.

struct Purge do
  labels :: List<String>
  blobs :: List<Bytes>
  objects :: List<Bytes>
  next :: U64
end

fn earlier(current :: U64, candidate :: U64) -> U64 do
  if U64.to_string(current) == "0" || U64.compare(candidate, current) < 0 do
    candidate
  else
    current
  end
end

fn direct_conversation_ids(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
  let session_ids = load_session_ids(database_path, wrapping_key)?
  let conversations = for session_id in session_ids do
    load_session_record(database_path, wrapping_key, session_id)?.record.conversation_id
  end
  Ok(List.reduce(conversations,
    [],
    fn(unique, id) do
      if List.any(unique, fn(known) do Bytes.secure_equals(known, id) end) do
        unique
      else
        List.append(unique, id)
      end
    end))
end

fn purge_direct(database_path :: String,
  wrapping_key :: borrow StorageKey,
  conversation_id :: Bytes,
  now :: U64,
  purge :: Purge) -> Purge!String do
  let entries = history_entries_for(database_path, wrapping_key, conversation_id)?
  let expiries = for entry in entries do
    history_expires_at(entry)?
  end
  let pairs = List.zip(entries, expiries)
  let expired = List.filter(pairs,
    fn(pair) do
      let (_, expiry) = pair
      case expiry do
        None -> false
        Some(at) -> U64.compare(at, now) <= 0
      end
    end)
  let kept = List.filter(pairs,
    fn(pair) do
      let (_, expiry) = pair
      case expiry do
        None -> true
        Some(at) -> U64.compare(at, now) > 0
      end
    end)
  let next = List.reduce(kept,
    purge.next,
    fn(soonest, pair) do
      let (_, expiry) = pair
      case expiry do
        None -> soonest
        Some(at) -> earlier(soonest, at)
      end
    end)
  if List.length(expired) == 0 do
    return Ok(%{purge | next: next})
  end
  let removed = List.reduce(expired,
    [],
    fn(ids, pair) do
      let (entry, _) = pair
      List.concat(ids, attachment_object_ids(entry.inner.attachment_manifest))
    end)
  let remaining = for pair in kept do
    let (entry, _) = pair
    entry
  end
  let (label, blob) = history_sealed_for(remaining, wrapping_key, conversation_id)?
  Ok(Purge {
    labels: List.append(purge.labels, label),
    blobs: List.append(purge.blobs, blob),
    objects: List.concat(purge.objects, removed),
    next: next
  })
end

fn purge_group(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  now :: U64,
  purge :: Purge) -> Purge!String do
  let entries = group_history_entries(database_path, wrapping_key, group_id)?
  let expired = List.filter(entries, fn(entry) do group_entry_expired(entry, now) end)
  let kept = List.filter(entries, fn(entry) do !group_entry_expired(entry, now) end)
  let next = List.reduce(kept,
    purge.next,
    fn(soonest, entry) do
      if U64.to_string(entry.expires_at) == "0" do
        soonest
      else
        earlier(soonest, entry.expires_at)
      end
    end)
  if List.length(expired) == 0 do
    return Ok(%{purge | next: next})
  end
  let removed = List.reduce(expired,
    [],
    fn(ids, entry) do List.concat(ids, attachment_object_ids(entry.attachment)) end)
  let (label, blob) = group_history_sealed(kept, wrapping_key, group_id)?
  Ok(Purge {
    labels: List.append(purge.labels, label),
    blobs: List.append(purge.blobs, blob),
    objects: List.concat(purge.objects, removed),
    next: next
  })
end

fn purge_conversations(database_path :: String,
  wrapping_key :: borrow StorageKey,
  conversation_ids :: List<Bytes>,
  now :: U64,
  purge :: Purge) -> Purge!String do
  case conversation_ids do
    [] -> Ok(purge)
    id :: rest -> purge_conversations(database_path,
      wrapping_key,
      rest,
      now,
      purge_direct(database_path, wrapping_key, id, now, purge)?)
  end
end

fn purge_groups(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_ids :: List<Bytes>,
  now :: U64,
  purge :: Purge) -> Purge!String do
  case group_ids do
    [] -> Ok(purge)
    id :: rest -> purge_groups(database_path,
      wrapping_key,
      rest,
      now,
      purge_group(database_path, wrapping_key, id, now, purge)?)
  end
end

fn purge_all(database_path :: String,
  wrapping_key :: borrow StorageKey,
  now :: U64) -> Purge!String do
  let empty = Purge { labels: [], blobs: [], objects: [], next: mobile_wide("0")? }
  let direct = purge_conversations(database_path,
    wrapping_key,
    direct_conversation_ids(database_path, wrapping_key)?,
    now,
    empty)?
  purge_groups(database_path,
    wrapping_key,
    group_index_ids(database_path, wrapping_key)?,
    now,
    direct)
end

## Deletes every message whose time is up at `now` in one transaction, and
## returns when the next one will be (0: none is waiting).

pub fn expiry_purge_at(database_path :: String, now :: U64) -> U64!String do
  ensure_schema(database_path)?
  let wrapping_key = platform_key()?
  let purge = purge_all(database_path, wrapping_key, now)?
  if List.length(purge.labels) > 0 do
    let (label, blob) = expired_objects_added(database_path, wrapping_key, purge.objects)?
    store_updated_blobs(database_path,
      List.append(purge.labels, label),
      List.append(purge.blobs, blob))?
  end
  Ok(purge.next)
end

## `mesh_messenger_expiry_purge`: purges, then hands over (and forgets) the
## objects of every message purged since the last call. Output list: the next
## expiry (u64 milliseconds, 0 for none), then each object ID (32 bytes).

pub fn expiry_purge(database_path :: String) -> Bytes!String do
  let next = expiry_purge_at(database_path, current_time()?)?
  let wrapping_key = platform_key()?
  let pending = expired_objects_load(database_path, wrapping_key)?
  if List.length(pending) > 0 do
    store_updated_blobs(database_path,
      [expired_objects_label()],
      [expired_objects_sealed([], wrapping_key)?])?
  end
  encode_output_list(List.concat([mobile_write_u64(next)?], pending))
end
