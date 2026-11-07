from Mobile.SiblingMembership import require_sibling_observation
from Mobile.SessionPolicy import NativeSessionPolicy
from Mobile.ReceiveSources import ReceiveSources, require_receive_writes, require_receive_sources
from Mobile.HeaderRoutingState import (
  HeaderRoutingState,
  HeaderCursor,
  empty_header_routing,
  decode_header_routing,
  encode_header_routing,
  reserve_header_cursor,
  advance_header_cursor
)
from Mobile.Sessions import (
  load_session_ids,
  load_session_record,
  restore_session,
  session_uses_headers
)
from Mobile.Types import MobileLoadedSession
from Session.State import RatchetState, RatchetMessage
from Session.HeaderRatchet import he_header_matches
from Storage.AccountGuard import (
  AccountBasis,
  load_account_basis,
  commit_account_changes,
  require_account_basis
)
from Storage.Records import with_record_transaction, put_blobs
from Storage.Keys import open_local, seal_local, local_context
from Storage.Blobs import load_blob
from Transport.Packet import session_aad

pub struct HeaderRoute do
  loaded :: MobileLoadedSession
  basis :: AccountBasis
  cursor_blob :: Bytes
end

fn cursor_label() -> String do
  "header-routing/v1"
end

fn session_label(id :: Bytes) -> String do
  "session/v1/#{Bytes.to_hex(id)}"
end

fn same_sources(left :: AccountBasis, right :: AccountBasis) -> Bool do
  Bytes.secure_equals(left.profile, right.profile)
    && Bytes.secure_equals(List.get(left.records, 0), List.get(right.records, 0))
    && Bytes.secure_equals(List.get(left.records, 1), List.get(right.records, 1))
end

fn routing_state(path :: String, key :: borrow StorageKey) -> HeaderRoutingState!String do
  case load_blob(path, cursor_label()) do
    Err(error) -> if error == "local_state_not_found" do
      empty_header_routing()
    else
      Err(error)
    end
    Ok(blob) -> decode_header_routing(open_local(blob, key, local_context(cursor_label())?)?)
  end
end

fn checked_probe(state :: consume RatchetState,
  message :: RatchetMessage,
  aad :: Bytes) -> Bool!String do
  case he_header_matches(state, message, aad) do
    Err(_) -> Err("ratchet_retryable")
    Ok(value)
  end
end

fn scan(path :: String,
  key :: borrow StorageKey,
  ids :: List<Bytes>,
  message :: RatchetMessage,
  index :: Int,
  end_offset :: Int) -> Option<MobileLoadedSession>!String do
  if index >= end_offset do
    return Ok(None)
  end
  let id = List.get(ids, index)
  let loaded = load_session_record(path, key, id)?
  if session_uses_headers(loaded.record.snapshot) do
    let state = restore_session(loaded, key)?
    if checked_probe(state, message, session_aad(id)?)? do
      return Ok(Some(loaded))
    end
  end
  scan(path, key, ids, message, index + 1, end_offset)
end

fn sealed_cursor(key :: borrow StorageKey, state :: HeaderRoutingState) -> Bytes!String do
  seal_local(encode_header_routing(state)?, key, local_context(cursor_label())?)
end

## One call scans at most16 sessions, each with at most7 authenticated header keys.
## No read admission ceiling: older indexes above4096 remain progressively readable.
## Direct probe fixtures may use this wrapper without a prior UI/profile read.
pub fn route_header(path :: String,
  key :: borrow StorageKey,
  envelope :: Bytes,
  packet :: Bytes,
  message :: RatchetMessage) -> HeaderRoute!String do
  route_header_for_profile(path, key, envelope, packet, message, None)
end

## Production receive binds the routing snapshot to its earlier local profile
## before any probe or cursor mutation, including a pending/no-match batch.
pub fn route_header_guarded(path :: String,
  key :: borrow StorageKey,
  envelope :: Bytes,
  packet :: Bytes,
  message :: RatchetMessage,
  public_profile :: Bytes) -> HeaderRoute!String do
  route_header_for_profile(path, key, envelope, packet, message, Some(public_profile))
end

fn route_header_for_profile(path :: String,
  key :: borrow StorageKey,
  envelope :: Bytes,
  packet :: Bytes,
  message :: RatchetMessage,
  expected_profile :: Option<Bytes>) -> HeaderRoute!String do
  if message.version != 4 || Bytes.length(envelope) != 16 do
    return Err("invalid_ratchet_message")
  end
  let initial = load_account_basis(path, ["sessions/v1", cursor_label()])?
  case expected_profile do
    None -> nil
    Some(profile) -> if !Bytes.secure_equals(open_local(initial.profile,
        key,
        local_context("profile/v1")?)?,
      profile) do
      return Err("account_state_changed")
    end
  end
  let ids = load_session_ids(path, key)?
  let state = routing_state(path, key)?
  let (reserved, cursor) = reserve_header_cursor(state,
    envelope,
    Crypto.sha256(packet),
    Crypto.sha256(initial.profile),
    Crypto.sha256(List.get(initial.records, 0)),
    List.length(ids))?
  let selected = case cursor do
    None -> do
      commit_account_changes(path, initial, [cursor_label()], [sealed_cursor(key, reserved)?], [])?
      return if List.length(ids) == 0 do
        Err("unknown_session")
      else
        Err("header_selection_capacity")
      end
    end
    Some(value) -> value
  end
  let end_offset = if selected.offset + 16 < List.length(ids) do
    selected.offset + 16
  else
    List.length(ids)
  end
  let labels = for index in selected.offset..end_offset do
    session_label(List.get(ids, index))
  end
  let before = load_account_basis(path, ["sessions/v1", cursor_label()] ++ labels)?
  if !same_sources(initial, before) do
    return Err("header_selection_pending")
  end
  case scan(path, key, ids, message, selected.offset, end_offset) do
    Err(error)
    Ok(Some(loaded)) -> do
      let finished = advance_header_cursor(reserved, envelope, end_offset, true)?
      Ok(HeaderRoute { loaded: loaded, basis: before, cursor_blob: sealed_cursor(key, finished)? })
    end
    Ok(None) -> do
      let finished = end_offset >= List.length(ids)
      let next = advance_header_cursor(reserved, envelope, end_offset, finished)?
      commit_account_changes(path, before, [cursor_label()], [sealed_cursor(key, next)?], [])?
      if finished do
        Err("unknown_session")
      else
        Err("header_selection_pending")
      end
    end
  end
end

## The chosen session, index, cursor and profile must still equal the exact scan.
## This transaction is the only point that makes the ratchet/history and cursor removal visible.
pub fn commit_header_receive(path :: String,
  route :: HeaderRoute,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  commit_header_receive_with_sources(path, route, None, labels, blobs)
end

pub fn commit_header_receive_with_sources(path :: String,
  route :: HeaderRoute,
  sources :: Option<ReceiveSources>,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  commit_header_receive_with_observation(path, route, sources, labels, blobs, None)
end

pub fn commit_header_receive_with_observation(path :: String,
  route :: HeaderRoute,
  sources :: Option<ReceiveSources>,
  labels :: List<String>,
  blobs :: List<Bytes>,
  observation :: Option<(NativeSessionPolicy, U64)>) -> Result<(), String> do
  if List.length(labels) != List.length(blobs)
    || List.contains(labels, cursor_label())
    || List.length(List.filter(labels, fn(value) -> value == route.loaded.label end)) != 1
    || List.any(blobs, fn(value) -> Bytes.length(value) == 0 end)
    || List.any(labels,
      fn(value) -> String.starts_with(value, "history/v1/")
        && !List.contains(route.basis.labels, value) end) do
    return Err("invalid_header_receive_commit")
  end
  require_receive_writes(route.basis, sources, labels)?
  with_record_transaction(path,
    fn(database) do
      require_receive_sources(database, route.basis, sources)?
      require_sibling_observation(observation)?
      put_blobs(database, labels ++ [cursor_label()], blobs ++ [route.cursor_blob], 0)
    end)
end
