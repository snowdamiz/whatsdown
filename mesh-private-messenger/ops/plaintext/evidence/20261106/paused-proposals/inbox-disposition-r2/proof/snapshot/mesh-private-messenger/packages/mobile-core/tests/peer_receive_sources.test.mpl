from Mobile.ReceiveSources import ReceiveSources, capture_receive_sources
from Mobile.History import accepted_request_writes_from_sources, update_conversation
from Mobile.HeaderAdmission import (
  commit_legacy_receive_with_sources,
  commit_initial_admission_with_sources
)
from Mobile.HeaderRouting import HeaderRoute, commit_header_receive_with_sources
from Mobile.Sessions import (
  load_session_record,
  seal_session_ids,
  updated_session_record,
  prepared_conversation_alias
)
from Mobile.Types import MobilePolicyRequest, MobileSessionRecord, MobileSyncPayload
from Mobile.Profile import load_profile
from Storage.AccountGuard import AccountBasis, load_account_basis
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_blobs, store_record_changes, erase_local_state
from Tests.Support import database_path, repeated
from Tests.GroupLifecycleSupport import group_account_fixture
from Transport.Packet import decode_client_profile

fn label(id :: Bytes) -> String do
  "session/v1/#{Bytes.to_hex(id)}"
end

fn fixture_record(peer :: Bytes, snapshot :: Bytes) -> MobileSessionRecord!String do
  Ok(MobileSessionRecord {
    snapshot: snapshot,
    local_account_id: repeated(1, 32)?,
    local_device_id: repeated(2, 16)?,
    peer_account_id: peer,
    peer_device_id: repeated(4, 16)?,
    peer_username: "peer",
    peer_mailbox: repeated(5, 32)?,
    conversation_id: repeated(6, 16)?,
    request_state: 0,
    blocked: false,
    verified: false,
    key_changed: false,
    disappearing_seconds: 0,
    strongest_suite: 1,
    safety_number: repeated(97, 64)?,
    peer_transport_key: Bytes.empty()
  })
end

fn seed(path :: String, key :: borrow StorageKey, ids :: List<Bytes>) -> Result<(), String> do
  let labels = for id in ids do
    label(id)
  end
  let blobs = for index in 0..List.length(ids) do
    let snapshot = Bytes.from_utf8("opaque boundary snapshot/#{index}")
    let record = fixture_record(repeated(if index == 0 do
          1
        else
          3
        end,
        32)?,
      snapshot)?
    seal_local(updated_session_record(snapshot, record)?,
      key,
      local_context(List.get(labels, index))?)?
  end
  store_updated_blobs(path,
    ["profile/v1", "sessions/v1"] ++ labels,
    [
      seal_local(Bytes.from_utf8("profile"), key, local_context("profile/v1")?)?,
      seal_session_ids(ids, key)?
    ]
      ++ blobs)
end

fn basis(path :: String, self_id :: Bytes) -> AccountBasis!String do
  load_account_basis(path, ["sessions/v1", "header-routing/v1", label(self_id)])
end

fn commit_mode(mode :: Int,
  path :: String,
  key :: borrow StorageKey,
  before :: AccountBasis,
  sources :: ReceiveSources,
  ids :: List<Bytes>,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  if mode == 0 do
    commit_legacy_receive_with_sources(path, before, Some(sources), labels, blobs)
  else if mode == 1 do
    let added = Crypto.sha256(Bytes.from_utf8("initial candidate"))
    commit_initial_admission_with_sources(path,
      Some(before),
      Some(sources),
      label(added),
      Bytes.from_utf8("initial candidate"),
      seal_session_ids(ids ++ [added], key)?,
      labels,
      blobs,
      [],
      [],
      [])
  else
    commit_header_receive_with_sources(path,
      HeaderRoute {
        loaded: load_session_record(path, key, List.head(ids))?,
        basis: before,
        cursor_blob: Bytes.from_utf8("candidate cursor")
      },
      Some(sources),
      labels,
      blobs)
  end
end

fn wide_sources() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("receive-peer-chunk-boundaries")?
  ensure_schema(path)?
  let key = platform_key()?
  let ids = for index in 0..130 do
    Crypto.sha256(Bytes.from_utf8("peer/#{index}"))
  end
  let self_id = List.head(ids)
  let peer = repeated(3, 32)?
  seed(path, key, ids)?
  let before = basis(path, self_id)?
  let sources = capture_receive_sources(path, key, before, ids, peer)?
  assert(List.length(sources.batches) == 3)
  assert(List.all(sources.batches, fn(batch) -> List.length(batch.labels) <= 64 end))
  let (labels, blobs) = accepted_request_writes_from_sources(key, peer, sources)?
  assert(List.length(labels) == 129)
  let own = load_blob(path, label(self_id))?
  commit_mode(0, path, key, before, sources, ids, [label(self_id)] ++ labels, [own] ++ blobs)?
  for index in 1..130 do
    let loaded = load_session_record(path, key, List.get(ids, index))?
    assert(loaded.record.request_state == 1)
    assert(Bytes.secure_equals(loaded.record.snapshot,
      Bytes.from_utf8("opaque boundary snapshot/#{index}")))
  end
  # All three entrypoints validate every batch before the first selected-row,
  # peer-row, initial-index or cursor mutation. These are storage-boundary
  # fixtures; the separate real-HE case exercises cryptographic advancement.
  for mode in 0..3 do
    for action in [2, 5] do
      seed(path, key, ids)?
      let before = basis(path, self_id)?
      let sources = capture_receive_sources(path, key, before, ids, peer)?
      let (labels, blobs) = accepted_request_writes_from_sources(key, peer, sources)?
      let own = load_blob(path, label(self_id))?
      update_conversation(MobilePolicyRequest {
        database_path: path,
        peer_profile: peer,
        action: action,
        value: 60,
        expected_safety: Bytes.empty()
      })?
      let winner = load_blob(path, List.last(labels))?
      assert(case commit_mode(mode,
        path,
        key,
        before,
        sources,
        ids,
        [label(self_id)] ++ labels,
        [own] ++ blobs) do
        Err("account_state_changed") -> true
        _ -> false
      end)
      assert(Bytes.secure_equals(load_blob(path, List.last(labels))?, winner))
      assert(Bytes.secure_equals(load_blob(path, label(self_id))?, own))
      assert(Result.is_err(load_blob(path, "header-routing/v1")))
      assert(Result.is_err(load_blob(path,
        label(Crypto.sha256(Bytes.from_utf8("initial candidate"))))))
    end
  end
  erase_local_state(path)?
  Ok(true)
end

fn alias_absence() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = group_account_fixture()?
  let path = fixture.bob_path
  let key = platform_key()?
  let local = decode_client_profile(load_profile(path)?)?
  let peer = decode_client_profile(load_profile(fixture.alice_path)?)?
  let self_id = Crypto.sha256(Bytes.from_utf8("self receive fixture"))
  let own_label = label(self_id)
  let self_record = fixture_record(local.account_id, Bytes.empty())?
  let own = seal_local(updated_session_record(Bytes.empty(), self_record)?,
    key,
    local_context(own_label)?)?
  store_updated_blobs(path, ["sessions/v1", own_label], [seal_session_ids([self_id], key)?, own])?
  let before = basis(path, self_id)?
  let sources = capture_receive_sources(path, key, before, [self_id], peer.account_id)?
  assert(String.length(sources.alias_label) > 0)
  let sync = MobileSyncPayload {
    peer_username: "alice",
    peer_account_id: peer.account_id,
    conversation_id: repeated(7, 16)?,
    client_message_id: repeated(8, 16)?,
    client_timestamp: U64.parse("1")?,
    body: Bytes.from_utf8("sync"),
    disappearing_seconds: 60,
    safety_number: repeated(97, 64)?
  }
  let (_, alias_labels, alias_blobs) = prepared_conversation_alias(path,
    key,
    local,
    sync,
    [self_id])?
  assert(List.head(alias_labels) == sources.alias_label)
  assert(Result.is_err(load_blob(path, sources.alias_label)))
  # An orphan row created after the actual absence capture must survive even
  # if the original index was not changed by that competing writer.
  let winner = seal_local(Bytes.from_utf8("orphan winner"),
    key,
    local_context(sources.alias_label)?)?
  store_updated_blobs(path, [sources.alias_label], [winner])?
  assert(Result.is_err(commit_legacy_receive_with_sources(path,
    before,
    Some(sources),
    [own_label] ++ alias_labels,
    [own] ++ alias_blobs)))
  assert(Bytes.secure_equals(load_blob(path, sources.alias_label)?, winner))
  assert(case capture_receive_sources(path, key, before, [self_id], peer.account_id) do
    Err("receive_alias_exists") -> true
    _ -> false
  end)
  store_record_changes(path, [], [], [sources.alias_label])?
  let fresh = capture_receive_sources(path, key, before, [self_id], peer.account_id)?
  let (_, alias_labels, alias_blobs) = prepared_conversation_alias(path,
    key,
    local,
    sync,
    [self_id])?
  commit_legacy_receive_with_sources(path,
    before,
    Some(fresh),
    [own_label] ++ alias_labels,
    [own] ++ alias_blobs)?
  assert(Bytes.secure_equals(load_blob(path, fresh.alias_label)?, List.head(alias_blobs)))
  assert(Bytes.secure_equals(load_blob(path, own_label)?, own))
  erase_local_state(fixture.alice_path)?
  erase_local_state(path)?
  Ok(true)
end

test("130 captured session rows cross the64-row basis bound; fresh acceptance succeeds and all receive commits preserve newer policies") do
  case wide_sources() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("self-sync alias selection captures real absence before preparation and refuses an orphan winner without recapture") do
  case alias_absence() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
