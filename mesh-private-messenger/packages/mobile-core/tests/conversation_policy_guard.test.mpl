from Mobile.ConversationPolicy import prepare_conversation_policy, commit_conversation_policy
from Mobile.Codec import mobile_write_u32, mobile_append
from Mobile.History import update_conversation
from Mobile.Sessions import load_session_record, seal_session_ids, updated_session_record
from Mobile.Types import MobilePolicyRequest, MobileSessionRecord
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_blobs, erase_local_state
from Tests.Support import database_path, repeated

fn session_id(index :: Int) -> Bytes!String do
  mobile_append(mobile_write_u32(index)?, repeated(42, 28)?)
end

fn record(index :: Int) -> MobileSessionRecord!String do
  Ok(MobileSessionRecord {
    snapshot: Bytes.from_utf8("original ratchet snapshot"),
    local_account_id: repeated(1, 32)?,
    local_device_id: repeated(2, 16)?,
    peer_account_id: repeated(3, 32)?,
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

fn install(path :: String, key :: borrow StorageKey, count :: Int) -> Unit!String do
  ensure_schema(path)?
  let ids = for index in 0..count do
    session_id(index)?
  end
  let labels = for value in ids do
    "session/v1/#{Bytes.to_hex(value)}"
  end
  let blobs = for index in 0..count do
    let value = record(index)?
    seal_local(updated_session_record(value.snapshot, value)?,
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

fn stale_ratchet() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("policy-ratchet-guard")?
  let key = platform_key()?
  install(path, key, 1)?
  let prepared = prepare_conversation_policy(path, key, repeated(3, 32)?, 5, 60)?
  let id = session_id(0)?
  let label = "session/v1/#{Bytes.to_hex(id)}"
  let loaded = load_session_record(path, key, id)?
  let next = %{loaded.record | snapshot: Bytes.from_utf8("new ratchet generation"), blocked: true}
  let blob = seal_local(updated_session_record(next.snapshot, next)?, key, local_context(label)?)?
  store_updated_blobs(path, [label], [blob])?
  assert(case commit_conversation_policy(path, prepared) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(path, label)?, blob))
  let latest = load_session_record(path, key, id)?
  assert(latest.record.blocked && latest.record.disappearing_seconds == 0)
  assert(Bytes.secure_equals(latest.record.snapshot, next.snapshot))
  erase_local_state(path)
end

fn stale_sources() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  for changed in ["profile/v1", "sessions/v1", "contact-address-pending/v1"] do
    let path = database_path("policy-sources-guard")?
    install(path, key, 1)?
    let prepared = prepare_conversation_policy(path, key, repeated(3, 32)?, 2, 0)?
    let id = session_id(0)?
    let label = "session/v1/#{Bytes.to_hex(id)}"
    let original = load_blob(path, label)?
    let newer = Bytes.from_utf8("newer source")
    store_updated_blobs(path, [changed], [newer])?
    assert(case commit_conversation_policy(path, prepared) do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(Bytes.secure_equals(load_blob(path, label)?, original))
    assert(Bytes.secure_equals(load_blob(path, changed)?, newer))
    erase_local_state(path)?
  end
  Ok(nil)
end

fn positive_chunked() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("policy-chunked-positive")?
  let key = platform_key()?
  # Existing legacy indexes are not constrained to the outbound fanout limit.
  install(path, key, 513)?
  for action in [1, 2, 3, 4, 5] do
    update_conversation(MobilePolicyRequest {
      database_path: path,
      peer_profile: repeated(3, 32)?,
      action: action,
      value: 60,
      expected_safety: Bytes.empty()
    })?
  end
  for index in [0, 63, 64, 255, 256, 511, 512] do
    let loaded = load_session_record(path, key, session_id(index)?)?
    assert(loaded.record.request_state == 1)
    assert(!loaded.record.blocked && loaded.record.verified && !loaded.record.key_changed)
    assert(loaded.record.disappearing_seconds == 60)
    assert(Bytes.secure_equals(loaded.record.snapshot,
      Bytes.from_utf8("original ratchet snapshot")))
  end
  assert(Bytes.length(load_blob(path, "contact-address-pending/v1")?) > 0)
  erase_local_state(path)
end

test("a stale local expiry change preserves a newer blocked ratchet generation") do
  case stale_ratchet() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("local policy commit preserves newer profile index and contact rotation") do
  case stale_sources() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("fresh conversation policy updates preserve ratchets across a legacy index above fanout capacity") do
  case positive_chunked() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
