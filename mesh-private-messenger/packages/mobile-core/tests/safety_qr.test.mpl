from MobileCore import (
  create_account_export,
  start_conversation_export,
  receive_initial_export,
  safety_number_export,
  update_conversation_export,
  list_conversations_export
)
from Mobile.History import decode_conversation_summary
from Tests.Support import append, database_path, vector, write_u32

fn request(values :: List<Bytes>) -> Bytes!String do
  let pieces = for value in values do
    vector(value)?
  end
  case Bytes.concat_many(pieces, 1000000) do
    Err(_) -> Err("test framing failed")
    Ok(value)
  end
end

fn verify(path :: String, peer :: Bytes, safety :: Bytes) -> Bytes!String do
  update_conversation_export(request([
    Bytes.from_utf8(path),
    peer,
    Bytes.from_hex("06")?,
    write_u32(0)?,
    safety
  ])?)
end

fn proof() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let alice = database_path("safety-qr-alice")?
  let bob = database_path("safety-qr-bob")?
  let a = create_account_export(request([Bytes.from_utf8(alice), Bytes.from_utf8("alice")])?)?
  let b = create_account_export(request([Bytes.from_utf8(bob), Bytes.from_utf8("bob")])?)?
  let initial = start_conversation_export(request([
    Bytes.from_utf8(alice),
    b,
    Bytes.from_utf8("hello")
  ])?)?
  receive_initial_export(request([Bytes.from_utf8(bob), initial])?)?
  let safety = safety_number_export(request([Bytes.from_utf8(bob), a])?)?
  assert(Bytes.secure_equals(safety, safety_number_export(request([Bytes.from_utf8(alice), b])?)?))
  assert(!decode_conversation_summary(list_conversations_export(Bytes.from_utf8(alice))?)?.verified)
  # This is the real unchanged native export. Old readers reject the new action
  # instead of treating a scanned number as the old unconditional mark action.
  verify(alice, b, safety)?
  assert(decode_conversation_summary(list_conversations_export(Bytes.from_utf8(alice))?)?.verified)
  let mismatch = Bytes.from_utf8("0000000000000000000000000000000000000000000000000000000000000000")
  assert(case verify(bob, a, mismatch) do
    Err("safety_number_mismatch") -> true
    _ -> false
  end)
  assert(!decode_conversation_summary(list_conversations_export(Bytes.from_utf8(bob))?)?.verified)
  for malformed in [
    Bytes.empty(),
    Bytes.from_utf8("short"),
    Bytes.from_utf8("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
  ] do
    assert(Result.is_err(verify(bob, a, malformed)))
  end
  let base = request([Bytes.from_utf8(bob), a, Bytes.from_hex("06")?, write_u32(0)?])?
  assert(Result.is_err(update_conversation_export(base)))
  assert(Result.is_err(update_conversation_export(append(append(base, vector(safety)?)?,
    Bytes.from_hex("00")?)?)))
  verify(bob, a, safety)?
  assert(decode_conversation_summary(list_conversations_export(Bytes.from_utf8(bob))?)?.verified)
  File.delete(alice)?
  File.delete(bob)?
  Ok(nil)
end

test("scanned safety numbers verify only an exact current match through the native policy export") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

from Mobile.SafetyVerification import prepare_safety_verification, commit_safety_verification
from Mobile.Profile import peer_account_id
from Mobile.Sessions import (
  load_session_ids,
  load_session_record,
  updated_session_record,
  seal_session_ids
)
from Storage.Keys import platform_key, local_context, seal_local
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs

fn guarded_proof() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let alice = database_path("safety-qr-guard-alice")?
  let bob = database_path("safety-qr-guard-bob")?
  let a = create_account_export(request([Bytes.from_utf8(alice), Bytes.from_utf8("alice")])?)?
  let b = create_account_export(request([Bytes.from_utf8(bob), Bytes.from_utf8("bob")])?)?
  start_conversation_export(request([Bytes.from_utf8(alice), b, Bytes.from_utf8("hello")])?)?
  let key = platform_key()?
  let peer = peer_account_id(b)?
  let ids = load_session_ids(alice, key)?
  let loaded = load_session_record(alice, key, List.head(ids))?
  let expected = loaded.record.safety_number
  # Every mutable source used to prepare the comparison is checked again in
  # the write transaction. Restoring it permits a fresh, explicit comparison.
  for label in ["profile/v1", "sessions/v1", loaded.label] do
    let before = load_blob(alice, label)?
    let prepared = prepare_safety_verification(alice, key, peer, expected)?
    store_updated_blobs(alice, [label], [Bytes.from_utf8("replacement ciphertext")])?
    assert(case commit_safety_verification(alice, prepared) do
      Err("safety_verification_changed") -> true
      _ -> false
    end)
    assert(Bytes.secure_equals(load_blob(alice, label)?, Bytes.from_utf8("replacement ciphertext")))
    store_updated_blobs(alice, [label], [before])?
    assert(!load_session_record(alice, key, List.head(ids))?.record.verified)
  end
  # Cross the64-row snapshot boundary with genuine encrypted records. A late
  # conflict in the last page must roll back verification in the first page.
  let extra = for index in 0..70 do
    Crypto.sha256(Bytes.from_utf8("safety alias #{index}"))
  end
  let labels = for id in extra do
    "session/v1/#{Bytes.to_hex(id)}"
  end
  let blobs = for label in labels do
    seal_local(updated_session_record(loaded.record.snapshot, loaded.record)?,
      key,
      local_context(label)?)?
  end
  store_updated_blobs(alice,
    labels ++ ["sessions/v1"],
    blobs ++ [seal_session_ids(ids ++ extra, key)?])?
  let prepared = prepare_safety_verification(alice, key, peer, expected)?
  let last_label = List.get(labels, 69)
  store_updated_blobs(alice, [last_label], [Bytes.from_utf8("concurrent ratchet")])?
  assert(case commit_safety_verification(alice, prepared) do
    Err("safety_verification_changed") -> true
    _ -> false
  end)
  assert(!load_session_record(alice, key, List.head(ids))?.record.verified)
  store_updated_blobs(alice, [last_label], [List.get(blobs, 69)])?
  commit_safety_verification(alice, prepare_safety_verification(alice, key, peer, expected)?)?
  for id in ids ++ extra do
    assert(load_session_record(alice, key, id)?.record.verified)
  end
  File.delete(alice)?
  File.delete(bob)?
  Ok(nil)
end

test("safety verification refuses replaced custody, index and session records and commits all snapshot pages atomically") do
  case guarded_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
