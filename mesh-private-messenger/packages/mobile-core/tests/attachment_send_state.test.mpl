from Mobile.AttachmentSendState import capture_direct_attachment, commit_direct_attachment
from Mobile.Profile import load_profile
from MobileCore import create_account_export
from Storage.Blobs import load_blob
from Storage.OutboxGuard import PreparedOutboxIndex, OutboxBasis
from Storage.Records import store_updated_blobs
from Storage.Keys import platform_key
from Tests.GroupLifecycleWire import group_vectors
from Tests.Support import database_path
from Transport.Packet import decode_client_profile, direct_conversation_id

fn exercise(changed :: Int) -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("attachment_direct_commit")?
  let peer_path = database_path("attachment_direct_peer")?
  let profile_wire = create_account_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("direct-sender")
  ])?)?
  let peer = decode_client_profile(create_account_export(group_vectors([
    Bytes.from_utf8(peer_path),
    Bytes.from_utf8("direct-peer")
  ])?)?)?
  let local = decode_client_profile(profile_wire)?
  let conversation = direct_conversation_id(local.account_id, peer.account_id)?
  let history_label = "history/v1/#{Bytes.to_hex(conversation)}"
  let label = if changed == 0 do
    "transparency-device-set/v1/#{Bytes.to_hex(peer.account_id)}"
  else if changed == 1 do
    "device-set/v1/#{Bytes.to_hex(local.account_id)}"
  else if changed == 2 do
    "transparency-fork/v1"
  else
    history_label
  end
  let key = platform_key()?
  let before = capture_direct_attachment(path, key, profile_wire, peer)?
  # The late outbox snapshot still has unchanged custody and index. It cannot
  # detect a recipient upgrade/revocation, fork evidence or concurrent history.
  store_updated_blobs(path, [label], [Bytes.from_utf8("concurrent source state")])?
  let index = PreparedOutboxIndex {
    value: Bytes.from_utf8("prepared outbox"),
    before: OutboxBasis {
      profile: load_blob(path, "profile/v1")?,
      index: Bytes.empty(),
      postage: Bytes.empty(),
      delivery: Bytes.empty()
    }
  }
  let result = commit_direct_attachment(path,
    Some(before),
    [],
    [],
    Bytes.from_utf8("prepared session index"),
    [history_label],
    [Bytes.from_utf8("prepared history")],
    ["outbox-envelope/v1/test"],
    [Bytes.from_utf8("prepared encrypted attachment")],
    index)
  assert(result == Err("account_state_changed"))
  assert(Bytes.to_utf8(load_blob(path, label)?)? == "concurrent source state")
  assert(Result.is_err(load_blob(path, "outbox-envelope/v1/test")))
  let fresh = capture_direct_attachment(path, key, load_profile(path)?, peer)?
  commit_direct_attachment(path,
    Some(fresh),
    [],
    [],
    Bytes.from_utf8("prepared session index"),
    [history_label],
    [Bytes.from_utf8("prepared history")],
    ["outbox-envelope/v1/test"],
    [Bytes.from_utf8("prepared encrypted attachment")],
    index)?
  assert(Bytes.to_utf8(load_blob(path,
    "outbox-envelope/v1/test")?)? == "prepared encrypted attachment")
  File.delete(path)?
  File.delete(peer_path)?
  Ok(nil)
end

test("direct attachment commit guards peer credentials, own devices, forks and history") do
  for changed in 0..4 do
    case exercise(changed) do
      Err(error) -> do
        println(error)
        assert(false)
      end
      Ok(_) -> assert(true)
    end
  end
end
