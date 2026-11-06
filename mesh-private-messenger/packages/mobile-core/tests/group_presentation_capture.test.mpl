from Mobile.Codec import current_time, mobile_wide
from Mobile.Groups import capture_group_attachment_send
from Mobile.GroupState import group_history_label, updated_group_history_blob
from Mobile.Profile import load_profile
from Transport.Packet import decode_client_profile
from Mobile.Presentation import present_message
from Mobile.Types import MobileGroupHistoryEntry
from Storage.Blobs import load_blob
from Storage.FanoutCommit import commit_fanout_records
from Storage.Keys import platform_key
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.GroupLifecycleWire import group_vectors
from Tests.PresentationFixture import fixture_save_presentation
from Tests.Support import repeated

# Exercise the real presentation preparation/history write plan with a
# deterministic A->B change between stages. The late-capture behavioral mutant
# changes only this Boolean; it must fail the same rejection/retention checks.
fn captured_presentation_stays_current() -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("fixture secure store")
  end
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let key = platform_key()?
  let profile = decode_client_profile(load_profile(accounts.alice_path)?)?
  let user_key = Bytes.from_utf8("user/#{Bytes.to_hex(accounts.alice_account.account_id)}")
  let label = "presentation/v1/user/#{Bytes.to_hex(accounts.alice_account.account_id)}"
  let _ = fixture_save_presentation(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    user_key,
    group_vectors([Bytes.from_utf8("Synthetic presentation A"), Bytes.empty()])?
  ])?)?
  let first = capture_group_attachment_send(accounts.alice_path, group)?
  let presented = present_message(accounts.alice_path, group, Bytes.from_utf8("Synthetic body"))?
  let _ = fixture_save_presentation(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    user_key,
    group_vectors([Bytes.from_utf8("Synthetic presentation B"), Bytes.empty()])?
  ])?)?
  let replacement = load_blob(accounts.alice_path, label)?
  let late_capture = false
  let before = if late_capture do
    capture_group_attachment_send(accounts.alice_path, group)?
  else
    first
  end
  let (labels, blobs) = updated_group_history_blob(accounts.alice_path,
    key,
    group,
    accounts.alice_account.account_id,
    MobileGroupHistoryEntry {
      disappearing_seconds: 0,
      message_id: repeated(79, 32)?,
      direction: 1,
      epoch: mobile_wide("1")?,
      sender_account_id: accounts.alice_account.account_id,
      sender_device_id: profile.device_id,
      timestamp: current_time()?,
      body: presented,
      attachment: Bytes.empty()
    })?
  let committed = commit_fanout_records(accounts.alice_path, before, labels, blobs, [])
  let valid = committed == Err("account_state_changed")
    && Bytes.secure_equals(load_blob(accounts.alice_path, label)?, replacement)
    && load_blob(accounts.alice_path, group_history_label(group)) == Err("local_state_not_found")
  File.delete(accounts.alice_path)?
  File.delete(accounts.bob_path)?
  File.delete(accounts.linked_path)?
  Ok(valid)
end

test("presentation A cannot commit under a later B snapshot or replace B/history") do
  assert(declassify(Result.unwrap_or(captured_presentation_stays_current(), false),
    "synthetic public group presentation A/B race equality and rejection Boolean only; no application disclosure"))
end

from MobileCore import group_send_export
from Storage.Keys import seal_local, local_context
from Storage.Records import store_updated_blobs

fn presentation_error_keeps_priority() -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("fixture secure store")
  end
  let accounts = group_account_fixture()?
  let key = platform_key()?
  let label = "presentation/v1/user/#{Bytes.to_hex(accounts.alice_account.account_id)}"
  # Both capture (unknown group) and preparation (authenticated malformed
  # presentation) fail. Earlier capture must not change the public first error.
  store_updated_blobs(accounts.alice_path,
    [label],
    [seal_local(Bytes.from_utf8("malformed synthetic presentation"), key, local_context(label)?)?])?
  let result = group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    repeated(83, 32)?,
    Bytes.from_utf8("Synthetic body")
  ])?)
  let valid = result == Err("invalid_presentation")
  File.delete(accounts.alice_path)?
  File.delete(accounts.bob_path)?
  File.delete(accounts.linked_path)?
  Ok(valid)
end

test("capturing earlier preserves presentation validation before missing group error") do
  assert(declassify(Result.unwrap_or(presentation_error_keeps_priority(), false),
    "synthetic public malformed-presentation versus missing-group error priority Boolean only; no application disclosure"))
end
