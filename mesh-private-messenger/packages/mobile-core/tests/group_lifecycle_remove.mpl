from MobileCore import group_history_export, group_inspect_export, group_receive_export, group_remove_export, group_send_export, outbox_list_export
from Protocol.V1 import AccountIdentity, DeviceCredential, DirectoryEntry, OuterEnvelope, encode_outer_envelope
from Tests.GroupLifecycleSupport import GroupAccountFixture
from Tests.GroupLifecycleWire import acknowledge, group_vectors, outer, output_list

fn group_remove_ensure(value :: Bool, error :: String) -> Result <(), String > do
  if value do
    Ok(nil)
  else
    Err(error)
  end
end

pub fn exercise_group_removal(accounts :: GroupAccountFixture, group_id :: Bytes) -> Bool ! String do
  let removal_output = group_remove_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id, accounts.alice_account.account_id, accounts.linked_credential.device_id]) ?) ?
  let removals = output_list(removal_output) ?
  group_remove_ensure(List.length(removals) == 1, "removal delivery count mismatch") ?
  let bob_removal = List.head(removals)
  group_remove_ensure(Bytes.secure_equals(outer(bob_removal) ?.mailbox_token,
  accounts.bob_entry.mailbox_token),
  "removal mailbox mismatch") ?
  acknowledge(accounts.alice_path, removals, 0) ?
  group_remove_ensure(Bytes.secure_equals(group_receive_export(group_vectors([Bytes.from_utf8(accounts.bob_path), bob_removal]) ?) ?,
  group_id),
  "bob removal receive mismatch") ?
  let after_removal = Bytes.from_utf8("removed devices stay removed")
  let after_output = group_send_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id, after_removal]) ?) ?
  let after_deliveries = output_list(after_output) ?
  group_remove_ensure(List.length(after_deliveries) == 1, "post-removal delivery count mismatch") ?
  let bob_after = List.head(after_deliveries)
  group_remove_ensure(Bytes.secure_equals(outer(bob_after) ?.mailbox_token,
  accounts.bob_entry.mailbox_token),
  "post-removal mailbox mismatch") ?
  let bob_after_outer = outer(bob_after) ?
  let retargeted = case encode_outer_envelope(% { bob_after_outer | mailbox_token : accounts.linked_entry.mailbox_token }) do
    Err( _) -> Err("outer envelope encode failed")
    Ok( encoded) -> Ok(encoded)
  end ?
  case group_receive_export(group_vectors([Bytes.from_utf8(accounts.linked_path), retargeted]) ?) do
    Ok( _) -> Err("removed linked device accepted a future epoch") ?
    Err( error) -> group_remove_ensure(error == "group_future_epoch", "wrong removed-device error") ?
  end
  group_remove_ensure(Bytes.secure_equals(group_receive_export(group_vectors([Bytes.from_utf8(accounts.bob_path), bob_after]) ?) ?,
  after_removal),
  "bob post-removal receive mismatch") ?
  acknowledge(accounts.alice_path, after_deliveries, 0) ?
  let final_inspect = output_list(group_inspect_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id]) ?) ?) ?
  group_remove_ensure(List.length(output_list(List.get(final_inspect, 6)) ?) == 2,
  "final group member count mismatch") ?
  let alice_history = output_list(group_history_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id]) ?) ?) ?
  group_remove_ensure(List.length(alice_history) == 1, "alice history count mismatch") ?
  group_remove_ensure(Bytes.secure_equals(List.get(output_list(List.head(alice_history)) ?, 6),
  after_removal),
  "alice history body mismatch") ?
  group_remove_ensure(List.length(output_list(outbox_list_export(Bytes.from_utf8(accounts.alice_path)) ?) ?) == 0,
  "alice outbox was not empty") ?
  Ok(true)
end
