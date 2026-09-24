from MobileCore import (
  group_add_export,
  group_history_export,
  group_key_package_export,
  group_receive_export,
  group_send_export,
  presentation_save_export,
  presentation_load_export,
  process_delivery_batch_export
)
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import AccountIdentity, DirectoryEntry, MailboxAck, OuterEnvelope
from Tests.GroupLifecycleSupport import GroupAccountFixture
from Tests.GroupLifecycleWire import ack, acknowledge, assert_group_transport, delivery_batch, envelope_for, group_vectors, outer, output_list
from Tests.Support import append, repeated, vector, write_u32

fn group_messages_ensure(value :: Bool, error :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(error)
  end
end

fn group_packet(kind :: Int, payload :: Bytes) -> Bytes!String do
  let version = append(repeated(1, 1)?, Bytes.from_utf8("GRP"))?
  append(append(version, repeated(kind, 1)?)?, vector(payload)?)
end

fn malformed_group_packet() -> Bytes!String do
  let version = append(repeated(1, 1)?, Bytes.from_utf8("GRP"))?
  append(append(version, repeated(3, 1)?)?, write_u32(8)?)
end

fn malformed_welcome_packet() -> Bytes!String do
  let version = append(repeated(1, 1)?, Bytes.from_utf8("GWB"))?
  let baseline = append(version, vector(repeated(0, 188)?)?)?
  group_packet(1, append(baseline, vector(repeated(1, 1)?)?)?)
end

fn replace_group_ciphertext(input :: Bytes, ciphertext :: Bytes) -> Bytes!String do
  let value = outer(input)?
  case encode_outer_envelope(%{value | ciphertext: ciphertext}) do
    Err(_) -> Err("outer envelope encode failed")
    Ok(encoded)
  end
end

fn assert_poison_ack(path :: String, envelope :: Bytes) -> Result<(), String> do
  let acknowledgement = ack(process_delivery_batch_export(group_vectors([
    Bytes.from_utf8(path),
    delivery_batch(envelope)?
  ])?)?)?
  group_messages_ensure(List.length(acknowledgement.envelope_ids) == 1 && Bytes.secure_equals(List.head(acknowledgement.envelope_ids),
      outer(envelope)?.envelope_id),
    "malformed group delivery was not acknowledged")
end

pub fn exercise_linked_greeting(accounts :: GroupAccountFixture, group_id :: Bytes) -> Bool!String do
  let linked_package = group_key_package_export(Bytes.from_utf8(accounts.linked_path))?
  let linked_welcome_output = group_add_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_id,
    accounts.alice_set,
    linked_package
  ])?)?
  let linked_deliveries = output_list(linked_welcome_output)?
  group_messages_ensure(List.length(linked_deliveries) == 2, "linked welcome count mismatch")?
  let bob_commit = envelope_for(linked_deliveries, accounts.bob_entry.mailbox_token, 0)?
  let linked_welcome = envelope_for(linked_deliveries, accounts.linked_entry.mailbox_token, 0)?
  assert_group_transport(bob_commit, group_id, accounts.alice_account.account_id)?
  assert_group_transport(linked_welcome, group_id, accounts.alice_account.account_id)?
  acknowledge(accounts.alice_path, linked_deliveries, 0)?
  assert_poison_ack(accounts.bob_path,
    replace_group_ciphertext(bob_commit, malformed_group_packet()?)?)?
  assert_poison_ack(accounts.bob_path,
    replace_group_ciphertext(bob_commit, malformed_welcome_packet()?)?)?
  group_messages_ensure(Bytes.secure_equals(group_receive_export(group_vectors([
        Bytes.from_utf8(accounts.linked_path),
        linked_welcome
      ])?)?,
      group_id),
    "linked welcome receive mismatch")?
  let group_key = Bytes.from_utf8("group/" <> Bytes.to_hex(group_id))
  let group_presentation = group_vectors([Bytes.from_utf8("Weekend walks"), Bytes.empty()])?
  case presentation_save_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    group_key,
    group_presentation
  ])?) do
    Ok(_) -> Err("non-creator changed group presentation")?
    Err(error) -> group_messages_ensure(error == "group_creator_required",
      "wrong group permission error")?
  end
  presentation_save_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_key,
    group_presentation
  ])?)?
  let greeting = Bytes.from_utf8("hello every device")
  let presentation_key = Bytes.from_utf8("user/" <> Bytes.to_hex(accounts.alice_account.account_id))
  let presentation = group_vectors([
    Bytes.from_utf8("alice"),
    Bytes.from_utf8("data:image/jpeg;base64,/9j/2Q==")
  ])?
  presentation_save_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    presentation_key,
    presentation
  ])?)?
  let greeting_output = group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_id,
    greeting
  ])?)?
  let greetings = output_list(greeting_output)?
  group_messages_ensure(List.length(greetings) == 2, "greeting delivery count mismatch")?
  let bob_greeting = envelope_for(greetings, accounts.bob_entry.mailbox_token, 0)?
  assert_group_transport(bob_greeting, group_id, accounts.alice_account.account_id)?
  let padded = outer(bob_greeting)?
  group_messages_ensure(Bytes.length(padded.ciphertext) == padded.padding_bucket,
    "group message does not fill its padding bucket")?
  let bob_greeting_batch = delivery_batch(bob_greeting)?
  group_messages_ensure(Bytes.length(process_delivery_batch_export(group_vectors([
      Bytes.from_utf8(accounts.bob_path),
      bob_greeting_batch
    ])?)?) == 0,
    "future greeting was not deferred")?
  group_messages_ensure(List.length(output_list(group_history_export(group_vectors([
      Bytes.from_utf8(accounts.bob_path),
      group_id
    ])?)?)?) == 0,
    "future greeting entered history")?
  group_messages_ensure(Bytes.secure_equals(group_receive_export(group_vectors([
        Bytes.from_utf8(accounts.bob_path),
        bob_commit
      ])?)?,
      group_id),
    "bob commit receive mismatch")?
  let bob_greeting_ack = ack(process_delivery_batch_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    bob_greeting_batch
  ])?)?)?
  group_messages_ensure(List.length(bob_greeting_ack.envelope_ids) == 1,
    "bob greeting acknowledgement count mismatch")?
  group_messages_ensure(Bytes.secure_equals(List.head(bob_greeting_ack.envelope_ids),
      outer(bob_greeting)?.envelope_id),
    "bob greeting acknowledgement mismatch")?
  let bob_greeting_history = output_list(group_history_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    group_id
  ])?)?)?
  group_messages_ensure(List.length(bob_greeting_history) == 1,
    "bob greeting history count mismatch")?
  let bob_greeting_record = output_list(List.head(bob_greeting_history))?
  # Nine fields end with the message ID; the tenth says what became of a sent message.
  group_messages_ensure(List.length(bob_greeting_record) == 10 && Bytes.length(List.get(bob_greeting_record,
      8)) == 32,
    "group history must expose a stable message ID")?
  let alice_greeting_history = output_list(group_history_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_id
  ])?)?)?
  let alice_greeting_record = output_list(List.head(alice_greeting_history))?
  group_messages_ensure(Bytes.length(List.get(bob_greeting_record, 8)) == 32 && Bytes.secure_equals(List.get(bob_greeting_record,
        8),
      List.get(alice_greeting_record, 8)),
    "sender and recipient group message IDs differ")?
  group_messages_ensure(Bytes.secure_equals(List.get(bob_greeting_record, 6), greeting),
    "bob greeting history body mismatch")?
  group_messages_ensure(Bytes.secure_equals(presentation_load_export(group_vectors([
        Bytes.from_utf8(accounts.bob_path),
        presentation_key
      ])?)?,
      presentation),
    "sender presentation did not travel with the encrypted message")?
  group_messages_ensure(Bytes.secure_equals(presentation_load_export(group_vectors([
        Bytes.from_utf8(accounts.bob_path),
        group_key
      ])?)?,
      group_presentation),
    "group presentation did not travel with the encrypted message")?
  group_messages_ensure(Bytes.secure_equals(group_receive_export(group_vectors([
        Bytes.from_utf8(accounts.linked_path),
        envelope_for(greetings, accounts.linked_entry.mailbox_token, 0)?
      ])?)?,
      greeting),
    "linked greeting receive mismatch")?
  acknowledge(accounts.alice_path, greetings, 0)?
  let announcement = output_list(group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_id,
    Bytes.empty()
  ])?)?)?
  group_receive_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    envelope_for(announcement, accounts.bob_entry.mailbox_token, 0)?
  ])?)?
  group_receive_export(group_vectors([
    Bytes.from_utf8(accounts.linked_path),
    envelope_for(announcement, accounts.linked_entry.mailbox_token, 0)?
  ])?)?
  group_messages_ensure(List.length(output_list(group_history_export(group_vectors([
      Bytes.from_utf8(accounts.bob_path),
      group_id
    ])?)?)?) == 1,
    "photo announcement appeared as an empty chat message")?
  acknowledge(accounts.alice_path, announcement, 0)?
  Ok(true)
end

pub fn exercise_group_message_boundary(accounts :: GroupAccountFixture, group_id :: Bytes) -> Bool!String do
  let maximum = repeated(97, 65290)?
  let maximum_output = group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_id,
    maximum
  ])?)?
  let maximum_deliveries = output_list(maximum_output)?
  group_messages_ensure(List.length(maximum_deliveries) == 2, "maximum delivery count mismatch")?
  let maximum_for_bob = envelope_for(maximum_deliveries, accounts.bob_entry.mailbox_token, 0)?
  group_messages_ensure(outer(maximum_for_bob)?.suite == 4, "maximum delivery suite mismatch")?
  group_messages_ensure(Bytes.length(outer(maximum_for_bob)?.ciphertext) == 65536,
    "maximum ciphertext length mismatch")?
  group_messages_ensure(Bytes.secure_equals(group_receive_export(group_vectors([
        Bytes.from_utf8(accounts.bob_path),
        maximum_for_bob
      ])?)?,
      maximum),
    "bob maximum receive mismatch")?
  group_messages_ensure(Bytes.secure_equals(group_receive_export(group_vectors([
        Bytes.from_utf8(accounts.linked_path),
        envelope_for(maximum_deliveries, accounts.linked_entry.mailbox_token, 0)?
      ])?)?,
      maximum),
    "linked maximum receive mismatch")?
  acknowledge(accounts.alice_path, maximum_deliveries, 0)?
  case group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_id,
    repeated(98, 65291)?
  ])?) do
    Ok(_) -> Err("oversized group message was accepted")?
    Err(error) -> group_messages_ensure(error == "group_message_too_large",
      "wrong oversized group message error")?
  end
  Ok(true)
end
