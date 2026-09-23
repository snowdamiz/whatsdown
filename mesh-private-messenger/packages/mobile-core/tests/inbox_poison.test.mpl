import File
from MobileCore import (
  age_delivery_attempts_for_test,
  create_account_export,
  mailbox_fetch_export,
  outbox_ack_export,
  process_delivery_batch_export,
  receive_message_export,
  send_message_export,
  start_conversation_export,
  test_ratchet_jump_envelope,
  update_conversation_export
)
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.MailboxWire import decode_mailbox_ack, decode_mailbox_fetch, encode_delivery_batch
from Protocol.V1 import DeliveredEnvelope, MailboxAck, MailboxFetch, OuterEnvelope
from Tests.Support import append, database_path, vector, write_u32

fn request(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    request(values, index + 1, append(output, vector(List.get(values, index))?)?)
  end
end

fn entries(sequence :: U64,
  envelopes :: List<Bytes>,
  index :: Int,
  output :: List<DeliveredEnvelope>) -> List<DeliveredEnvelope> do
  if index >= List.length(envelopes) do
    output
  else
    entries(sequence,
      envelopes,
      index + 1,
      List.append(output,
        DeliveredEnvelope {
          sequence: sequence,
          envelope: List.get(envelopes, index)
        }))
  end
end

fn batch(sequence :: String, envelopes :: List<Bytes>) -> Bytes!String do
  case encode_delivery_batch(entries(U64.parse(sequence)?, envelopes, 0, List.new())) do
    Err(_) -> Err("delivery batch encode failed")
    Ok(value)
  end
end

# How many envelopes the device acknowledged, which is how many it is done with.

fn settled(path :: String, deliveries :: Bytes) -> Int!String do
  let answer = process_delivery_batch_export(request([Bytes.from_utf8(path), deliveries],
    0,
    Bytes.empty())?)?
  if Bytes.length(answer) == 0 do
    Ok(0)
  else
    case decode_mailbox_ack(answer) do
      Err(_) -> Err("mailbox ack decode failed")
      Ok(value) -> Ok(List.length(value.envelope_ids))
    end
  end
end

# Where the device's next fetch starts.

fn asks_after(path :: String) -> String!String do
  case decode_mailbox_fetch(mailbox_fetch_export(Bytes.from_utf8(path))?) do
    Err(_) -> Err("mailbox fetch decode failed")
    Ok(value) -> Ok(U64.to_string(value.after_sequence))
  end
end

fn retried(path :: String, deliveries :: Bytes, remaining :: Int) -> Bool!String do
  if remaining <= 0 do
    Ok(true)
  else
    let done = settled(path, deliveries)?
    if done != 0 do
      Ok(false)
    else
      retried(path, deliveries, remaining - 1)
    end
  end
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let alice = database_path("inbox-poison-alice")?
  let bob = database_path("inbox-poison-bob")?
  let alice_profile = create_account_export(request([
      Bytes.from_utf8(alice),
      Bytes.from_utf8("alice")
    ],
    0,
    Bytes.empty())?)?
  create_account_export(request([Bytes.from_utf8(bob), Bytes.from_utf8("bob")], 0, Bytes.empty())?)?
  let hello = start_conversation_export(request([
      Bytes.from_utf8(bob),
      alice_profile,
      Bytes.from_utf8("hello")
    ],
    0,
    Bytes.empty())?)?
  outbox_ack_export(request([Bytes.from_utf8(bob), hello], 0, Bytes.empty())?)?
  let late = send_message_export(request([
      Bytes.from_utf8(bob),
      alice_profile,
      Bytes.from_utf8("second")
    ],
    0,
    Bytes.empty())?)?
  # The second message arrives without the first, so it cannot be opened yet. It
  # is left for later, and the next fetch asks past it: whatever is behind it in
  # the mailbox still gets through.
  assert(asks_after(alice)? == "0")
  assert(settled(alice, batch("5", [late])?)? == 0)
  assert(asks_after(alice)? == "5")
  # A pass that reaches the end starts over next time.
  assert(settled(alice, batch("0", List.new())?)? == 0)
  assert(asks_after(alice)? == "0")
  # It is tried again on every pass, but not for ever. A day after the first
  # try it is still kept while it has been tried fewer than sixteen times, or a
  # device that was merely switched off overnight would lose it...
  age_delivery_attempts_for_test(alice, 86400000)?
  assert(retried(alice, batch("5", [late])?, 14)?)
  # ...and the sixteenth try, with the first still a day old, is the last.
  assert(settled(alice, batch("5", [late])?)? == 1)
  # Twenty tries inside one day do not give up on it either: whatever is wrong
  # may be this device's own trouble, and pass.
  assert(retried(alice, batch("5", [late])?, 20)?)
  age_delivery_attempts_for_test(alice, 86400000)?
  assert(settled(alice, batch("5", [late])?)? == 1)
  assert(settled(alice, batch("0", List.new())?)? == 0)
  # A message numbered too far ahead can never be opened: the ones in between are
  # not coming. It is dropped at once, leaving the session as it was, so the
  # genuine next message still opens.
  assert(settled(alice, batch("6", [hello])?)? == 1)
  let third = send_message_export(request([
      Bytes.from_utf8(bob),
      alice_profile,
      Bytes.from_utf8("third")
    ],
    0,
    Bytes.empty())?)?
  let too_far = test_ratchet_jump_envelope(alice, third)?
  assert(settled(alice, batch("7", [too_far])?)? == 1)
  assert(asks_after(alice)? == "0")
  assert(settled(alice, batch("8", [third])?)? == 1)
  File.delete(alice)?
  File.delete(bob)?
  Ok(true)
end

test("an envelope that cannot be opened yet holds nothing else up and is given up on") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
