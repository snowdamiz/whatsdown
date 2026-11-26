import File
from Mobile.Codec import mobile_wide, outer_bytes
from Mobile.Groups import receive_mobile_group_classified
from Mobile.Inbox import permanent_direct_delivery_error
from Mobile.Messages import receive_initial_message, receive_message
from Mobile.Types import MobileGroupReceiveOutcome, MobileReceiveRequest
from MobileCore import (
  create_account_export,
  install_classical_session_for_test,
  legacy_outer_for_test,
  start_conversation_export
)
from Protocol.V1 import protocol_legacy_packet_cutoff_ms
from Tests.GroupConsistencySupport import request
from Tests.GroupLifecycleWire import outer, output_list
from Tests.Support import database_path, repeated
from Transport.Packet import decode_client_profile

# Receive paths read the clock from the request, so a test stands on either
# side of the cutoff without waiting for it.

fn clock(offset_ms :: Int) -> U64!String do
  mobile_wide(Int.to_string(protocol_legacy_packet_cutoff_ms() + offset_ms))
end

fn at(path :: String, envelope :: Bytes, now :: U64) -> MobileReceiveRequest do
  MobileReceiveRequest { database_path: path, outer: envelope, now: now }
end

fn error_of(result :: Bytes!String) -> String do
  case result do
    Ok(_) -> "read"
    Err(error) -> error
  end
end

fn group_error(request :: MobileReceiveRequest) -> String do
  case receive_mobile_group_classified(request) do
    GroupReceiveApplied(_) -> "read"
    GroupReceiveRetry(error) -> "retry " <> error
    GroupReceiveRejected(error) -> error
  end
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let alice_path = database_path("legacy-alice")?
  let bob_path = database_path("legacy-bob")?
  let alice_profile = create_account_export(request([
    Bytes.from_utf8(alice_path),
    Bytes.from_utf8("alice")
  ])?)?
  create_account_export(request([Bytes.from_utf8(bob_path), Bytes.from_utf8("bob")])?)?
  let delayed = List.head(output_list(install_classical_session_for_test(alice_path, bob_path)?)?)
  assert(outer(delayed)?.suite == 1)
  # From the cutoff a bare packet is refused before anything reads it, and for
  # good, so the inbox acknowledges it instead of fetching it again.
  let refused = error_of(receive_message(at(alice_path, delayed, clock(0)?)))
  assert(refused == "legacy_packet_refused" && permanent_direct_delivery_error(refused))
  # Until then the same packet reads.
  assert(Bytes.secure_equals(receive_message(at(alice_path, delayed, clock(-1)?))?,
    Bytes.from_utf8("delayed suite-1")))
  let mailbox = decode_client_profile(alice_profile)?.entry.mailbox_token
  let initial = legacy_outer_for_test(mailbox, 2, repeated(7, 64)?, clock(-1)?)?
  assert(error_of(receive_initial_message(at(alice_path,
    initial,
    clock(0)?))) == "legacy_packet_refused")
  assert(error_of(receive_initial_message(at(alice_path,
    initial,
    clock(-1)?))) != "legacy_packet_refused")
  let group = legacy_outer_for_test(mailbox, 3, repeated(7, 64)?, clock(-1)?)?
  assert(group_error(at(alice_path, group, clock(0)?)) == "legacy_packet_refused")
  assert(group_error(at(alice_path, group, clock(-1)?)) == "invalid_group_packet")
  # Sealed packets do not depend on the date.
  let carol_path = database_path("legacy-carol")?
  create_account_export(request([Bytes.from_utf8(carol_path), Bytes.from_utf8("carol")])?)?
  let greeting = Bytes.from_utf8("sealed after the cutoff")
  let sealed = start_conversation_export(request([
    Bytes.from_utf8(carol_path),
    alice_profile,
    greeting
  ])?)?
  assert(outer(sealed)?.suite == 4)
  assert(Bytes.secure_equals(receive_initial_message(at(alice_path, sealed, clock(31536000000)?))?,
    greeting))
  File.delete(alice_path)?
  File.delete(bob_path)?
  File.delete(carol_path)?
  Ok(true)
end

test("bare legacy packets read until the cutoff and never after it; sealed packets always read") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn builds(mailbox :: Bytes, packet :: Bytes, now :: U64, suite :: Int) -> Bool do
  case outer_bytes(mailbox, suite, packet, now) do
    Ok(_) -> true
    Err(_) -> false
  end
end

fn only_sealed() -> Bool!String do
  let mailbox = repeated(9, 32)?
  let packet = repeated(7, 64)?
  let now = clock(0)?
  Ok(builds(mailbox, packet, now, 4)
    && !builds(mailbox, packet, now, 1)
    && !builds(mailbox, packet, now, 2)
    && !builds(mailbox, packet, now, 3))
end

test("the envelope builder every send path uses writes only the sealed outer suite") do
  case only_sealed() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
