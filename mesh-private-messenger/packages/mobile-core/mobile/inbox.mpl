from Identity.Device import DeviceKeys
from Mobile.Codec import canonical_outer, current_time
from Mobile.Groups import receive_mobile_group_classified
from Mobile.Messages import receive_initial_message, receive_message
from Mobile.Profile import load_profile, open_device
from Mobile.Transport import MobileOpenedPacket, open_outer_packet, opened_packet_kind
from Mobile.Types import (
  MobileBatchRequest,
  MobileDirectReceiveOutcome,
  MobileGroupReceiveOutcome,
  MobileReceiveRequest
)
from Protocol.MailboxWire import decode_delivery_batch, sign_mailbox_ack
from Protocol.V1 import (
  AccountIdentity,
  DeliveredEnvelope,
  DeviceCredential,
  DirectoryEntry,
  OuterEnvelope,
  PrekeyBundle,
  protocol_sealed_outer_suite
)
from Storage.Keys import platform_key
from Transport.Packet import ClientProfile, decode_client_profile, is_sealed_initial_packet

##! Mobile.Inbox implementation.

pub fn permanent_direct_delivery_error(error :: String) -> Bool do
  error == "wrong_mailbox" || error == "invalid_recipient_packet" || error == "invalid_outer_envelope" || error == "noncanonical_outer_envelope" || error == "invalid_initial_packet" || error == "invalid_initial_message" || error == "outer_suite_mismatch" || error == "invalid_initiator_account" || error == "invalid_initiator_credential" || error == "initial_receive_failed" || error == "invalid_initial_plaintext" || error == "invalid_peer_profile" || error == "invalid_inner_envelope" || error == "initial_identity_mismatch" || error == "invalid_sync_payload" || error == "sync_conversation_mismatch" || error == "invalid_ratchet_packet" || error == "invalid_ratchet_message" || error == "message_rejected" || error == "one_time_prekey_not_found" || error == "replayed_initial_message" || error == "blocked_message"
end

# Packet kinds: 1 initial, 2 ratchet, 3 group, 0 unknown. A sealed envelope
# reveals its kind only after this device opens it; legacy envelopes named it in
# the clear through the outer suite and the packet magic.

fn sealed_packet_kind(database_path :: String, profile :: ClientProfile, outer :: OuterEnvelope) -> Int ! String do
  let wrapping_key = platform_key() ?
  let device = open_device(profile, wrapping_key, database_path) ?
  # ponytail: the chosen receive path opens the seal again (one extra X25519
  # and AEAD per delivery); thread the opened packet through if it ever shows.
  let opened = open_outer_packet(outer, device.identity_private_key) ?
  Ok(opened_packet_kind(opened))
end

fn delivery_kind(database_path :: String, profile :: ClientProfile, outer :: OuterEnvelope) -> Int ! String do
  if outer.suite == protocol_sealed_outer_suite() do
    sealed_packet_kind(database_path, profile, outer)
  else if outer.suite == 3 do
    Ok(3)
  else if is_sealed_initial_packet(outer.ciphertext) do
    Ok(1)
  else
    Ok(2)
  end
end

fn receive_mobile_direct_classified(request :: MobileReceiveRequest, kind :: Int) -> MobileDirectReceiveOutcome do
  let received = if kind == 1 do
    receive_initial_message(request)
  else
    receive_message(request)
  end
  case received do
    Ok( output) -> DirectReceiveApplied(output)
    Err( error) -> if permanent_direct_delivery_error(error) do
      DirectReceiveRejected(error)
    else
      DirectReceiveRetry(error)
    end
  end
end

# An envelope is acknowledged once it is durably applied or permanently
# rejected; anything that might succeed later is left for redelivery.

fn acknowledge_delivery(database_path :: String,
profile :: ClientProfile,
outer :: OuterEnvelope,
encoded :: Bytes) -> Bool do
  let request = MobileReceiveRequest {
    database_path : database_path,
    outer : encoded
  }
  case delivery_kind(database_path, profile, outer) do
    Err( error) -> permanent_direct_delivery_error(error)
    Ok( 3) -> case receive_mobile_group_classified(request) do
      GroupReceiveApplied( _) -> true
      GroupReceiveRetry( _) -> false
      GroupReceiveRejected( _) -> true
    end
    Ok( 0) -> true
    Ok( kind) -> case receive_mobile_direct_classified(request, kind) do
      DirectReceiveApplied( _) -> true
      DirectReceiveRetry( _) -> false
      DirectReceiveRejected( _) -> true
    end
  end
end

fn process_deliveries(database_path :: String,
profile :: ClientProfile,
deliveries :: List < DeliveredEnvelope >,
index :: Int,
envelope_ids :: List < Bytes >) -> List < Bytes > do
  if index >= List.length(deliveries) do
    envelope_ids
  else
    let delivered = List.get(deliveries, index)
    case canonical_outer(delivered.envelope) do
      Err( _) -> process_deliveries(database_path, profile, deliveries, index + 1, envelope_ids)
      Ok( outer) -> do
        let next_ids = if acknowledge_delivery(database_path, profile, outer, delivered.envelope) do
          List.append(envelope_ids, outer.envelope_id)
        else
          envelope_ids
        end
        process_deliveries(database_path, profile, deliveries, index + 1, next_ids)
      end
    end
  end
end

pub fn process_delivery_batch(request :: MobileBatchRequest) -> Bytes ! String do
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let deliveries = case decode_delivery_batch(request.batch) do
    Err( _) -> Err("invalid_delivery_batch")
    Ok( values) -> Ok(values)
  end ?
  let envelope_ids = process_deliveries(request.database_path, profile, deliveries, 0, List.new())
  if List.length(envelope_ids) == 0 do
    Ok(Bytes.empty())
  else
    let wrapping_key = platform_key() ?
    let device = open_device(profile, wrapping_key, request.database_path) ?
    case sign_mailbox_ack(device.signing_private_key,
    Crypto.sha256(profile.entry.mailbox_token),
    current_time() ?,
    envelope_ids) do
      Err( _) -> Err("mailbox_ack_encoding_failed")
      Ok( encoded) -> Ok(encoded)
    end
  end
end
