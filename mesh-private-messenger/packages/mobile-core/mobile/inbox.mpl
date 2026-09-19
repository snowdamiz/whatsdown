from Mobile.Codec import canonical_outer
from Mobile.Groups import receive_mobile_group_classified
from Mobile.Messages import receive_initial_message, receive_message
from Mobile.Profile import load_profile
from Mobile.Types import (
  MobileBatchRequest,
  MobileDirectReceiveOutcome,
  MobileGroupReceiveOutcome,
  MobileReceiveRequest
)
from Protocol.MailboxWire import decode_delivery_batch, encode_mailbox_ack
from Protocol.V1 import (
  AccountIdentity,
  DeliveredEnvelope,
  DeviceCredential,
  DirectoryEntry,
  MailboxAck,
  OuterEnvelope,
  PrekeyBundle
)
from Transport.Packet import ClientProfile, decode_client_profile, is_sealed_initial_packet

##! Mobile.Inbox implementation.

pub fn permanent_direct_delivery_error(error :: String) -> Bool do
  error == "wrong_mailbox" || error == "invalid_outer_envelope" || error == "noncanonical_outer_envelope" || error == "invalid_initial_packet" || error == "invalid_initial_message" || error == "outer_suite_mismatch" || error == "invalid_initiator_account" || error == "invalid_initiator_credential" || error == "initial_receive_failed" || error == "invalid_initial_plaintext" || error == "invalid_peer_profile" || error == "invalid_inner_envelope" || error == "initial_identity_mismatch" || error == "invalid_sync_payload" || error == "sync_conversation_mismatch" || error == "invalid_ratchet_packet" || error == "invalid_ratchet_message" || error == "message_rejected" || error == "one_time_prekey_not_found" || error == "blocked_message"
end

fn receive_mobile_direct_classified(request :: MobileReceiveRequest) -> MobileDirectReceiveOutcome do
  let received = case canonical_outer(request.outer) do
    Err( error) -> Err(error)
    Ok( outer) -> if is_sealed_initial_packet(outer.ciphertext) do
      receive_initial_message(request)
    else
      receive_message(request)
    end
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

fn process_deliveries(database_path :: String,
deliveries :: List < DeliveredEnvelope >,
index :: Int,
envelope_ids :: List < Bytes >) -> List < Bytes > do
  if index >= List.length(deliveries) do
    envelope_ids
  else
    let delivered = List.get(deliveries, index)
    case canonical_outer(delivered.envelope) do
      Err( _) -> process_deliveries(database_path, deliveries, index + 1, envelope_ids)
      Ok( outer) -> do
        let request = MobileReceiveRequest {
          database_path : database_path,
          outer : delivered.envelope
        }
        let acknowledge = if outer.suite == 3 do
          case receive_mobile_group_classified(request) do
            GroupReceiveApplied( _) -> true
            GroupReceiveRetry( _) -> false
            GroupReceiveRejected( _) -> true
          end
        else
          case receive_mobile_direct_classified(request) do
            DirectReceiveApplied( _) -> true
            DirectReceiveRetry( _) -> false
            DirectReceiveRejected( _) -> true
          end
        end
        let next_ids = if acknowledge do
          List.append(envelope_ids, outer.envelope_id)
        else
          envelope_ids
        end
        process_deliveries(database_path, deliveries, index + 1, next_ids)
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
  let envelope_ids = process_deliveries(request.database_path, deliveries, 0, List.new())
  if List.length(envelope_ids) == 0 do
    Ok(Bytes.empty())
  else
    case encode_mailbox_ack(MailboxAck {
      version : 1,
      mailbox_token : profile.entry.mailbox_token,
      envelope_ids : envelope_ids
    }) do
      Err( _) -> Err("mailbox_ack_encoding_failed")
      Ok( encoded) -> Ok(encoded)
    end
  end
end
