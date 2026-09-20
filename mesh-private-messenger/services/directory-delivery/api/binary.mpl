from Storage.Transparency import transparency_username
from Protocol.DirectoryWire import decode_device_revocation, decode_directory_entry
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.MailboxWire import decode_mailbox_ack, decode_mailbox_fetch, encode_delivery_batch
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import MailboxAck, MailboxFetch
from Prekeys.Pool import PrekeyPublishResponse, decode_prekey_claim, decode_prekey_publish, encode_prekey_publish_response
from Privacy.Edge import RequestStamp, decode_sealed_delivery, decode_stamped_request, open_delivery, open_delivery_with_key, request_stamp_key, verify_request_stamp
from Push.Binding import decode_push_bind, decode_push_unbind
from Storage.Delivery import DeliveryInsert, acknowledge_mailbox, enqueue_envelope, fetch_mailbox
from Storage.MailboxAuth import authorize_mailbox_ack, authorize_mailbox_fetch
from Storage.Devices import DeviceWrite, register_device, resolve_devices, revoke_device
from Storage.Push import PushWrite, bind_push, unbind_push
from Storage.RateLimit import allow_request
from Storage.Prekeys import PrekeyClaimWrite, PrekeyPublishWrite, claim_prekey, publish_prekeys
from Storage.Transparency import consistency_from, configured_evidence_for_username, create_configured_checkpoint, latest_checkpoint, store_witness, validate_signing_config, witnesses_for_checkpoint
from Transparency.Merkle import WitnessKey
from Transparency.Wire import decode_transparency_evidence, decode_transparency_lookup, decode_transparency_tree_query, decode_witnesses, encode_checkpoint, encode_consistency_proof, encode_inclusion_proof, encode_transparency_evidence, encode_witnesses

pub struct BinaryResult do
  status :: Int
  body :: Bytes
end

fn response(status :: Int, body :: Bytes) -> BinaryResult do
  BinaryResult {
    status : status,
    body : body
  }
end

fn empty(status :: Int) -> BinaryResult do
  response(status, Bytes.empty())
end

pub type Admission do
  Admitted( payload :: Bytes)

  AdmissionMalformed

  AdmissionRefused
end

pub type CheckedRequest do
  RequestPaid( payload :: Bytes, spent_key :: Bytes)

  RequestMalformed

  RequestUnpaid
end

# Anonymous directory requests must carry proof of work for this exact endpoint
# and request. Checking it needs no database, so malformed and unpaid requests
# are refused before anything reaches for the pool: a caller who has done no
# work cannot make the service touch its database.

pub fn check_request(label :: String,
body :: Bytes,
maximum_payload :: Int,
now :: U64,
difficulty :: Int) -> CheckedRequest ! String do
  case decode_stamped_request(body, maximum_payload) do
    Err( _) -> Ok(RequestMalformed)
    Ok( ( stamp, payload)) -> if verify_request_stamp(label,
    payload,
    stamp,
    now,
    U64.parse("300000") ?,
    difficulty) ? do
      Ok(RequestPaid(payload, request_stamp_key(label, payload, stamp) ?))
    else
      Ok(RequestUnpaid)
    end
    Ok( _) -> Ok(RequestMalformed)
  end
end

# A spent stamp is remembered for longer than it stays valid, so it admits one
# request only.

pub fn spend_request(pool :: PoolHandle, payload :: Bytes, spent_key :: Bytes) -> Admission ! String do
  if allow_request(pool, spent_key, 1, 600) ? do
    Ok(Admitted(payload))
  else
    Ok(AdmissionRefused)
  end
end

pub fn admit_request(pool :: PoolHandle,
label :: String,
body :: Bytes,
maximum_payload :: Int,
now :: U64,
difficulty :: Int) -> Admission ! String do
  case check_request(label, body, maximum_payload, now, difficulty) ? do
    RequestMalformed -> Ok(AdmissionMalformed)
    RequestUnpaid -> Ok(AdmissionRefused)
    RequestPaid( payload, spent_key) -> spend_request(pool, payload, spent_key)
  end
end

# 400 for a malformed frame and 429 for missing, stale or spent work, matching
# the privacy edge. Either way the caller mints a fresh stamp and retries.

pub fn admission_failure(result :: Result < Admission, String >) -> BinaryResult do
  case result do
    Err( _) -> empty(500)
    Ok( AdmissionMalformed) -> empty(400)
    Ok( _) -> empty(429)
  end
end

fn device_write(result :: Result < DeviceWrite, String >) -> BinaryResult do
  case result do
    Err( _) -> empty(500)
    Ok( DeviceAccepted) -> empty(201)
    Ok( DeviceUnchanged) -> empty(200)
    Ok( DeviceConflict) -> empty(409)
    Ok( DeviceInvalid) -> empty(400)
    # The transparency log has no room for this transition. Nothing was
    # committed; lookups and existing accounts are unaffected.
    Ok( DeviceLogFull) -> empty(507)
  end
end

pub fn register_device_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_directory_entry(body) do
    Err( _) -> empty(400)
    Ok( entry) -> device_write(register_device(pool, entry))
  end
end

pub fn resolve_devices_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_transparency_lookup(body) do
    Err( _) -> empty(400)
    Ok( lookup) -> case transparency_username(pool, lookup.username) do
      Err( _) -> empty(500)
      Ok( None) -> empty(404)
      Ok( Some( username)) -> resolved_device_evidence(pool, username, lookup.previous_tree_size)
    end
  end
end

fn resolved_device_evidence(pool :: PoolHandle, username :: String, previous_tree_size :: Int) -> BinaryResult do
  case resolve_devices(pool, username) do
    Err( _) -> empty(500)
    Ok( None) -> empty(404)
    Ok( Some( _)) -> case configured_evidence_for_username(pool, username, previous_tree_size) do
      Err( _) -> empty(500)
      Ok( evidence) -> case encode_transparency_evidence(evidence) do
        Err( _) -> empty(500)
        Ok( encoded) -> response(200, encoded)
      end
    end
  end
end

fn configured_public_key(name :: String) -> Bytes ! String do
  case Bytes.from_hex(Env.get(name, "")) do
    Err( _) -> Err("invalid transparency configuration")
    Ok( value) -> if Bytes.length(value) == 32 do
      Ok(value)
    else
      Err("invalid transparency configuration")
    end
  end
end

fn delivery_private_key() -> X25519PrivateKey ! String do
  let material = case Env.get_secret_hex("MESSENGER_DELIVERY_SEALING_SEED_HEX") do
    Err( _) -> Err("invalid delivery configuration")
    Ok( value) -> Ok(value)
  end ?
  case Crypto.x25519_from_secret(material) do
    Err( _) -> Err("invalid delivery configuration")
    Ok( pair) -> Ok(pair.private_key)
  end
end

fn trusted_witness(witness_id :: String) -> WitnessKey ! String do
  if witness_id == "witness-a" do
    Ok(WitnessKey {
      witness_id : witness_id,
      public_key : configured_public_key("MESSENGER_WITNESS_A_PUBLIC_KEY_HEX") ?
    })
  else if witness_id == "witness-b" do
    Ok(WitnessKey {
      witness_id : witness_id,
      public_key : configured_public_key("MESSENGER_WITNESS_B_PUBLIC_KEY_HEX") ?
    })
  else
    Err("untrusted witness")
  end
end

pub fn validate_transparency_config() -> Result <(), String > do
  validate_signing_config() ?
  let _ = trusted_witness("witness-a") ?
  let _ = trusted_witness("witness-b") ?
  Ok(nil)
end

pub fn validate_delivery_config() -> Result <(), String > do
  let _private_key = delivery_private_key() ?
  Ok(nil)
end

pub fn submit_witness_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_witnesses(body) do
    Err( _) -> empty(400)
    Ok( values) -> if List.length(values) != 1 do
      empty(400)
    else
      let value = List.head(values)
      case trusted_witness(value.witness_id) do
        Err( _) -> empty(400)
        Ok( trusted) -> case store_witness(pool, value, trusted) do
          Err( _) -> empty(400)
          Ok( _) -> empty(201)
        end
      end
    end
  end
end

pub fn checkpoint_request(pool :: PoolHandle) -> BinaryResult do
  case latest_checkpoint(pool) do
    Err( _) -> empty(500)
    Ok( None) -> empty(404)
    Ok( Some( checkpoint)) -> case encode_checkpoint(checkpoint) do
      Err( _) -> empty(500)
      Ok( encoded) -> response(200, encoded)
    end
  end
end

pub fn witnesses_request(pool :: PoolHandle) -> BinaryResult do
  case latest_checkpoint(pool) do
    Err( _) -> empty(500)
    Ok( None) -> empty(404)
    Ok( Some( checkpoint)) -> case witnesses_for_checkpoint(pool, checkpoint.sequence) do
      Err( _) -> empty(500)
      Ok( values) -> case encode_witnesses(values) do
        Err( _) -> empty(500)
        Ok( encoded) -> response(200, encoded)
      end
    end
  end
end

pub fn inclusion_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  let evidence = resolve_devices_request(pool, body)
  if evidence.status != 200 do
    evidence
  else
    case decode_transparency_evidence(evidence.body) do
      Err( _) -> empty(500)
      Ok( value) -> case encode_inclusion_proof(value.inclusion) do
        Err( _) -> empty(500)
        Ok( encoded) -> response(200, encoded)
      end
    end
  end
end

pub fn consistency_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_transparency_tree_query(body) do
    Err( _) -> empty(400)
    Ok( query) -> case create_configured_checkpoint(pool) do
      Err( _) -> empty(500)
      Ok( _) -> case consistency_from(pool, query.previous_tree_size) do
        Err( _) -> empty(400)
        Ok( proof) -> case encode_consistency_proof(proof) do
          Err( _) -> empty(500)
          Ok( encoded) -> response(200, encoded)
        end
      end
    end
  end
end

pub fn revoke_device_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_device_revocation(body) do
    Err( _) -> empty(400)
    Ok( revocation) -> case revoke_device(pool, revocation) do
      Err( _) -> empty(500)
      Ok( DeviceAccepted) -> empty(200)
      Ok( DeviceUnchanged) -> empty(200)
      Ok( DeviceConflict) -> empty(409)
      Ok( DeviceInvalid) -> empty(400)
      Ok( DeviceLogFull) -> empty(507)
    end
  end
end

pub fn submit_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_outer_envelope(body) do
    Err( _) -> empty(400)
    Ok( envelope) -> case enqueue_envelope(pool, envelope) do
      Err( _) -> empty(500)
      Ok( Accepted) -> empty(202)
      Ok( Duplicate) -> empty(200)
      Ok( MailboxFull) -> empty(429)
      Ok( MailboxRevoked) -> empty(410)
      Ok( RateLimited) -> empty(429)
      Ok( ExpiryRejected) -> empty(400)
    end
  end
end

pub fn submit_sealed_request(pool :: PoolHandle, body :: Bytes, private_seed :: Bytes) -> BinaryResult do
  case decode_sealed_delivery(body) do
    Err( _) -> empty(400)
    Ok( sealed) -> case open_delivery(sealed, private_seed) do
      Err( _) -> empty(400)
      Ok( outer) -> submit_request(pool, outer)
    end
  end
end

fn submit_sealed_with_key(pool :: PoolHandle, body :: Bytes, private_key :: borrow X25519PrivateKey) -> BinaryResult do
  case decode_sealed_delivery(body) do
    Err( _) -> empty(400)
    Ok( sealed) -> case open_delivery_with_key(sealed, private_key) do
      Err( _) -> empty(400)
      Ok( outer) -> submit_request(pool, outer)
    end
  end
end

pub fn submit_configured_sealed_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult ! String do
  let private_key = delivery_private_key() ?
  Ok(submit_sealed_with_key(pool, body, private_key))
end

# Mailbox reads and acknowledgements answer 403 for every authorization failure
# (unknown or revoked mailbox, stale timestamp, wrong key) so that the response
# does not disclose which mailboxes exist.

pub fn fetch_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_mailbox_fetch(body) do
    Err( _) -> empty(400)
    Ok( request) -> case authorize_mailbox_fetch(pool, request) do
      Err( _) -> empty(500)
      Ok( None) -> empty(403)
      Ok( Some( owner)) -> case fetch_mailbox(pool, owner, request.after_sequence) do
        Err( _) -> empty(500)
        Ok( deliveries) -> case encode_delivery_batch(deliveries) do
          Err( _) -> empty(500)
          Ok( encoded) -> response(200, encoded)
        end
      end
    end
  end
end

pub fn acknowledge_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_mailbox_ack(body) do
    Err( _) -> empty(400)
    Ok( ack) -> case authorize_mailbox_ack(pool, ack) do
      Err( _) -> empty(500)
      Ok( None) -> empty(403)
      Ok( Some( owner)) -> case acknowledge_mailbox(pool, owner, ack.envelope_ids) do
        Err( _) -> empty(500)
        Ok( _) -> empty(200)
      end
    end
  end
end

pub fn bind_push_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_push_bind(body) do
    Err( _) -> empty(400)
    Ok( request) -> case bind_push(pool, request) do
      Err( _) -> empty(500)
      Ok( PushAccepted) -> empty(201)
      Ok( PushUnauthorized) -> empty(403)
      Ok( PushStale) -> empty(409)
    end
  end
end

pub fn unbind_push_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_push_unbind(body) do
    Err( _) -> empty(400)
    Ok( request) -> case unbind_push(pool, request) do
      Err( _) -> empty(500)
      Ok( PushAccepted) -> empty(200)
      Ok( PushUnauthorized) -> empty(403)
      Ok( PushStale) -> empty(409)
    end
  end
end

pub fn publish_prekeys_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_prekey_publish(body) do
    Err( _) -> empty(400)
    Ok( request) -> case publish_prekeys(pool, request) do
      Err( _) -> empty(500)
      Ok( PrekeysPublished( active_ids)) -> case encode_prekey_publish_response(PrekeyPublishResponse {
        account_id : request.account_id,
        device_id : request.device_id,
        active_ids : active_ids
      }) do
        Err( _) -> empty(500)
        Ok( encoded) -> response(201, encoded)
      end
      Ok( PrekeysUnchanged( active_ids)) -> case encode_prekey_publish_response(PrekeyPublishResponse {
        account_id : request.account_id,
        device_id : request.device_id,
        active_ids : active_ids
      }) do
        Err( _) -> empty(500)
        Ok( encoded) -> response(200, encoded)
      end
      Ok( PrekeysUnauthorized) -> empty(403)
      Ok( PrekeysConflict) -> empty(409)
      Ok( PrekeyPoolFull( active_ids)) -> case encode_prekey_publish_response(PrekeyPublishResponse {
        account_id : request.account_id,
        device_id : request.device_id,
        active_ids : active_ids
      }) do
        Err( _) -> empty(500)
        Ok( encoded) -> response(429, encoded)
      end
    end
  end
end

pub fn claim_prekey_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_prekey_claim(body) do
    Err( _) -> empty(400)
    Ok( request) -> case claim_prekey(pool, request) do
      Err( _) -> empty(500)
      Ok( PrekeyClaimMissing) -> empty(404)
      Ok( PrekeyClaimExhausted) -> empty(409)
      Ok( PrekeyClaimed( bundle)) -> case encode_prekey_bundle(bundle) do
        Err( _) -> empty(500)
        Ok( encoded) -> response(200, encoded)
      end
    end
  end
end
