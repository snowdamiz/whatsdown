from Storage.Transparency import transparency_username
from Protocol.DirectoryWire import (
  decode_account_deletion,
  decode_device_departure,
  decode_device_revocation,
  decode_directory_entry
)
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.MailboxWire import decode_mailbox_ack, decode_mailbox_fetch, encode_delivery_batch
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import MailboxAck, MailboxFetch
from Prekeys.Pool import (
  PrekeyPublishResponse,
  decode_prekey_claim,
  decode_prekey_publish,
  encode_prekey_publish_response
)
from Privacy.Edge import (
  RequestStamp,
  decode_sealed_delivery,
  decode_stamped_request,
  open_delivery,
  open_delivery_with_key,
  request_stamp_key,
  verify_request_stamp
)
from Push.Binding import decode_push_bind, decode_push_unbind
from Storage.Delivery import (
  DeliveryInsert,
  acknowledge_mailbox,
  enqueue_envelope,
  enqueue_held_envelope,
  fetch_mailbox
)
from Credits.CreditFrames import credits_decode_held
from Storage.MailboxAuth import authorize_mailbox_ack, authorize_mailbox_fetch
from Runtime.MailboxStream import wake_mailbox
from Storage.Devices import (
  AccountRemoval,
  DeviceWrite,
  delete_account,
  leave_device,
  register_device,
  resolve_devices,
  revoke_device
)
from Storage.Push import PushWrite, bind_push, unbind_push
from Storage.RateLimit import allow_request
from Storage.Prekeys import PrekeyClaimWrite, PrekeyPublishWrite, claim_prekey, publish_prekeys
from Storage.Transparency import (
  configured_evidence_for_username,
  configured_evidence_v2_for_username,
  consistency_from,
  create_configured_checkpoint,
  latest_checkpoint,
  store_witness,
  transparency_consistency_v2,
  validate_signing_config,
  witnesses_for_checkpoint
)
from Storage.TransparencyPruning import transparency_pruning_cap, transparency_pruning_mode
from Storage.TransparencyWitnesses import AttestationWrite, transparency_configured_registry
from Transparency.Codec import transparency_frame_version
from Transparency.CompactWire import (
  transparency_decode_cosignatures,
  transparency_decode_evidence_v2,
  transparency_decode_lookup_v2,
  transparency_decode_tree_query_v2,
  transparency_encode_consistency_v2,
  transparency_encode_evidence_v2,
  transparency_encode_inclusion_v2
)
from Transparency.Merkle import WitnessAttestation
from Transparency.Wire import (
  decode_transparency_evidence,
  decode_transparency_lookup,
  decode_transparency_tree_query,
  decode_witnesses,
  encode_checkpoint,
  encode_consistency_proof,
  encode_inclusion_proof,
  encode_transparency_evidence,
  encode_witnesses
)

pub struct BinaryResult do
  status :: Int
  body :: Bytes
end

fn response(status :: Int, body :: Bytes) -> BinaryResult do
  BinaryResult { status: status, body: body }
end

fn empty(status :: Int) -> BinaryResult do
  response(status, Bytes.empty())
end

pub type Admission do
  Admitted(payload :: Bytes)
  AdmissionMalformed
  AdmissionRefused
end

pub type CheckedRequest do
  RequestPaid(payload :: Bytes, spent_key :: Bytes)
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
  difficulty :: Int) -> CheckedRequest!String do
  case decode_stamped_request(body, maximum_payload) do
    Err(_) -> Ok(RequestMalformed)
    Ok((stamp, payload)) -> if verify_request_stamp(label,
      payload,
      stamp,
      now,
      U64.parse("300000")?,
      difficulty)? do
      Ok(RequestPaid(payload, request_stamp_key(label, payload, stamp)?))
    else
      Ok(RequestUnpaid)
    end
  end
end

# A spent stamp is remembered for longer than it stays valid, so it admits one
# request only.

pub fn spend_request(pool :: PoolHandle,
  payload :: Bytes,
  spent_key :: Bytes) -> Admission!String do
  if allow_request(pool, spent_key, 1, 600)? do
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
  difficulty :: Int) -> Admission!String do
  case check_request(label, body, maximum_payload, now, difficulty)? do
    RequestMalformed -> Ok(AdmissionMalformed)
    RequestUnpaid -> Ok(AdmissionRefused)
    RequestPaid(payload, spent_key) -> spend_request(pool, payload, spent_key)
  end
end

# 400 for a malformed frame and 429 for missing, stale or spent work, matching
# the privacy edge. Either way the caller mints a fresh stamp and retries.

pub fn admission_failure(result :: Result<Admission, String>) -> BinaryResult do
  case result do
    Err(_) -> empty(500)
    Ok(AdmissionMalformed) -> empty(400)
    Ok(_) -> empty(429)
  end
end

fn device_write(result :: Result<DeviceWrite, String>) -> BinaryResult do
  case result do
    Err(_) -> empty(500)
    Ok(DeviceAccepted) -> empty(201)
    Ok(DeviceUnchanged) -> empty(200)
    Ok(DeviceConflict) -> empty(409)
    Ok(DeviceInvalid) -> empty(400)
    Ok(DeviceRemoved(statement)) -> response(410, statement)
    Ok(DeviceRetired(_)) -> empty(500)
  end
end

pub fn register_device_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_directory_entry(body) do
    Err(_) -> empty(400)
    Ok(entry) -> device_write(register_device(pool, entry))
  end
end

# A version 1 lookup gets version 1 evidence (full lists), which only exists
# while the log fits it: above that it answers 426, and the client must update.
# A version 2 lookup gets compact evidence.

pub fn resolve_devices_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  let lookup = case transparency_frame_version(body) do
    Ok(2) -> transparency_decode_lookup_v2(body)
    _ -> decode_transparency_lookup(body)
  end
  case lookup do
    Err(_) -> empty(400)
    Ok(value) -> case transparency_username(pool, value.username) do
      Err(_) -> empty(500)
      Ok(None) -> empty(404)
      Ok(Some(username)) -> resolved_device_evidence(pool,
        username,
        value.previous_tree_size,
        transparency_frame_version(body) == Ok(2))
    end
  end
end

fn evidence_failure(error :: String) -> BinaryResult do
  if String.contains(error, "transparency_v1_ceiling") do
    empty(426)
  else if String.contains(error, "invalid consistency size") do
    empty(400)
  else
    empty(500)
  end
end

fn encoded_evidence(pool :: PoolHandle,
  username :: String,
  previous_tree_size :: Int,
  compact :: Bool) -> Bytes!String do
  if compact do
    transparency_encode_evidence_v2(configured_evidence_v2_for_username(pool,
      username,
      previous_tree_size)?)
  else
    encode_transparency_evidence(configured_evidence_for_username(pool,
      username,
      previous_tree_size)?)
  end
end

fn resolved_device_evidence(pool :: PoolHandle,
  username :: String,
  previous_tree_size :: Int,
  compact :: Bool) -> BinaryResult do
  case resolve_devices(pool, username) do
    Err(_) -> empty(500)
    Ok(None) -> empty(404)
    Ok(Some(_)) -> case encoded_evidence(pool, username, previous_tree_size, compact) do
      Err(error) -> evidence_failure(error)
      Ok(encoded) -> response(200, encoded)
    end
  end
end

fn delivery_private_key() -> X25519PrivateKey!String do
  let material = case Env.get_secret_hex("MESSENGER_DELIVERY_SEALING_SEED_HEX") do
    Err(_) -> Err("invalid delivery configuration")
    Ok(value)
  end?
  case Crypto.x25519_from_secret(material) do
    Err(_) -> Err("invalid delivery configuration")
    Ok(pair) -> Ok(pair.private_key)
  end
end

## The log's C2SP origin (and the key name its notes are signed under):
## MESSENGER_TRANSPARENCY_LOG_ORIGIN, by default morseapp.io/log/main.

pub fn transparency_log_origin() -> String!String do
  let origin = Env.get("MESSENGER_TRANSPARENCY_LOG_ORIGIN", "morseapp.io/log/main")
  let bytes = Bytes.to_list(Bytes.from_utf8(origin))
  if List.length(bytes) > 0
    && List.length(bytes) <= 255
    && List.all(bytes, fn byte -> byte > 32 && byte < 127 && byte != 43 end) do
    Ok(origin)
  else
    Err("invalid MESSENGER_TRANSPARENCY_LOG_ORIGIN")
  end
end

pub fn validate_transparency_config() -> Result<(), String> do
  validate_signing_config()?
  transparency_configured_registry()?
  transparency_log_origin()?
  transparency_pruning_mode()?
  transparency_pruning_cap()?
  Ok(nil)
end

pub fn validate_delivery_config() -> Result<(), String> do
  let _private_key = delivery_private_key()?
  Ok(nil)
end

pub fn attestation_status(write :: AttestationWrite) -> Int do
  case write do
    AttestationStored -> 201
    AttestationDuplicate -> 200
    AttestationConflict -> 409
  end
end

# Exactly one Morse statement, in a KTW v1 frame or as the one kind-1 entry of
# a KTW v2 frame.

fn one_statement(body :: Bytes) -> WitnessAttestation!String do
  case transparency_frame_version(body) do
    Ok(2) -> case transparency_decode_cosignatures(body)? do
      [value] -> if value.kind == 1 do
        Ok(WitnessAttestation {
          witness_id: value.witness_id,
          checkpoint_hash: value.checkpoint_hash,
          signature: value.signature
        })
      else
        Err("not a Morse statement")
      end
      _ -> Err("one attestation per request")
    end
    _ -> case decode_witnesses(body)? do
      [value] -> Ok(value)
      _ -> Err("one attestation per request")
    end
  end
end

## 201 stored, 200 already stored, 409 a different attestation is stored for
## this witness, 400 anything that does not verify on the current checkpoint
## under a non-retired registry entry.

pub fn submit_witness_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case one_statement(body) do
    Err(_) -> empty(400)
    Ok(value) -> case store_witness(pool, value) do
      Err(_) -> empty(400)
      Ok(write) -> empty(attestation_status(write))
    end
  end
end

pub fn checkpoint_request(pool :: PoolHandle) -> BinaryResult do
  case latest_checkpoint(pool) do
    Err(_) -> empty(500)
    Ok(None) -> empty(404)
    Ok(Some(checkpoint)) -> case encode_checkpoint(checkpoint) do
      Err(_) -> empty(500)
      Ok(encoded) -> response(200, encoded)
    end
  end
end

pub fn witnesses_request(pool :: PoolHandle) -> BinaryResult do
  case latest_checkpoint(pool) do
    Err(_) -> empty(500)
    Ok(None) -> empty(404)
    Ok(Some(checkpoint)) -> case witnesses_for_checkpoint(pool, checkpoint.sequence) do
      Err(_) -> empty(500)
      Ok(values) -> case encode_witnesses(values) do
        Err(_) -> empty(500)
        Ok(encoded) -> response(200, encoded)
      end
    end
  end
end

fn inclusion_of(body :: Bytes, evidence :: Bytes) -> Bytes!String do
  if transparency_frame_version(body) == Ok(2) do
    transparency_encode_inclusion_v2(transparency_decode_evidence_v2(evidence)?.inclusion)
  else
    encode_inclusion_proof(decode_transparency_evidence(evidence)?.inclusion)
  end
end

pub fn inclusion_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  let evidence = resolve_devices_request(pool, body)
  if evidence.status != 200 do
    evidence
  else
    case inclusion_of(body, evidence.body) do
      Err(_) -> empty(500)
      Ok(encoded) -> response(200, encoded)
    end
  end
end

fn consistency_v1_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_transparency_tree_query(body) do
    Err(_) -> empty(400)
    Ok(query) -> case create_configured_checkpoint(pool) do
      Err(_) -> empty(500)
      Ok(_) -> case consistency_from(pool, query.previous_tree_size) do
        Err(error) -> if String.contains(error, "transparency_v1_ceiling") do
          empty(426)
        else
          empty(400)
        end
        Ok(proof) -> case encode_consistency_proof(proof) do
          Err(_) -> empty(500)
          Ok(encoded) -> response(200, encoded)
        end
      end
    end
  end
end

fn compact_consistency(pool :: PoolHandle,
  tree :: Int,
  old_size :: Int,
  new_size :: Int) -> BinaryResult do
  case transparency_consistency_v2(pool, tree, old_size, new_size) do
    Err(_) -> empty(400)
    Ok(proof) -> case transparency_encode_consistency_v2(proof) do
      Err(_) -> empty(500)
      Ok(encoded) -> response(200, encoded)
    end
  end
end

# new_size 0 asks for the current checkpoint, refreshed as a lookup would.

fn consistency_v2_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case transparency_decode_tree_query_v2(body) do
    Err(_) -> empty(400)
    Ok(query) -> if query.new_size != 0 do
      compact_consistency(pool, query.tree, query.old_size, query.new_size)
    else
      case create_configured_checkpoint(pool) do
        Err(_) -> empty(500)
        Ok(checkpoint) -> case U64.to_int(checkpoint.tree_size) do
          Err(_) -> empty(500)
          Ok(size) -> compact_consistency(pool, query.tree, query.old_size, size)
        end
      end
    end
  end
end

## KTS v1 gets KTC v1 (full list, 426 once the log outgrows it); KTS v2 gets a
## compact KTC v2 in the tree it names.

pub fn consistency_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  if transparency_frame_version(body) == Ok(2) do
    consistency_v2_request(pool, body)
  else
    consistency_v1_request(pool, body)
  end
end

pub fn revoke_device_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_device_revocation(body) do
    Err(_) -> empty(400)
    Ok(revocation) -> case revoke_device(pool, revocation) do
      Err(_) -> empty(500)
      Ok(DeviceAccepted) -> empty(200)
      Ok(DeviceUnchanged) -> empty(200)
      Ok(DeviceConflict) -> empty(409)
      Ok(DeviceInvalid) -> empty(400)
      Ok(DeviceRemoved(_)) -> empty(410)
      Ok(DeviceRetired(mailbox)) -> do
        # The removed device fetches at once, fails, reconnects, and is told why.
        wake_mailbox(mailbox)
        empty(200)
      end
    end
  end
end

# 204 once the account is gone: deleted now, earlier, or never registered, so a
# retry after a lost answer succeeds. A client erases its copy only on 204; the
# 404 of a directory without this route must leave the account whole.

pub fn delete_account_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_account_deletion(body) do
    Err(_) -> empty(400)
    Ok(deletion) -> case delete_account(pool, deletion) do
      Err(_) -> empty(500)
      Ok(AccountRemoved(mailboxes)) -> do
        # Its other devices fetch at once, fail, reconnect, and are told why.
        List.map(mailboxes, fn(mailbox) -> wake_mailbox(mailbox) end)
        empty(204)
      end
      Ok(AccountRemovalRefused) -> empty(403)
    end
  end
end

# 204 once the device is out of its account, also when it or the account
# already was. 409 for the last device, which deletes the account instead.

pub fn leave_device_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_device_departure(body) do
    Err(_) -> empty(400)
    Ok(departure) -> case leave_device(pool, departure) do
      Err(_) -> empty(500)
      Ok(DeviceInvalid) -> empty(403)
      Ok(DeviceConflict) -> empty(409)
      Ok(_) -> empty(204)
    end
  end
end

fn delivery_status(result :: Result<DeliveryInsert, String>) -> BinaryResult do
  case result do
    Err(error) -> if String.contains(error, "credit_hold_missing") do
      empty(409)
    else
      empty(500)
    end
    Ok(Accepted) -> empty(202)
    Ok(Duplicate) -> empty(200)
    Ok(MailboxFull) -> empty(429)
    Ok(MailboxRevoked) -> empty(410)
    Ok(RateLimited) -> empty(429)
    Ok(ExpiryRejected) -> empty(400)
    Ok(PostageRequired(policy)) -> response(402, policy)
  end
end

pub fn submit_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_outer_envelope(body) do
    Err(_) -> empty(400)
    Ok(envelope) -> delivery_status(enqueue_envelope(pool, envelope))
  end
end

# An envelope the edge redeemed credits for arrives as HLD: the hold it took,
# then the sealed delivery. 409 when the hold is not there to take.

fn submit_opened(pool :: PoolHandle, outer :: Bytes, hold :: Option<Bytes>) -> BinaryResult do
  case hold do
    None -> submit_request(pool, outer)
    Some(redemption_id) -> case decode_outer_envelope(outer) do
      Err(_) -> empty(400)
      Ok(envelope) -> delivery_status(enqueue_held_envelope(pool, envelope, redemption_id))
    end
  end
end

pub fn submit_sealed_request(pool :: PoolHandle,
  body :: Bytes,
  private_seed :: Bytes) -> BinaryResult do
  case decode_sealed_delivery(body) do
    Err(_) -> empty(400)
    Ok(sealed) -> case open_delivery(sealed, private_seed) do
      Err(_) -> empty(400)
      Ok(outer) -> submit_request(pool, outer)
    end
  end
end

fn submit_sealed_with_key(pool :: PoolHandle,
  body :: Bytes,
  private_key :: borrow X25519PrivateKey) -> BinaryResult do
  let (hold, sealed_bytes) = case credits_decode_held(body) do
    Err(_) -> return empty(400)
    Ok(pair) -> pair
  end
  case decode_sealed_delivery(sealed_bytes) do
    Err(_) -> empty(400)
    Ok(sealed) -> case open_delivery_with_key(sealed, private_key) do
      Err(_) -> empty(400)
      Ok(outer) -> submit_opened(pool, outer, hold)
    end
  end
end

pub fn submit_configured_sealed_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult!String do
  let private_key = delivery_private_key()?
  Ok(submit_sealed_with_key(pool, body, private_key))
end

# Mailbox reads and acknowledgements answer 403 for every authorization failure
# (unknown or revoked mailbox, stale timestamp, wrong key) so that the response
# does not disclose which mailboxes exist.

pub fn fetch_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_mailbox_fetch(body) do
    Err(_) -> empty(400)
    Ok(request) -> case authorize_mailbox_fetch(pool, request) do
      Err(_) -> empty(500)
      Ok(None) -> empty(403)
      Ok(Some(owner)) -> case fetch_mailbox(pool, owner, request.after_sequence) do
        Err(_) -> empty(500)
        Ok(deliveries) -> case encode_delivery_batch(deliveries) do
          Err(_) -> empty(500)
          Ok(encoded) -> response(200, encoded)
        end
      end
    end
  end
end

pub fn acknowledge_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_mailbox_ack(body) do
    Err(_) -> empty(400)
    Ok(ack) -> case authorize_mailbox_ack(pool, ack) do
      Err(_) -> empty(500)
      Ok(None) -> empty(403)
      Ok(Some(owner)) -> case acknowledge_mailbox(pool, owner, ack.envelope_ids) do
        Err(_) -> empty(500)
        Ok(_) -> empty(200)
      end
    end
  end
end

pub fn bind_push_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_push_bind(body) do
    Err(_) -> empty(400)
    Ok(request) -> case bind_push(pool, request) do
      Err(_) -> empty(500)
      Ok(PushAccepted) -> empty(201)
      Ok(PushUnauthorized) -> empty(403)
      Ok(PushStale) -> empty(409)
    end
  end
end

pub fn unbind_push_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_push_unbind(body) do
    Err(_) -> empty(400)
    Ok(request) -> case unbind_push(pool, request) do
      Err(_) -> empty(500)
      Ok(PushAccepted) -> empty(200)
      Ok(PushUnauthorized) -> empty(403)
      Ok(PushStale) -> empty(409)
    end
  end
end

pub fn publish_prekeys_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_prekey_publish(body) do
    Err(_) -> empty(400)
    Ok(request) -> case publish_prekeys(pool, request) do
      Err(_) -> empty(500)
      Ok(PrekeysPublished(active_ids)) -> case encode_prekey_publish_response(PrekeyPublishResponse {
        account_id: request.account_id,
        device_id: request.device_id,
        active_ids: active_ids
      }) do
        Err(_) -> empty(500)
        Ok(encoded) -> response(201, encoded)
      end
      Ok(PrekeysUnchanged(active_ids)) -> case encode_prekey_publish_response(PrekeyPublishResponse {
        account_id: request.account_id,
        device_id: request.device_id,
        active_ids: active_ids
      }) do
        Err(_) -> empty(500)
        Ok(encoded) -> response(200, encoded)
      end
      Ok(PrekeysUnauthorized) -> empty(403)
      Ok(PrekeysConflict) -> empty(409)
      Ok(PrekeyPoolFull(active_ids)) -> case encode_prekey_publish_response(PrekeyPublishResponse {
        account_id: request.account_id,
        device_id: request.device_id,
        active_ids: active_ids
      }) do
        Err(_) -> empty(500)
        Ok(encoded) -> response(429, encoded)
      end
    end
  end
end

pub fn claim_prekey_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case decode_prekey_claim(body) do
    Err(_) -> empty(400)
    Ok(request) -> case claim_prekey(pool, request) do
      Err(_) -> empty(500)
      Ok(PrekeyClaimMissing) -> empty(404)
      Ok(PrekeyClaimExhausted) -> empty(409)
      Ok(PrekeyClaimed(bundle)) -> case encode_prekey_bundle(bundle) do
        Err(_) -> empty(500)
        Ok(encoded) -> response(200, encoded)
      end
    end
  end
end
