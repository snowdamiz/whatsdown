##! Inactive fixed prekey gateway. The private HTTP adapter supplies trusted configuration.
from Api.Binary import (
  BinaryResult,
  Admission,
  admit_request,
  admission_failure,
  claim_prekey_request,
  resolve_log_availability,
  resolve_devices_request_for,
  consistency_request_for,
  legacy_bridge_request
)
from Ohttp.BinaryHttp import decode_request, encode_response
from Ohttp.Policy import prekey_claim_request, admit_prekey_claim_request, prekey_claim_response
from Ohttp.Types import BhttpFraming, default_bhttp_limits
from Ohttp.LookupPolicy import OhttpLookupOperation, admit_lookup_request, lookup_response

fn empty(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

fn request_crypto_failure(error :: CryptoError) -> BinaryResult do
  case error do
    InvalidLength(_, _) -> empty(400)
    InvalidKey -> empty(400)
    InvalidPublicKey -> empty(400)
    AuthenticationFailed -> empty(400)
    UnsupportedOperation -> empty(400)
    _ -> empty(503)
  end
end

fn execute_inner(pool :: PoolHandle,
  plaintext :: Bytes,
  core_origin :: String,
  development :: Bool,
  now :: U64,
  difficulty :: Int) -> BinaryResult do
  let limits = default_bhttp_limits()
  let request = case decode_request(plaintext, %{limits | content_bytes: 120}) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  let stamped = case admit_prekey_claim_request(request, core_origin, development) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case admit_request(pool, "mesh-msg/v1/work/prekey-claim", stamped, 100, now, difficulty) do
    Ok(Admitted(payload)) -> claim_prekey_request(pool, payload)
    refused -> admission_failure(refused)
  end
end

fn execute_read_inner(pool :: PoolHandle,
  plaintext :: Bytes,
  core_origin :: String,
  development :: Bool,
  now :: U64,
  difficulty :: Int) -> (BinaryResult, Option<OhttpLookupOperation>) do
  let request = case decode_request(plaintext, %{default_bhttp_limits() | content_bytes: 120}) do
    Err(_) -> return (empty(400), None)
    Ok(value) -> value
  end
  case admit_prekey_claim_request(request, core_origin, development) do
    Ok(_) -> return (execute_inner(pool, plaintext, core_origin, development, now, difficulty),
      None)
    Err(_) -> nil
  end
  let query = case admit_lookup_request(request, core_origin, development) do
    Err(_) -> return (empty(400), None)
    Ok(value) -> value
  end
  let result = case query.operation do
    OhttpDirectoryLookup(version) -> do
      # Preserve the public endpoint's cutover check BEFORE spending work.
      let availability = resolve_log_availability(pool, version)
      if availability.status != 204 do
        availability
      else
        case admit_request(pool, "mesh-msg/v1/work/resolve", query.body, 76, now, difficulty) do
          Ok(Admitted(payload)) -> resolve_devices_request_for(pool, version, payload)
          refused -> admission_failure(refused)
        end
      end
    end
    OhttpConsistencyLookup(version) -> consistency_request_for(pool, version, query.body)
    OhttpLegacyBridgeLookup -> legacy_bridge_request(pool, query.body)
  end
  (result, Some(query.operation))
end

# The old prekey-only authority stays narrow. Only the separately selected read
# gateway grants the fixed five lookup paths, in addition to the same prekey read.
pub fn execute_prekey_ohttp(pool :: PoolHandle,
  private_key :: borrow X25519PrivateKey,
  key_id :: Int,
  wire :: Bytes,
  core_origin :: String,
  development :: Bool,
  now :: U64,
  difficulty :: Int) -> BinaryResult do
  execute_ohttp(pool, private_key, key_id, wire, core_origin, development, now, difficulty, false)
end

pub fn execute_read_ohttp(pool :: PoolHandle,
  private_key :: borrow X25519PrivateKey,
  key_id :: Int,
  wire :: Bytes,
  core_origin :: String,
  development :: Bool,
  now :: U64,
  difficulty :: Int) -> BinaryResult do
  execute_ohttp(pool, private_key, key_id, wire, core_origin, development, now, difficulty, true)
end

fn execute_ohttp(pool :: PoolHandle,
  private_key :: borrow X25519PrivateKey,
  key_id :: Int,
  wire :: Bytes,
  core_origin :: String,
  development :: Bool,
  now :: U64,
  difficulty :: Int,
  reads :: Bool) -> BinaryResult do
  if key_id < 0 || key_id > 255 || difficulty < 1 || difficulty > 24 do
    return empty(503)
  end
  # Validate only the configured origin here. A dummy empty payload performs no
  # admission and is never dispatched. Request authority comes from this config.
  case prekey_claim_request(core_origin, development, Bytes.empty()) do
    Err(_) -> return empty(503)
    Ok(_) -> nil
  end
  let opening = case Ohttp.decapsulate_request(private_key, key_id, wire) do
    Err(error) -> return request_crypto_failure(error)
    Ok(value) -> value
  end
  let (result, operation) = if reads do
    execute_read_inner(pool, opening.plaintext, core_origin, development, now, difficulty)
  else
    (execute_inner(pool, opening.plaintext, core_origin, development, now, difficulty), None)
  end
  let wrapped = case operation do
    None -> prekey_claim_response(result.status, result.body)
    Some(value) -> lookup_response(value, result.status, result.body)
  end
  let response = case wrapped do
    Err(_) -> return empty(500)
    Ok(value) -> value
  end
  let encoded = case encode_response(response, BhttpKnownLength, default_bhttp_limits()) do
    Err(_) -> return empty(500)
    Ok(value) -> value
  end
  case Ohttp.encapsulate_response(opening.response_context, encoded) do
    Err(_) -> empty(503)
    Ok(ciphertext) -> BinaryResult { status: 200, body: ciphertext }
  end
end
