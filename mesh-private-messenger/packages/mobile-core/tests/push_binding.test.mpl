import File
from MobileCore import create_account_export, directory_entry_export, expo_registration_body_for_test, install_legacy_disabled_push_state_for_test, install_legacy_enabled_push_state_for_test, install_legacy_pending_unbind_push_state_for_test, push_action_complete_with_test_config, push_action_export, push_bind_prepare_with_test_config, push_intent_export, push_status_export, push_unbind_prepare_export, push_update_commit_export
from Protocol.V1 import DeviceCredential, DirectoryEntry, PrekeyBundle, decode_device_credential, decode_directory_entry, decode_prekey_bundle
from Push.Binding import PushBindRequest, PushUnbindRequest, decode_push_bind, decode_push_unbind, push_bind_signing_bytes, push_unbind_signing_bytes
from Push.Token import open_provider_token
from Tests.Support import append, database_path, repeated, vector

fn encode_vectors(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_vectors(values, index + 1, append(output, vector(List.get(values, index)) ?) ?)
  end
end

fn request(values :: List < Bytes >) -> Bytes ! String do
  encode_vectors(values, 0, Bytes.empty())
end

fn commit_push_wire_for_test(path :: String, wire :: Bytes) -> Bytes ! String do
  push_update_commit_export(request([Bytes.from_utf8(path), wire]) ?)
end

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("test byte encoding failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn raw_push_frame(platform :: Int, development :: Int, app_id :: Bytes, device_token :: Bytes) -> Bytes ! String do
  let header = case Bytes.from_list([1, platform, development]) do
    Err( _) -> Err("test byte encoding failed")
    Ok( value) -> Ok(value)
  end ?
  append(append(header, vector(app_id) ?) ?, vector(device_token) ?)
end

fn push_config_frame(project_id :: Bytes, broker_public_key :: Bytes) -> Bytes ! String do
  append(append(append(Bytes.from_utf8("1\n"), project_id) ?, Bytes.from_utf8("\n")) ?,
  Bytes.from_utf8(Bytes.to_hex(broker_public_key)))
end

fn install_push_config(project_id :: Bytes, broker_public_key :: Bytes) -> Bool ! String do
  Ok(Test.set_push_token(Bytes.from_utf8("expo/config/v1"),
  push_config_frame(project_id, broker_public_key) ?))
end

fn push_action_byte(action :: Bytes, index :: Int) -> Int ! String do
  case Bytes.get(action, index) do
    Err( _) -> Err("invalid push action fixture")
    Ok( value) -> Ok(value)
  end
end

fn push_action_kind(action :: Bytes) -> Int ! String do
  let magic = case Bytes.slice(action, 0, 4) do
    Err( _) -> Err("invalid push action fixture")
    Ok( value) -> Ok(value)
  end ?
  let expected = case Bytes.from_list([1, 80, 70, 65]) do
    Err( _) -> Err("invalid push action fixture")
    Ok( value) -> Ok(value)
  end ?
  if Bytes.length(action) < 18 || !Bytes.secure_equals(magic, expected) do
    Err("invalid push action fixture")
  else
    push_action_byte(action, 4)
  end
end

fn push_action_payload(action :: Bytes) -> Bytes ! String do
  if Bytes.length(action) < 18 do
    Err("invalid push action fixture")
  else
    case Bytes.slice(action, 18, Bytes.length(action) - 18) do
      Err( _) -> Err("invalid push action fixture")
      Ok( value) -> Ok(value)
    end
  end
end

fn push_action_epoch(action :: Bytes) -> U64 ! String do
  if Bytes.length(action) < 18 do
    Err("invalid push action fixture")
  else
    case Bytes.read_u64_be(action, 6) do
      Err( _) -> Err("invalid push action fixture")
      Ok( value) -> Ok(value)
    end
  end
end

fn push_done_matches(action :: Bytes, status :: Int, surface_error :: Int) -> Bool ! String do
  Ok(Bytes.length(action) == 19 && (push_action_kind(action) ?) == 0 && (push_action_byte(action, 5) ?) == surface_error && (push_action_byte(action,
  18) ?) == status)
end

fn complete_push_action_for_test(path :: String,
action :: Bytes,
outcome :: Int,
endpoint :: String) -> Bytes ! String do
  push_action_complete_with_test_config(request([Bytes.from_utf8(path), action, byte(outcome) ?]) ?,
  endpoint)
end

fn tamper_last_byte(input :: Bytes) -> Bytes ! String do
  let length = Bytes.length(input)
  if length == 0 do
    Err("empty push action fixture")
  else
    let last = Bytes.get(input, length - 1) ?
    let replacement = if last == 0 do
      1
    else
      0
    end
    append(Bytes.slice(input, 0, length - 1) ?, byte(replacement) ?)
  end
end

fn seed(value :: Int) -> Bytes ! String do
  case Bytes.repeat(value, 32) do
    Err( _) -> Err("seed allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn signature_valid(public_key :: Bytes, signed :: Bytes, signature :: Bytes) -> Bool ! String do
  case Crypto.verify(SigningPublicKey { bytes : public_key },
  signed,
  Signature { bytes : signature }) do
    Err( _) -> Ok(false)
    Ok( value) -> Ok(value)
  end
end

fn valid_bind_signature(value :: PushBindRequest, public_key :: Bytes) -> Bool ! String do
  signature_valid(public_key, push_bind_signing_bytes(value) ?, value.signature)
end

fn valid_unbind_signature(value :: PushUnbindRequest, public_key :: Bytes) -> Bool ! String do
  signature_valid(public_key, push_unbind_signing_bytes(value) ?, value.signature)
end

fn directory_entry(input :: Bytes) -> DirectoryEntry ! String do
  case decode_directory_entry(input) do
    Err( _) -> Err("directory entry decode failed")
    Ok( value) -> Ok(value)
  end
end

fn prekey_bundle(input :: Bytes) -> PrekeyBundle ! String do
  case decode_prekey_bundle(input) do
    Err( _) -> Err("prekey bundle decode failed")
    Ok( value) -> Ok(value)
  end
end

fn device_credential(input :: Bytes) -> DeviceCredential ! String do
  case decode_device_credential(input) do
    Err( _) -> Err("device credential decode failed")
    Ok( value) -> Ok(value)
  end
end

fn raw_token_absent(path :: String, token :: Bytes) -> Bool ! String do
  let database = Sqlite.open(path) ?
  let rows = Sqlite.query(database,
  "SELECT CAST(count(*) AS TEXT) AS value FROM encrypted_blobs WHERE instr(lower(hex(ciphertext)), ?) > 0",
  [Bytes.to_hex(token)]) ?
  Sqlite.close(database)
  Ok(List.length(rows) == 1 && Map.get(List.head(rows), "value") == "0")
end

fn request_string(root, name :: String) -> String ! String do
  ((root
    |> Json.object_get(name)) ?
    |> Json.as_string())
end

fn valid_expo_request_for_project(request :: Request,
path :: String,
expected_token :: String,
expected_project_id :: String) -> Bool ! String do
  let content_type = case Request.header(request, "Content-Type") do
    None -> case Request.header(request, "content-type") do
      None -> false
      Some( value) -> value == "application/json"
    end
    Some( value) -> value == "application/json"
  end
  let root = Json.parse(Request.body(request)) ?
  let development = ((root
    |> Json.object_get("development")) ?
    |> Json.as_bool()) ?
  let kind = request_string(root, "type") ?
  let device_id = request_string(root, "deviceId") ?
  let device_token = request_string(root, "deviceToken") ?
  Ok(Request.method(request) == "POST" && Request.path(request) == path && content_type && Regex.is_match(~r/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  device_id) && request_string(root, "appId") ? == "com.example.whatsdown" && request_string(root,
  "projectId") ? == expected_project_id && ((kind == "apns" && development) || (kind == "fcm" && !development)) && device_token == expected_token)
end

fn expo_response(request :: Request,
path :: String,
expected_token :: String,
status :: Int,
body :: String) -> Response do
  case valid_expo_request_for_project(request,
  path,
  expected_token,
  "01234567-89ab-cdef-0123-456789abcdef") do
    Err( _) -> HTTP.response(400, "{}")
    Ok( false) -> HTTP.response(400, "{}")
    Ok( true) -> HTTP.response(status, body)
  end
end

fn expo_first(request :: Request) -> Response do
  expo_response(request,
  "/--/api/v2/push/getExpoPushToken",
  "apns-device-token",
  200,
  "{\"data\":{\"expoPushToken\":\"ExponentPushToken[first-device-token]\"}}")
end

fn expo_status(request :: Request) -> Response do
  expo_response(request, "/status", "status-device-token", 503, "{}")
end

fn expo_malformed(request :: Request) -> Response do
  expo_response(request, "/malformed", "malformed-response-token", 200, "{\"data\":{}}")
end

fn expo_invalid(request :: Request) -> Response do
  expo_response(request,
  "/invalid",
  "invalid-provider-token",
  200,
  "{\"data\":{\"expoPushToken\":\"invalid-token\"}}")
end

fn expo_second(request :: Request) -> Response do
  expo_response(request,
  "/second",
  "fcm-device-token",
  200,
  "{\"data\":{\"expoPushToken\":\"ExponentPushToken[second-device-token]\"}}")
end

fn expo_rebound(request :: Request) -> Response do
  expo_response(request,
  "/rebound",
  "rebound-device-token",
  200,
  "{\"data\":{\"expoPushToken\":\"ExpoPushToken[rebound-device-token]\"}}")
end

fn expo_rotated(request :: Request) -> Response do
  case valid_expo_request_for_project(request,
  "/rotated",
  "rotated-device-token",
  "fedcba98-7654-3210-fedc-ba9876543210") do
    Err( _) -> HTTP.response(400, "{}")
    Ok( false) -> HTTP.response(400, "{}")
    Ok( true) -> HTTP.response(200,
    "{\"data\":{\"expoPushToken\":\"ExpoPushToken[rotated-device-token]\"}}")
  end
end

actor expo_registration_server() do
  HTTP.router()
    |> HTTP.on_post("/--/api/v2/push/getExpoPushToken", expo_first)
    |> HTTP.on_post("/status", expo_status)
    |> HTTP.on_post("/malformed", expo_malformed)
    |> HTTP.on_post("/invalid", expo_invalid)
    |> HTTP.on_post("/second", expo_second)
    |> HTTP.on_post("/rebound", expo_rebound)
    |> HTTP.on_post("/rotated", expo_rotated)
    |> HTTP.serve(18997)
end

fn durable_push_action_loop_proof(project_id :: Bytes,
app_id :: Bytes,
broker_public_key :: Bytes,
endpoint :: String) -> Bool ! String do
  let path = database_path("push-action-loop") ?
  let _ = create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8("push-actions")]) ?) ?
  let raw_token = Bytes.from_utf8("rebound-device-token")
  let raw_frame = raw_push_frame(1, 1, app_id, raw_token) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), raw_frame))
  assert(push_done_matches(push_intent_export(request([Bytes.from_utf8(path), byte(0) ?]) ?) ?,
  0,
  0) ?)
  case push_intent_export(request([Bytes.from_utf8(path), byte(1) ?, project_id, broker_public_key]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_push_intent")
  end
  case push_intent_export(request([Bytes.from_utf8(path), byte(0) ?, project_id]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_push_intent")
  end
  case push_intent_export(request([Bytes.from_utf8(path), byte(1) ?]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_configuration_required")
  end
  let valid_config_frame = push_config_frame(project_id, broker_public_key) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/config/v1"),
  append(Bytes.from_utf8("2"),
  Bytes.slice(valid_config_frame, 1, Bytes.length(valid_config_frame) - 1) ?) ?))
  case push_intent_export(request([Bytes.from_utf8(path), byte(1) ?]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_push_configuration")
  end
  assert(Test.set_push_token(Bytes.from_utf8("expo/config/v1"),
  push_config_frame(Bytes.from_utf8("01234567-89AB-cdef-0123-456789abcdef"), broker_public_key) ?))
  case push_intent_export(request([Bytes.from_utf8(path), byte(1) ?]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_push_project_id")
  end
  assert(Test.set_push_token(Bytes.from_utf8("expo/config/v1"),
  append(append(append(Bytes.from_utf8("1\n"), project_id) ?, Bytes.from_utf8("\n")) ?,
  Bytes.from_utf8("AB" <> String.slice(Bytes.to_hex(broker_public_key), 2, 64))) ?))
  case push_intent_export(request([Bytes.from_utf8(path), byte(1) ?]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_push_broker_public_key")
  end
  assert(Test.set_push_token(Bytes.from_utf8("expo/config/v1"),
  push_config_frame(project_id, repeated(0, 32) ?) ?))
  case push_intent_export(request([Bytes.from_utf8(path), byte(1) ?]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_push_broker_public_key")
  end
  assert(install_push_config(project_id, broker_public_key) ?)
  let permission_action = push_intent_export(request([Bytes.from_utf8(path), byte(1) ?]) ?) ?
  assert((push_action_kind(permission_action) ?) == 1)
  assert(Bytes.secure_equals(push_status_export(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("pending-bind")))
  let prime_action = complete_push_action_for_test(path, permission_action, 0, endpoint) ?
  assert((push_action_kind(prime_action) ?) == 2)
  assert(U64.compare(push_action_epoch(prime_action) ?, push_action_epoch(permission_action) ?) > 0)
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), raw_frame))
  assert(install_push_config(project_id, broker_public_key) ?)
  let bind_action = complete_push_action_for_test(path, prime_action, 0, endpoint) ?
  assert((push_action_kind(bind_action) ?) == 3)
  assert(U64.compare(push_action_epoch(bind_action) ?, push_action_epoch(prime_action) ?) > 0)
  let bind = decode_push_bind(push_action_payload(bind_action) ?) ?
  assert(install_push_config(project_id, broker_public_key) ?)
  let enabled = complete_push_action_for_test(path, bind_action, 0, endpoint) ?
  assert(push_done_matches(enabled, 1, 0) ?)
  assert(U64.compare(push_action_epoch(enabled) ?, push_action_epoch(bind_action) ?) > 0)
  assert(Bytes.secure_equals(push_status_export(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("enabled")))
  assert(install_push_config(project_id, broker_public_key) ?)
  let stale_prime = push_intent_export(request([Bytes.from_utf8(path), byte(0) ?]) ?) ?
  assert((push_action_kind(stale_prime) ?) == 2)
  assert(U64.compare(push_action_epoch(stale_prime) ?, push_action_epoch(enabled) ?) > 0)
  let clear_action = push_intent_export(request([Bytes.from_utf8(path), byte(2) ?]) ?) ?
  assert((push_action_kind(clear_action) ?) == 5)
  assert(U64.compare(push_action_epoch(clear_action) ?, push_action_epoch(stale_prime) ?) > 0)
  assert(Bytes.secure_equals(push_status_export(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("pending-unbind")))
  assert(Bytes.secure_equals(push_action_export(Bytes.from_utf8(path)) ?, clear_action))
  let unbind_after_failed_clear = complete_push_action_for_test(path, clear_action, 1, endpoint) ?
  assert((push_action_kind(unbind_after_failed_clear) ?) == 4)
  assert(U64.compare(push_action_epoch(unbind_after_failed_clear) ?,
  push_action_epoch(clear_action) ?) > 0)
  assert(Bytes.secure_equals(push_action_export(Bytes.from_utf8(path)) ?, unbind_after_failed_clear))
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), raw_frame))
  assert(Bytes.secure_equals(push_intent_export(request([Bytes.from_utf8(path), byte(0) ?]) ?) ?,
  unbind_after_failed_clear))
  assert(install_push_config(project_id, broker_public_key) ?)
  let enable_during_unbind = push_intent_export(request([Bytes.from_utf8(path), byte(1) ?]) ?) ?
  assert((push_action_kind(enable_during_unbind) ?) == 4)
  assert(U64.compare(push_action_epoch(enable_during_unbind) ?,
  push_action_epoch(unbind_after_failed_clear) ?) > 0)
  assert(Bytes.secure_equals(complete_push_action_for_test(path,
  unbind_after_failed_clear,
  0,
  endpoint) ?,
  enable_during_unbind))
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), raw_frame))
  let disable_during_unbind = push_intent_export(request([Bytes.from_utf8(path), byte(2) ?]) ?) ?
  assert((push_action_kind(disable_during_unbind) ?) == 4)
  assert(U64.compare(push_action_epoch(disable_during_unbind) ?,
  push_action_epoch(enable_during_unbind) ?) > 0)
  assert(Bytes.secure_equals(complete_push_action_for_test(path, enable_during_unbind, 0, endpoint) ?,
  disable_during_unbind))
  assert(Bytes.secure_equals(complete_push_action_for_test(path, stale_prime, 0, endpoint) ?,
  disable_during_unbind))
  let unbind = decode_push_unbind(push_action_payload(disable_during_unbind) ?) ?
  assert(U64.compare(unbind.revision, bind.revision) > 0)
  assert(Bytes.secure_equals(push_action_export(Bytes.from_utf8(path)) ?, disable_during_unbind))
  case complete_push_action_for_test(path, tamper_last_byte(disable_during_unbind) ?, 0, endpoint) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_action_mismatch")
  end
  let unbind_failed = complete_push_action_for_test(path, disable_during_unbind, 1, endpoint) ?
  assert(push_done_matches(unbind_failed, 3, 1) ?)
  assert(Bytes.secure_equals(push_action_export(Bytes.from_utf8(path)) ?, disable_during_unbind))
  assert(Bytes.secure_equals(push_intent_export(request([Bytes.from_utf8(path), byte(0) ?]) ?) ?,
  disable_during_unbind))
  let final_clear = complete_push_action_for_test(path, disable_during_unbind, 0, endpoint) ?
  assert((push_action_kind(final_clear) ?) == 5)
  assert(U64.compare(push_action_epoch(final_clear) ?, push_action_epoch(disable_during_unbind) ?) > 0)
  let final_clear_failed = complete_push_action_for_test(path, final_clear, 1, endpoint) ?
  assert(push_done_matches(final_clear_failed, 3, 1) ?)
  assert(Bytes.secure_equals(push_action_export(Bytes.from_utf8(path)) ?, final_clear))
  assert(Bytes.secure_equals(push_intent_export(request([Bytes.from_utf8(path), byte(0) ?]) ?) ?,
  final_clear))
  let disabled = complete_push_action_for_test(path, final_clear, 0, endpoint) ?
  assert(push_done_matches(disabled, 0, 0) ?)
  assert(U64.compare(push_action_epoch(disabled) ?, push_action_epoch(final_clear) ?) > 0)
  assert(Bytes.secure_equals(push_status_export(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("disabled")))
  assert(raw_token_absent(path, raw_token) ?)
  assert(raw_token_absent(path, Bytes.from_utf8("ExpoPushToken[rebound-device-token]")) ?)
  assert(install_legacy_disabled_push_state_for_test(path) ?)
  assert(Bytes.secure_equals(push_status_export(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("pending-unbind")))
  let migrated_clear = push_action_export(Bytes.from_utf8(path)) ?
  assert((push_action_kind(migrated_clear) ?) == 5)
  let migrated_disabled = complete_push_action_for_test(path, migrated_clear, 0, endpoint) ?
  assert(push_done_matches(migrated_disabled, 0, 0) ?)
  assert(install_legacy_pending_unbind_push_state_for_test(path) ?)
  let migrated_unbind_clear = push_action_export(Bytes.from_utf8(path)) ?
  assert((push_action_kind(migrated_unbind_clear) ?) == 5)
  let migrated_unbind = complete_push_action_for_test(path, migrated_unbind_clear, 0, endpoint) ?
  assert((push_action_kind(migrated_unbind) ?) == 4)
  let migrated_final_clear = complete_push_action_for_test(path, migrated_unbind, 0, endpoint) ?
  assert((push_action_kind(migrated_final_clear) ?) == 5)
  let migrated_pending_disabled = complete_push_action_for_test(path,
  migrated_final_clear,
  0,
  endpoint) ?
  assert(push_done_matches(migrated_pending_disabled, 0, 0) ?)
  File.delete(path) ?
  Ok(true)
end

fn rotated_push_config_proof(project_a :: Bytes,
project_b :: Bytes,
broker_a_public_key :: Bytes,
broker_a_seed :: Bytes,
broker_b_public_key :: Bytes,
broker_b_seed :: Bytes,
app_id :: Bytes,
endpoint_a :: String,
endpoint_b :: String) -> Bool ! String do
  let path = database_path("push-config-rotation") ?
  let _ = create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8("push-rotation")]) ?) ?
  assert(install_push_config(project_a, broker_a_public_key) ?)
  let permission_a = push_intent_export(request([Bytes.from_utf8(path), byte(1) ?]) ?) ?
  let prime_a = complete_push_action_for_test(path, permission_a, 0, endpoint_a) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"),
  raw_push_frame(1, 1, app_id, Bytes.from_utf8("rebound-device-token")) ?))
  assert(install_push_config(project_b, broker_b_public_key) ?)
  case complete_push_action_for_test(path, prime_a, 0, endpoint_a) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_configuration_changed")
  end
  assert(install_push_config(project_a, broker_a_public_key) ?)
  let bind_a_action = complete_push_action_for_test(path, prime_a, 0, endpoint_a) ?
  let bind_a = decode_push_bind(push_action_payload(bind_a_action) ?) ?
  assert(install_push_config(project_b, broker_b_public_key) ?)
  case complete_push_action_for_test(path, bind_a_action, 0, endpoint_b) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_configuration_changed")
  end
  assert(install_push_config(project_b, broker_b_public_key) ?)
  let clear = push_intent_export(request([Bytes.from_utf8(path), byte(1) ?]) ?) ?
  assert((push_action_kind(clear) ?) == 5)
  assert(U64.compare(push_action_epoch(clear) ?, push_action_epoch(bind_a_action) ?) > 0)
  assert(Bytes.secure_equals(complete_push_action_for_test(path, bind_a_action, 0, endpoint_b) ?,
  clear))
  let unbind_action = complete_push_action_for_test(path, clear, 0, endpoint_b) ?
  assert((push_action_kind(unbind_action) ?) == 4)
  let unbind = decode_push_unbind(push_action_payload(unbind_action) ?) ?
  assert(U64.compare(unbind.revision, bind_a.revision) > 0)
  let final_clear = complete_push_action_for_test(path, unbind_action, 0, endpoint_b) ?
  assert((push_action_kind(final_clear) ?) == 5)
  let permission_b = complete_push_action_for_test(path, final_clear, 0, endpoint_b) ?
  assert((push_action_kind(permission_b) ?) == 1)
  let prime_b = complete_push_action_for_test(path, permission_b, 0, endpoint_b) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"),
  raw_push_frame(1, 1, app_id, Bytes.from_utf8("rotated-device-token")) ?))
  assert(install_push_config(project_b, broker_b_public_key) ?)
  let bind_b_action = complete_push_action_for_test(path, prime_b, 0, endpoint_b) ?
  assert((push_action_kind(bind_b_action) ?) == 3)
  let bind_b = decode_push_bind(push_action_payload(bind_b_action) ?) ?
  assert(U64.compare(bind_b.revision, unbind.revision) > 0)
  assert(Bytes.secure_equals(open_provider_token(bind_b.provider_token_ciphertext, broker_b_seed) ?,
  Bytes.from_utf8("ExpoPushToken[rotated-device-token]")))
  case open_provider_token(bind_b.provider_token_ciphertext, broker_a_seed) do
    Ok( _) -> assert(false)
    Err( _) -> assert(true)
  end
  assert(install_push_config(project_b, broker_b_public_key) ?)
  assert(push_done_matches(complete_push_action_for_test(path, bind_b_action, 0, endpoint_b) ?,
  1,
  0) ?)
  assert(install_push_config(project_b, broker_b_public_key) ?)
  let persisted_prime = push_intent_export(request([Bytes.from_utf8(path), byte(0) ?]) ?) ?
  assert((push_action_kind(persisted_prime) ?) == 2)
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"),
  raw_push_frame(1, 1, app_id, Bytes.from_utf8("rotated-device-token")) ?))
  assert(install_push_config(project_b, broker_b_public_key) ?)
  assert(push_done_matches(complete_push_action_for_test(path, persisted_prime, 0, endpoint_b) ?,
  1,
  0) ?)
  assert(install_legacy_enabled_push_state_for_test(path) ?)
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), Bytes.from_utf8("unused")))
  assert(Test.set_push_token(Bytes.from_utf8("expo/config/v1"), Bytes.empty()))
  case push_intent_export(request([Bytes.from_utf8(path), byte(0) ?]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_push_configuration")
  end
  assert(install_push_config(project_b, broker_b_public_key) ?)
  let legacy_clear = push_intent_export(request([Bytes.from_utf8(path), byte(0) ?]) ?) ?
  assert((push_action_kind(legacy_clear) ?) == 5)
  File.delete(path) ?
  Ok(true)
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("push-binding") ?
  let _ = create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8("alice")]) ?) ?
  let entry = directory_entry(directory_entry_export(Bytes.from_utf8(path)) ?) ?
  let bundle = prekey_bundle(entry.prekey_bundle) ?
  let credential = device_credential(bundle.device_credential) ?
  let mailbox_hash = Crypto.sha256(entry.mailbox_token)
  let broker_seed = seed(7) ?
  let broker = case Crypto.x25519_from_seed(broker_seed) do
    Err( _) -> Err("broker key failed")
    Ok( value) -> Ok(value)
  end ?
  let rotated_broker_seed = seed(9) ?
  let rotated_broker = case Crypto.x25519_from_seed(rotated_broker_seed) do
    Err( _) -> Err("rotated broker key failed")
    Ok( value) -> Ok(value)
  end ?
  let attacker_seed = seed(8) ?
  let project_id = Bytes.from_utf8("01234567-89ab-cdef-0123-456789abcdef")
  let rotated_project_id = Bytes.from_utf8("fedcba98-7654-3210-fedc-ba9876543210")
  let app_id = Bytes.from_utf8("com.example.whatsdown")
  let first_raw_token = Bytes.from_utf8("apns-device-token")
  let first_frame = raw_push_frame(1, 1, app_id, first_raw_token) ?
  let endpoint = "http://127.0.0.1:18997/--/api/v2/push/getExpoPushToken"
  let status_endpoint = "http://127.0.0.1:18997/status"
  let malformed_endpoint = "http://127.0.0.1:18997/malformed"
  let invalid_endpoint = "http://127.0.0.1:18997/invalid"
  let second_endpoint = "http://127.0.0.1:18997/second"
  let rebound_endpoint = "http://127.0.0.1:18997/rebound"
  let rotated_endpoint = "http://127.0.0.1:18997/rotated"
  let device_fixture = Bytes.from_hex("00112233445566778899aabbccddeeff") ?
  assert(expo_registration_body_for_test(first_frame, device_fixture, project_id) ? == "{\"type\":\"apns\",\"deviceId\":\"00112233-4455-6677-8899-aabbccddeeff\",\"development\":true,\"appId\":\"com.example.whatsdown\",\"deviceToken\":\"apns-device-token\",\"projectId\":\"01234567-89ab-cdef-0123-456789abcdef\"}")
  assert(Bytes.secure_equals(push_status_export(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("disabled")))
  let _server = spawn(expo_registration_server)
  Timer.sleep(100)
  assert(durable_push_action_loop_proof(project_id,
  app_id,
  broker.public_key.bytes,
  rebound_endpoint) ?)
  assert(rotated_push_config_proof(project_id,
  rotated_project_id,
  broker.public_key.bytes,
  broker_seed,
  rotated_broker.public_key.bytes,
  rotated_broker_seed,
  app_id,
  rebound_endpoint,
  rotated_endpoint) ?)
  let invalid_android = raw_push_frame(2, 1, app_id, Bytes.from_utf8("fcm-device-token")) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), invalid_android))
  case push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  endpoint) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_material_invalid")
  end
  let trailing_frame = append(first_frame, byte(0) ?) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), trailing_frame))
  case push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  endpoint) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_material_invalid")
  end
  let invalid_utf8 = raw_push_frame(1, 1, app_id, byte(255) ?) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), invalid_utf8))
  case push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  endpoint) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_material_invalid")
  end
  let padded_frame = raw_push_frame(1, 1, app_id, Bytes.from_utf8(" apns-device-token")) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), padded_frame))
  case push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  endpoint) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_material_invalid")
  end
  let oversized_frame = raw_push_frame(1, 1, app_id, repeated(97, 4097) ?) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), oversized_frame))
  case push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  endpoint) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_material_invalid")
  end
  let status_frame = raw_push_frame(1, 1, app_id, Bytes.from_utf8("status-device-token")) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), status_frame))
  case push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  status_endpoint) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_provider_rejected")
  end
  let malformed_response = raw_push_frame(1, 1, app_id, Bytes.from_utf8("malformed-response-token")) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), malformed_response))
  case push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  malformed_endpoint) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_provider_response_invalid")
  end
  let invalid_provider = raw_push_frame(1, 1, app_id, Bytes.from_utf8("invalid-provider-token")) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), invalid_provider))
  case push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  invalid_endpoint) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_provider_response_invalid")
  end
  assert(Bytes.secure_equals(push_status_export(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("disabled")))
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), first_frame))
  let first_wire = push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  endpoint) ?
  assert(Bytes.secure_equals(push_status_export(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("pending-bind")))
  let first = decode_push_bind(first_wire) ?
  assert(U64.compare(first.revision, U64.parse("1") ?) == 0)
  assert(first.provider == 1)
  assert(Bytes.secure_equals(first.mailbox_token_hash, mailbox_hash))
  assert(Bytes.length(first.wake_token_hash) == 32)
  assert(!Bytes.secure_equals(first.wake_token_hash, mailbox_hash))
  let first_token = Bytes.from_utf8("ExponentPushToken[first-device-token]")
  assert(Bytes.secure_equals(open_provider_token(first.provider_token_ciphertext, broker_seed) ?,
  first_token))
  case open_provider_token(first.provider_token_ciphertext, attacker_seed) do
    Ok( _) -> assert(false)
    Err( _) -> assert(true)
  end
  assert(valid_bind_signature(first, credential.signing_public_key) ?)
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), Bytes.from_utf8("invalid")))
  assert(Bytes.secure_equals(push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), Bytes.empty()]) ?,
  Bytes.from_utf8("invalid"),
  "not a url") ?,
  first_wire))
  case commit_push_wire_for_test(path, Bytes.from_utf8("wrong")) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_update_mismatch")
  end
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), first_frame))
  assert(Bytes.secure_equals(push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  endpoint) ?,
  first_wire))
  assert(Bytes.length(commit_push_wire_for_test(path, first_wire) ?) == 0)
  assert(Bytes.secure_equals(push_status_export(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("enabled")))
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), first_frame))
  assert(Bytes.length(push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  endpoint) ?) == 0)
  let second_raw_token = Bytes.from_utf8("fcm-device-token")
  let second_frame = raw_push_frame(2, 0, app_id, second_raw_token) ?
  let second_token = Bytes.from_utf8("ExponentPushToken[second-device-token]")
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), second_frame))
  let second_wire = push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  second_endpoint) ?
  let second = decode_push_bind(second_wire) ?
  assert(U64.compare(second.revision, U64.parse("2") ?) == 0)
  assert(Bytes.secure_equals(second.wake_token_hash, first.wake_token_hash))
  assert(Bytes.secure_equals(open_provider_token(second.provider_token_ciphertext, broker_seed) ?,
  second_token))
  assert(valid_bind_signature(second, credential.signing_public_key) ?)
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), Bytes.from_utf8("invalid")))
  assert(Bytes.secure_equals(push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  endpoint) ?,
  second_wire))
  assert(Bytes.length(commit_push_wire_for_test(path, second_wire) ?) == 0)
  let unbind_wire = push_unbind_prepare_export(Bytes.from_utf8(path)) ?
  assert(Bytes.secure_equals(push_status_export(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("pending-unbind")))
  let unbind = decode_push_unbind(unbind_wire) ?
  assert(U64.compare(unbind.revision, U64.parse("3") ?) == 0)
  assert(Bytes.secure_equals(unbind.mailbox_token_hash, mailbox_hash))
  assert(valid_unbind_signature(unbind, credential.signing_public_key) ?)
  assert(Bytes.secure_equals(push_unbind_prepare_export(Bytes.from_utf8(path)) ?, unbind_wire))
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), Bytes.from_utf8("invalid")))
  case push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  endpoint) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_update_pending")
  end
  let committed_unbind = commit_push_wire_for_test(path, unbind_wire) ?
  assert(Bytes.length(committed_unbind) == 0)
  let disabled_status = push_status_export(Bytes.from_utf8(path)) ?
  assert(Bytes.secure_equals(disabled_status, Bytes.from_utf8("disabled")))
  assert(Bytes.length(push_unbind_prepare_export(Bytes.from_utf8(path)) ?) == 0)
  let rebound_raw_token = Bytes.from_utf8("rebound-device-token")
  let rebound_token = Bytes.from_utf8("ExpoPushToken[rebound-device-token]")
  let rebound_frame = raw_push_frame(1, 1, app_id, rebound_raw_token) ?
  assert(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"), rebound_frame))
  let rebound_wire = push_bind_prepare_with_test_config(request([Bytes.from_utf8(path), project_id]) ?,
  broker.public_key.bytes,
  rebound_endpoint) ?
  Process.request_shutdown()
  Timer.sleep(50)
  let rebound = decode_push_bind(rebound_wire) ?
  assert(U64.compare(rebound.revision, U64.parse("4") ?) == 0)
  assert(!Bytes.secure_equals(rebound.wake_token_hash, first.wake_token_hash))
  let cancel_rebound_wire = push_unbind_prepare_export(Bytes.from_utf8(path)) ?
  let cancel_rebound = decode_push_unbind(cancel_rebound_wire) ?
  assert(U64.compare(cancel_rebound.revision, U64.parse("5") ?) == 0)
  assert(valid_unbind_signature(cancel_rebound, credential.signing_public_key) ?)
  assert(Bytes.secure_equals(push_unbind_prepare_export(Bytes.from_utf8(path)) ?,
  cancel_rebound_wire))
  case commit_push_wire_for_test(path, rebound_wire) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_update_mismatch")
  end
  assert(raw_token_absent(path, first_token) ?)
  assert(raw_token_absent(path, second_token) ?)
  assert(raw_token_absent(path, rebound_token) ?)
  assert(raw_token_absent(path, first_raw_token) ?)
  assert(raw_token_absent(path, second_raw_token) ?)
  assert(raw_token_absent(path, rebound_raw_token) ?)
  assert(Bytes.length(commit_push_wire_for_test(path, cancel_rebound_wire) ?) == 0)
  assert(Bytes.secure_equals(push_status_export(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("disabled")))
  let database = Sqlite.open(path) ?
  let _ = Sqlite.execute_values(database,
  "UPDATE encrypted_blobs SET ciphertext = ? WHERE record_hash = ?",
  [Binary(Bytes.from_utf8("corrupt")), Text(Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("push-binding/v1"))))]) ?
  Sqlite.close(database)
  case push_unbind_prepare_export(Bytes.from_utf8(path)) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "push_state_corrupt")
  end
  File.delete(path) ?
  Ok(true)
end

test("Mesh registers and binds push tokens without exposing raw platform material") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
