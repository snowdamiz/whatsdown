from Binary.Reader import BinaryReader, finish, reader
from Mobile.Codec import (
  current_time,
  mobile_read_byte,
  mobile_utf8,
  mobile_wide,
  take_fixed,
  take_vector
)
from Mobile.Types import (
  MobileExpoRawToken,
  MobilePushBuildConfig,
  MobileReadBytes,
  MobileSecurityConfig
)
from Privacy.Edge import encode_privacy_submission, mint_submission, seal_delivery

##! Mobile.Platform implementation.

pub fn privacy_submission(outer :: Bytes) -> Bytes ! String do
  let config = native_security_config() ?
  let sealed = seal_delivery(outer, X25519PublicKey { bytes : config.delivery_public_key }) ?
  let expires_at = U64.add(current_time() ?, mobile_wide("300000") ?) ?
  encode_privacy_submission(mint_submission(sealed, expires_at, config.abuse_difficulty) ?)
end

fn canonical_push_material_text(input :: Bytes) -> String ! String do
  let text = mobile_utf8(input, "invalid") ?
  if String.trim(text) != text || String.contains(text, "\r") || String.contains(text, "\n") do
    Err("invalid")
  else
    Ok(text)
  end
end

fn parse_expo_raw_token_inner(input :: Bytes) -> MobileExpoRawToken ! String do
  let start = case reader(input, 4362) do
    Err( _) -> Err("invalid")
    Ok( value) -> Ok(value)
  end ?
  let version = take_fixed(start, 1) ?
  let platform = take_fixed(version.state, 1) ?
  let development = take_fixed(platform.state, 1) ?
  let app_id = take_vector(development.state, 255) ?
  let device_token = take_vector(app_id.state, 4096) ?
  let _ = case finish(device_token.state) do
    Err( _) -> Err("invalid")
    Ok( _) -> Ok(nil)
  end ?
  let version_value = mobile_read_byte(version.value) ?
  let platform_value = mobile_read_byte(platform.value) ?
  let development_value = mobile_read_byte(development.value) ?
  if version_value != 1 || (platform_value != 1 && platform_value != 2) || (development_value != 0 && development_value != 1) || (platform_value == 2 && development_value != 0) || Bytes.length(app_id.value) == 0 || Bytes.length(device_token.value) == 0 do
    Err("invalid")
  else
    Ok(MobileExpoRawToken {
      platform : platform_value,
      development : development_value == 1,
      app_id : canonical_push_material_text(app_id.value) ?,
      device_token : canonical_push_material_text(device_token.value) ?
    })
  end
end

pub fn parse_expo_raw_token(input :: Bytes) -> MobileExpoRawToken ! String do
  case parse_expo_raw_token_inner(input) do
    Err( _) -> Err("push_material_invalid")
    Ok( value) -> Ok(value)
  end
end

pub fn expo_project_id(input :: Bytes) -> String ! String do
  case Bytes.to_utf8(input) do
    Err( _) -> Err("invalid_push_project_id")
    Ok( value) -> if Regex.is_match(~r/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    value) do
      Ok(value)
    else
      Err("invalid_push_project_id")
    end
  end
end

fn expo_device_id(device_id :: Bytes) -> String ! String do
  if Bytes.length(device_id) != 16 do
    Err("push_device_id_invalid")
  else
    let value = Bytes.to_hex(device_id)
    Ok(String.slice(value, 0, 8) <> "-" <> String.slice(value, 8, 12) <> "-" <> String.slice(value,
    12,
    16) <> "-" <> String.slice(value, 16, 20) <> "-" <> String.slice(value, 20, 32))
  end
end

pub fn expo_registration_body(material :: MobileExpoRawToken,
device_id :: Bytes,
project_id :: String) -> String ! String do
  let kind = if material.platform == 1 do
    "apns"
  else
    "fcm"
  end
  let development = if material.development do
    "true"
  else
    "false"
  end
  Ok("{\"type\":" <> Json.encode_string(kind) <> ",\"deviceId\":" <> Json.encode_string(expo_device_id(device_id) ?) <> ",\"development\":" <> development <> ",\"appId\":" <> Json.encode_string(material.app_id) <> ",\"deviceToken\":" <> Json.encode_string(material.device_token) <> ",\"projectId\":" <> Json.encode_string(project_id) <> "}")
end

fn expo_provider_token_inner(body :: String) -> Bytes ! String do
  let root = Json.parse(body) ?
  let data = (root
    |> Json.object_get("data")) ?
  let value = (data
    |> Json.object_get("expoPushToken")) ?
  Ok(Bytes.from_utf8((value
    |> Json.as_string()) ?))
end

fn expo_provider_token(body :: String) -> Bytes ! String do
  case expo_provider_token_inner(body) do
    Err( _) -> Err("push_provider_response_invalid")
    Ok( value) -> Ok(value)
  end
end

pub fn register_expo_token(material :: MobileExpoRawToken,
device_id :: Bytes,
project_id :: String,
endpoint :: String) -> Bytes ! String do
  let body = expo_registration_body(material, device_id, project_id) ?
  let response = case (Http.build(:post, endpoint)
    |> Http.header("Content-Type", "application/json")
    |> Http.body(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(4096)
    |> Http.max_redirects(0)
    |> Http.send()) do
    Err( _) -> Err("push_provider_unavailable")
    Ok( value) -> Ok(value)
  end ?
  if response.status < 200 || response.status >= 300 do
    Err("push_provider_rejected")
  else
    expo_provider_token(response.body)
  end
end

fn contributory_x25519_public_key(input :: Bytes,
invalid_error :: String,
validation_error :: String) -> X25519PublicKey ! String do
  if Bytes.length(input) != 32 do
    Err(invalid_error)
  else
    let probe = case Crypto.x25519_generate() do
      Err( _) -> Err(validation_error)
      Ok( value) -> Ok(value)
    end ?
    let shared = case Crypto.x25519_shared(probe.private_key, X25519PublicKey { bytes : input }) do
      Err( _) -> Err(invalid_error)
      Ok( value) -> Ok(value)
    end ?
    Secret.destroy(shared)
    Ok(X25519PublicKey { bytes : input })
  end
end

pub fn push_broker_public_key(input :: Bytes) -> X25519PublicKey ! String do
  contributory_x25519_public_key(input,
  "invalid_push_broker_public_key",
  "push_configuration_validation_failed")
end

pub fn native_push_build_config() -> MobilePushBuildConfig ! String do
  let frame = case Host.push_get_token(Bytes.from_utf8("expo/config/v1")) do
    Err( _) -> Err("push_configuration_required")
    Ok( value) -> Ok(value)
  end ?
  if Bytes.length(frame) != 103 do
    Err("invalid_push_configuration")
  else
    let text = mobile_utf8(frame, "invalid_push_configuration") ?
    let fields = String.split(text, "\n")
    if List.length(fields) != 3 || List.get(fields, 0) != "1" do
      Err("invalid_push_configuration")
    else
      let project_id = Bytes.from_utf8(List.get(fields, 1))
      let _ = expo_project_id(project_id) ?
      let broker_hex = List.get(fields, 2)
      let broker_public_key = case Bytes.from_hex(broker_hex) do
        Err( _) -> Err("invalid_push_broker_public_key")
        Ok( value) -> Ok(value)
      end ?
      if String.length(broker_hex) != 64 || Bytes.to_hex(broker_public_key) != broker_hex do
        Err("invalid_push_broker_public_key")
      else
        let key = push_broker_public_key(broker_public_key) ?
        Ok(MobilePushBuildConfig {
          project_id : project_id,
          broker_public_key : key.bytes
        })
      end
    end
  end
end

fn security_config_key(input :: String) -> Bytes ! String do
  let value = case Bytes.from_hex(input) do
    Err( _) -> Err("invalid_messenger_configuration")
    Ok( parsed) -> Ok(parsed)
  end ?
  if String.length(input) != 64 || Bytes.length(value) != 32 || Bytes.to_hex(value) != input do
    Err("invalid_messenger_configuration")
  else
    Ok(value)
  end
end

fn security_delivery_key(input :: Bytes) -> X25519PublicKey ! String do
  contributory_x25519_public_key(input,
  "invalid_messenger_configuration",
  "messenger_configuration_validation_failed")
end

fn parse_security_config(frame :: Bytes) -> MobileSecurityConfig ! String do
  if Bytes.length(frame) < 263 || Bytes.length(frame) > 264 do
    Err("invalid_messenger_configuration")
  else
    let text = mobile_utf8(frame, "invalid_messenger_configuration") ?
    let fields = String.split(text, "\n")
    if List.length(fields) != 6 || List.get(fields, 0) != "1" do
      Err("invalid_messenger_configuration")
    else
      let service_key = security_config_key(List.get(fields, 1)) ?
      let witness_a = security_config_key(List.get(fields, 2)) ?
      let witness_b = security_config_key(List.get(fields, 3)) ?
      let delivery_bytes = security_config_key(List.get(fields, 4)) ?
      let difficulty = case String.to_int(List.get(fields, 5)) do
        None -> Err("invalid_messenger_configuration")
        Some( value) -> Ok(value)
      end ?
      let canonical = "1\n" <> Bytes.to_hex(service_key) <> "\n" <> Bytes.to_hex(witness_a) <> "\n" <> Bytes.to_hex(witness_b) <> "\n" <> Bytes.to_hex(delivery_bytes) <> "\n" <> Int.to_string(difficulty)
      if difficulty < 1 || difficulty > 24 || text != canonical || Bytes.secure_equals(witness_a,
      witness_b) do
        Err("invalid_messenger_configuration")
      else
        let delivery_key = security_delivery_key(delivery_bytes) ?
        Ok(MobileSecurityConfig {
          transparency_service_public_key : service_key,
          witness_a_public_key : witness_a,
          witness_b_public_key : witness_b,
          delivery_public_key : delivery_key.bytes,
          abuse_difficulty : difficulty
        })
      end
    end
  end
end

pub fn native_security_config() -> MobileSecurityConfig ! String do
  let frame = case Host.push_get_token(Bytes.from_utf8("messenger/config/v1")) do
    Err( _) -> Err("messenger_configuration_required")
    Ok( value) -> Ok(value)
  end ?
  parse_security_config(frame)
end

pub fn expo_push_endpoint() -> String do
  "https://exp.host/--/api/v2/push/getExpoPushToken"
end
