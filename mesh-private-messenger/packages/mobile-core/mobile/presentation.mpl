from Mobile.Profile import load_profile
from Transport.Packet import decode_client_profile
from Mobile.Codec import mobile_reader, mobile_finish, mobile_utf8, mobile_join, mobile_vector, take_vector
from Mobile.Types import MobilePayloadRequest, MobileTriplePayloadRequest
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.Records import store_updated_session

##! Small presentation records travel inside authenticated encrypted messages.
##! Storage keys come from the authenticated sender/group, never from the payload.

pub fn presentation_data(input :: Bytes) -> Bytes ! String do
  let state = mobile_reader(input, 12400, "invalid_presentation") ?
  let name = take_vector(state, 96) ?
  let avatar = take_vector(name.state, 12288) ?
  mobile_finish(avatar.state, "invalid_presentation") ?
  let name_text = mobile_utf8(name.value, "invalid_presentation") ?
  let avatar_text = mobile_utf8(avatar.value, "invalid_presentation") ?
  if String.length(String.trim(name_text)) == 0 || (Bytes.length(avatar.value) > 0 && !String.starts_with(avatar_text, "data:image/jpeg;base64,")) do
    Err("invalid_presentation")
  else
    Ok(input)
  end
end

fn presentation_label(key :: Bytes) -> String ! String do
  let text = mobile_utf8(key, "invalid_presentation_key") ?
  let parts = String.split(text, "/")
  if List.length(parts) != 2 do
    Err("invalid_presentation_key")
  else
    let kind = List.get(parts, 0)
    let id = List.get(parts, 1)
    if (kind != "user" && kind != "group") || String.length(id) != 64 do
      Err("invalid_presentation_key")
    else
      let decoded = Bytes.from_hex(id) ?
      if Bytes.to_hex(decoded) != id do Err("invalid_presentation_key") else Ok("presentation/v1/" <> text) end
    end
  end
end

pub fn load_presentation_record(database_path :: String, wrapping_key :: borrow StorageKey, key :: Bytes) -> Bytes ! String do
  let label = presentation_label(key) ?
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do Ok(Bytes.empty()) else Err(error) end
    Ok(blob) -> open_local(blob, wrapping_key, local_context(label) ?)
  end
end

fn save_record(database_path :: String, wrapping_key :: borrow StorageKey, key :: Bytes, data :: Bytes) -> Bytes ! String do
  let label = presentation_label(key) ?
  let checked = presentation_data(data) ?
  let previous = load_presentation_record(database_path, wrapping_key, key) ?
  if Bytes.secure_equals(previous, checked) do Ok(checked) else
    store_updated_session(database_path, label, seal_local(checked, wrapping_key, local_context(label) ?) ?) ?
    Ok(checked)
  end
end

pub fn load_presentation(request :: MobilePayloadRequest) -> Bytes ! String do
  let wrapping_key = platform_key() ?
  load_presentation_record(request.database_path, wrapping_key, request.payload)
end

pub fn save_presentation(request :: MobileTriplePayloadRequest) -> Bytes ! String do
  let wrapping_key = platform_key() ?
  save_record(request.database_path, wrapping_key, request.first, request.second)
end

pub fn encode_presented_message(body :: Bytes, profile :: Bytes, group :: Bytes) -> Bytes ! String do
  presentation_data(profile) ?
  if Bytes.length(group) > 0 do presentation_data(group) ? else Bytes.empty() end
  mobile_join([Bytes.from_utf8("MORSE-PRESENTATION/1\n"), mobile_vector(body) ?, mobile_vector(profile) ?, mobile_vector(group) ?], 0, Bytes.empty())
end

fn decode_presented_message(input :: Bytes) -> Result<(Bytes, Bytes, Bytes), String> do
  let state = mobile_reader(input, 65342, "invalid_presentation") ?
  let body = take_vector(state, 40000) ?
  let profile = take_vector(body.state, 12400) ?
  let group = take_vector(profile.state, 12400) ?
  mobile_finish(group.state, "invalid_presentation") ?
  presentation_data(profile.value) ?
  if Bytes.length(group.value) > 0 do presentation_data(group.value) ? else Bytes.empty() end
  Ok((body.value, profile.value, group.value))
end

pub fn consume_presented_message(database_path :: String, wrapping_key :: borrow StorageKey,
sender_id :: Bytes, group_id :: Bytes, input :: Bytes) -> Bytes ! String do
  let prefix = Bytes.from_utf8("MORSE-PRESENTATION/1\n")
  if Bytes.length(input) < Bytes.length(prefix) do Ok(input) else
    let head = Bytes.slice(input, 0, Bytes.length(prefix)) ?
    if !Bytes.secure_equals(head, prefix) do Ok(input) else
      let encoded = Bytes.slice(input, Bytes.length(prefix), Bytes.length(input) - Bytes.length(prefix)) ?
      case decode_presented_message(encoded) do
        Err(_) -> Ok(input)
        Ok(value) -> do
          let (body, profile, group) = value
          save_record(database_path, wrapping_key, Bytes.from_utf8("user/" <> Bytes.to_hex(sender_id)), profile) ?
          if Bytes.length(group_id) == 32 && Bytes.length(group) > 0 do
            let key = Bytes.from_utf8("group/" <> Bytes.to_hex(group_id))
            # Group details are set at creation. Existing details win over a stale relay.
            let existing = load_presentation_record(database_path, wrapping_key, key) ?
            if Bytes.length(existing) == 0 do save_record(database_path, wrapping_key, key, group) ? else existing end
          else Bytes.empty() end
          Ok(body)
        end
      end
    end
  end
end

# Legacy maximum-size messages remain sendable without presentation overhead.
pub fn present_message(database_path :: String, group_id :: Bytes, body :: Bytes) -> Bytes ! String do
  let local = decode_client_profile(load_profile(database_path) ?) ?
  let wrapping_key = platform_key() ?
  let saved = load_presentation_record(database_path, wrapping_key, Bytes.from_utf8("user/" <> Bytes.to_hex(local.account_id))) ?
  let profile = if Bytes.length(saved) > 0 do saved else
    mobile_join([mobile_vector(Bytes.from_utf8(local.username)) ?, mobile_vector(Bytes.empty()) ?], 0, Bytes.empty()) ?
  end
  let group = if Bytes.length(group_id) == 32 do
    load_presentation_record(database_path, wrapping_key, Bytes.from_utf8("group/" <> Bytes.to_hex(group_id))) ?
  else Bytes.empty() end
  let presented = encode_presented_message(body, profile, group) ?
  if Bytes.length(presented) > 65342 || Bytes.length(body) > 40000 do Ok(body) else Ok(presented) end
end

pub fn presented_body(input :: Bytes) -> Bytes do
  let prefix = Bytes.from_utf8("MORSE-PRESENTATION/1\n")
  if Bytes.length(input) < Bytes.length(prefix) do input else
    case Bytes.slice(input, 0, Bytes.length(prefix)) do
      Err(_) -> input
      Ok(head) -> if !Bytes.secure_equals(head, prefix) do input else
        case Bytes.slice(input, Bytes.length(prefix), Bytes.length(input) - Bytes.length(prefix)) do
          Err(_) -> input
          Ok(encoded) -> case decode_presented_message(encoded) do
            Err(_) -> input
            Ok(value) -> do let (body, profile, group) = value body end
          end
        end
      end
    end
  end
end
