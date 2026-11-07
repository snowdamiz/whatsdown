##! Transport destinations come from native build resources, never a JS URL.

pub struct MobileNetworkPins do
  development :: Bool
  core_origin :: String
  edge_origin :: String
  object_origin :: String
  stream_url :: String
  object_work_difficulty :: Int
end

fn invalid() -> String do
  "invalid_network_configuration"
end

fn origin(input :: String, development :: Bool) -> String!String do
  if String.length(input) < 8
    || String.length(input) > 2048
    || !Regex.is_match(~r/^[\x21-\x7e]+$/, input)
    || String.contains(input, "\\")
    || String.contains(input, "@")
    || String.contains(input, "?")
    || String.contains(input, "#") do
    return Err(invalid())
  end
  let canonical = case Http.url_origin(input) do
    Err(_) -> return Err(invalid())
    Ok(value) -> value
  end
  if input != canonical do
    return Err(invalid())
  end
  if String.starts_with(input, "https://") do
    return Ok(input)
  end
  if development
    && Regex.is_match(~r/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:[1-9][0-9]{0,4})?$/, input) do
    Ok(input)
  else
    Err(invalid())
  end
end

fn stream(input :: String, development :: Bool) -> String!String do
  let secure = String.starts_with(input, "wss://")
  let start = if secure do
    6
  else
    5
  end
  if !secure && !String.starts_with(input, "ws://") do
    return Err(invalid())
  end
  let converted = (if secure do
    "https://"
  else
    "http://"
  end)
    <> String.slice(input, start, String.length(input))
  let parsed = case Http.url_origin(converted) do
    Err(_) -> return Err(invalid())
    Ok(value) -> value
  end
  origin(parsed, development)?
  if converted != parsed <> "/v1/mailbox/stream" do
    Err(invalid())
  else
    Ok(input)
  end
end

pub fn decode_network_pins(input :: Bytes) -> MobileNetworkPins!String do
  if Bytes.length(input) == 0 || Bytes.length(input) > 8244 do
    return Err(invalid())
  end
  let text = case Bytes.to_utf8(input) do
    Err(_) -> return Err(invalid())
    Ok(value) -> value
  end
  let fields = String.split(text, "\n")
  if List.length(fields) < 2 do
    return Err(invalid())
  end
  let legacy = List.get(fields, 0) == "1" && List.length(fields) == 6
  let current = List.get(fields, 0) == "2" && List.length(fields) == 7
  if (!legacy && !current) || (List.get(fields, 1) != "0" && List.get(fields, 1) != "1") do
    return Err(invalid())
  end
  let development = List.get(fields, 1) == "1"
  let difficulty = if legacy do
    16
  else
    let encoded = List.get(fields, 6)
    if !Regex.is_match(~r/^([1-9]|1[0-9]|2[0-4])$/, encoded) do
      return Err(invalid())
    end
    case String.to_int(encoded) do
      None -> return Err(invalid())
      Some(value) -> value
    end
  end
  Ok(MobileNetworkPins {
    development: development,
    core_origin: origin(List.get(fields, 2), development)?,
    edge_origin: origin(List.get(fields, 3), development)?,
    object_origin: origin(List.get(fields, 4), development)?,
    stream_url: stream(List.get(fields, 5), development)?,
    object_work_difficulty: difficulty
  })
end

pub fn native_network_pins() -> MobileNetworkPins!String do
  let input = case Host.push_get_token(Bytes.from_utf8("messenger/network/v1")) do
    Err(_) -> return Err("network_configuration_required")
    Ok(value) -> value
  end
  decode_network_pins(input)
end
