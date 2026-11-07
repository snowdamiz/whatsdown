##! RPC roots are immutable native resources bound to the complete release frame.
from Transparency.Config import SecurityConfig, encode_security_config
from Transparency.RpcTransport import RpcTls, RpcEndpoint, rpc_endpoint
from Mobile.Codec import mobile_read_u32

pub fn native_rpc_tls_frame() -> Bytes!String do
  let frame = case Host.push_get_token(Bytes.from_utf8("messenger/rpc-tls-roots/v1")) do
    Err(_) -> return Err("rpc_tls_config_unavailable")
    Ok(value) -> value
  end
  if Bytes.length(frame) < 2 || Bytes.length(frame) > 82002 do
    Err("rpc_tls_config_invalid")
  else
    Ok(frame)
  end
end

fn origin_order(a :: String, b :: String) -> Int do
  if a < b do
    -1
  else if a == b do
    0
  else
    1
  end
end

fn rows(frame :: Bytes,
  origins :: List<String>,
  index :: Int,
  offset :: Int,
  total :: Int,
  explicit :: Bool) -> List<RpcEndpoint>!String do
  if index == List.length(origins) do
    if offset != Bytes.length(frame) || !explicit do
      return Err("rpc_tls_config_invalid")
    end
    return Ok([])
  end
  if offset + 2 > Bytes.length(frame) do
    return Err("rpc_tls_config_invalid")
  end
  let name_size = case Bytes.read_u16_be(frame, offset) do
    Err(_) -> return Err("rpc_tls_config_invalid")
    Ok(value) -> value
  end
  if name_size < 1 || name_size > 2048 || offset + 6 + name_size > Bytes.length(frame) do
    return Err("rpc_tls_config_invalid")
  end
  let name = Bytes.to_utf8(Bytes.slice(frame, offset + 2, name_size)?)?
  # Exact sorted equality also rejects noncanonical spelling, duplicates and
  # missing/unknown origins. Never bind roots by a host prefix or row position.
  if name != List.get(origins, index) do
    return Err("rpc_tls_config_invalid")
  end
  let size = mobile_read_u32(Bytes.slice(frame, offset + 2 + name_size, 4)?)?
  let start = offset + 6 + name_size
  if size > 65536 - total || start + size > Bytes.length(frame) do
    return Err("rpc_tls_config_invalid")
  end
  let tls = if size == 0 do
    WebPki
  else
    OriginRoots(name, Bytes.slice(frame, start, size)?)
  end
  let rest = rows(frame, origins, index + 1, start + size, total + size, explicit || size > 0)?
  Ok([rpc_endpoint(name, tls)?] ++ rest)
end

fn roots_at(rows :: List<RpcEndpoint>, url :: String) -> RpcEndpoint!String do
  let origin = Http.url_origin(url)?
  for row in rows do
    if row.url == origin do
      return rpc_endpoint(url, row.tls)
    end
  end
  Err("rpc_tls_config_invalid")
end

fn decode(frame :: Bytes, config :: SecurityConfig) -> List<RpcEndpoint>!String do
  # Canonical encoding validates the full configuration even for the sentinel.
  let canonical = encode_security_config(config)?
  if Bytes.secure_equals(frame, Bytes.from_hex("0100")?) do
    return Ok(for url in config.rpc_urls do rpc_endpoint(url, WebPki)? end)
  end
  if Bytes.length(frame) < 34 || Bytes.length(frame) > 82002
    || Bytes.get(frame, 0)? != 1 do
    return Err("rpc_tls_config_invalid")
  end
  let count = Bytes.get(frame, 1)?
  if count < 3 || count > 8 || count != List.length(config.rpc_urls)
    || !Bytes.secure_equals(Bytes.slice(frame, 2, 32)?, Crypto.sha256(canonical)) do
    return Err("rpc_tls_config_invalid")
  end
  let origins = for url in config.rpc_urls do Http.url_origin(url)? end
  for origin in origins do
    if !String.starts_with(origin, "https://") do
      return Err("rpc_tls_config_invalid")
    end
  end
  let parsed = rows(frame, List.sort(origins, origin_order), 0, 34, 0, false)?
  Ok(for url in config.rpc_urls do roots_at(parsed, url)? end)
end

# Only framing/binding is pure here. Public Http validates each attempted PEM;
# unused certificate DER is not eagerly validated by this decoder.
pub fn decode_native_rpc_tls(frame :: Bytes, config :: SecurityConfig) -> List<RpcEndpoint>!String do
  case decode(frame, config) do
    Err(_) -> Err("rpc_tls_config_invalid")
    Ok(value)
  end
end
