##! Issuer CA authority comes only from immutable native build resources.

from Mobile.Codec import mobile_read_u32

fn invalid() -> String do
  "issuer_tls_config_invalid"
end

pub fn decode_issuer_tls_root(input :: Bytes, issuer_origin :: String) -> Option<Bytes>!String do
  if Bytes.length(input) < 7 || Bytes.length(input) > 67591 || Bytes.get(input, 0)? != 1 do
    return Err(invalid())
  end
  let name_size = case Bytes.read_u16_be(input, 1) do
    Err(_) -> return Err(invalid())
    Ok(value) -> value
  end
  if name_size > 2048 || Bytes.length(input) < 7 + name_size do
    return Err(invalid())
  end
  let pem_size = case mobile_read_u32(Bytes.slice(input, 3 + name_size, 4)?) do
    Err(_) -> return Err(invalid())
    Ok(value) -> value
  end
  if pem_size > 65536 || Bytes.length(input) != 7 + name_size + pem_size do
    return Err(invalid())
  end
  if name_size == 0 && pem_size == 0 do
    return Ok(None)
  end
  if name_size == 0 || pem_size == 0 do
    return Err(invalid())
  end
  let name = case Bytes.to_utf8(Bytes.slice(input, 3, name_size)?) do
    Err(_) -> return Err(invalid())
    Ok(value) -> value
  end
  let canonical = case Http.url_origin(name) do
    Err(_) -> return Err(invalid())
    Ok(value) -> value
  end
  if name != issuer_origin
    || name != canonical
    || !String.starts_with(name, "https://")
    || !Regex.is_match(~r/^[\x21-\x7e]+$/, name)
    || String.contains(name, "\\")
    || String.contains(name, "@")
    || String.contains(name, "?")
    || String.contains(name, "#") do
    return Err(invalid())
  end
  Ok(Some(Bytes.slice(input, 7 + name_size, pem_size)?))
end

pub fn issuer_tls_request(request :: Int, issuer_origin :: String) -> Int!String do
  let input = case Host.push_get_token(Bytes.from_utf8("messenger/issuer-tls-root/v1")) do
    Err(_) -> do
      Http.cancel(request)
      return Err(invalid())
    end
    Ok(value) -> value
  end
  issuer_tls_request_with_frame(request, issuer_origin, input)
end

# Captured callers use these exact bytes; this path never rereads native resources.
pub fn issuer_tls_request_with_frame(request :: Int,
  issuer_origin :: String,
  captured_frame :: Bytes) -> Int!String do
  let roots = case decode_issuer_tls_root(captured_frame, issuer_origin) do
    Err(error) -> do
      Http.cancel(request)
      return Err(error)
    end
    Ok(value) -> value
  end
  case roots do
    None -> Ok(request)
    Some(pem) -> Ok(Http.trust_root_pem(request, pem))
  end
end
