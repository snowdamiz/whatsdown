# Caller-owned authority pairs each full RPC URL with its exact TLS policy.
# The guard may only refuse; it cannot replace responses or select new roots.
pub type RpcTls do
  WebPki
  OriginRoots(String, Bytes)
end

pub struct RpcEndpoint do
  url :: String
  tls :: RpcTls
end

pub struct RpcTransport do
  sources :: List<RpcEndpoint>
  require_current :: Fun() -> Result<(), String>
end

pub fn rpc_fatal_error(error :: String) -> Bool do
  error == "rpc_tls_config_invalid" || String.starts_with(error, "rpc_context_changed:")
end

pub fn require_rpc_current(require_current :: Fun() -> Result<(), String>) -> Result<(), String> do
  case require_current() do
    Ok(_) -> Ok(nil)
    Err(error) -> Err("rpc_context_changed:" <> error)
  end
end

pub fn validate_rpc_endpoint(endpoint :: RpcEndpoint) -> Result<(), String> do
  let origin = case Http.url_origin(endpoint.url) do
    Err(_) -> return Err("rpc_tls_config_invalid")
    Ok(value) -> value
  end
  if String.length(endpoint.url) > 2048
    || String.contains(endpoint.url, "@")
    || String.contains(endpoint.url, "#")
    || String.contains(endpoint.url, "\\")
    || (endpoint.url != origin
      && !String.starts_with(endpoint.url, origin <> "/")
      && !String.starts_with(endpoint.url, origin <> "?")) do
    return Err("rpc_tls_config_invalid")
  end
  case endpoint.tls do
    WebPki -> Ok(nil)
    OriginRoots(bound, pem) -> if bound != origin
      || !String.starts_with(origin, "https://")
      || Bytes.length(pem) < 1
      || Bytes.length(pem) > 65536 do
      Err("rpc_tls_config_invalid")
    else
      Ok(nil)
    end
  end
end

pub fn rpc_endpoint(url :: String, tls :: RpcTls) -> RpcEndpoint!String do
  let endpoint = RpcEndpoint { url: url, tls: tls }
  validate_rpc_endpoint(endpoint)?
  Ok(endpoint)
end

pub fn rpc_transport(sources :: List<RpcEndpoint>,
  require_current :: Fun() -> Result<(), String>) -> RpcTransport!String do
  for source in sources do
    validate_rpc_endpoint(source)?
  end
  Ok(RpcTransport { sources: sources, require_current: require_current })
end

pub fn webpki_rpc_transport(urls :: List<String>) -> RpcTransport!String do
  let sources = for url in urls do
    rpc_endpoint(url, WebPki)?
  end
  rpc_transport(sources, fn() do Ok(nil) end)
end

pub fn rpc_urls(rpc :: RpcTransport) -> List<String> do
  for source in rpc.sources do source.url end
end

fn same_endpoint(first :: RpcEndpoint, second :: RpcEndpoint) -> Bool do
  first.url == second.url && case (first.tls, second.tls) do
    (WebPki, WebPki) -> true
    (OriginRoots(a, x), OriginRoots(b, y)) -> a == b && Bytes.secure_equals(x, y)
    _ -> false
  end
end

# Revalidate at each send: public records can be constructed or updated directly.
pub fn require_rpc_endpoint(rpc :: RpcTransport, endpoint :: RpcEndpoint) -> Result<(), String> do
  validate_rpc_endpoint(endpoint)?
  for source in rpc.sources do
    if same_endpoint(source, endpoint) do
      return Ok(nil)
    end
  end
  Err("rpc_tls_config_invalid")
end
