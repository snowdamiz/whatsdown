## Internal read-only report transport. Policy comes from trusted deployment
## configuration; requests carry only a nonce. Account validation stays in Read.
from Read import read_public_report
from Privacy.Edge import internal_delivery_token, internal_delivery_authorized

struct SnapshotServer do
  template :: String
  policy_hash :: String
  generator_hash :: String
  token :: String
end

fn lower_hash(value :: String) -> Bool do
  case Bytes.from_hex(value) do
    Err(_) -> false
    Ok(bytes) -> Bytes.length(bytes) == 32 && Bytes.to_hex(bytes) == value
  end
end

fn seconds_now() -> String do
  Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()) / 1000)
end

fn configuration() -> SnapshotServer!String do
  let raw = Env.get("MORSE_PUBLIC_REPORT_CONFIG", "")
  let policy_hash = Env.get("MORSE_PUBLIC_REPORT_POLICY_SHA256", "")
  if String.length(raw) < 2
    || Bytes.length(Bytes.from_utf8(raw)) > 32768
    || !lower_hash(policy_hash)
    || Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(raw))) != policy_hash do
    return Err("invalid_public_report_policy")
  end
  let root = Json.parse(raw)?
  if Json.as_int(Json.object_get(root, "schema_version")?)? != 1 do
    return Err("invalid_public_report_policy")
  end
  case Json.object_get(root, "generated_at_unix") do
    Ok(_) -> return Err("public_report_clock_is_server_owned")
    Err(_) -> nil
  end
  let scope = Json.as_string(Json.object_get(root, "scope")?)?
  if scope != "configured-rpc"
    && !(scope == "local-fixture"
      && Env.get("MORSE_PUBLIC_REPORT_ALLOW_FIXTURE", "") == "owned-local-only") do
    return Err("invalid_public_report_scope")
  end
  let template = Json.encode(root)
  if !String.starts_with(template, "{") || !String.ends_with(template, "}") do
    return Err("invalid_public_report_policy")
  end
  let binary = List.get(Env.args(), 0)
  # This fixed companion is emitted with the executable by the trusted build.
  # It associates that build, not a caller assertion or runtime attestation.
  if !String.starts_with(binary, "/") || String.ends_with(binary, "/") do
    return Err("invalid_public_report_executable_path")
  end
  let identity_path = binary <> ".sha256"
  let identity_size = File.size(identity_path)?
  if identity_size < 64 || identity_size > 65 do
    return Err("invalid_public_report_build_identity")
  end
  let identity = File.read(identity_path)?
  let generator_hash = String.trim(identity)
  if !lower_hash(generator_hash)
    || (identity != generator_hash && identity != generator_hash <> "\n")
    || generator_hash != Env.get("MORSE_PUBLIC_REPORT_GENERATOR_SHA256", "") do
    return Err("invalid_public_report_build_identity")
  end
  Ok(SnapshotServer {
    template: template,
    policy_hash: policy_hash,
    generator_hash: generator_hash,
    token: internal_delivery_token(Env.get("MORSE_PUBLIC_REPORT_INTERNAL_TOKEN", ""))?
  })
end

fn produce(config :: SnapshotServer, nonce :: String) -> String!String do
  let started = seconds_now()
  # Json.encode produced this object, so the closing brace is structural.
  let input = String.slice(config.template, 0, String.length(config.template) - 1)
    <> ",\"generated_at_unix\":"
    <> Json.encode_string(started)
    <> "}"
  let report = read_public_report(input)?
  Ok("{\"schema_version\":1,\"nonce\":"
    <> Json.encode_string(nonce)
    <> ",\"policy_sha256\":"
    <> Json.encode_string(config.policy_hash)
    <> ",\"generator_sha256\":"
    <> Json.encode_string(config.generator_hash)
    <> ",\"started_at_unix\":"
    <> Json.encode_string(started)
    <> ",\"completed_at_unix\":"
    <> Json.encode_string(seconds_now())
    <> ",\"report\":"
    <> report
    <> "}")
end

fn handle(request :: Request, config :: SnapshotServer) -> Response do
  if !internal_delivery_authorized(Request.header(request, "authorization"), config.token) do
    return HTTP.response(401, "unauthorized")
  end
  let body = Request.body_bytes(request)
  if Bytes.length(body) != 64 do
    return HTTP.response(400, "invalid nonce")
  end
  let nonce = case Bytes.to_utf8(body) do
    Err(_) -> return HTTP.response(400, "invalid nonce")
    Ok(value) -> value
  end
  if !lower_hash(nonce) do
    return HTTP.response(400, "invalid nonce")
  end
  case produce(config, nonce) do
    Err(_) -> HTTP.response(503, "unavailable")
    Ok(value) -> HTTP.response_bytes_with_headers(200,
      Bytes.from_utf8(value),
      Map.new()
        |> Map.put("Content-Type", "application/json")
        |> Map.put("Cache-Control", "no-store"))
  end
end

pub fn serve_snapshot() -> String!String do
  let config = configuration()?
  let port = Env.get_int("PORT", 18094)
  if port < 1 || port > 65535 do
    return Err("invalid_public_report_port")
  end
  HTTP.serve(HTTP.router()
      |> HTTP.on_get("/health", fn(_request :: Request) do HTTP.response(200, "ok") end)
      |> HTTP.on_post("/internal/v1/public-report",
        fn(request :: Request) do handle(request, config) end),
    port)
  Ok("")
end
