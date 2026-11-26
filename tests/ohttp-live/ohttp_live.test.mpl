from MobileCore import (
  create_account_export,
  mailbox_fetch_export,
  oblivious_decapsulate_export,
  oblivious_encapsulate_export,
  register_request_export,
  resolve_request_export,
  verify_transparency_export
)
from Privacy.OhttpWire import OhttpKeyConfig, ohttp_key_config_encode
from Security.Config import SecurityConfig, SecurityWitness, security_config_encode

##! §22 M3 against the real services (ops/cloudflare/live.test.mjs starts
##! them): the mobile core seals a lookup and a mailbox fetch to the gateway
##! key, they go through the real privacy edge to the real directory, and the
##! evidence that comes back verifies.

fn must<T, E>(value :: Result<T, E>, error :: String) -> T!String do
  case value do
    Err(_) -> Err(error)
    Ok(output)
  end
end

fn vector(value :: Bytes) -> Bytes!String do
  let length = must(Bytes.write_u32_be(must(U64.parse(Int.to_string(Bytes.length(value))),
      "length")?),
    "length")?
  must(Bytes.concat(length, value), "concat")
end

fn vectors(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    vectors(values,
      index + 1,
      must(Bytes.concat(output, vector(List.get(values, index))?), "concat")?)
  end
end

fn request(values :: List<Bytes>) -> Bytes!String do
  vectors(values, 0, Bytes.empty())
end

fn configured(name :: String) -> Bytes!String do
  let value = must(Bytes.from_hex(Env.get(name, "")), "invalid #{name}")?
  if Bytes.length(value) == 32 do
    Ok(value)
  else
    Err("invalid #{name}")
  end
end

fn gateway_public_key() -> Bytes!String do
  let seed = case Env.get_secret_hex("MESSENGER_OHTTP_GATEWAY_SEED_HEX") do
    Err(_) -> Err("invalid gateway seed")
    Ok(value)
  end?
  case Crypto.x25519_from_secret(seed) do
    Err(_) -> Err("invalid gateway seed")
    Ok(pair) -> Ok(pair.public_key.bytes)
  end
end

fn delivery_public_key() -> Bytes!String do
  let seed = case Env.get_secret_hex("MESSENGER_DELIVERY_SEALING_SEED_HEX") do
    Err(_) -> Err("invalid delivery seed")
    Ok(value)
  end?
  case Crypto.x25519_from_secret(seed) do
    Err(_) -> Err("invalid delivery seed")
    Ok(pair) -> Ok(pair.public_key.bytes)
  end
end

fn install(edge_url :: String) -> Bool!String do
  let frame = security_config_encode(SecurityConfig {
    version: 2,
    service_public_key: configured("MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX")?,
    delivery_public_key: delivery_public_key()?,
    abuse_difficulty: Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 8),
    threshold: 2,
    witnesses: [
      SecurityWitness {
        witness_id: "witness-a",
        public_key: configured("MESSENGER_WITNESS_A_PUBLIC_KEY_HEX")?,
        label: "Morse"
      },
      SecurityWitness {
        witness_id: "witness-b",
        public_key: configured("MESSENGER_WITNESS_B_PUBLIC_KEY_HEX")?,
        label: "Morse"
      }
    ],
    judge_program_id: "",
    log_account: "",
    rpc_urls: List.new(),
    relays: List.new(),
    issuer_origin: "",
    c2sp_origin: "",
    minimum_suite: 1,
    ohttp_key_config: ohttp_key_config_encode(OhttpKeyConfig {
      key_id: Env.get_int("MESSENGER_OHTTP_GATEWAY_KEY_ID", 1),
      public_key: gateway_public_key()?
    })?,
    ohttp_relay: edge_url,
    set_id: Bytes.empty()
  })?
  Ok(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame))
end

fn field(input :: Bytes, offset :: Int) -> (Bytes, Int)!String do
  let length = must(U64.to_int(must(Bytes.read_u32_be(input, offset), "field")?), "field")?
  Ok((must(Bytes.slice(input, offset + 4, length), "field")?, offset + 4 + length))
end

# One request through the relay, as the app makes it: (status, body).

fn oblivious(method :: String, path :: String, body :: Bytes) -> (Int, Bytes)!String do
  let sealed = oblivious_encapsulate_export(request([
    Bytes.from_utf8(method),
    Bytes.from_utf8(path),
    body
  ])?)?
  let (relay, after_relay) = field(sealed, 0)?
  let (encapsulated, after_request) = field(sealed, after_relay)?
  let (key, _) = field(sealed, after_request)?
  let response = must(Http.build(:post, must(Bytes.to_utf8(relay), "relay")? <> "/v1/ohttp")
      |> Http.header("Content-Type", "message/ohttp-req")
      |> Http.body_bytes(encapsulated)
      |> Http.timeout(10000)
      |> Http.max_response_bytes(1048640)
      |> Http.send(),
    "relay unreachable")?
  if response.status != 200 do
    Err("relay answered #{response.status}")
  else
    let opened = oblivious_decapsulate_export(request([key, response.body_bytes])?)?
    Ok((must(Bytes.read_u16_be(opened, 0), "status")?,
      must(Bytes.slice(opened, 2, Bytes.length(opened) - 2), "body")?))
  end
end

# The witnesses sign a checkpoint a moment after the registration makes one.

fn verified(path :: String, username :: String, attempts :: Int) -> Bytes!String do
  let lookup = resolve_request_export(request([Bytes.from_utf8(path), Bytes.from_utf8(username)])?)?
  let (status, evidence) = oblivious("POST", "/v1/devices/resolve", lookup)?
  let result = if status == 200 do
    verify_transparency_export(request([
      Bytes.from_utf8(path),
      Bytes.from_utf8(username),
      evidence
    ])?)
  else
    Err("lookup through the relay answered #{status}")
  end
  case result do
    Ok(value)
    Err(error) -> if attempts < 60 do
      Timer.sleep(500)
      verified(path, username, attempts + 1)
    else
      Err(error)
    end
  end
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let core_url = Env.get("MESSENGER_OHTTP_LIVE_CORE_URL", "")
  let edge_url = Env.get("MESSENGER_OHTTP_LIVE_EDGE_URL", "")
  let path = Env.get("MESSENGER_OHTTP_LIVE_DB_PATH", "")
  if core_url == "" || edge_url == "" || path == "" do
    Err("missing live proof configuration")
  else
    assert(install(edge_url)?)
    create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8("carol")])?)?
    let registered = must(Http.build(:put, core_url <> "/v1/devices/register")
        |> Http.header("Content-Type", "application/octet-stream")
        |> Http.body_bytes(register_request_export(Bytes.from_utf8(path))?)
        |> Http.timeout(10000)
        |> Http.send(),
      "registration failed")?
    assert(registered.status == 201)
    assert(Bytes.length(verified(path, "carol", 0)?) > 0)
    let (status, batch) = oblivious("POST",
      "/v1/mailbox/fetch",
      mailbox_fetch_export(Bytes.from_utf8(path))?)?
    assert(status == 200 && must(Bytes.get(batch, 4), "count")? == 0)
    Ok(true)
  end
end

test("a lookup and a mailbox fetch go sealed through the live edge to the live gateway") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
