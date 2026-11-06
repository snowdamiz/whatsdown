from Mobile.NativeIssuerTls import decode_issuer_tls_root, issuer_tls_request
from Mobile.Codec import mobile_write_u32

fn frame(origin :: String, pem :: Bytes) -> Bytes!String do
  let name = Bytes.from_utf8(origin)
  let length = case Bytes.write_u16_be(Bytes.length(name)) do
    Err(_) -> return Err("test_frame")
    Ok(value) -> value
  end
  let size = mobile_write_u32(Bytes.length(pem))?
  Bytes.concat(Bytes.concat(Bytes.concat(Bytes.from_hex("01")?, length)?, name)?,
    Bytes.concat(size, pem)?)
end

fn rejected(value :: Bytes, origin :: String) -> Bool do
  case decode_issuer_tls_root(value, origin) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn proof() -> Bool!String do
  let origin = "https://issuer.example:8443"
  let absent = Bytes.from_hex("01000000000000")?
  assert(decode_issuer_tls_root(absent, origin)? == None)
  let pem = Bytes.from_utf8("-----BEGIN CERTIFICATE-----\ninvalidDER\n-----END CERTIFICATE-----\n")
  assert(decode_issuer_tls_root(frame(origin, pem)?, origin)? == Some(pem))
  for bad in [
    Bytes.empty(),
    Bytes.from_hex("02000000000000")?,
    Bytes.from_hex("0100000000000000")?,
    frame(origin, Bytes.empty())?,
    frame("", pem)?,
    Bytes.concat(frame(origin, pem)?, Bytes.from_hex("00")?)?
  ] do
    assert(rejected(bad, origin))
  end
  for bad in [
    "https://other.example",
    origin <> "/",
    "https://ISSUER.example:8443",
    "http://issuer.example:8443",
    "https://user@issuer.example:8443",
    origin <> "?x=1",
    "https://issuer.example:443"
  ] do
    assert(rejected(frame(bad, pem)?, origin))
  end
  assert(Test.install_in_memory_secure_store())
  let handle = Http.build(:get, "http://127.0.0.1:9")
    |> Http.timeout(-1)
  case issuer_tls_request(handle, origin) do
    Err(error) -> assert(error == "issuer_tls_config_invalid")
    Ok(_) -> assert(false)
  end
  case Http.send(handle) do
    Err(error) -> assert(String.contains(error, "already-consumed HTTP request handle"))
    Ok(_) -> assert(false)
  end
  let handle = Http.build(:get, origin)
  assert(Test.set_push_token(Bytes.from_utf8("messenger/issuer-tls-root/v1"), absent))
  assert(issuer_tls_request(handle, origin)? == handle)
  assert(Test.set_push_token(Bytes.from_utf8("messenger/issuer-tls-root/v1"), frame(origin, pem)?))
  let poisoned = issuer_tls_request(handle, origin)?
  case Http.send(poisoned) do
    Err(error) -> assert(String.starts_with(error, "INVALID_TLS_ROOTS:"))
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("native issuer roots bind a strict resource to the native origin and fail closed") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
