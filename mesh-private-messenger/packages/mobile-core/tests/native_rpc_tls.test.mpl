from Mobile.NativeRpcTls import decode_native_rpc_tls, native_rpc_tls_frame
from Mobile.Codec import mobile_byte, mobile_write_u32, mobile_join
from Transparency.Config import SecurityConfig, decode_security_config, encode_security_config
from Transparency.RpcTransport import RpcTls, RpcEndpoint

fn config() -> SecurityConfig!String do
  decode_security_config(Bytes.from_utf8(String.join([
    "4", String.repeat("11", 32), String.repeat("22", 32), "8", "2", "2",
    "a #{String.repeat("01", 32)} Morse", "b #{String.repeat("02", 32)} Outside",
    "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb", "3",
    "https://c.example:8443/rpc?key=3", "https://a.example/rpc?key=1", "https://b.example/rpc?key=2",
    "-", "2", "2", "2", "a #{String.repeat("01", 32)} Morse",
    "b #{String.repeat("02", 32)} Outside", String.repeat("1", 32), "morse-main"
  ], "\n")))
end

fn row(origin :: String, pem :: Bytes) -> Bytes!String do
  let length = case Bytes.write_u16_be(String.length(origin)) do
    Err(_) -> return Err("test_length")
    Ok(value) -> value
  end
  mobile_join([length, Bytes.from_utf8(origin), mobile_write_u32(Bytes.length(pem))?, pem], 0, Bytes.empty())
end

fn frame(config :: SecurityConfig, names :: List<String>, pems :: List<Bytes>) -> Bytes!String do
  let rows = for index in 0..List.length(names) do row(List.get(names, index), List.get(pems, index))? end
  mobile_join([Bytes.from_hex("01")?, mobile_byte(List.length(names))?,
    Crypto.sha256(encode_security_config(config)?)] ++ rows, 0, Bytes.empty())
end

fn invalid(value :: Bytes, config :: SecurityConfig) -> Bool do
  case decode_native_rpc_tls(value, config) do
    Err("rpc_tls_config_invalid") -> true
    _ -> false
  end
end

fn proof() -> Bool!String do
  let security = config()?
  let origins = ["https://a.example", "https://b.example", "https://c.example:8443"]
  let pem = Bytes.from_utf8("deferred runtime PEM validation")
  let pems = [pem, Bytes.empty(), pem]
  let present = frame(security, origins, pems)?
  let sources = decode_native_rpc_tls(present, security)?
  assert(List.get(sources, 0).url == List.get(security.rpc_urls, 0))
  assert(case List.get(sources, 0).tls do
    OriginRoots(origin, roots) -> origin == "https://c.example:8443" && Bytes.secure_equals(pem, roots)
    _ -> false
  end)
  assert(case List.get(sources, 2).tls do WebPki -> true
    _ -> false
  end)
  let absent = Bytes.from_hex("0100")?
  for source in decode_native_rpc_tls(absent, security)? do
    assert(case source.tls do WebPki -> true
    _ -> false
  end)
  end
  for malformed in [Bytes.empty(), Bytes.from_hex("01")?, Bytes.from_hex("0200")?,
    Bytes.concat(absent, Bytes.from_hex("00")?)?, Bytes.slice(present, 0, Bytes.length(present)-1)?,
    Bytes.concat(present, Bytes.from_hex("00")?)?, frame(security, origins, [Bytes.empty(), Bytes.empty(), Bytes.empty()])?,
    frame(security, ["https://a.example", "https://a.example", "https://c.example:8443"], pems)?,
    frame(security, ["https://b.example", "https://a.example", "https://c.example:8443"], pems)?] do
    assert(invalid(malformed, security))
  end
  for wrong in ["https://a.example:8443", "https://a.example.evil", "https://A.example",
    "https://a.example:443", "https://a.example/", "https://user@a.example", "http://a.example",
    "https://a.example?x", "https://a.example#x", "https://a.example\\x"] do
    assert(invalid(frame(security, [wrong, "https://b.example", "https://c.example:8443"], pems)?, security))
  end
  let changed = %{security | rpc_urls: ["https://c.example:8443/changed?key=3", "https://a.example/rpc?key=1", "https://b.example/rpc?key=2"]}
  assert(invalid(present, changed))
  assert(invalid(present, %{security | service_public_key: Bytes.from_hex(String.repeat("12",32))?}))
  let too_many = Bytes.from_utf8(String.repeat("x", 32769))
  assert(invalid(frame(security, origins, [too_many, Bytes.empty(), too_many])?, security))
  assert(Test.install_in_memory_secure_store())
  assert(case native_rpc_tls_frame() do Err("rpc_tls_config_unavailable") -> true
    _ -> false
  end)
  assert(Test.set_push_token(Bytes.from_utf8("messenger/rpc-tls-roots/v1"), absent))
  assert(Bytes.secure_equals(native_rpc_tls_frame()?, absent))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/rpc-tls-roots/v1"), Bytes.empty()))
  assert(case native_rpc_tls_frame() do Err("rpc_tls_config_invalid") -> true
    _ -> false
  end)
  Ok(true)
end

test("native RPC resource binds complete exact origins to canonical release bytes without fallback") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
