from Mobile.Codec import mobile_join, mobile_vector, mobile_byte

fn fields_at(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    fields_at(values, index + 1, Bytes.concat(output, mobile_vector(List.get(values, index))?)?)
  end
end

pub fn fields(values :: List<Bytes>) -> Bytes!String do
  fields_at(values, 0, Bytes.empty())
end

pub fn intent(path :: String, value :: Int) -> Bytes!String do
  fields([Bytes.from_utf8(path), mobile_byte(value)?])
end

pub fn complete(path :: String, action :: Bytes, outcome :: Int) -> Bytes!String do
  fields([Bytes.from_utf8(path), action, mobile_byte(outcome)?])
end

pub fn config(port :: Int) -> Result<(), String> do
  let broker = case Crypto.x25519_generate() do
    Err(_) -> return Err("test broker generation failed")
    Ok(value) -> value
  end
  if !(Test.set_push_token(Bytes.from_utf8("expo/config/v1"),
    Bytes.from_utf8("1\n01234567-89ab-cdef-0123-456789abcdef\n"
      <> Bytes.to_hex(broker.public_key.bytes)))) do
    return Err("push fixture configuration failed")
  end
  let origin = "http://127.0.0.1:" <> Int.to_string(port)
  if !(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("2\n1\n"
      <> origin
      <> "\n"
      <> origin
      <> "\n"
      <> origin
      <> "\nws://127.0.0.1:"
      <> Int.to_string(port)
      <> "/v1/mailbox/stream\n1"))) do
    return Err("push fixture configuration failed")
  end
  if !(Test.set_push_token(Bytes.from_utf8("expo/raw/v1"),
    Bytes.concat(mobile_join([mobile_byte(1)?, mobile_byte(1)?, mobile_byte(1)?],
        0,
        Bytes.empty())?,
      fields([Bytes.from_utf8("app.morse.test"), Bytes.from_utf8("device-token")])?)?)) do
    return Err("push fixture configuration failed")
  end
  Ok(nil)
end
