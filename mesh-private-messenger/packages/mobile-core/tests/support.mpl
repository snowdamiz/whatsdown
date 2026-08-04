pub fn append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("test byte concatenation failed")
    Ok( value) -> Ok(value)
  end
end

pub fn write_u32(value :: Int) -> Bytes ! String do
  let wide = case U64.parse(Int.to_string(value)) do
    Err( _) -> Err("test integer conversion failed")
    Ok( parsed) -> Ok(parsed)
  end ?
  case Bytes.write_u32_be(wide) do
    Err( _) -> Err("test integer encoding failed")
    Ok( encoded) -> Ok(encoded)
  end
end

pub fn read_u32(value :: Bytes) -> Int ! String do
  case Bytes.read_u32_be(value, 0) do
    Err( _) -> Err("test integer decoding failed")
    Ok( wide) -> case U64.to_int(wide) do
      Err( _) -> Err("test integer conversion failed")
      Ok( parsed) -> Ok(parsed)
    end
  end
end

pub fn vector(value :: Bytes) -> Bytes ! String do
  append(write_u32(Bytes.length(value)) ?, value)
end

pub fn repeated(value :: Int, length :: Int) -> Bytes ! String do
  case Bytes.repeat(value, length) do
    Err( _) -> Err("test byte allocation failed")
    Ok( output) -> Ok(output)
  end
end

pub fn database_path(label :: String) -> String ! String do
  case Crypto.random_bytes(8) do
    Err( _) -> Err("test path generation failed")
    Ok( value) -> Ok("/tmp/mesh_mobile_" <> label <> "_" <> Bytes.to_hex(value) <> ".db")
  end
end

pub fn install_security_config(service_public_key :: Bytes,
witness_a_public_key :: Bytes,
witness_b_public_key :: Bytes,
delivery_public_key :: Bytes,
difficulty :: Int) -> Bool do
  Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
  Bytes.from_utf8("1\n" <> Bytes.to_hex(service_public_key) <> "\n" <> Bytes.to_hex(witness_a_public_key) <> "\n" <> Bytes.to_hex(witness_b_public_key) <> "\n" <> Bytes.to_hex(delivery_public_key) <> "\n" <> Int.to_string(difficulty)))
end
