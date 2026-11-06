pub fn install_security_config(service_public_key :: Bytes,
  witness_a_public_key :: Bytes,
  witness_b_public_key :: Bytes,
  delivery_public_key :: Bytes,
  difficulty :: Int) -> Bool do
  Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    Bytes.from_utf8("1\n"
      <> Bytes.to_hex(service_public_key)
      <> "\n"
      <> Bytes.to_hex(witness_a_public_key)
      <> "\n"
      <> Bytes.to_hex(witness_b_public_key)
      <> "\n"
      <> Bytes.to_hex(delivery_public_key)
      <> "\n"
      <> Int.to_string(difficulty)))
end
