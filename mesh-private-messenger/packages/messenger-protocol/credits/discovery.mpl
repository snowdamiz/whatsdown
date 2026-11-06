pub struct CreditIssuerQuery do
  purpose :: Int
  previous_size :: U64
end

pub fn encode_credit_issuer_query(query :: CreditIssuerQuery) -> Bytes!String do
  if query.purpose != 0 && query.purpose != 1 do
    return Err("invalid_credit_issuer_query")
  end
  let purpose = case Bytes.from_list([query.purpose]) do
    Err(_) -> return Err("invalid_credit_issuer_query")
    Ok(value) -> value
  end
  let size = case Bytes.write_u64_be(query.previous_size) do
    Err(_) -> return Err("invalid_credit_issuer_query")
    Ok(value) -> value
  end
  Bytes.concat(Bytes.concat(Bytes.from_hex("0143494b")?, purpose)?, size)
end

pub fn decode_credit_issuer_query(input :: Bytes) -> CreditIssuerQuery!String do
  if Bytes.length(input) != 13 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "0143494b" do
    return Err("invalid_credit_issuer_query")
  end
  let purpose = Bytes.get(input, 4)?
  if purpose != 0 && purpose != 1 do
    return Err("invalid_credit_issuer_query")
  end
  let size = case Bytes.read_u64_be(input, 5) do
    Err(_) -> return Err("invalid_credit_issuer_query")
    Ok(value) -> value
  end
  Ok(CreditIssuerQuery { purpose: purpose, previous_size: size })
end
