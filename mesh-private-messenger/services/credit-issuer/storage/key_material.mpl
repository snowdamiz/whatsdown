from Credits.Issuer import CreditIssuerKey, issuer_key_id

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_issuer_row")
  end
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_issuer_row")
  end
end

pub fn issuer_key_context(service_key :: Bytes,
  object_id :: Bytes,
  purpose :: Int) -> Bytes!String do
  if Bytes.length(service_key) != 32 || Bytes.length(object_id) != 32 do
    return Err("invalid_issuer_context")
  end
  Bytes.from_hex("01"
    <> Bytes.to_hex(service_key)
    <> String.repeat("00", 48)
    <> Bytes.to_hex(object_id)
    <> (if purpose == 18 do
      "0012"
    else
      "0006"
    end)
    <> "0000000000000001")
end

pub fn issuer_quote_key_context(service_key :: Bytes, id :: Bytes) -> Bytes!String do
  issuer_key_context(service_key,
    Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-credit-quote-key-v1"), id)?),
    6)
end

pub fn issuer_key_rows(conn :: borrow PgConn, id :: Bytes) -> List<Map<String, DbValue>>!String do
  Pg.query_values(conn,
    "SELECT key_id, epoch::text, purpose::text, spki, quote_public_key, sealed_private_key, sealed_quote_key, admitted_evidence FROM issuer_keys WHERE key_id = $1 FOR SHARE",
    [Binary(id)])
end

pub fn issuer_key_from_row(row :: Map<String, DbValue>) -> CreditIssuerKey!String do
  let purpose = case String.to_int(text(Map.get(row, "purpose"))?) do
    Some(value) -> value
    None -> return Err("invalid_issuer_row")
  end
  let key = CreditIssuerKey {
    epoch: U64.parse(text(Map.get(row, "epoch"))?)?,
    purpose: purpose,
    spki: binary(Map.get(row, "spki"))?,
    quote_public_key: binary(Map.get(row, "quote_public_key"))?
  }
  if !Bytes.secure_equals(issuer_key_id(key)?, binary(Map.get(row, "key_id"))?) do
    return Err("invalid_issuer_row")
  end
  Ok(key)
end
