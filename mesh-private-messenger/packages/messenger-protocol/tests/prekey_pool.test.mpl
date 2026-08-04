from Prekeys.Pool import PrekeyPublishRequest, PrekeyPublishResponse, decode_prekey_publish, decode_prekey_publish_response, encode_prekey_publish, encode_prekey_publish_response

fn repeated(value :: Int, length :: Int) -> Bytes ! String do
  case Bytes.repeat(value, length) do
    Err( _) -> Err("test allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("test allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn ids(index :: Int, count :: Int, output :: List < U64 >) -> List < U64 > ! String do
  if index >= count do
    Ok(output)
  else
    ids(index + 1, count, List.append(output, U64.parse(Int.to_string(index + 1)) ?))
  end
end

fn proof() -> Bool ! String do
  let response = PrekeyPublishResponse {
    account_id : repeated(1, 32) ?,
    device_id : repeated(2, 16) ?,
    active_ids : [U64.parse("2") ?, U64.parse("9") ?]
  }
  let encoded = encode_prekey_publish_response(response) ?
  let decoded = decode_prekey_publish_response(encoded) ?
  assert(Bytes.length(encoded) == 69)
  assert(Bytes.secure_equals(decoded.account_id, response.account_id))
  assert(Bytes.secure_equals(decoded.device_id, response.device_id))
  assert(List.length(decoded.active_ids) == 2)
  assert(U64.compare(List.get(decoded.active_ids, 0), U64.parse("2") ?) == 0)
  assert(U64.compare(List.get(decoded.active_ids, 1), U64.parse("9") ?) == 0)
  case decode_prekey_publish_response(append(encoded, repeated(0, 1) ?) ?) do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  case encode_prekey_publish_response(% { response | active_ids : [U64.parse("9") ?, U64.parse("2") ?] }) do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  case encode_prekey_publish_response(% { response | active_ids : ids(0, 65, List.new()) ? }) do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  let empty = decode_prekey_publish_response(encode_prekey_publish_response(% { response | active_ids : List.new() }) ?) ?
  assert(List.length(empty.active_ids) == 0)
  let recovery = encode_prekey_publish(PrekeyPublishRequest {
    account_id : response.account_id,
    device_id : response.device_id,
    prekeys : List.new(),
    signature : repeated(3, 64) ?
  }) ?
  assert(Bytes.length(recovery) == 117)
  assert(List.length(decode_prekey_publish(recovery) ?.prekeys) == 0)
  Ok(true)
end

test("publication acknowledgement identifies the exact active server prekeys") do
  case proof() do
    Err( _) -> assert(false)
    Ok( value) -> assert(value)
  end
end
