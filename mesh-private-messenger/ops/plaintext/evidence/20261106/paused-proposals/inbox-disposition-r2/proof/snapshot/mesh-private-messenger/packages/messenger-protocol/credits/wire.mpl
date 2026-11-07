# RFC 9578 type 0x0002 framing. These codecs do not authenticate a token;
# Credits.Token verifies signatures and the core atomically spends nullifiers.
pub struct CreditTokenInput do
  nonce :: Bytes
  challenge_digest :: Bytes
  token_key_id :: Bytes
end

pub struct CreditToken do
  input :: CreditTokenInput
  authenticator :: Bytes
end

pub struct CreditTokenRequest do
  truncated_key_id :: Int
  blinded_message :: Bytes
end

pub struct CreditFrame do
  binding :: Bytes
  tokens :: List<CreditToken>
end

fn byte_list(values :: List<Int>) -> Bytes!String do
  case Bytes.from_list(values) do
    Ok(value)
    Err(_) -> Err("invalid_credit_wire")
  end
end

fn read_u16(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_be(input, offset) do
    Ok(value)
    Err(_) -> Err("invalid_credit_wire")
  end
end

fn write_u16(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Ok(encoded)
    Err(_) -> Err("invalid_credit_wire")
  end
end

fn cat(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    cat(parts, index + 1, Bytes.concat(output, List.get(parts, index))?)
  end
end

pub fn encode_token_input(value :: CreditTokenInput) -> Bytes!String do
  if Bytes.length(value.nonce) != 32
    || Bytes.length(value.challenge_digest) != 32
    || Bytes.length(value.token_key_id) != 32 do
    return Err("invalid_credit_token_input")
  end
  cat([Bytes.from_hex("0002")?, value.nonce, value.challenge_digest, value.token_key_id],
    0,
    Bytes.empty())
end

pub fn decode_token_input(input :: Bytes) -> CreditTokenInput!String do
  if Bytes.length(input) != 98 || read_u16(input, 0)? != 2 do
    return Err("invalid_credit_token_input")
  end
  Ok(CreditTokenInput {
    nonce: Bytes.slice(input, 2, 32)?,
    challenge_digest: Bytes.slice(input, 34, 32)?,
    token_key_id: Bytes.slice(input, 66, 32)?
  })
end

pub fn encode_credit_token(value :: CreditToken) -> Bytes!String do
  if Bytes.length(value.authenticator) != 256 do
    return Err("invalid_credit_token")
  end
  Bytes.concat(encode_token_input(value.input)?, value.authenticator)
end

pub fn decode_credit_token(input :: Bytes) -> CreditToken!String do
  if Bytes.length(input) != 354 do
    return Err("invalid_credit_token")
  end
  Ok(CreditToken {
    input: decode_token_input(Bytes.slice(input, 0, 98)?)?,
    authenticator: Bytes.slice(input, 98, 256)?
  })
end

pub fn encode_token_request(value :: CreditTokenRequest) -> Bytes!String do
  if value.truncated_key_id < 0
    || value.truncated_key_id > 255
    || Bytes.length(value.blinded_message) != 256 do
    return Err("invalid_credit_token_request")
  end
  Bytes.concat(byte_list([0, 2, value.truncated_key_id])?, value.blinded_message)
end

pub fn decode_token_request(input :: Bytes) -> CreditTokenRequest!String do
  if Bytes.length(input) != 259 || read_u16(input, 0)? != 2 do
    return Err("invalid_credit_token_request")
  end
  Ok(CreditTokenRequest {
    truncated_key_id: Bytes.get(input, 2)?,
    blinded_message: Bytes.slice(input, 3, 256)?
  })
end

pub fn credit_nullifier(value :: CreditTokenInput) -> Bytes!String do
  Ok(Crypto.sha256(encode_token_input(value)?))
end

# The opaque challenge is common to every client of a pinned service/purpose.
# It contains no purchase, wallet, amount, user, timestamp or request identifier.
pub fn credit_challenge(service_key :: Bytes, purpose :: Int) -> Bytes!String do
  if Bytes.length(service_key) != 32 || (purpose != 0 && purpose != 1) do
    return Err("invalid_credit_challenge")
  end
  cat([Bytes.from_utf8("morse-credit-v1"), byte_list([0])?, service_key, byte_list([purpose])?],
    0,
    Bytes.empty())
end

fn frame_nullifiers(value :: CreditFrame) -> List<Bytes>!String do
  let count = List.length(value.tokens)
  # The most expensive launch extra is 50 credits. Bound every request to 64
  # signatures, independent of the number of tokens in a purchased pack.
  if count < 1 || count > 64 || Bytes.length(value.binding) != 32 do
    return Err("invalid_credit_frame")
  end
  let nullifiers = for token in value.tokens do
    encode_credit_token(token)?
    credit_nullifier(token.input)?
  end
  for index in 0..count do
    let candidate = List.get(nullifiers, index)
    for earlier in 0..index do
      if Bytes.secure_equals(candidate, List.get(nullifiers, earlier)) do
        return Err("duplicate_credit_token")
      end
    end
  end
  Ok(nullifiers)
end

pub fn encode_credit_frame(value :: CreditFrame) -> Bytes!String do
  frame_nullifiers(value)?
  let header = cat([
      Bytes.from_hex("01435244")?,
      value.binding,
      write_u16(List.length(value.tokens))?
    ],
    0,
    Bytes.empty())?
  let encoded = for token in value.tokens do
    encode_credit_token(token)?
  end
  cat(encoded, 0, header)
end

pub fn decode_credit_frame(input :: Bytes) -> CreditFrame!String do
  let length = Bytes.length(input)
  if length < 392 || length > 22694 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01435244" do
    return Err("invalid_credit_frame")
  end
  let count = read_u16(input, 36)?
  if count < 1 || count > 64 || length != 38 + count * 354 do
    return Err("invalid_credit_frame")
  end
  let tokens = for index in 0..count do
    decode_credit_token(Bytes.slice(input, 38 + index * 354, 354)?)?
  end
  let value = CreditFrame { binding: Bytes.slice(input, 4, 32)?, tokens: tokens }
  frame_nullifiers(value)?
  Ok(value)
end

# Only framing/binding is checked here. A successful result is not permission
# to perform an action: the verifier and the shared spent-set transaction follow.
pub fn check_credit_frame(value :: CreditFrame,
  request_body :: Bytes,
  expected_credits :: Int) -> List<Bytes>!String do
  if expected_credits < 1
    || expected_credits > 64
    || List.length(value.tokens) != expected_credits do
    return Err("credit_amount_mismatch")
  end
  if !Bytes.secure_equals(value.binding, Crypto.sha256(request_body)) do
    return Err("credit_binding_mismatch")
  end
  frame_nullifiers(value)
end
