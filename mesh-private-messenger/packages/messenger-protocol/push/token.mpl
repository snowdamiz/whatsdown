from Binary.Reader import BinaryReader, finish, read_fixed, read_u8, read_vector, reader

pub struct SealedProviderToken do
  ephemeral_public_key :: Bytes
  nonce :: Bytes
  ciphertext :: Bytes
end

pub struct PushWakeRequest do
  version :: Int
  wake_token_hash :: Bytes
  provider :: Int
  sealed_provider_token :: Bytes
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("push token allocation failed")
    Ok(output) -> Ok(output)
  end
end

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid push token byte")
    Ok(output) -> Ok(output)
  end
end

fn vector(value :: Bytes) -> Bytes ! String do
  let length = U64.parse(Int.to_string(Bytes.length(value))) ?
  let prefix = case Bytes.write_u32_be(length) do
    Err(_) -> Err("invalid push token length")
    Ok(output) -> Ok(output)
  end ?
  join([prefix, value], 0, Bytes.empty())
end

fn start(input :: Bytes, maximum :: Int) -> BinaryReader ! String do
  if Bytes.length(input) > maximum do
    Err("push token wire oversized")
  else
    case reader(input, maximum) do
      Err(_) -> Err("invalid push token wire")
      Ok(output) -> Ok(output)
    end
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes ! String do
  case read_fixed(state, length) do
    Err(_) -> Err("invalid push token wire")
    Ok((next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt ! String do
  case read_u8(state) do
    Err(_) -> Err("invalid push token wire")
    Ok((next, value)) -> Ok(ReadInt {
      state : next,
      value : value
    })
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes ! String do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid push token wire")
    Ok((next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
  end
end

fn done(state :: BinaryReader) -> Result <(), String > do
  case finish(state) do
    Err(_) -> Err("invalid push token wire")
    Ok(_) -> Ok(nil)
  end
end

fn matches(input :: Bytes, expected :: Bytes, index :: Int) -> Bool do
  if index >= Bytes.length(expected) do
    true
  else
    case Bytes.get(input, index) do
      Err(_) -> false
      Ok(actual) -> case Bytes.get(expected, index) do
        Err(_) -> false
        Ok(wanted) -> actual == wanted && matches(input, expected, index + 1)
      end
    end
  end
end

fn printable(input :: Bytes, index :: Int) -> Bool do
  if index >= Bytes.length(input) do
    true
  else
    case Bytes.get(input, index) do
      Err(_) -> false
      Ok(value) -> value >= 33 && value <= 126 && printable(input, index + 1)
    end
  end
end

fn valid_provider_token(token :: Bytes) -> Bool do
  let length = Bytes.length(token)
  let expo = Bytes.from_utf8("ExpoPushToken[")
  let exponent = Bytes.from_utf8("ExponentPushToken[")
  if length < 20 || length > 512 || !printable(token, 0) do
    false
  else
    case Bytes.get(token, length - 1) do
      Err(_) -> false
      Ok(ending) -> ending == 93 && (matches(token, expo, 0) || matches(token, exponent, 0))
    end
  end
end

fn authenticated(ephemeral_public_key :: Bytes, broker_public_key :: Bytes) -> Bytes ! String do
  if Bytes.length(ephemeral_public_key) != 32 || Bytes.length(broker_public_key) != 32 do
    Err("invalid push broker key")
  else
    join([Bytes.from_utf8("mesh-msg/v1/push-provider-token"), ephemeral_public_key, broker_public_key],
    0,
    Bytes.empty())
  end
end

fn token_key(shared :: SecretBytes, authenticated_data :: Bytes) -> AeadKey ! String do
  let material = case Crypto.hkdf_sha256(shared,
  Crypto.sha256(Bytes.from_utf8("mesh-msg/v1/push-provider-token-salt")),
  authenticated_data,
  32) do
    Err(_) -> Err("push token key derivation failed")
    Ok(output) -> Ok(output)
  end ?
  Secret.destroy(shared)
  case Crypto.aead_key(material) do
    Err(_) -> Err("push token key derivation failed")
    Ok(output) -> Ok(output)
  end
end

fn encode_sealed(value :: SealedProviderToken) -> Bytes ! String do
  if Bytes.length(value.ephemeral_public_key) != 32 || Bytes.length(value.nonce) != 12 || Bytes.length(value.ciphertext) < 36 || Bytes.length(value.ciphertext) > 528 do
    Err("invalid sealed provider token")
  else
    join([byte(1) ?, Bytes.from_utf8("SPT"), value.ephemeral_public_key, value.nonce, vector(value.ciphertext) ?],
    0,
    Bytes.empty())
  end
end

fn decode_sealed(input :: Bytes) -> SealedProviderToken ! String do
  let version = take_u8(start(input, 580) ?) ?
  let magic = take_fixed(version.state, 3) ?
  let public_key = take_fixed(magic.state, 32) ?
  let nonce = take_fixed(public_key.state, 12) ?
  let ciphertext = take_vector(nonce.state, 528) ?
  done(ciphertext.state) ?
  if version.value != 1 || !Bytes.secure_equals(magic.value, Bytes.from_utf8("SPT")) || Bytes.length(ciphertext.value) < 36 do
    Err("invalid sealed provider token")
  else
    Ok(SealedProviderToken {
      ephemeral_public_key : public_key.value,
      nonce : nonce.value,
      ciphertext : ciphertext.value
    })
  end
end

pub fn valid_sealed_provider_token(input :: Bytes) -> Bool do
  case decode_sealed(input) do
    Err(_) -> false
    Ok(value) -> case encode_sealed(value) do
      Err(_) -> false
      Ok(canonical) -> Bytes.secure_equals(canonical, input)
    end
  end
end

pub fn seal_provider_token(token :: Bytes, broker_public_key :: X25519PublicKey) -> Bytes ! String do
  if !valid_provider_token(token) do
    Err("invalid provider token")
  else
    let ephemeral = case Crypto.x25519_generate() do
      Err(_) -> Err("push token key generation failed")
      Ok(output) -> Ok(output)
    end ?
    let authenticated_data = authenticated(ephemeral.public_key.bytes, broker_public_key.bytes) ?
    let shared = case Crypto.x25519_shared(ephemeral.private_key, broker_public_key) do
      Err(_) -> Err("push token key agreement failed")
      Ok(output) -> Ok(output)
    end ?
    let key = token_key(shared, authenticated_data) ?
    let nonce = case Crypto.random_bytes(12) do
      Err(_) -> Err("push token nonce generation failed")
      Ok(output) -> Ok(output)
    end ?
    let ciphertext = case Crypto.aead_seal(key, nonce, authenticated_data, token) do
      Err(_) -> Err("push token sealing failed")
      Ok(output) -> Ok(output)
    end ?
    encode_sealed(SealedProviderToken {
      ephemeral_public_key : ephemeral.public_key.bytes,
      nonce : nonce,
      ciphertext : ciphertext
    })
  end
end

pub fn open_provider_token_with_key(input :: Bytes, broker_private_key :: borrow X25519PrivateKey) -> Bytes ! String do
  let sealed = decode_sealed(input) ?
  let broker_public_key = case Crypto.x25519_public(broker_private_key) do
    Err(_) -> Err("invalid push broker key")
    Ok(output) -> Ok(output)
  end ?
  let authenticated_data = authenticated(sealed.ephemeral_public_key, broker_public_key.bytes) ?
  let shared = case Crypto.x25519_shared(broker_private_key,
  X25519PublicKey { bytes : sealed.ephemeral_public_key }) do
    Err(_) -> Err("push token key agreement failed")
    Ok(output) -> Ok(output)
  end ?
  let key = token_key(shared, authenticated_data) ?
  let token = case Crypto.aead_open(key, sealed.nonce, authenticated_data, sealed.ciphertext) do
    Err(_) -> Err("push token opening failed")
    Ok(output) -> Ok(output)
  end ?
  if valid_provider_token(token) do
    Ok(token)
  else
    Err("invalid provider token")
  end
end

pub fn open_provider_token(input :: Bytes, broker_private_seed :: Bytes) -> Bytes ! String do
  if Bytes.length(broker_private_seed) != 32 do
    Err("invalid push broker key")
  else
    let broker = case Crypto.x25519_from_seed(broker_private_seed) do
      Err(_) -> Err("invalid push broker key")
      Ok(output) -> Ok(output)
    end ?
    open_provider_token_with_key(input, broker.private_key)
  end
end

pub fn encode_push_wake(value :: PushWakeRequest) -> Bytes ! String do
  if value.version != 1 || Bytes.length(value.wake_token_hash) != 32 || value.provider != 1 do
    Err("invalid push wake")
  else
    let sealed = decode_sealed(value.sealed_provider_token) ?
    let canonical = encode_sealed(sealed) ?
    if !Bytes.secure_equals(canonical, value.sealed_provider_token) do
      Err("noncanonical sealed provider token")
    else
      join([byte(1) ?, Bytes.from_utf8("PWK"), value.wake_token_hash, byte(value.provider) ?, vector(canonical) ?],
      0,
      Bytes.empty())
    end
  end
end

pub fn decode_push_wake(input :: Bytes) -> PushWakeRequest ! String do
  let version = take_u8(start(input, 621) ?) ?
  let magic = take_fixed(version.state, 3) ?
  let wake_token_hash = take_fixed(magic.state, 32) ?
  let provider = take_u8(wake_token_hash.state) ?
  let sealed = take_vector(provider.state, 580) ?
  done(sealed.state) ?
  let value = PushWakeRequest {
    version : version.value,
    wake_token_hash : wake_token_hash.value,
    provider : provider.value,
    sealed_provider_token : sealed.value
  }
  if !Bytes.secure_equals(magic.value, Bytes.from_utf8("PWK")) do
    Err("invalid push wake wire")
  else
    let canonical = encode_push_wake(value) ?
    if Bytes.secure_equals(canonical, input) do
      Ok(value)
    else
      Err("noncanonical push wake")
    end
  end
end
