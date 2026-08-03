from Binary.Reader import BinaryReader, finish, read_fixed, read_vector, reader
from Protocol.V1 import decode_outer_envelope, encode_outer_envelope

pub struct SealedDelivery do
  ephemeral_public_key :: Bytes
  nonce :: Bytes
  ciphertext :: Bytes
end

pub struct AnonymousAbuseToken do
  expires_at :: U64
  nonce :: Int
end

pub struct PrivacySubmission do
  token :: AnonymousAbuseToken
  sealed :: SealedDelivery
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadWide do
  state :: BinaryReader
  value :: U64
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("privacy allocation failed")
    Ok( value) -> Ok(value)
  end
end

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn write_u32(value :: Int) -> Bytes ! String do
  if value < 0 do
    Err("negative privacy integer")
  else
    case U64.parse(Int.to_string(value)) do
      Err( _) -> Err("unparseable privacy integer")
      Ok( wide) -> case Bytes.write_u32_be(wide) do
        Err( _) -> Err("oversized privacy integer #{value}")
        Ok( encoded) -> Ok(encoded)
      end
    end
  end
end

fn write_u64(value :: U64) -> Bytes ! String do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err("unencodable privacy integer")
    Ok( encoded) -> Ok(encoded)
  end
end

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("invalid privacy integer")
    Ok( encoded) -> Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes ! String do
  join([write_u32(Bytes.length(value)) ?, value], 0, Bytes.empty())
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes ! String do
  case read_fixed(state, length) do
    Err( _) -> Err("invalid privacy wire")
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err("invalid privacy wire")
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes ! String do
  case read_vector(state, maximum) do
    Err( _) -> Err("invalid privacy wire")
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err("invalid privacy wire")
  end
end

fn take_u32(state :: BinaryReader) -> ReadInt ! String do
  let bytes = take_fixed(state, 4) ?
  case Bytes.read_u32_be(bytes.value, 0) do
    Err( _) -> Err("invalid privacy integer")
    Ok( value) -> case U64.to_int(value) do
      Err( _) -> Err("invalid privacy integer")
      Ok( parsed) -> Ok(ReadInt {
        state : bytes.state,
        value : parsed
      })
    end
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide ! String do
  let bytes = take_fixed(state, 8) ?
  case Bytes.read_u64_be(bytes.value, 0) do
    Err( _) -> Err("invalid privacy integer")
    Ok( value) -> Ok(ReadWide {
      state : bytes.state,
      value : value
    })
  end
end

fn start(input :: Bytes, maximum :: Int, magic :: String) -> BinaryReader ! String do
  if Bytes.length(input) > maximum do
    Err("privacy wire oversized")
  else
    case reader(input, maximum) do
      Err( _) -> Err("invalid privacy wire")
      Ok( initial) -> do
        let version = take_fixed(initial, 1) ?
        let prefix = take_fixed(version.state, 3) ?
        if !Bytes.secure_equals(version.value, byte(1) ?) || !Bytes.secure_equals(prefix.value,
        Bytes.from_utf8(magic)) do
          Err("invalid privacy wire")
        else
          Ok(prefix.state)
        end
      end
    end
  end
end

fn done(state :: BinaryReader) -> Result <(), String > do
  case finish(state) do
    Err( _) -> Err("invalid privacy wire")
    Ok( _) -> Ok(nil)
  end
end

fn canonical_outer(value :: Bytes) -> Bytes ! String do
  let decoded = case decode_outer_envelope(value) do
    Err( _) -> Err("invalid outer envelope")
    Ok( output) -> Ok(output)
  end ?
  let encoded = case encode_outer_envelope(decoded) do
    Err( _) -> Err("invalid outer envelope")
    Ok( output) -> Ok(output)
  end ?
  if Bytes.secure_equals(value, encoded) do
    Ok(encoded)
  else
    Err("noncanonical outer envelope")
  end
end

fn authenticated(ephemeral_public_key :: Bytes, delivery_public_key :: Bytes) -> Bytes ! String do
  if Bytes.length(ephemeral_public_key) != 32 || Bytes.length(delivery_public_key) != 32 do
    Err("invalid delivery key")
  else
    join([Bytes.from_utf8("mesh-msg/v1/sealed-delivery"), ephemeral_public_key, delivery_public_key],
    0,
    Bytes.empty())
  end
end

fn delivery_key(shared :: SecretBytes, authenticated_data :: Bytes) -> AeadKey ! String do
  let material = case Crypto.hkdf_sha256(shared,
  Crypto.sha256(Bytes.from_utf8("mesh-msg/v1/sealed-delivery-salt")),
  authenticated_data,
  32) do
    Err( _) -> Err("delivery key derivation failed")
    Ok( value) -> Ok(value)
  end ?
  Secret.destroy(shared)
  case Crypto.aead_key(material) do
    Err( _) -> Err("delivery key derivation failed")
    Ok( value) -> Ok(value)
  end
end

pub fn seal_delivery(outer_bytes :: Bytes, delivery_public_key :: X25519PublicKey) -> SealedDelivery ! String do
  let outer = canonical_outer(outer_bytes) ?
  let ephemeral = case Crypto.x25519_generate() do
    Err( _) -> Err("delivery key generation failed")
    Ok( value) -> Ok(value)
  end ?
  let ephemeral_public_key = ephemeral.public_key.bytes
  let authenticated_data = authenticated(ephemeral_public_key, delivery_public_key.bytes) ?
  let shared = case Crypto.x25519_shared(ephemeral.private_key, delivery_public_key) do
    Err( _) -> Err("delivery key agreement failed")
    Ok( value) -> Ok(value)
  end ?
  let key = delivery_key(shared, authenticated_data) ?
  let nonce = case Crypto.random_bytes(12) do
    Err( _) -> Err("delivery nonce generation failed")
    Ok( value) -> Ok(value)
  end ?
  let ciphertext = case Crypto.aead_seal(key, nonce, authenticated_data, outer) do
    Err( _) -> Err("delivery sealing failed")
    Ok( value) -> Ok(value)
  end ?
  Ok(SealedDelivery {
    ephemeral_public_key : ephemeral_public_key,
    nonce : nonce,
    ciphertext : ciphertext
  })
end

pub fn open_delivery(value :: SealedDelivery, delivery_private_seed :: Bytes) -> Bytes ! String do
  if Bytes.length(delivery_private_seed) != 32 || Bytes.length(value.ephemeral_public_key) != 32 || Bytes.length(value.nonce) != 12 || Bytes.length(value.ciphertext) < 16 || Bytes.length(value.ciphertext) > 65622 do
    Err("invalid sealed delivery")
  else
    let delivery = case Crypto.x25519_from_seed(delivery_private_seed) do
      Err( _) -> Err("invalid delivery key")
      Ok( output) -> Ok(output)
    end ?
    let authenticated_data = authenticated(value.ephemeral_public_key, delivery.public_key.bytes) ?
    let shared = case Crypto.x25519_shared(delivery.private_key,
    X25519PublicKey { bytes : value.ephemeral_public_key }) do
      Err( _) -> Err("delivery key agreement failed")
      Ok( output) -> Ok(output)
    end ?
    let key = delivery_key(shared, authenticated_data) ?
    let plaintext = case Crypto.aead_open(key, value.nonce, authenticated_data, value.ciphertext) do
      Err( _) -> Err("delivery opening failed")
      Ok( output) -> Ok(output)
    end ?
    canonical_outer(plaintext)
  end
end

pub fn encode_sealed_delivery(value :: SealedDelivery) -> Bytes ! String do
  if Bytes.length(value.ephemeral_public_key) != 32 || Bytes.length(value.nonce) != 12 || Bytes.length(value.ciphertext) < 16 || Bytes.length(value.ciphertext) > 65622 do
    Err("invalid sealed delivery")
  else
    join([byte(1) ?, Bytes.from_utf8("SED"), value.ephemeral_public_key, value.nonce, vector(value.ciphertext) ?],
    0,
    Bytes.empty())
  end
end

pub fn decode_sealed_delivery(input :: Bytes) -> SealedDelivery ! String do
  let public_key = take_fixed(start(input, 65674, "SED") ?, 32) ?
  let nonce = take_fixed(public_key.state, 12) ?
  let ciphertext = take_vector(nonce.state, 65622) ?
  done(ciphertext.state) ?
  if Bytes.length(ciphertext.value) < 16 do
    Err("invalid sealed delivery")
  else
    Ok(SealedDelivery {
      ephemeral_public_key : public_key.value,
      nonce : nonce.value,
      ciphertext : ciphertext.value
    })
  end
end

fn work_hash(sealed_bytes :: Bytes, expires_at :: U64, nonce :: Int) -> Bytes ! String do
  Ok(Crypto.sha256(join([Bytes.from_utf8("mesh-msg/v1/anonymous-abuse-token"), write_u64(expires_at) ?, write_u32(nonce) ?, Crypto.sha256(sealed_bytes)],
  0,
  Bytes.empty()) ?))
end

fn power_of_two(exponent :: Int, value :: Int) -> Int do
  if exponent <= 0 do
    value
  else
    power_of_two(exponent - 1, value * 2)
  end
end

fn leading_zero_bits(hash :: Bytes, index :: Int, remaining :: Int) -> Bool do
  if remaining <= 0 do
    true
  else
    case Bytes.get(hash, index) do
      Err( _) -> false
      Ok( value) -> if remaining >= 8 do
        value == 0 && leading_zero_bits(hash, index + 1, remaining - 8)
      else
        value < power_of_two(8 - remaining, 1)
      end
    end
  end
end

fn mine(sealed_bytes :: Bytes, expires_at :: U64, difficulty :: Int, nonce :: Int) -> AnonymousAbuseToken ! String do
  if nonce >= 2147483647 do
    Err("abuse token search exhausted")
  else if leading_zero_bits(work_hash(sealed_bytes, expires_at, nonce) ?, 0, difficulty) do
    Ok(AnonymousAbuseToken {
      expires_at : expires_at,
      nonce : nonce
    })
  else
    mine(sealed_bytes, expires_at, difficulty, nonce + 1)
  end
end

pub fn mint_submission(sealed :: SealedDelivery, expires_at :: U64, difficulty :: Int) -> PrivacySubmission ! String do
  if difficulty < 1 || difficulty > 24 do
    Err("invalid abuse difficulty")
  else
    Ok(PrivacySubmission {
      token : mine(encode_sealed_delivery(sealed) ?, expires_at, difficulty, 0) ?,
      sealed : sealed
    })
  end
end

pub fn verify_submission(input :: Bytes, now :: U64, maximum_future :: U64, difficulty :: Int) -> Bool ! String do
  let expires_at = take_u64(start(input, 65694, "PRV") ?) ?
  let nonce = take_u32(expires_at.state) ?
  let sealed = take_vector(nonce.state, 65674) ?
  done(sealed.state) ?
  let _ = decode_sealed_delivery(sealed.value) ?
  if difficulty < 1 || difficulty > 24 do
    Ok(false)
  else
    let latest = case U64.add(now, maximum_future) do
      Err( _) -> Err("invalid abuse token window")
      Ok( value) -> Ok(value)
    end ?
    Ok(U64.compare(expires_at.value, now) >= 0 && U64.compare(expires_at.value, latest) <= 0 && leading_zero_bits(work_hash(sealed.value,
    expires_at.value,
    nonce.value) ?,
    0,
    difficulty))
  end
end

pub fn sealed_delivery_bytes(input :: Bytes) -> Bytes ! String do
  let expires_at = take_u64(start(input, 65694, "PRV") ?) ?
  let nonce = take_u32(expires_at.state) ?
  let sealed = take_vector(nonce.state, 65674) ?
  done(sealed.state) ?
  let _ = decode_sealed_delivery(sealed.value) ?
  Ok(sealed.value)
end

pub fn encode_privacy_submission(value :: PrivacySubmission) -> Bytes ! String do
  join([byte(1) ?, Bytes.from_utf8("PRV"), write_u64(value.token.expires_at) ?, write_u32(value.token.nonce) ?, vector(encode_sealed_delivery(value.sealed) ?) ?],
  0,
  Bytes.empty())
end

pub fn decode_privacy_submission(input :: Bytes) -> PrivacySubmission ! String do
  let expires_at = take_u64(start(input, 65694, "PRV") ?) ?
  let nonce = take_u32(expires_at.state) ?
  let sealed = take_vector(nonce.state, 65674) ?
  done(sealed.state) ?
  Ok(PrivacySubmission {
    token : AnonymousAbuseToken {
      expires_at : expires_at.value,
      nonce : nonce.value
    },
    sealed : decode_sealed_delivery(sealed.value) ?
  })
end
