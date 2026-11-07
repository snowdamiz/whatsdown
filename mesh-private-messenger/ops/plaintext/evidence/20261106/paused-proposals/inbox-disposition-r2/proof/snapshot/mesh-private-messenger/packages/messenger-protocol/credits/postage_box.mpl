from Credits.ActionWire import (
  CreditActionSubmission,
  encode_credit_action_submission,
  decode_credit_action_submission
)
from Privacy.Edge import decode_sealed_delivery
from Identity.Device import is_retryable_verification_crypto_error

# Structural carrier only: callers still authenticate the witnessed recipient
# snapshot/policy and the core verifies tokens before granting any delivery.
# One padded credit box binds the full ordered set of up to8 encrypted deliveries.
pub struct SealedPostageBatch do
  deliveries :: List<Bytes>
  credit_box :: Bytes
end

struct ReadPostageDeliveries do
  deliveries :: List<Bytes>
  offset :: Int
end

fn postage_join(parts :: List<Bytes>, maximum :: Int) -> Bytes!String do
  let builder = case BytesBuilder.new(maximum) do
    Err(_) -> return Err("invalid_postage_box")
    Ok(value) -> value
  end
  for part in parts do
    case BytesBuilder.write_bytes(builder, part) do
      Err(_) -> return Err("invalid_postage_box")
      Ok(_) -> nil
    end
  end
  case BytesBuilder.finish(builder) do
    Err(_) -> Err("invalid_postage_box")
    Ok(value)
  end
end

fn postage_size(value :: Int) -> Bytes!String do
  case Bytes.write_u32_be(U64.parse(Int.to_string(value))?) do
    Err(_) -> Err("invalid_postage_box")
    Ok(value)
  end
end

fn postage_count(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid_postage_box")
    Ok(value)
  end
end

fn checked_postage_deliveries(deliveries :: List<Bytes>) -> Result<(), String> do
  if List.length(deliveries) < 1 || List.length(deliveries) > 8 do
    return Err("invalid_postage_batch")
  end
  for index in 0..List.length(deliveries) do
    let delivery = List.get(deliveries, index)
    decode_sealed_delivery(delivery)?
    for previous in 0..index do
      if Bytes.secure_equals(delivery, List.get(deliveries, previous)) do
        return Err("duplicate_postage_delivery")
      end
    end
  end
  Ok(nil)
end

# Ordered hash transcript stays below400 bytes; each frame hash uses only the
# pre-existing sealed-delivery bound (65674). No aggregate crypto input grows.
pub fn postage_batch_digest(deliveries :: List<Bytes>) -> Bytes!String do
  checked_postage_deliveries(deliveries)?
  let hashes = for delivery in deliveries do
    postage_join([postage_size(Bytes.length(delivery))?, Crypto.sha256(delivery)], 36)?
  end
  Ok(Crypto.sha256(postage_join([
      Bytes.from_utf8("morse-credit-postage-batch-v1"),
      postage_count(List.length(deliveries))?
    ]
      ++ hashes,
    400)?))
end

fn postage_info() -> Bytes do
  Bytes.from_utf8("morse-credit-postage-box-v1")
end

fn postage_aad(core :: X25519PublicKey, deliveries :: List<Bytes>) -> Bytes!String do
  postage_join([core.bytes, postage_batch_digest(deliveries)?], 64)
end

fn postage_cap(value :: CreditActionSubmission) -> Bytes!String do
  if value.action.kind != 3
    || Bytes.length(value.request_body) > 1024
    || !List.contains([1, 5, 25], List.length(value.frame.tokens)) do
    return Err("invalid_postage_credit_submission")
  end
  let encoded = encode_credit_action_submission(value)?
  if Bytes.length(encoded) > 16378 do
    return Err("invalid_postage_credit_submission")
  end
  Ok(encoded)
end

fn padded_postage_cap(value :: CreditActionSubmission) -> Bytes!String do
  let encoded = postage_cap(value)?
  let length = case Bytes.write_u16_be(Bytes.length(encoded)) do
    Err(_) -> return Err("invalid_postage_box")
    Ok(value) -> value
  end
  let padding = case Bytes.repeat(0, 16378 - Bytes.length(encoded)) do
    Err(_) -> return Err("invalid_postage_box")
    Ok(value) -> value
  end
  postage_join([Bytes.from_hex("01504350")?, length, encoded, padding], 16384)
end

fn unpack_postage_cap(plaintext :: Bytes) -> CreditActionSubmission!String do
  if Bytes.length(plaintext) != 16384
    || Bytes.to_hex(Bytes.slice(plaintext, 0, 4)?) != "01504350" do
    return Err("invalid_postage_box")
  end
  let length = case Bytes.read_u16_be(plaintext, 4) do
    Err(_) -> return Err("invalid_postage_box")
    Ok(value) -> value
  end
  if length < 129 || length > 16378 do
    return Err("invalid_postage_box")
  end
  let padding = case Bytes.repeat(0, 16378 - length) do
    Err(_) -> return Err("invalid_postage_box")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(Bytes.slice(plaintext, 6 + length, 16378 - length)?, padding) do
    return Err("invalid_postage_box")
  end
  let value = decode_credit_action_submission(Bytes.slice(plaintext, 6, length)?)?
  postage_cap(value)?
  Ok(value)
end

pub fn seal_postage_credit_box(core :: X25519PublicKey,
  deliveries :: List<Bytes>,
  submission :: CreditActionSubmission) -> Bytes!String do
  let plaintext = padded_postage_cap(submission)?
  let sealed = case Crypto.hpke_seal(core,
    postage_info(),
    postage_aad(core, deliveries)?,
    plaintext) do
    Err(_) -> return Err("postage_box_crypto_failed")
    Ok(value) -> value
  end
  if Bytes.length(sealed) != 16432 do
    return Err("invalid_postage_box")
  end
  postage_join([Bytes.from_hex("01504342")?, sealed], 16436)
end

fn valid_postage_credit_box(value :: Bytes) -> Bool!String do
  Ok(Bytes.length(value) == 16436 && Bytes.to_hex(Bytes.slice(value, 0, 4)?) == "01504342")
end

pub fn open_postage_credit_box(core :: borrow X25519PrivateKey,
  deliveries :: List<Bytes>,
  credit_box :: Bytes) -> CreditActionSubmission!String do
  if !valid_postage_credit_box(credit_box)? do
    return Err("invalid_postage_box")
  end
  let public_key = case Crypto.x25519_public(core) do
    Err(_) -> return Err("postage_box_crypto_failed")
    Ok(value) -> value
  end
  let plaintext = case Crypto.hpke_open(core,
    postage_info(),
    postage_aad(public_key, deliveries)?,
    Bytes.slice(credit_box, 4, 16432)?) do
    Err(error) -> return Err(if is_retryable_verification_crypto_error(error) do
      "postage_box_crypto_failed"
    else
      "invalid_postage_box"
    end)
    Ok(value) -> value
  end
  unpack_postage_cap(plaintext)
end

pub fn encode_sealed_postage_batch(value :: SealedPostageBatch) -> Bytes!String do
  checked_postage_deliveries(value.deliveries)?
  if !valid_postage_credit_box(value.credit_box)? do
    return Err("invalid_postage_box")
  end
  let parts = for delivery in value.deliveries do
    postage_join([postage_size(Bytes.length(delivery))?, delivery], 65678)?
  end
  postage_join([Bytes.from_hex("01505342")?, postage_count(List.length(value.deliveries))?]
      ++ parts
      ++ [value.credit_box],
    541865)
end

fn read_postage_deliveries(input :: Bytes,
  count :: Int,
  offset :: Int,
  values :: List<Bytes>) -> ReadPostageDeliveries!String do
  if count == 0 do
    Ok(ReadPostageDeliveries { deliveries: List.reverse(values), offset: offset })
  else
    if offset + 4 > Bytes.length(input) - 16436 do
      return Err("invalid_postage_batch")
    end
    let length = case Bytes.read_u32_be(input, offset) do
      Err(_) -> return Err("invalid_postage_batch")
      Ok(value) -> U64.to_int(value)?
    end
    if length < 68 || length > 65674 || offset + 4 + length > Bytes.length(input) - 16436 do
      return Err("invalid_postage_batch")
    end
    let delivery = Bytes.slice(input, offset + 4, length)?
    read_postage_deliveries(input, count - 1, offset + 4 + length, [delivery] ++ values)
  end
end

pub fn decode_sealed_postage_batch(input :: Bytes) -> SealedPostageBatch!String do
  if Bytes.length(input) < 16513
    || Bytes.length(input) > 541865
    || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01505342" do
    return Err("invalid_postage_batch")
  end
  let count = Bytes.get(input, 4)?
  if count < 1 || count > 8 do
    return Err("invalid_postage_batch")
  end
  let read = read_postage_deliveries(input, count, 5, [])?
  if read.offset + 16436 != Bytes.length(input) do
    return Err("invalid_postage_batch")
  end
  let value = SealedPostageBatch {
    deliveries: read.deliveries,
    credit_box: Bytes.slice(input, read.offset, 16436)?
  }
  encode_sealed_postage_batch(value)?
  Ok(value)
end
