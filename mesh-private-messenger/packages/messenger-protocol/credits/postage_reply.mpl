from Credits.ActionWire import decode_credit_action_receipt
from Credits.Cancellation import decode_credit_cancellation
from Credits.PostageBox import postage_batch_digest
from Identity.Device import is_retryable_verification_crypto_error

# Response privacy only. HPKE base mode does not authenticate the core sender:
# after opening, the caller MUST verify the CAR/CCR signature with its pinned
# core key and exact saved submission before changing any reservation.
fn reply_checked_receipt(value :: Bytes) -> Bytes!String do
  if Bytes.length(value) < 4 || Bytes.length(value) > 462 do
    return Err("invalid_postage_reply")
  end
  let magic = Bytes.to_hex(Bytes.slice(value, 0, 4)?)
  if magic == "01434152" do
    decode_credit_action_receipt(value)?
    nil
  else if magic == "01434352" do
    decode_credit_cancellation(value)?
    nil
  else
    return Err("invalid_postage_reply")
  end
  Ok(value)
end

fn reply_info() -> Bytes do
  Bytes.from_utf8("morse-credit-postage-reply-v1")
end

fn reply_aad(public_key :: X25519PublicKey, deliveries :: List<Bytes>) -> Bytes!String do
  Bytes.concat(public_key.bytes, postage_batch_digest(deliveries)?)
end

fn padded_reply(receipt :: Bytes) -> Bytes!String do
  reply_checked_receipt(receipt)?
  let size = case Bytes.write_u16_be(Bytes.length(receipt)) do
    Err(_) -> return Err("invalid_postage_reply")
    Ok(value) -> value
  end
  let padding = case Bytes.repeat(0, 506 - Bytes.length(receipt)) do
    Err(_) -> return Err("invalid_postage_reply")
    Ok(value) -> value
  end
  Bytes.concat(Bytes.concat(Bytes.concat(Bytes.from_hex("01505250")?, size)?, receipt)?, padding)
end

pub fn is_sealed_postage_reply(input :: Bytes) -> Bool do
  if Bytes.length(input) != 564 do
    false
  else
    case Bytes.slice(input, 0, 4) do
      Err(_) -> false
      Ok(value) -> Bytes.to_hex(value) == "01504352"
    end
  end
end

pub fn seal_postage_reply(public_key :: X25519PublicKey,
  deliveries :: List<Bytes>,
  receipt :: Bytes) -> Bytes!String do
  let sealed = case Crypto.hpke_seal(public_key,
    reply_info(),
    reply_aad(public_key, deliveries)?,
    padded_reply(receipt)?) do
    Err(_) -> return Err("postage_reply_crypto_failed")
    Ok(value) -> value
  end
  let output = Bytes.concat(Bytes.from_hex("01504352")?, sealed)?
  if !is_sealed_postage_reply(output) do
    return Err("invalid_postage_reply")
  end
  Ok(output)
end

# The digest must come from the caller's exact authenticated saved request.
# This permits compacting a completed intent without retaining all ciphertexts;
# it establishes no sender trust and still requires the pinned inner receipt.
pub fn open_postage_reply_for_digest(private :: borrow X25519PrivateKey,
  batch_digest :: Bytes,
  sealed :: Bytes) -> Bytes!String do
  if Bytes.length(batch_digest) != 32 || !is_sealed_postage_reply(sealed) do
    return Err("invalid_postage_reply")
  end
  let public_key = case Crypto.x25519_public(private) do
    Err(_) -> return Err("postage_reply_crypto_failed")
    Ok(value) -> value
  end
  let plaintext = case Crypto.hpke_open(private,
    reply_info(),
    Bytes.concat(public_key.bytes, batch_digest)?,
    Bytes.slice(sealed, 4, 560)?) do
    Err(error) -> return Err(if is_retryable_verification_crypto_error(error) do
      "postage_reply_crypto_failed"
    else
      "invalid_postage_reply"
    end)
    Ok(value) -> value
  end
  if Bytes.length(plaintext) != 512 || Bytes.to_hex(Bytes.slice(plaintext, 0, 4)?) != "01505250" do
    return Err("invalid_postage_reply")
  end
  let length = case Bytes.read_u16_be(plaintext, 4) do
    Err(_) -> return Err("invalid_postage_reply")
    Ok(value) -> value
  end
  if length < 172 || length > 462 do
    return Err("invalid_postage_reply")
  end
  let padding = case Bytes.repeat(0, 506 - length) do
    Err(_) -> return Err("invalid_postage_reply")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(Bytes.slice(plaintext, length + 6, 506 - length)?, padding) do
    return Err("invalid_postage_reply")
  end
  reply_checked_receipt(Bytes.slice(plaintext, 6, length)?)
end

pub fn open_postage_reply(private :: borrow X25519PrivateKey,
  deliveries :: List<Bytes>,
  sealed :: Bytes) -> Bytes!String do
  open_postage_reply_for_digest(private, postage_batch_digest(deliveries)?, sealed)
end
