from Identity.Device import is_retryable_verification_crypto_error
from Transport.Padding import pad_message, unpad_message

pub fn is_group_transport(input :: Bytes) -> Bool do
  if Bytes.length(input) < 52 || Bytes.length(input) > 65536 do
    false
  else
    case Bytes.slice(input, 0, 4) do
      Ok( header) -> Bytes.to_hex(header) == "01534750"
      Err( _) -> false
    end
  end
end

# Reuse the recipient HPKE construction used for direct initial packets, with a
# separate domain. Group signatures and membership validation remain inside it.

pub fn seal_group_transport(packet :: Bytes, recipient :: X25519PublicKey) -> Bytes ! String do
  if Bytes.length(packet) == 0 || Bytes.length(packet) > 65480 do
    Err("group_message_too_large")
  else
    let padded = pad_message(packet, 52) ?
    let sealed = case Crypto.hpke_seal(recipient,
    Bytes.from_utf8("mesh-msg/v1/recipient-group"),
    recipient.bytes,
    padded) do
      Ok( value) -> Ok(value)
      Err( _) -> Err("group_transport_crypto_failed")
    end ?
    Bytes.concat(Bytes.from_hex("01534750") ?, sealed)
  end
end

pub fn open_group_transport(input :: Bytes, recipient :: borrow X25519PrivateKey) -> Bytes ! String do
  if !is_group_transport(input) do
    Err("invalid_group_packet")
  else
    let public_key = case Crypto.x25519_public(recipient) do
      Ok( value) -> Ok(value)
      Err( _) -> Err("group_transport_crypto_failed")
    end ?
    let plaintext = case Crypto.hpke_open(recipient,
    Bytes.from_utf8("mesh-msg/v1/recipient-group"),
    public_key.bytes,
    Bytes.slice(input, 4, Bytes.length(input) - 4) ?) do
      Ok( value) -> Ok(value)
      Err( error) -> if is_retryable_verification_crypto_error(error) do
        Err("group_transport_crypto_failed")
      else
        Err("invalid_group_packet")
      end
    end ?
    case unpad_message(plaintext, 52) do
      Ok( value) -> Ok(value)
      Err( _) -> Err("invalid_group_packet")
    end
  end
end
