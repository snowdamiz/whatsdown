##! Recipient-sealed transport, version 1 (`RCP`).
##!
##! Every packet a client deposits - initial, ratchet, or group - is sealed to
##! the recipient device's authenticated X25519 identity key, so the delivery
##! service stores one indistinguishable shape: a size bucket of opaque bytes.
##! It learns no session identifier, ratchet header, group identifier, protocol
##! suite, or packet kind. The inner protocol still authenticates the sender.

from Identity.Device import is_retryable_verification_crypto_error
from Transport.Padding import pad_message, unpad_message

fn recipient_info() -> Bytes do
  Bytes.from_utf8("mesh-msg/v1/recipient-packet")
end

fn has_magic(input :: Bytes, magic :: String) -> Bool do
  if Bytes.length(input) < 4 do
    false
  else
    case Bytes.slice(input, 0, 4) do
      Ok(header) -> Bytes.to_hex(header) == magic
      Err(_) -> false
    end
  end
end

pub fn is_recipient_packet(input :: Bytes) -> Bool do
  Bytes.length(input) >= 52 && Bytes.length(input) <= 65536 && has_magic(input, "01524350")
end

## 1 initial, 2 ratchet, 3 group, 0 anything else. Read from the opened packet;
## nothing outside the seal carries it.

pub fn recipient_packet_kind(packet :: Bytes) -> Int do
  if has_magic(packet, "01475250") do
    3
  else if has_magic(packet, "014d3850") && Bytes.length(packet) >= 5 do
    case Bytes.get(packet, 4) do
      Ok(1) -> 1
      Ok(2) -> 2
      _ -> 0
    end
  else
    0
  end
end

pub fn seal_recipient_packet(packet :: Bytes, recipient :: X25519PublicKey) -> Bytes!String do
  if Bytes.length(packet) == 0 || Bytes.length(packet) > 65480 do
    Err("recipient_packet_too_large")
  else
    let padded = pad_message(packet, 52)?
    let sealed = case Crypto.hpke_seal(recipient, recipient_info(), recipient.bytes, padded) do
      Ok(value)
      Err(_) -> Err("recipient_crypto_failed")
    end?
    Bytes.concat(Bytes.from_hex("01524350")?, sealed)
  end
end

pub fn open_recipient_packet(input :: Bytes, recipient :: borrow X25519PrivateKey) -> Bytes!String do
  if !is_recipient_packet(input) do
    Err("invalid_recipient_packet")
  else
    let public_key = case Crypto.x25519_public(recipient) do
      Ok(value)
      Err(_) -> Err("recipient_crypto_failed")
    end?
    let plaintext = case Crypto.hpke_open(recipient,
      recipient_info(),
      public_key.bytes,
      Bytes.slice(input, 4, Bytes.length(input) - 4)?) do
      Ok(value)
      Err(error) -> if is_retryable_verification_crypto_error(error) do
        Err("recipient_crypto_failed")
      else
        Err("invalid_recipient_packet")
      end
    end?
    case unpad_message(plaintext, 52) do
      Ok(value)
      Err(_) -> Err("invalid_recipient_packet")
    end
  end
end
