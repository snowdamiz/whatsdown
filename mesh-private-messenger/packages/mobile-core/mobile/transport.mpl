##! Recipient-sealed delivery for every packet this device deposits or receives.
##!
##! New envelopes are always outer suite 4: the delivery service sees a mailbox
##! address, a size bucket, and opaque bytes, never a session identifier, a
##! ratchet header, a group identifier, a protocol suite, or the packet kind.
##! Envelopes queued under the legacy outer suites 1-3 stay readable.

from Mobile.Codec import outer_bytes
from Protocol.V1 import OuterEnvelope, protocol_sealed_outer_suite
from Transport.Recipient import is_recipient_packet, open_recipient_packet, recipient_packet_kind, seal_recipient_packet

pub struct MobileOpenedPacket do
  sealed :: Bool
  packet :: Bytes
end

pub fn sealed_outer_bytes(mailbox_token :: Bytes,
packet :: Bytes,
recipient_dh_public_key :: Bytes,
now :: U64) -> Bytes ! String do
  let sealed = seal_recipient_packet(packet, X25519PublicKey { bytes : recipient_dh_public_key }) ?
  outer_bytes(mailbox_token, protocol_sealed_outer_suite(), sealed, now)
end

## The outer suite and the packet shape must agree: a sealed suite that does not
## carry a sealed packet, or a sealed packet under a legacy suite, is rejected
## rather than reinterpreted.

pub fn open_outer_packet(outer :: OuterEnvelope, recipient :: borrow X25519PrivateKey) -> MobileOpenedPacket ! String do
  let sealed_suite = outer.suite == protocol_sealed_outer_suite()
  if sealed_suite != is_recipient_packet(outer.ciphertext) do
    Err("invalid_recipient_packet")
  else if sealed_suite do
    Ok(MobileOpenedPacket {
      sealed : true,
      packet : open_recipient_packet(outer.ciphertext, recipient) ?
    })
  else
    Ok(MobileOpenedPacket {
      sealed : false,
      packet : outer.ciphertext
    })
  end
end

## 1 initial, 2 ratchet, 3 group, 0 unknown; known only after opening the seal.

pub fn opened_packet_kind(opened :: MobileOpenedPacket) -> Int do
  recipient_packet_kind(opened.packet)
end
