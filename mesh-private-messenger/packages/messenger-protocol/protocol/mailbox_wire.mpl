##! Mailbox fetch, acknowledgement, and delivery-batch codecs.
##!
##! Fetch and acknowledgement are version 2: statements signed by the device
##! that owns the mailbox. The address published in the directory lets anyone
##! deposit an envelope; it never authorizes reading or removing one.

from Binary.Reader import BinaryReader
from Protocol.WirePrimitives import (
  ProtocolReadDeliveries,
  protocol_append,
  protocol_byte,
  protocol_join,
  protocol_open,
  protocol_read_ack_ids,
  protocol_require_end,
  protocol_take_fixed,
  protocol_take_u64,
  protocol_take_u8,
  protocol_take_vector,
  protocol_valid_magic,
  protocol_vector,
  protocol_write_u64
)
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.V1 import DeliveredEnvelope, MailboxAck, MailboxFetch, ProtocolError
from Transparency.Client import checkpoint_fresh_at

fn mailbox_signature(signing_key :: borrow SigningPrivateKey, signing_bytes :: Bytes) -> Bytes!ProtocolError do
  case Crypto.sign(signing_key, signing_bytes) do
    Err(_) -> Err(MalformedEncoding)
    Ok(signature) -> Ok(signature.bytes)
  end
end

## One freshness policy for every signed, timestamped statement: at most five
## minutes old and at most one minute ahead of the verifier's clock.

pub fn mailbox_request_is_fresh(issued_at :: U64, now :: U64) -> Bool do
  checkpoint_fresh_at(issued_at, now)
end

fn mailbox_fetch_content(value :: MailboxFetch) -> Bytes!ProtocolError do
  if value.version != 2 do
    Err(UnsupportedVersion)
  else
    if Bytes.length(value.mailbox_token_hash) != 32 do
      Err(InvalidFieldLength)
    else
      protocol_join([
          protocol_byte(value.version)?,
          Bytes.from_utf8("FET"),
          value.mailbox_token_hash,
          protocol_write_u64(value.after_sequence)?,
          protocol_write_u64(value.issued_at)?
        ],
        0,
        Bytes.empty())
    end
  end
end

pub fn mailbox_fetch_signing_bytes(value :: MailboxFetch) -> Bytes!ProtocolError do
  protocol_append(Bytes.from_utf8("mesh-msg/v2/mailbox-fetch"), mailbox_fetch_content(value)?)
end

pub fn encode_mailbox_fetch(value :: MailboxFetch) -> Bytes!ProtocolError do
  let content = mailbox_fetch_content(value)?
  if Bytes.length(value.signature) != 64 do
    Err(InvalidFieldLength)
  else
    protocol_append(content, value.signature)
  end
end

pub fn sign_mailbox_fetch(signing_key :: borrow SigningPrivateKey,
  mailbox_token_hash :: Bytes,
  after_sequence :: U64,
  issued_at :: U64) -> Bytes!ProtocolError do
  let unsigned = MailboxFetch {
    version: 2,
    mailbox_token_hash: mailbox_token_hash,
    after_sequence: after_sequence,
    issued_at: issued_at,
    signature: Bytes.empty()
  }
  let signature = mailbox_signature(signing_key, mailbox_fetch_signing_bytes(unsigned)?)?
  encode_mailbox_fetch(% { unsigned | signature: signature })
end

pub fn decode_mailbox_fetch(input :: Bytes) -> MailboxFetch!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 116)?)?
  if version.value != 2 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "FET")?
    let mailbox_token_hash = protocol_take_fixed(magic.state, 32)?
    let after_sequence = protocol_take_u64(mailbox_token_hash.state)?
    let issued_at = protocol_take_u64(after_sequence.state)?
    let signature = protocol_take_fixed(issued_at.state, 64)?
    protocol_require_end(signature.state)?
    Ok(MailboxFetch {
      version: version.value,
      mailbox_token_hash: mailbox_token_hash.value,
      after_sequence: after_sequence.value,
      issued_at: issued_at.value,
      signature: signature.value
    })
  end
end

fn validate_delivery_entries(values :: List<DeliveredEnvelope>, index :: Int) -> Result<(), ProtocolError> do
  if List.length(values) > 8 do
    Err(OversizedInput)
  else
    if index >= List.length(values) do
      Ok(nil)
    else
      decode_outer_envelope(List.get(values, index).envelope)?
      validate_delivery_entries(values, index + 1)
    end
  end
end

fn encode_delivery_entries(values :: List<DeliveredEnvelope>, index :: Int, output :: Bytes) -> Bytes!ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    let next = protocol_join([
        output,
        protocol_write_u64(value.sequence)?,
        protocol_vector(value.envelope)?
      ],
      0,
      Bytes.empty())?
    encode_delivery_entries(values, index + 1, next)
  end
end

pub fn encode_delivery_batch(values :: List<DeliveredEnvelope>) -> Bytes!ProtocolError do
  validate_delivery_entries(values, 0)?
  encode_delivery_entries(values,
    0,
    protocol_join([protocol_byte(1)?, Bytes.from_utf8("BAT"), protocol_byte(List.length(values))?],
      0,
      Bytes.empty())?)
end

fn read_delivery_entries(state :: BinaryReader,
  count :: Int,
  index :: Int,
  output :: List<DeliveredEnvelope>) -> ProtocolReadDeliveries!ProtocolError do
  if index >= count do
    Ok(ProtocolReadDeliveries {
      state: state,
      value: output
    })
  else
    let sequence = protocol_take_u64(state)?
    let envelope = protocol_take_vector(sequence.state, 65606)?
    decode_outer_envelope(envelope.value)?
    read_delivery_entries(envelope.state,
      count,
      index + 1,
      List.append(output,
        DeliveredEnvelope {
          sequence: sequence.value,
          envelope: envelope.value
        }))
  end
end

pub fn decode_delivery_batch(input :: Bytes) -> List<DeliveredEnvelope>!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 524949)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "BAT")?
    let count = protocol_take_u8(magic.state)?
    if count.value > 8 do
      Err(OversizedInput)
    else
      let values = read_delivery_entries(count.state, count.value, 0, List.new())?
      protocol_require_end(values.state)?
      Ok(values.value)
    end
  end
end

fn validate_ack_ids(values :: List<Bytes>, index :: Int) -> Result<(), ProtocolError> do
  if List.length(values) == 0 || List.length(values) > 8 do
    Err(InvalidFieldLength)
  else
    if index >= List.length(values) do
      Ok(nil)
    else
      if Bytes.length(List.get(values, index)) != 16 do
        Err(InvalidFieldLength)
      else
        validate_ack_ids(values, index + 1)
      end
    end
  end
end

fn encode_ack_ids(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_ack_ids(values,
      index + 1,
      protocol_join([output, List.get(values, index)], 0, Bytes.empty())?)
  end
end

fn mailbox_ack_content(value :: MailboxAck) -> Bytes!ProtocolError do
  if value.version != 2 do
    Err(UnsupportedVersion)
  else
    if Bytes.length(value.mailbox_token_hash) != 32 do
      Err(InvalidFieldLength)
    else
      validate_ack_ids(value.envelope_ids, 0)?
      encode_ack_ids(value.envelope_ids,
        0,
        protocol_join([
            protocol_byte(value.version)?,
            Bytes.from_utf8("ACK"),
            value.mailbox_token_hash,
            protocol_write_u64(value.issued_at)?,
            protocol_byte(List.length(value.envelope_ids))?
          ],
          0,
          Bytes.empty())?)
    end
  end
end

pub fn mailbox_ack_signing_bytes(value :: MailboxAck) -> Bytes!ProtocolError do
  protocol_append(Bytes.from_utf8("mesh-msg/v2/mailbox-ack"), mailbox_ack_content(value)?)
end

pub fn encode_mailbox_ack(value :: MailboxAck) -> Bytes!ProtocolError do
  let content = mailbox_ack_content(value)?
  if Bytes.length(value.signature) != 64 do
    Err(InvalidFieldLength)
  else
    protocol_append(content, value.signature)
  end
end

pub fn sign_mailbox_ack(signing_key :: borrow SigningPrivateKey,
  mailbox_token_hash :: Bytes,
  issued_at :: U64,
  envelope_ids :: List<Bytes>) -> Bytes!ProtocolError do
  let unsigned = MailboxAck {
    version: 2,
    mailbox_token_hash: mailbox_token_hash,
    issued_at: issued_at,
    envelope_ids: envelope_ids,
    signature: Bytes.empty()
  }
  let signature = mailbox_signature(signing_key, mailbox_ack_signing_bytes(unsigned)?)?
  encode_mailbox_ack(% { unsigned | signature: signature })
end

pub fn decode_mailbox_ack(input :: Bytes) -> MailboxAck!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 237)?)?
  if version.value != 2 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "ACK")?
    let mailbox_token_hash = protocol_take_fixed(magic.state, 32)?
    let issued_at = protocol_take_u64(mailbox_token_hash.state)?
    let count = protocol_take_u8(issued_at.state)?
    if count.value == 0 || count.value > 8 do
      Err(InvalidFieldLength)
    else
      let ids = protocol_read_ack_ids(count.state, count.value, 0, List.new())?
      let signature = protocol_take_fixed(ids.state, 64)?
      protocol_require_end(signature.state)?
      Ok(MailboxAck {
        version: version.value,
        mailbox_token_hash: mailbox_token_hash.value,
        issued_at: issued_at.value,
        envelope_ids: ids.value,
        signature: signature.value
      })
    end
  end
end
