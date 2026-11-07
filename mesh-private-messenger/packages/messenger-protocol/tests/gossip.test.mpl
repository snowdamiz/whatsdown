from Transparency.Gossip import (
  CheckpointHint,
  GossipControl,
  encode_hint,
  decode_hint,
  encode_gossip,
  decode_gossip
)
from Transparency.Merkle import sign_checkpoint, sign_witness, WitnessAttestation
from Protocol.EnvelopeWire import encode_inner_envelope, decode_inner_envelope
from Protocol.V1 import InnerEnvelope, ProtocolExtension

fn fixture_only(value :: Plaintext<Bool>) -> Bool do
  declassify(value, "synthetic public gossip fixture comparisons only; no application disclosure")
end

fn repeated(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("test bytes failed")
    Ok(value)
  end
end

fn appended(first :: Bytes, second :: Bytes) -> Bytes!String do
  case Bytes.concat(first, second) do
    Err(_) -> Err("test bytes failed")
    Ok(value)
  end
end

fn proof() -> Bool!String do
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("test signing key failed")
    Ok(value) -> value
  end
  let checkpoint = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    U64.parse("1")?,
    [Crypto.sha256(Bytes.from_utf8("leaf"))],
    repeated(0, 32)?,
    U64.parse("1000")?)?
  let hint = CheckpointHint { tree_size: checkpoint.tree_size, tree_root: checkpoint.tree_root }
  let hint_wire = encode_hint(hint)?
  assert(Bytes.length(hint_wire) == 40)
  assert(Bytes.secure_equals(encode_hint(decode_hint(hint_wire)?)?, hint_wire))
  case decode_hint(appended(hint_wire, repeated(0, 1)?)?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let id = repeated(42, 16)?
  let request = encode_gossip(CheckpointRequest(id, hint))?
  assert(Bytes.length(request) == 60)
  assert(Bytes.secure_equals(encode_gossip(decode_gossip(request)?)?, request))
  let attestation = sign_witness("witness-test", signer.private_key, checkpoint)?
  for reciprocal in [false, true] do
    let answer = encode_gossip(CheckpointAnswer(id, checkpoint, [attestation], reciprocal))?
    assert(Bytes.secure_equals(encode_gossip(decode_gossip(answer)?)?, answer))
    case decode_gossip(appended(answer, repeated(0, 1)?)?) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  case encode_gossip(CheckpointRequest(repeated(0, 17)?, hint)) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  # PAY v1 preserves unknown optional extensions; the older envelope decoder
  # still delivers the same application bytes without interpreting the hint.
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: repeated(1, 32)?,
    sender_device_id: repeated(2, 16)?,
    recipient_device_id: repeated(3, 16)?,
    conversation_id: repeated(4, 16)?,
    client_message_id: repeated(5, 16)?,
    client_timestamp: U64.parse("1000")?,
    message_type: 1,
    body: Bytes.from_utf8("hello"),
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: [ProtocolExtension { id: 2, mandatory: false, value: hint_wire }]
  }
  let encoded = case encode_inner_envelope(inner) do
    Err(_) -> return Err("test inner encode failed")
    Ok(value) -> value
  end
  let decoded = case decode_inner_envelope(encoded) do
    Err(_) -> return Err("test inner decode failed")
    Ok(value) -> value
  end
  Ok(Bytes.secure_equals(decoded.body, inner.body) && !List.head(decoded.extensions).mandatory)
end

test("checkpoint gossip uses bounded canonical controls and optional hints preserve legacy messages") do
  assert(fixture_only(Result.unwrap_or(proof(), false)))
end
