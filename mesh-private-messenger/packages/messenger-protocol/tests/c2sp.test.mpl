from Transparency.C2spText import (
  checkpoint_note_text,
  verify_checkpoint_cosignature,
  cosignature_fresh_at
)
from Transparency.Merkle import (
  sign_tree_checkpoint_for,
  WitnessAttestation,
  WitnessKey,
  checkpoint_hash,
  verify_witnesses,
  sign_witness
)
from Transparency.Wire import encode_checkpoint
from Transparency.Wire import encode_witnesses, decode_witnesses
from Transparency.Fork import (
  ForkProof,
  ForkTarget,
  fork_same_size,
  fork_rollback,
  encode_fork,
  decode_fork
)
from Transparency.Fork import ForkAnchor, ForkPaths, fork_at_anchor
from Transparency.Gossip import GossipControl, encode_gossip, decode_gossip
from Transparency.C2sp import (
  sign_checkpoint_note,
  decode_checkpoint_note,
  verify_checkpoint_note,
  verified_cosignature,
  signature_line
)

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test signing key failed")
    Ok(value)
  end
end

fn signature(key :: borrow SigningPrivateKey, text :: String) -> Bytes!String do
  case Crypto.sign(key, Bytes.from_utf8(text)) do
    Err(_) -> Err("test signature failed")
    Ok(value) -> Ok(value.bytes)
  end
end

fn cosignatures() -> Bool!String do
  let signer = signing_pair()?
  let witness = signing_pair()?
  let root = Bytes.from_hex("36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1")?
  let zero = Bytes.from_hex("0000000000000000000000000000000000000000000000000000000000000000")?
  let cp = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(3)?,
    root,
    zero,
    wide(1679315147000)?)?
  let wire = encode_checkpoint(cp)?
  # Construct the C2SP v1.1.0 signed text independently of the implementation.
  let head = "morseapp.io/log/main/v2\n3\n" <> Bytes.to_base64(root) <> "\n"
  let text = head <> "morse-checkpoint " <> Bytes.to_base64(wire) <> "\n"
  assert(checkpoint_note_text(wire)? == text)
  let prefix = "cosignature/v1\ntime 1679315147\n"
  let timestamp = Bytes.from_hex("00000000641850cb")?
  # The explicit timestamp vector is checked independently of the codec.
  case Bytes.read_u64_be(timestamp, 0) do
    Err(_) -> assert(false)
    Ok(value) -> assert(value == wide(1679315147)?)
  end
  let signed = Bytes.concat(timestamp, signature(witness.private_key, prefix <> text)?)?
  let attestation = WitnessAttestation {
    witness_id: "outside",
    checkpoint_hash: checkpoint_hash(cp)?,
    signature: signed
  }
  let pins = [WitnessKey { witness_id: "outside", public_key: witness.public_key.bytes }]
  assert(verify_witnesses(cp, [attestation], pins, 1)?)
  let attestation_wire = encode_witnesses([attestation])?
  assert(Bytes.get(attestation_wire, 0)? == 2)
  assert(verify_witnesses(cp, decode_witnesses(attestation_wire)?, pins, 1)?)
  let forged = %{attestation | signature: Bytes.concat(timestamp, Bytes.concat(zero, zero)?)?}
  assert(verify_witnesses(cp, [forged, attestation], pins, 1)?)
  assert(!verify_witnesses(cp,
    [attestation, attestation],
    [List.head(pins), WitnessKey { witness_id: "missing", public_key: signer.public_key.bytes }],
    2)?)
  let native = sign_witness("native", signer.private_key, cp)?
  let mixed_pins = pins
    ++ [WitnessKey { witness_id: "native", public_key: signer.public_key.bytes }]
  assert(verify_witnesses(cp,
    decode_witnesses(encode_witnesses([attestation, native])?)?,
    mixed_pins,
    2)?)
  assert(Bytes.get(encode_witnesses([native])?, 0)? == 1)
  let fork_checkpoint = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(2)?,
    wide(3)?,
    zero,
    zero,
    wide(1679315147001)?)?
  let fork_signed = Bytes.concat(timestamp,
    signature(witness.private_key,
      prefix <> checkpoint_note_text(encode_checkpoint(fork_checkpoint)?)?)?)?
  let fork_attestation = %{attestation |
    checkpoint_hash: checkpoint_hash(fork_checkpoint)?,
    signature: fork_signed
  }
  let fork = ForkProof {
    kind: 1,
    finder: zero,
    service_public_key: signer.public_key.bytes,
    first: cp,
    second: SignedCheckpoint(fork_checkpoint),
    contradiction: None,
    attestations: [attestation, fork_attestation]
  }
  let fork_wire = encode_fork(fork)?
  assert(Bytes.get(fork_wire, 0)? == 2)
  assert(List.length(fork_same_size(decode_fork(fork_wire)?,
    signer.public_key,
    pins)?.witnesses) == 1)
  let metadata_checkpoint = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    cp.sequence,
    cp.tree_size,
    cp.tree_root,
    zero,
    wide(1679315147001)?)?
  let metadata_signed = Bytes.concat(timestamp,
    signature(witness.private_key,
      prefix <> checkpoint_note_text(encode_checkpoint(metadata_checkpoint)?)?)?)?
  let metadata = %{fork |
    kind: 3,
    second: SignedCheckpoint(metadata_checkpoint),
    attestations: [
      attestation,
      %{attestation |
        checkpoint_hash: checkpoint_hash(metadata_checkpoint)?,
        signature: metadata_signed
      },
      native,
      sign_witness("native", signer.private_key, metadata_checkpoint)?
    ]
  }
  let verdict = fork_rollback(metadata, signer.public_key, mixed_pins)?
  assert(List.length(verdict.witnesses) == 1 && List.head(verdict.witnesses).witness_id == "native")
  let anchor = ForkAnchor {
    ring_index: 3,
    log_version: 2,
    service_public_key: signer.public_key.bytes,
    sequence: metadata_checkpoint.sequence,
    tree_size: metadata_checkpoint.tree_size,
    tree_root: metadata_checkpoint.tree_root,
    checkpoint_hash: checkpoint_hash(metadata_checkpoint)?,
    cosigners: mixed_pins,
    native_cosigners: [List.get(mixed_pins, 1)]
  }
  let anchored = %{metadata | second: AnchorReference(3)}
  assert(List.length(fork_at_anchor(anchored,
    signer.public_key,
    mixed_pins,
    anchor)?.witnesses) == 1)
  assert(List.length(fork_at_anchor(anchored,
    signer.public_key,
    mixed_pins,
    %{anchor | native_cosigners: List.new()})?.witnesses) == 0)
  let max_id = String.join(for _index in 0..64 do
      "a"
    end,
    "")
  let maximum = for _index in 0..16 do
    %{attestation | witness_id: max_id}
  end
  assert(Bytes.length(encode_witnesses(maximum)?) == 2774)
  let maximum_fork = %{fork |
    kind: 2,
    attestations: maximum,
    contradiction: Some(ForkPaths {
      leaf_index: wide(0)?,
      first_leaf: zero,
      second_leaf: root,
      first_path: for _index in 0..32 do
        zero
      end,
      second_path: for _index in 0..32 do
        zero
      end
    })
  }
  let maximum_fork_wire = encode_fork(maximum_fork)?
  assert(Bytes.length(maximum_fork_wire) == 5289)
  assert(Bytes.secure_equals(encode_fork(decode_fork(maximum_fork_wire)?)?, maximum_fork_wire))
  case decode_fork(Bytes.concat(maximum_fork_wire, Bytes.from_utf8("x"))?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let answer = encode_gossip(CheckpointAnswer(Bytes.slice(zero, 0, 16)?, cp, maximum, false))?
  assert(Bytes.length(answer) == 2987)
  assert(Bytes.secure_equals(encode_gossip(decode_gossip(answer)?)?, answer))
  assert(verify_checkpoint_cosignature(wire, signed, witness.public_key)?)
  assert(!verify_checkpoint_cosignature(wire, signed, signer.public_key)?)
  let omitted = Bytes.concat(timestamp, signature(witness.private_key, prefix <> head)?)?
  assert(!verify_checkpoint_cosignature(wire, omitted, witness.public_key)?)
  let changed = encode_checkpoint(%{cp | timestamp: wide(1679315147001)?})?
  assert(!verify_checkpoint_cosignature(changed, signed, witness.public_key)?)
  let other_origin = String.replace(text, "morseapp.io/log/main/v2", "morseapp.io/log/other/v2")
  assert(!verify_checkpoint_cosignature(wire,
    Bytes.concat(timestamp, signature(witness.private_key, prefix <> other_origin)?)?,
    witness.public_key)?)
  assert(cosignature_fresh_at(signed, wide(1679315447000)?)?)
  assert(!cosignature_fresh_at(signed, wide(1679315447001)?)?)
  assert(cosignature_fresh_at(signed, wide(1679315087000)?)?)
  assert(!cosignature_fresh_at(signed, wide(1679315086999)?)?)
  for length in 0..72 do
    assert(!verify_checkpoint_cosignature(wire,
      Bytes.slice(signed, 0, length)?,
      witness.public_key)?)
  end
  assert(!verify_checkpoint_cosignature(wire,
    Bytes.concat(signed, Bytes.from_utf8("x"))?,
    witness.public_key)?)
  case checkpoint_note_text(encode_checkpoint(%{cp | version: 1})?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let note = sign_checkpoint_note(cp, signer.private_key)?
  let decoded = decode_checkpoint_note(note)?
  assert(verify_checkpoint_note(decoded, signer.public_key)?)
  assert(!verify_checkpoint_note(decoded, witness.public_key)?)
  let witness_line = signature_line("witness.example/test", 4, witness.public_key.bytes, signed)?
  let with_witness = Bytes.concat(note, Bytes.from_utf8(witness_line))?
  let cosigned = decode_checkpoint_note(with_witness)?
  assert(verify_checkpoint_note(cosigned, signer.public_key)?)
  assert(Bytes.secure_equals(verified_cosignature(cosigned,
      "witness.example/test",
      witness.public_key)?,
    signed))
  case verified_cosignature(cosigned, "wrong.example/name", witness.public_key) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let no_extension = signature_line("witness.example/test", 4, witness.public_key.bytes, omitted)?
  case verified_cosignature(decode_checkpoint_note(Bytes.concat(note,
      Bytes.from_utf8(no_extension))?)?,
    "witness.example/test",
    witness.public_key) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  # Matching name + ID with an invalid signature is an error, not an unknown key.
  let broken_log = %{decoded |
    signatures: [%{List.head(decoded.signatures) | signature: Bytes.concat(zero, zero)?}]
  }
  assert(!verify_checkpoint_note(broken_log, signer.public_key)?)
  # The parser rejects ambiguous duplicate key identities before verification.
  case decode_checkpoint_note(Bytes.concat(with_witness, Bytes.from_utf8(witness_line))?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let note_text = Bytes.to_utf8(note)?
  for altered in [
    String.replace(note_text, "\n3\n", "\n03\n"),
    String.replace(note_text, "\n3\n", "\n4\n"),
    String.replace(note_text, "\n", "\r\n"),
    String.replace(note_text, "morse-checkpoint ", "morse-checkpoint  "),
    note_text <> "extra\n"
  ] do
    case decode_checkpoint_note(Bytes.from_utf8(altered)) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  let extra_signatures = String.join(for index in 0..15 do
      signature_line("unknown.example/#{index}",
        1,
        witness.public_key.bytes,
        Bytes.concat(zero, zero)?)?
    end,
    "")
  assert(verify_checkpoint_note(decode_checkpoint_note(Bytes.concat(note,
      Bytes.from_utf8(extra_signatures))?)?,
    signer.public_key)?)
  case decode_checkpoint_note(Bytes.concat(with_witness, Bytes.from_utf8(extra_signatures))?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("C2SP Ed25519 cosignatures authenticate the exact Morse extension and timestamp") do
  case cosignatures() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
