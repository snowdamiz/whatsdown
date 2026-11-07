from Transparency.AnchorWrite import (
  AnchorInstructionPair,
  anchor_post_instructions,
  anchor_cosign_instructions
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  sign_tree_checkpoint_for,
  sign_witness
)
from Transparency.C2spText import checkpoint_note_text
from Transparency.Wire import encode_checkpoint

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn proof() -> Bool!String do
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("test signer")
    Ok(value) -> value
  end
  let witness = case Crypto.signing_generate() do
    Err(_) -> return Err("test witness")
    Ok(value) -> value
  end
  let root = Crypto.sha256(Bytes.from_utf8("writer root"))
  let pin = WitnessKey { witness_id: "witness-a", public_key: witness.public_key.bytes }
  for version in [1, 2] do
    let checkpoint = sign_tree_checkpoint_for(version,
      signer.private_key,
      signer.public_key.bytes,
      wide(7)?,
      wide(3)?,
      root,
      root,
      wide(1000)?)?
    let pair = anchor_post_instructions(checkpoint, signer.public_key.bytes, 9)?
    assert(Bytes.length(pair.ed25519) == 258)
    assert(Bytes.to_hex(Bytes.slice(pair.ed25519, 0, 16)?) == "01003000ffff1000ffff70009200ffff")
    assert(Bytes.secure_equals(Bytes.slice(pair.ed25519, 16, 32)?, signer.public_key.bytes))
    assert(Bytes.secure_equals(Bytes.slice(pair.ed25519, 48, 64)?, checkpoint.signature))
    assert(Bytes.to_hex(Bytes.slice(pair.judge, 0, 3)?) == "030900")
    assert(Bytes.secure_equals(Bytes.slice(pair.judge, 3, 188)?, encode_checkpoint(checkpoint)?))
    let attestation = sign_witness(pin.witness_id, witness.private_key, checkpoint)?
    let native = anchor_cosign_instructions(checkpoint, attestation, pin, 4095, 15, 11)?
    assert(Bytes.length(native.judge) == 6)
    assert(Bytes.to_hex(Bytes.slice(native.judge, 0, 6)?) == "09ff0f0b000f")
    assert(Bytes.secure_equals(Bytes.slice(native.ed25519, 48, 64)?, attestation.signature))
    if version == 2 do
      let message = Bytes.from_utf8("cosignature/v1\ntime 1000\n"
        <> checkpoint_note_text(encode_checkpoint(checkpoint)?)?)
      let signed = case Crypto.sign(witness.private_key, message) do
        Err(_) -> return Err("test cosign")
        Ok(value) -> value
      end
      let seconds = case Bytes.write_u64_be(wide(1000)?) do
        Err(_) -> return Err("test seconds")
        Ok(value) -> value
      end
      let c2sp = %{attestation | signature: Bytes.concat(seconds, signed.bytes)?}
      let prepared = anchor_cosign_instructions(checkpoint, c2sp, pin, 0, 0, 0)?
      assert(Bytes.to_hex(Bytes.slice(prepared.judge, 0, 6)?) == "1e0000000000")
      assert(Bytes.length(prepared.judge) == 202)
      assert(Bytes.secure_equals(Bytes.slice(prepared.ed25519, 112, Bytes.length(message))?,
        message))
    end
    let altered = %{checkpoint | tree_root: Crypto.sha256(Bytes.from_utf8("changed"))}
    assert(case anchor_post_instructions(altered, signer.public_key.bytes, 0) do
      Err(_) -> true
      Ok(_) -> false
    end)
    assert(case anchor_post_instructions(checkpoint, witness.public_key.bytes, 0) do
      Err(_) -> true
      Ok(_) -> false
    end)
    for index in [-1, 65535] do
      assert(case anchor_post_instructions(checkpoint, signer.public_key.bytes, index) do
        Err(_) -> true
        Ok(_) -> false
      end)
    end
    assert(case anchor_cosign_instructions(altered, attestation, pin, 0, 0, 0) do
      Err(_) -> true
      Ok(_) -> false
    end)
    assert(case anchor_cosign_instructions(checkpoint,
      attestation,
      %{pin | public_key: signer.public_key.bytes},
      0,
      0,
      0) do
      Err(_) -> true
      Ok(_) -> false
    end)
    assert(case anchor_cosign_instructions(checkpoint, attestation, pin, 4096, 0, 0) do
      Err(_) -> true
      Ok(_) -> false
    end)
    assert(case anchor_cosign_instructions(checkpoint, attestation, pin, 0, 16, 0) do
      Err(_) -> true
      Ok(_) -> false
    end)
  end
  Ok(true)
end

test("Mesh prepares only verified canonical anchor and native/C2SP cosign instructions with bounded indices") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
