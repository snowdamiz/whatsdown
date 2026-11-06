from Credits.Issuer import (
  CreditIssuerKey,
  encode_issuer_key,
  decode_issuer_key,
  issuer_key_id,
  verify_issuer_key,
  retain_issuer_key
)
from Transparency.Merkle import (
  WitnessKey,
  WitnessAttestation,
  TransparencyCheckpoint,
  checkpoint_hash,
  verify_witnesses,
  leaf_hash_for,
  merkle_root_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_tree_checkpoint_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence, encode_checkpoint
from Transparency.C2spText import checkpoint_note_text

fn cosign(witness :: borrow SigningKeyPair,
  checkpoint :: TransparencyCheckpoint,
  seconds :: Int) -> WitnessAttestation!String do
  let message = Bytes.from_utf8("cosignature/v1\ntime #{seconds}\n"
    <> checkpoint_note_text(encode_checkpoint(checkpoint)?)?)
  let signature = case Crypto.sign(witness.private_key, message) do
    Err(_) -> return Err("test cosignature failed")
    Ok(value) -> value.bytes
  end
  let stamp = case Bytes.write_u64_be(wide(seconds)?) do
    Err(_) -> return Err("test timestamp failed")
    Ok(value) -> value
  end
  Ok(WitnessAttestation {
    witness_id: "outside",
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    signature: Bytes.concat(stamp, signature)?
  })
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test signing key failed")
    Ok(value)
  end
end

fn public_key() -> Bytes!String do
  Bytes.from_hex("30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b0609608648016503040202a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b111908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22af37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff89f55619709b096cbb9ea474cead264c2073fe49740c01f00e109106066983d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b7e225a5f0203010001")
end

fn codec() -> Bool!String do
  let value = CreditIssuerKey {
    quote_public_key: Bytes.from_hex(String.repeat("11", 32))?,
    epoch: wide(10)?,
    purpose: 0,
    spki: public_key()?
  }
  assert(Result.is_err(encode_issuer_key(%{value |
    quote_public_key: Bytes.from_hex(String.repeat("00", 32))?
  })))
  let encoded = encode_issuer_key(value)?
  assert(Bytes.length(encoded) == 387)
  assert(Bytes.to_hex(Bytes.slice(encoded, 0, 13)?) == "02494b59000000000000000a00")
  let decoded = decode_issuer_key(encoded)?
  assert(decoded.epoch == value.epoch && decoded.purpose == value.purpose)
  assert(Bytes.secure_equals(decoded.spki, value.spki))
  assert(Bytes.secure_equals(issuer_key_id(decoded)?, Crypto.sha256(public_key()?)))
  assert(Result.is_err(encode_issuer_key(%{value | purpose: 2})))
  assert(Result.is_err(encode_issuer_key(%{value | spki: Bytes.slice(public_key()?, 0, 341)?})))
  assert(Result.is_err(decode_issuer_key(Bytes.concat(encoded, Bytes.from_hex("00")?)?)))
  assert(Result.is_err(decode_issuer_key(Bytes.concat(Bytes.from_hex("03494b59")?,
    Bytes.slice(encoded, 4, 383)?)?)))
  # Same-size, different algorithm parameters must reach BR1's strict parser.
  let altered = Bytes.concat(Bytes.from_hex("31")?, Bytes.slice(public_key()?, 1, 341)?)?
  assert(Result.is_err(encode_issuer_key(%{value | spki: altered})))
  Ok(true)
end

test("issuer-key-v2 binds a separate quote signer to the BR1 profile with explicit epoch and purpose") do
  case codec() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn proof() -> Bool!String do
  let signer = signing_pair()?
  let witness = signing_pair()?
  let pins = [WitnessKey { witness_id: "outside", public_key: witness.public_key.bytes }]
  let now = 10 * 2592000 + 1000
  let key = CreditIssuerKey {
    quote_public_key: Bytes.from_hex(String.repeat("11", 32))?,
    epoch: wide(10)?,
    purpose: 0,
    spki: public_key()?
  }
  let entry = encode_issuer_key(key)?
  let tree = [leaf_hash_for(2, entry)?]
  let zero = Bytes.from_hex(String.repeat("00", 32))?
  let checkpoint = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(1)?,
    merkle_root_for(2, tree)?,
    zero,
    wide(now * 1000)?)?
  let evidence = TransparencyEvidence {
    entry_bytes: entry,
    inclusion: compact_inclusion_proof_for(2, tree, 0)?,
    consistency: compact_consistency_proof_for(2, [], tree)?,
    checkpoint: checkpoint,
    witnesses: [sign_witness("outside", witness.private_key, checkpoint)?]
  }
  let verified = verify_issuer_key(evidence,
    signer.public_key,
    pins,
    1,
    Bytes.empty(),
    wide(now)?,
    0)?
  assert(Bytes.secure_equals(verified.spki, key.spki))
  let current_cosignature = %{evidence | witnesses: [cosign(witness, checkpoint, now)?]}
  assert(Result.is_ok(verify_issuer_key(current_cosignature,
    signer.public_key,
    pins,
    1,
    Bytes.empty(),
    wide(now)?,
    0)))
  for seconds in [now - 301, now + 61] do
    let stale_cosignature = %{evidence | witnesses: [cosign(witness, checkpoint, seconds)?]}
    # A valid signature over a fresh checkpoint still needs the witness's own
    # signed timestamp. Core-supplied metadata cannot refresh that authority.
    assert(verify_witnesses(checkpoint, stale_cosignature.witnesses, pins, 1)?)
    assert(Result.is_err(verify_issuer_key(stale_cosignature,
      signer.public_key,
      pins,
      1,
      Bytes.empty(),
      wide(now)?,
      0)))
  end
  assert(Result.is_err(verify_issuer_key(evidence,
    signer.public_key,
    pins,
    1,
    Bytes.empty(),
    wide(now)?,
    1)))
  assert(Result.is_err(verify_issuer_key(evidence,
    witness.public_key,
    pins,
    1,
    Bytes.empty(),
    wide(now)?,
    0)))
  assert(Result.is_err(verify_issuer_key(%{evidence | witnesses: []},
    signer.public_key,
    pins,
    1,
    Bytes.empty(),
    wide(now)?,
    0)))
  assert(Result.is_err(verify_issuer_key(evidence,
    signer.public_key,
    pins,
    1,
    Bytes.empty(),
    wide(now + 301)?,
    0)))
  assert(Result.is_err(verify_issuer_key(%{evidence |
      entry_bytes: encode_issuer_key(%{key | epoch: wide(9)?})?
    },
    signer.public_key,
    pins,
    1,
    Bytes.empty(),
    wide(now)?,
    0)))
  assert(Result.is_err(verify_issuer_key(%{evidence | checkpoint: %{checkpoint | version: 1}},
    signer.public_key,
    pins,
    1,
    Bytes.empty(),
    wide(now)?,
    0)))
  let retained = retain_issuer_key([], verified, wide(now)?, 0)?
  assert(List.length(retain_issuer_key(retained, verified, wide(now)?, 0)?) == 1)
  assert(Result.is_err(retain_issuer_key(retained,
    %{key | quote_public_key: witness.public_key.bytes},
    wide(now)?,
    0)))
  let previous = %{key | epoch: wide(9)?}
  assert(List.length(retain_issuer_key(retained, previous, wide(now)?, 0)?) == 2)
  assert(Result.is_err(retain_issuer_key(retained, %{key | epoch: wide(8)?}, wide(now)?, 0)))
  assert(Result.is_err(retain_issuer_key(retained, %{key | purpose: 1}, wide(now)?, 0)))
  # A different key cannot replace a retained key for the same epoch/purpose.
  let another = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test RSA generation failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(another) do
    Err(_) -> return Err("test RSA public key failed")
    Ok(value) -> value
  end
  assert(Result.is_err(retain_issuer_key(retained, %{key | spki: public.bytes}, wide(now)?, 0)))
  Ok(true)
end

test("issuer keys require fresh witnessed RFC6962 inclusion and cannot replace an epoch pin") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
