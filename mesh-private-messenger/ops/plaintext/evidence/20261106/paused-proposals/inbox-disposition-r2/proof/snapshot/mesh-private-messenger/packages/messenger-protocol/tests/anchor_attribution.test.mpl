from Transparency.AnchorEvidence import attribute_anchor_fork, evidence_anchor
from Transparency.AnchorRing import AnchorEntry
from Transparency.AnchorWitnessSet import AnchorWitness, AnchorWitnessSet
from Transparency.Fork import ForkProof, ForkTarget, ForkVerdict, fork_at_anchor
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  WitnessAttestation,
  checkpoint_hash,
  sign_tree_checkpoint_for,
  sign_witness
)
from Transparency.C2spText import checkpoint_note_text
from Transparency.Wire import encode_checkpoint

fn signer() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("fixture key failure")
    Ok(value)
  end
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn bytes(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("fixture bytes failure")
    Ok(value)
  end
end

fn member(id :: String, public_key :: Bytes, address :: Int) -> AnchorWitness!String do
  Ok(AnchorWitness {
    witness_id: id,
    public_key: public_key,
    address: bytes(address, 32)?,
    payout: bytes(address + 10, 32)?
  })
end

fn c2sp(id :: String,
  key :: borrow SigningKeyPair,
  checkpoint :: TransparencyCheckpoint) -> WitnessAttestation!String do
  let signature = case Crypto.sign(key.private_key,
    Bytes.from_utf8("cosignature/v1\ntime 1\n"
      <> checkpoint_note_text(encode_checkpoint(checkpoint)?)?)) do
    Err(_) -> return Err("fixture signing failed")
    Ok(value) -> value.bytes
  end
  Ok(WitnessAttestation {
    witness_id: id,
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    signature: Bytes.concat(Bytes.from_hex("0000000000000001")?, signature)?
  })
end

fn proof() -> Bool!String do
  let log = signer()?
  let a = signer()?
  let b = signer()?
  let c = signer()?
  let outside = signer()?
  let replacement = signer()?
  let zero = bytes(0, 32)?
  let first = sign_tree_checkpoint_for(2,
    log.private_key,
    log.public_key.bytes,
    wide(4)?,
    wide(4)?,
    bytes(1, 32)?,
    zero,
    wide(1000)?)?
  let second = sign_tree_checkpoint_for(2,
    log.private_key,
    log.public_key.bytes,
    wide(5)?,
    wide(4)?,
    bytes(2, 32)?,
    checkpoint_hash(first)?,
    wide(2000)?)?
  let log_id = Crypto.sha256(Bytes.from_utf8("morse-main"))
  let set = AnchorWitnessSet {
    log_id: log_id,
    generation: 7,
    ready_at: wide(10)?,
    witnesses: [
      member("a", a.public_key.bytes, 1)?,
      member("b", b.public_key.bytes, 2)?,
      member("c", c.public_key.bytes, 3)?,
      member("outside", outside.public_key.bytes, 4)?
    ]
  }
  let entry = AnchorEntry {
    sequence: second.sequence,
    tree_size: second.tree_size,
    tree_root: second.tree_root,
    checkpoint_hash: checkpoint_hash(second)?,
    timestamp: second.timestamp,
    slot: wide(50)?,
    log_version: 2,
    rollback: false,
    cosign_bitmap: 15,
    native_bitmap: 9,
    witness_generation: 7
  }
  let pins = [
    WitnessKey { witness_id: "a", public_key: a.public_key.bytes },
    WitnessKey { witness_id: "b", public_key: b.public_key.bytes },
    WitnessKey { witness_id: "c", public_key: c.public_key.bytes }
  ]
  let original = ForkProof {
    kind: 1,
    finder: zero,
    service_public_key: log.public_key.bytes,
    first: first,
    second: AnchorReference(4095),
    attestations: [],
    contradiction: None
  }
  let valid_a = sign_witness("a", a.private_key, first)?
  let signatures = [
    %{valid_a | signature: bytes(0, 64)?},
    c2sp("b", b, first)?,
    sign_witness("outside", outside.private_key, first)?,
    valid_a,
    sign_witness("c", c.private_key, first)?,
    valid_a
  ]
  let enriched = attribute_anchor_fork(original,
    log.public_key,
    pins,
    log_id,
    entry,
    set,
    signatures)?
  assert(List.length(enriched.attestations) == 3)
  let anchor = evidence_anchor(log_id, 4095, log.public_key.bytes, entry, set)?
  let verdict = fork_at_anchor(enriched, log.public_key, pins, anchor)?
  assert(List.map(verdict.witnesses, fn(pin) do pin.witness_id end) == ["a", "b", "c"])
  # Cosignatures can arrive after the phone's read. Preserve valid private
  # signatures so the relay can resolve later public bits without this phone.
  let sparse = %{entry | cosign_bitmap: 1, native_bitmap: 1}
  let awaiting_cosigns = attribute_anchor_fork(original,
    log.public_key,
    pins,
    log_id,
    sparse,
    set,
    signatures)?
  assert(List.length(awaiting_cosigns.attestations) == 3)
  assert(List.length(fork_at_anchor(awaiting_cosigns,
    log.public_key,
    pins,
    evidence_anchor(log_id, 4095, log.public_key.bytes, sparse, set)?)?.witnesses) == 1)
  # The historical set never adds trust, and a reused ID never accuses a new key.
  let rotated = [
    WitnessKey { witness_id: "a", public_key: replacement.public_key.bytes },
    List.get(pins, 1)
  ]
  let after_rotation = attribute_anchor_fork(original,
    log.public_key,
    rotated,
    log_id,
    entry,
    set,
    signatures)?
  assert(List.map(after_rotation.attestations, fn(value) do value.witness_id end) == ["b"])
  assert(List.length(attribute_anchor_fork(original,
    log.public_key,
    [],
    log_id,
    entry,
    set,
    signatures)?.attestations) == 0)
  # Rollback claims require native semantics on both sides, even for a pinned key.
  let smaller = sign_tree_checkpoint_for(2,
    log.private_key,
    log.public_key.bytes,
    wide(6)?,
    wide(3)?,
    bytes(3, 32)?,
    checkpoint_hash(second)?,
    wide(3000)?)?
  let rollback = %{original | kind: 3, first: smaller}
  let rollback_signatures = [
    sign_witness("a", a.private_key, smaller)?,
    c2sp("b", b, smaller)?,
    sign_witness("c", c.private_key, smaller)?
  ]
  let native_only = attribute_anchor_fork(rollback,
    log.public_key,
    pins,
    log_id,
    entry,
    set,
    rollback_signatures)?
  assert(List.map(native_only.attestations, fn(value) do value.witness_id end) == ["a", "c"])
  assert(List.map(fork_at_anchor(native_only, log.public_key, pins, anchor)?.witnesses,
    fn(value) do value.witness_id end) == ["a"])
  # Wrong generation, wrong log and out-of-range cosign bits cannot be attributed.
  for invalid in [%{set | generation: 8}, %{set | log_id: bytes(9, 32)?}] do
    case attribute_anchor_fork(original,
      log.public_key,
      pins,
      log_id,
      entry,
      invalid,
      signatures) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  case attribute_anchor_fork(original,
    log.public_key,
    pins,
    log_id,
    %{entry | cosign_bitmap: 31},
    set,
    signatures) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case attribute_anchor_fork(%{original | first: %{first | signature: bytes(0, 64)?}},
    log.public_key,
    pins,
    log_id,
    entry,
    set,
    signatures) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("anchor fork attribution uses the historical set and release pins without expanding C2SP promises") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
