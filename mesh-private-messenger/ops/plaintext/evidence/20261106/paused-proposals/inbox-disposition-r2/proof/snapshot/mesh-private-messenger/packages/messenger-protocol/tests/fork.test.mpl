from Transparency.Fork import (
  ForkAnchor,
  fork_at_anchor,
  ForkProof,
  ForkTarget,
  ForkVerdict,
  ForkPaths,
  fork_same_size,
  fork_contradiction,
  fork_rollback,
  encode_fork,
  decode_fork,
  fork_hash
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  WitnessAttestation,
  sign_checkpoint,
  sign_witness,
  checkpoint_hash,
  compact_inclusion_proof
)

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn every_witness() -> Bool!String do
  let signer = signing_pair()?
  let zero = repeated(0, 32)?
  let first = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    [Crypto.sha256(Bytes.from_utf8("left"))],
    zero,
    wide(1000)?)?
  let second = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(2)?,
    [Crypto.sha256(Bytes.from_utf8("right"))],
    checkpoint_hash(first)?,
    wide(2000)?)?
  let witnesses = for index in 0..16 do
    let pair = signing_pair()?
    let id = "witness-#{index}"
    (WitnessKey { witness_id: id, public_key: pair.public_key.bytes },
      [sign_witness(id, pair.private_key, first)?, sign_witness(id, pair.private_key, second)?])
  end
  let pins = for (pin, _) in witnesses do
    pin
  end
  let signatures = List.flat_map(witnesses, fn((_, values)) -> values end)
  let proof = ForkProof {
    kind: 1,
    finder: zero,
    service_public_key: signer.public_key.bytes,
    first: first,
    second: SignedCheckpoint(second),
    attestations: signatures,
    contradiction: None
  }
  let wire = encode_fork(proof)?
  assert(Bytes.get(wire, 0)? == 3)
  let decoded = decode_fork(wire)?
  assert(List.length(decoded.attestations) == 32)
  assert(fork_same_size(decoded, signer.public_key, pins)?.witnesses == pins)
  assert(Bytes.secure_equals(fork_hash(proof)?, fork_hash(%{proof | finder: repeated(9, 32)?})?))
  # A missing second signature must implicate exactly the other 15 witnesses.
  let partial = %{proof | attestations: List.take(signatures, 31)}
  assert(List.length(fork_same_size(decode_fork(encode_fork(partial)?)?,
    signer.public_key,
    pins)?.witnesses) == 15)
  case encode_fork(%{proof | attestations: signatures ++ [List.head(signatures)]}) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("all sixteen double-signing witnesses fit in one canonical fork proof") do
  case every_witness() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test signing key failed")
    Ok(value)
  end
end

fn repeated(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("test bytes failed")
    Ok(value)
  end
end

fn anchor(checkpoint :: TransparencyCheckpoint,
  cosigners :: List<WitnessKey>) -> ForkAnchor!String do
  Ok(ForkAnchor {
    ring_index: 4095,
    log_version: checkpoint.version,
    service_public_key: checkpoint.service_public_key,
    sequence: checkpoint.sequence,
    tree_size: checkpoint.tree_size,
    tree_root: checkpoint.tree_root,
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    cosigners: cosigners,
    native_cosigners: cosigners
  })
end

fn same_size() -> Bool!String do
  let signer = signing_pair()?
  let both = signing_pair()?
  let only_first = signing_pair()?
  let only_second = signing_pair()?
  let zero = repeated(0, 32)?
  let first = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(7)?,
    [Crypto.sha256(Bytes.from_utf8("first"))],
    zero,
    wide(1000)?)?
  # Equal size at different sequences is still a fork.
  let second = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(9)?,
    [Crypto.sha256(Bytes.from_utf8("second"))],
    checkpoint_hash(first)?,
    wide(2000)?)?
  let pins = [
    WitnessKey { witness_id: "both", public_key: both.public_key.bytes },
    WitnessKey { witness_id: "first", public_key: only_first.public_key.bytes },
    WitnessKey { witness_id: "second", public_key: only_second.public_key.bytes }
  ]
  let proof = ForkProof {
    kind: 1,
    finder: zero,
    service_public_key: signer.public_key.bytes,
    first: first,
    second: SignedCheckpoint(second),
    contradiction: None,
    attestations: [
      sign_witness("both", both.private_key, first)?,
      sign_witness("both", both.private_key, second)?,
      sign_witness("first", only_first.private_key, first)?,
      sign_witness("second", only_second.private_key, second)?
    ]
  }
  let encoded = encode_fork(proof)?
  assert(Bytes.secure_equals(encode_fork(decode_fork(encoded)?)?, encoded))
  assert(Bytes.secure_equals(fork_hash(proof)?, fork_hash(%{proof | finder: repeated(9, 32)?})?))
  let changed = encode_fork(%{proof | finder: repeated(9, 32)?})?
  assert(!Bytes.secure_equals(encoded, changed))
  for length in 0..Bytes.length(encoded) do
    let partial = case Bytes.slice(encoded, 0, length) do
      Err(_) -> return Err("test slice failed")
      Ok(value) -> value
    end
    case decode_fork(partial) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  let trailing = case Bytes.concat(encoded, repeated(0, 1)?) do
    Err(_) -> return Err("test concat failed")
    Ok(value) -> value
  end
  case decode_fork(trailing) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let reference = %{proof | second: AnchorReference(4095)}
  assert(Bytes.secure_equals(encode_fork(decode_fork(encode_fork(reference)?)?)?,
    encode_fork(reference)?))
  # Unauthenticated bytes containing an index are never treated as a trusted anchor.
  case fork_same_size(reference, signer.public_key, pins) do
    Err(error) -> assert(error == "fork_anchor_resolution_required")
    Ok(_) -> assert(false)
  end
  let trusted_anchor = anchor(second, [List.get(pins, 0), List.get(pins, 2)])?
  let anchored = fork_at_anchor(reference, signer.public_key, pins, trusted_anchor)?
  assert(List.length(anchored.witnesses) == 1 && List.head(anchored.witnesses).witness_id == "both")
  case fork_at_anchor(reference, signer.public_key, pins, %{trusted_anchor | ring_index: 0}) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case fork_at_anchor(reference,
    signer.public_key,
    pins,
    %{trusted_anchor | service_public_key: zero}) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case encode_fork(%{proof | second: AnchorReference(4096)}) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let unrelated = signing_pair()?
  case fork_same_size(proof, unrelated.public_key, pins) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let verdict = fork_same_size(decode_fork(encoded)?, signer.public_key, pins)?
  assert(Bytes.secure_equals(verdict.service_public_key, signer.public_key.bytes))
  assert(List.length(verdict.witnesses) == 1)
  assert(List.head(verdict.witnesses).witness_id == "both")
  case fork_same_size(%{proof | second: SignedCheckpoint(first)}, signer.public_key, pins) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case fork_same_size(%{proof | second: SignedCheckpoint(%{second | signature: repeated(0, 64)?})},
    signer.public_key,
    pins) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("equal-size signed forks implicate the directory and only witnesses signing both views") do
  case same_size() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn contradiction_and_rollback() -> Bool!String do
  let signer = signing_pair()?
  let zero = repeated(0, 32)?
  let a = Crypto.sha256(Bytes.from_utf8("a"))
  let b = Crypto.sha256(Bytes.from_utf8("b"))
  let c = Crypto.sha256(Bytes.from_utf8("c"))
  let d = Crypto.sha256(Bytes.from_utf8("d"))
  let first_leaves = [a, b, c]
  let second_leaves = [a, d, c, d]
  let first = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(10)?,
    first_leaves,
    zero,
    wide(1000)?)?
  let second = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(11)?,
    second_leaves,
    checkpoint_hash(first)?,
    wide(2000)?)?
  let paths = ForkPaths {
    leaf_index: wide(1)?,
    first_leaf: b,
    second_leaf: d,
    first_path: compact_inclusion_proof(first_leaves, 1)?.leaf_hashes,
    second_path: compact_inclusion_proof(second_leaves, 1)?.leaf_hashes
  }
  let proof = ForkProof {
    kind: 2,
    finder: zero,
    service_public_key: signer.public_key.bytes,
    first: first,
    second: SignedCheckpoint(second),
    attestations: [],
    contradiction: Some(paths)
  }
  let encoded = encode_fork(proof)?
  assert(Bytes.secure_equals(encoded, encode_fork(decode_fork(encoded)?)?))
  assert(List.length(fork_contradiction(decode_fork(encoded)?,
    signer.public_key,
    [])?.witnesses) == 0)
  case fork_contradiction(%{proof | contradiction: Some(%{paths | second_leaf: b})},
    signer.public_key,
    []) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case fork_contradiction(%{proof |
      contradiction: Some(%{paths | first_path: paths.first_path ++ [zero]})
    },
    signer.public_key,
    []) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case fork_contradiction(%{proof | contradiction: Some(%{paths | leaf_index: wide(3)?})},
    signer.public_key,
    []) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  fork_at_anchor(%{proof | second: AnchorReference(4095)},
    signer.public_key,
    [],
    anchor(second, [])?)?
  # Sequence and size disagree; order of the supplied pair does not matter.
  let smaller = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(11)?,
    [a],
    checkpoint_hash(first)?,
    wide(2000)?)?
  let rollback = %{proof | kind: 3, second: SignedCheckpoint(smaller), contradiction: None}
  fork_rollback(rollback, signer.public_key, [])?
  fork_at_anchor(%{rollback | second: AnchorReference(4095)},
    signer.public_key,
    [],
    anchor(smaller, [])?)?
  fork_rollback(%{rollback | first: smaller, second: SignedCheckpoint(first)},
    signer.public_key,
    [])?
  # An equal-sequence checkpoint with a new timestamp is also equivocation.
  let restated = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(10)?,
    first_leaves,
    zero,
    wide(2000)?)?
  fork_rollback(%{rollback | second: SignedCheckpoint(restated)}, signer.public_key, [])?
  case fork_rollback(%{rollback | second: SignedCheckpoint(first)}, signer.public_key, []) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case fork_rollback(%{rollback | second: SignedCheckpoint(second)}, signer.public_key, []) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("contradiction paths prove the same changed index and rollback compares complete checkpoints") do
  case contradiction_and_rollback() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
