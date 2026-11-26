from Transparency.Client import transparency_verify_evidence_v2
from Transparency.Codec import transparency_frame_version
from Transparency.CompactWire import (
  CompactConsistency,
  CompactInclusion,
  TransparencyEvidenceV2,
  TransparencyLeafProof,
  TransparencyLeafQuery,
  TransparencyTreeQueryV2,
  WitnessCosignature,
  transparency_decode_consistency_v2,
  transparency_decode_cosignatures,
  transparency_decode_evidence_v2,
  transparency_decode_inclusion_v2,
  transparency_decode_leaf_proof,
  transparency_decode_leaf_query,
  transparency_decode_lookup_v2,
  transparency_decode_tree_query_v2,
  transparency_encode_consistency_v2,
  transparency_encode_cosignatures,
  transparency_encode_evidence_v2,
  transparency_encode_inclusion_v2,
  transparency_encode_leaf_proof,
  transparency_encode_leaf_query,
  transparency_encode_lookup_v2,
  transparency_encode_tree_query_v2
)
from Transparency.Merkle import (
  InclusionProof,
  TransparencyCheckpoint,
  WitnessKey,
  checkpoint_hash,
  leaf_hash,
  sign_checkpoint,
  sign_witness,
  transparency_sign_checkpoint_root
)
from Transparency.Note import note_checkpoint_body, note_cosign, note_read_cosignatures
from Transparency.Tree import (
  tlog_consistency_path,
  tlog_inclusion_path,
  tlog_leaf,
  tlog_list_oracle,
  tlog_node,
  tlog_root
)
from Transparency.Wire import (
  TransparencyLookup,
  decode_inclusion_proof,
  decode_transparency_lookup,
  encode_checkpoint,
  encode_inclusion_proof,
  encode_transparency_lookup
)

fn is_err<T>(result :: Result<T, String>) -> Bool do
  case result do
    Ok(_) -> false
    Err(_) -> true
  end
end

fn signer(seed :: Int) -> SigningKeyPair!String do
  let bytes = case Bytes.repeat(seed, 32) do
    Err(_) -> Err("seed failed")
    Ok(value)
  end?
  case Crypto.signing_from_seed(bytes) do
    Err(_) -> Err("signing key failed")
    Ok(value)
  end
end

fn repeated(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("bytes failed")
    Ok(output)
  end
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn joined(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("concat failed")
    Ok(value)
  end
end

fn entry(index :: Int) -> Bytes do
  Bytes.from_utf8("device-set-#{index}")
end

fn leaves(count :: Int) -> List<Bytes>!String do
  let values = for index in 0..count do
    leaf_hash(entry(index))?
  end
  Ok(values)
end

fn proof_frames() -> Bool!String do
  let hashes = leaves(37)?
  let oracle = tlog_list_oracle(1, hashes)
  let inclusion = CompactInclusion {
    leaf_index: 25,
    tree_size: 37,
    path: tlog_inclusion_path(1, oracle, 25, 37)?
  }
  let encoded = transparency_encode_inclusion_v2(inclusion)?
  assert(Bytes.length(encoded) == 21 + 32 * List.length(inclusion.path))
  assert(transparency_frame_version(encoded)? == 2)
  let decoded = transparency_decode_inclusion_v2(encoded)?
  assert(decoded.leaf_index == 25 && decoded.tree_size == 37)
  assert(List.length(decoded.path) == List.length(inclusion.path))
  let legacy = encode_inclusion_proof(InclusionProof {
    leaf_index: 1,
    tree_size: 2,
    leaf_hashes: List.take(hashes, 2)
  })?
  assert(transparency_frame_version(legacy)? == 1)
  assert(decode_inclusion_proof(legacy)?.tree_size == 2)
  assert(is_err(transparency_decode_inclusion_v2(legacy)))
  assert(is_err(decode_inclusion_proof(encoded)))
  assert(is_err(transparency_decode_inclusion_v2(joined(encoded, repeated(0, 1)?)?)))
  assert(is_err(transparency_encode_inclusion_v2(CompactInclusion {
    leaf_index: 37,
    tree_size: 37,
    path: []
  })))
  let too_long = for index in 0..65 do
    List.get(hashes, 0)
  end
  assert(is_err(transparency_encode_inclusion_v2(CompactInclusion {
    leaf_index: 0,
    tree_size: 37,
    path: too_long
  })))
  let consistency = CompactConsistency {
    old_size: 20,
    new_size: 37,
    path: tlog_consistency_path(1, oracle, 20, 37)?
  }
  let decoded_consistency = transparency_decode_consistency_v2(transparency_encode_consistency_v2(consistency)?)?
  assert(decoded_consistency.old_size == 20 && decoded_consistency.new_size == 37)
  assert(List.length(decoded_consistency.path) == List.length(consistency.path))
  assert(is_err(transparency_encode_consistency_v2(CompactConsistency {
    old_size: 38,
    new_size: 37,
    path: []
  })))
  let huge = CompactConsistency {
    old_size: 1_000_000_000_000,
    new_size: 4_611_686_018_427_387_903,
    path: []
  }
  assert(transparency_decode_consistency_v2(transparency_encode_consistency_v2(huge)?)?.new_size == 4_611_686_018_427_387_903)
  assert(is_err(transparency_encode_consistency_v2(CompactConsistency {
    old_size: 0,
    new_size: 4_611_686_018_427_387_904,
    path: []
  })))
  Ok(true)
end

test("KTI and KTC v2 carry compact paths and u64 sizes; v1 frames decode only as v1") do
  case proof_frames() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn query_frames() -> Bool!String do
  let account = "@1111111111111111111111111111111111111111111111111111111111111111"
  let by_account = transparency_encode_lookup_v2(TransparencyLookup {
    username: account,
    previous_tree_size: 5_000_000
  })?
  assert(Bytes.length(by_account) == 44)
  let decoded_account = transparency_decode_lookup_v2(by_account)?
  assert(decoded_account.username == account && decoded_account.previous_tree_size == 5_000_000)
  let by_name = transparency_encode_lookup_v2(TransparencyLookup {
    username: "alice",
    previous_tree_size: 4097
  })?
  assert(Bytes.length(by_name) == 4 + 4 + 5 + 8)
  assert(transparency_decode_lookup_v2(by_name)?.previous_tree_size == 4097)
  assert(is_err(encode_transparency_lookup(TransparencyLookup {
    username: "alice",
    previous_tree_size: 4097
  })))
  let legacy = encode_transparency_lookup(TransparencyLookup {
    username: "alice",
    previous_tree_size: 7
  })?
  assert(decode_transparency_lookup(legacy)?.previous_tree_size == 7)
  assert(is_err(transparency_decode_lookup_v2(legacy)))
  assert(is_err(decode_transparency_lookup(by_name)))
  assert(is_err(transparency_encode_lookup_v2(TransparencyLookup {
    username: "Alice",
    previous_tree_size: 0
  })))
  let tree_query = transparency_decode_tree_query_v2(transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
    old_size: 4096,
    new_size: 0,
    tree: 2
  })?)?
  assert(tree_query.old_size == 4096 && tree_query.new_size == 0 && tree_query.tree == 2)
  assert(is_err(transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
    old_size: 1,
    new_size: 2,
    tree: 3
  })))
  assert(is_err(transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
    old_size: 3,
    new_size: 2,
    tree: 1
  })))
  let leaf_query = transparency_decode_leaf_query(transparency_encode_leaf_query(TransparencyLeafQuery {
    leaf_index: 9,
    tree_size: 10,
    tree: 1
  })?)?
  assert(leaf_query.leaf_index == 9 && leaf_query.tree_size == 10 && leaf_query.tree == 1)
  assert(is_err(transparency_encode_leaf_query(TransparencyLeafQuery {
    leaf_index: 10,
    tree_size: 10,
    tree: 1
  })))
  let hashes = leaves(10)?
  let proof = TransparencyLeafProof {
    leaf_hash: List.get(hashes, 9),
    inclusion: CompactInclusion {
      leaf_index: 9,
      tree_size: 10,
      path: tlog_inclusion_path(2, tlog_list_oracle(2, hashes), 9, 10)?
    }
  }
  let decoded_proof = transparency_decode_leaf_proof(transparency_encode_leaf_proof(proof)?)?
  assert(Bytes.secure_equals(decoded_proof.leaf_hash, List.get(hashes, 9)))
  assert(decoded_proof.inclusion.tree_size == 10)
  Ok(true)
end

test("KTQ, KTA, KTS, KTP and KTL v2 round-trip past the old 4,096 bound and refuse bad fields") do
  case query_frames() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn attestation_frames() -> Bool!String do
  let values = [
    WitnessCosignature {
      kind: 1,
      witness_id: "witness-a",
      checkpoint_hash: repeated(1, 32)?,
      timestamp: 0,
      signature: repeated(2, 64)?
    },
    WitnessCosignature {
      kind: 2,
      witness_id: "outside-1",
      checkpoint_hash: Bytes.empty(),
      timestamp: 1_790_000_000,
      signature: repeated(3, 64)?
    }
  ]
  let encoded = transparency_encode_cosignatures(values)?
  assert(Bytes.length(encoded) == 6 + (1 + 4 + 9 + 96) + (1 + 4 + 9 + 72))
  let decoded = transparency_decode_cosignatures(encoded)?
  assert(List.length(decoded) == 2)
  assert(List.get(decoded, 0).kind == 1 && List.get(decoded, 0).witness_id == "witness-a")
  assert(List.get(decoded, 1).kind == 2 && List.get(decoded, 1).timestamp == 1_790_000_000)
  assert(is_err(transparency_decode_cosignatures(joined(encoded, repeated(0, 1)?)?)))
  let seventeen = for index in 0..17 do
    List.get(values, 0)
  end
  assert(is_err(transparency_encode_cosignatures(seventeen)))
  assert(is_err(transparency_encode_cosignatures([
    WitnessCosignature {
      kind: 3,
      witness_id: "witness-a",
      checkpoint_hash: repeated(1, 32)?,
      timestamp: 0,
      signature: repeated(2, 64)?
    }
  ])))
  let kind_three = case Bytes.from_hex("024b5457000103") do
    Err(_) -> Err("hex failed")
    Ok(value)
  end?
  assert(is_err(transparency_decode_cosignatures(kind_three)))
  Ok(true)
end

test("KTW v2 carries Morse and C2SP attestations and refuses unknown kinds and trailing bytes") do
  case attestation_frames() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

struct Fixture do
  first :: TransparencyCheckpoint
  second :: TransparencyCheckpoint
  evidence :: TransparencyEvidenceV2
  witnesses :: List<WitnessKey>
  body :: String
  now :: U64
end

fn attest(id :: String,
  key :: borrow SigningPrivateKey,
  checkpoint :: TransparencyCheckpoint) -> WitnessCosignature!String do
  let value = sign_witness(id, key, checkpoint)?
  Ok(WitnessCosignature {
    kind: 1,
    witness_id: id,
    checkpoint_hash: value.checkpoint_hash,
    timestamp: 0,
    signature: value.signature
  })
end

fn cosign(id :: String,
  name :: String,
  key :: borrow SigningPrivateKey,
  public_key :: Bytes,
  body :: String,
  timestamp :: Int) -> WitnessCosignature!String do
  let line = note_cosign(body, name, key, public_key, timestamp)?
  let value = List.get(note_read_cosignatures(line, name, public_key, body)?, 0)
  Ok(WitnessCosignature {
    kind: 2,
    witness_id: id,
    checkpoint_hash: Bytes.empty(),
    timestamp: value.timestamp,
    signature: value.signature
  })
end

fn fixture() -> Fixture!String do
  let log = signer(21)?
  let a = signer(22)?
  let b = signer(23)?
  let c = signer(24)?
  let hashes = leaves(37)?
  let first = sign_checkpoint(log.private_key,
    log.public_key.bytes,
    wide(1)?,
    List.take(hashes, 20),
    repeated(0, 32)?,
    wide(1_790_000_000_000)?)?
  let second = sign_checkpoint(log.private_key,
    log.public_key.bytes,
    wide(2)?,
    hashes,
    checkpoint_hash(first)?,
    wide(1_790_000_060_000)?)?
  let wrapped = for hash in hashes do
    tlog_leaf(2, hash)?
  end
  let rfc_oracle = tlog_list_oracle(2, wrapped)
  let rfc_root = tlog_root(2, rfc_oracle, 37)?
  let body = note_checkpoint_body("morseapp.io/log/main", 37, rfc_root, encode_checkpoint(second)?)?
  let oracle = tlog_list_oracle(1, hashes)
  let evidence = TransparencyEvidenceV2 {
    entry_bytes: entry(25),
    inclusion: CompactInclusion {
      leaf_index: 25,
      tree_size: 37,
      path: tlog_inclusion_path(1, oracle, 25, 37)?
    },
    consistency: CompactConsistency {
      old_size: 20,
      new_size: 37,
      path: tlog_consistency_path(1, oracle, 20, 37)?
    },
    checkpoint: second,
    witnesses: [
      attest("witness-a", a.private_key, second)?,
      attest("witness-b", b.private_key, second)?,
      cosign("witness-c",
        "witness.example/c",
        c.private_key,
        c.public_key.bytes,
        body,
        1_790_000_070)?
    ],
    c2sp_root: rfc_root,
    c2sp_path: tlog_inclusion_path(2, rfc_oracle, 25, 37)?
  }
  Ok(Fixture {
    first: first,
    second: second,
    evidence: evidence,
    witnesses: [
      WitnessKey { witness_id: "witness-a", public_key: a.public_key.bytes },
      WitnessKey { witness_id: "witness-b", public_key: b.public_key.bytes },
      WitnessKey { witness_id: "witness-c", public_key: c.public_key.bytes }
    ],
    body: body,
    now: wide(1_790_000_100_000)?
  })
end

fn only(evidence :: TransparencyEvidenceV2, ids :: List<String>) -> TransparencyEvidenceV2 do
  %{evidence |
    witnesses: List.filter(evidence.witnesses, fn value -> List.contains(ids, value.witness_id) end)
  }
end

fn accepts(value :: Fixture,
  evidence :: TransparencyEvidenceV2,
  origin :: String,
  previous :: Bytes,
  now :: U64) -> Bool!String do
  transparency_verify_evidence_v2(evidence,
    SigningPublicKey { bytes: value.second.service_public_key },
    value.witnesses,
    2,
    origin,
    previous,
    now)
end

fn evidence_round_trip() -> Bool!String do
  let value = fixture()?
  let encoded = transparency_encode_evidence_v2(value.evidence)?
  let decoded = transparency_decode_evidence_v2(encoded)?
  assert(Bytes.secure_equals(decoded.entry_bytes, entry(25)))
  assert(List.length(decoded.witnesses) == 3)
  assert(Bytes.secure_equals(decoded.c2sp_root, value.evidence.c2sp_root))
  assert(List.length(decoded.c2sp_path) == List.length(value.evidence.c2sp_path))
  assert(is_err(transparency_decode_evidence_v2(joined(encoded, repeated(0, 1)?)?)))
  let viewless = %{value.evidence | c2sp_root: Bytes.empty(), c2sp_path: []}
  assert(is_err(transparency_encode_evidence_v2(viewless)))
  let morse_only = only(viewless, ["witness-a", "witness-b"])
  assert(List.length(transparency_decode_evidence_v2(transparency_encode_evidence_v2(morse_only)?)?.witnesses) == 2)
  Ok(true)
end

test("KTE v2 round-trips and requires the C2SP view whenever a kind-2 attestation is present") do
  case evidence_round_trip() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn threshold_rules() -> Bool!String do
  let value = fixture()?
  let previous = encode_checkpoint(value.first)?
  let origin = "morseapp.io/log/main"
  let evidence = value.evidence
  assert(accepts(value, only(evidence, ["witness-a", "witness-b"]), origin, previous, value.now)?)
  assert(!accepts(value, only(evidence, ["witness-a"]), origin, previous, value.now)?)
  assert(accepts(value, only(evidence, ["witness-a", "witness-c"]), origin, previous, value.now)?)
  assert(!accepts(value, only(evidence, ["witness-a", "witness-c"]), "-", previous, value.now)?)
  assert(!accepts(value,
    only(evidence, ["witness-a", "witness-c"]),
    "morseapp.io/log/canary",
    previous,
    value.now)?)
  assert(!accepts(value,
    only(evidence, ["witness-a", "witness-c"]),
    origin,
    previous,
    wide(1_790_000_370_001)?)?)
  let a_twice = %{evidence |
    witnesses: [List.get(evidence.witnesses, 0), List.get(evidence.witnesses, 0)]
  }
  assert(!accepts(value, a_twice, origin, previous, value.now)?)
  let renamed = %{List.get(evidence.witnesses, 1) | witness_id: "witness-z"}
  assert(!accepts(value,
    %{evidence | witnesses: [List.get(evidence.witnesses, 0), renamed]},
    origin,
    previous,
    value.now)?)
  Ok(true)
end

test("k pinned attestations pass and k - 1 fail; a witness counts once whatever its kind") do
  case threshold_rules() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn dual_inclusion() -> Bool!String do
  let value = fixture()?
  let previous = encode_checkpoint(value.first)?
  let origin = "morseapp.io/log/main"
  let c2sp = only(value.evidence, ["witness-a", "witness-c"])
  assert(accepts(value, c2sp, origin, previous, value.now)?)
  let hashes = leaves(37)?
  let wrapped = for hash in hashes do
    tlog_leaf(2, hash)?
  end
  let other_path = tlog_inclusion_path(2, tlog_list_oracle(2, wrapped), 24, 37)?
  assert(!accepts(value, %{c2sp | c2sp_path: other_path}, origin, previous, value.now)?)
  let shorter_root = tlog_root(2, tlog_list_oracle(2, wrapped), 36)?
  assert(!accepts(value, %{c2sp | c2sp_root: shorter_root}, origin, previous, value.now)?)
  let substituted = tlog_node(2, List.get(wrapped, 0), List.get(wrapped, 1))?
  assert(!accepts(value,
    %{c2sp | c2sp_path: [substituted] ++ List.drop(c2sp.c2sp_path, 1)},
    origin,
    previous,
    value.now)?)
  Ok(true)
end

test("a C2SP cosignature counts only when the entry is proven in the cosigned RFC 6962 tree") do
  case dual_inclusion() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn history_rules() -> Bool!String do
  let value = fixture()?
  let origin = "morseapp.io/log/main"
  let evidence = only(value.evidence, ["witness-a", "witness-b"])
  let previous = encode_checkpoint(value.first)?
  assert(accepts(value, evidence, origin, previous, value.now)?)
  assert(!accepts(value, %{evidence | entry_bytes: entry(24)}, origin, previous, value.now)?)
  let from_empty = %{evidence |
    consistency: CompactConsistency { old_size: 0, new_size: 37, path: [] }
  }
  assert(accepts(value, from_empty, origin, Bytes.empty(), value.now)?)
  assert(!accepts(value, from_empty, origin, previous, value.now)?)
  assert(!accepts(value, evidence, origin, Bytes.empty(), value.now)?)
  let log = signer(21)?
  let rival = sign_checkpoint(log.private_key,
    log.public_key.bytes,
    wide(2)?,
    List.take(leaves(37)?, 20),
    checkpoint_hash(value.first)?,
    wide(1_790_000_060_000)?)?
  assert(!accepts(value, evidence, origin, encode_checkpoint(rival)?, value.now)?)
  Ok(true)
end

test("v2 evidence must extend the cached checkpoint and contain the looked-up entry") do
  case history_rules() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

# Every leaf of this synthetic log is the same entry, so proofs for a
# trillion-leaf tree are computed in O(log n) without a leaf list.

fn uniform_node(level :: Int, leaf :: Bytes) -> Bytes!String do
  if level == 0 do
    Ok(leaf)
  else
    let child = uniform_node(level - 1, leaf)?
    tlog_node(1, child, child)
  end
end

fn beyond_ceiling() -> Bool!String do
  let log = signer(31)?
  let a = signer(32)?
  let b = signer(33)?
  let leaf = leaf_hash(entry(0))?
  let oracle = fn level, index -> uniform_node(level, leaf) end
  let old_size = 1_000_000
  let size = 1_000_000_000_001
  let first = transparency_sign_checkpoint_root(log.private_key,
    log.public_key.bytes,
    wide(1)?,
    wide(old_size)?,
    tlog_root(1, oracle, old_size)?,
    repeated(0, 32)?,
    wide(1000)?)?
  let second = transparency_sign_checkpoint_root(log.private_key,
    log.public_key.bytes,
    wide(2)?,
    wide(size)?,
    tlog_root(1, oracle, size)?,
    checkpoint_hash(first)?,
    wide(2000)?)?
  let evidence = TransparencyEvidenceV2 {
    entry_bytes: entry(0),
    inclusion: CompactInclusion {
      leaf_index: size - 1,
      tree_size: size,
      path: tlog_inclusion_path(1, oracle, size - 1, size)?
    },
    consistency: CompactConsistency {
      old_size: old_size,
      new_size: size,
      path: tlog_consistency_path(1, oracle, old_size, size)?
    },
    checkpoint: second,
    witnesses: [
      attest("witness-a", a.private_key, second)?,
      attest("witness-b", b.private_key, second)?
    ],
    c2sp_root: Bytes.empty(),
    c2sp_path: []
  }
  let encoded = transparency_encode_evidence_v2(evidence)?
  assert(Bytes.length(encoded) < 4096)
  assert(transparency_verify_evidence_v2(transparency_decode_evidence_v2(encoded)?,
    log.public_key,
    [
      WitnessKey { witness_id: "witness-a", public_key: a.public_key.bytes },
      WitnessKey { witness_id: "witness-b", public_key: b.public_key.bytes }
    ],
    2,
    "-",
    encode_checkpoint(first)?,
    wide(2000)?)?)
  Ok(true)
end

test("v2 evidence for a trillion-entry log is under 4 KB and verifies") do
  case beyond_ceiling() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
