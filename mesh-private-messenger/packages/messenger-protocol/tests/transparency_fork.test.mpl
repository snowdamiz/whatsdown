from Transparency.Codec import tcodec_join
from Transparency.Fork import (
  ForkEvidence,
  ForkLog,
  ForkRingEntry,
  fork_contradiction,
  fork_decode,
  fork_encode,
  fork_kind_between,
  fork_proof_hash,
  fork_rollback,
  fork_same_size,
  fork_verify
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  checkpoint_hash,
  leaf_hash,
  sign_checkpoint,
  sign_witness
)
from Transparency.Tree import tlog_inclusion_path, tlog_list_oracle

fn seed(value :: Int) -> Bytes!String do
  case Bytes.repeat(value, 32) do
    Err(_) -> Err("seed failed")
    Ok(bytes)
  end
end

fn signer(value :: Int) -> SigningKeyPair!String do
  case Crypto.signing_from_seed(seed(value)?) do
    Err(_) -> Err("signing key failed")
    Ok(pair)
  end
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn joined(parts :: List<Bytes>) -> Bytes!String do
  tcodec_join(parts)
end

fn flipped(value :: Bytes, position :: Int) -> Bytes!String do
  let before = case Bytes.slice(value, 0, position) do
    Err(_) -> Err("slice failed")
    Ok(bytes)
  end?
  let byte = case Bytes.get(value, position) do
    Err(_) -> Err("get failed")
    Ok(found)
  end?
  let tail = case Bytes.slice(value, position + 1, Bytes.length(value) - position - 1) do
    Err(_) -> Err("slice failed")
    Ok(bytes)
  end?
  let middle = case Bytes.from_list([(byte + 1) % 256]) do
    Err(_) -> Err("byte failed")
    Ok(bytes)
  end?
  joined([before, middle, tail])
end

fn replaced_byte(value :: Bytes, position :: Int, byte :: Int) -> Bytes!String do
  let current = case Bytes.get(value, position) do
    Err(_) -> Err("get failed")
    Ok(found)
  end?
  if current == byte do
    Ok(value)
  else
    let before = case Bytes.slice(value, 0, position) do
      Err(_) -> Err("slice failed")
      Ok(bytes)
    end?
    let tail = case Bytes.slice(value, position + 1, Bytes.length(value) - position - 1) do
      Err(_) -> Err("slice failed")
      Ok(bytes)
    end?
    let middle = case Bytes.from_list([byte]) do
      Err(_) -> Err("byte failed")
      Ok(bytes)
    end?
    joined([before, middle, tail])
  end
end

# A log whose directory signed two histories: leaf 3 differs between them.

struct Scene do
  log :: ForkLog
  honest :: List<Bytes>
  forked :: List<Bytes>
  honest6 :: TransparencyCheckpoint
  honest6_later :: TransparencyCheckpoint
  honest6_restamped :: TransparencyCheckpoint
  honest8 :: TransparencyCheckpoint
  forked6 :: TransparencyCheckpoint
  forked8 :: TransparencyCheckpoint
  rollback_high :: TransparencyCheckpoint
  rollback_low :: TransparencyCheckpoint
end

fn leaves(forked :: Bool) -> List<Bytes>!String do
  let values = for index in 0..8 do
    if forked && index == 3 do
      leaf_hash(Bytes.from_utf8("entry-3-forked"))?
    else
      leaf_hash(Bytes.from_utf8("entry-#{index}"))?
    end
  end
  Ok(values)
end

fn checkpoint(sequence :: Int,
  values :: List<Bytes>,
  size :: Int,
  previous :: Bytes,
  timestamp :: Int) -> TransparencyCheckpoint!String do
  let log_signer = signer(81)?
  sign_checkpoint(log_signer.private_key,
    log_signer.public_key.bytes,
    wide(sequence)?,
    List.take(values, size),
    previous,
    wide(timestamp)?)
end

fn scene() -> Scene!String do
  let log_signer = signer(81)?
  let a = signer(161)?
  let b = signer(178)?
  let c = signer(195)?
  let honest = leaves(false)?
  let forked = leaves(true)?
  let zero = seed(0)?
  let honest6 = checkpoint(5, honest, 6, zero, 1_790_000_000_000)?
  let forked6 = checkpoint(5, forked, 6, zero, 1_790_000_000_000)?
  let rollback_high = checkpoint(7, honest, 8, checkpoint_hash(honest6)?, 1_790_000_120_000)?
  Ok(Scene {
    log: ForkLog {
      service_public_key: log_signer.public_key.bytes,
      witnesses: [
        WitnessKey { witness_id: "witness-a", public_key: a.public_key.bytes },
        WitnessKey { witness_id: "witness-b", public_key: b.public_key.bytes },
        WitnessKey { witness_id: "witness-c", public_key: c.public_key.bytes }
      ]
    },
    honest: honest,
    forked: forked,
    honest6: honest6,
    honest6_later: checkpoint(6, honest, 6, checkpoint_hash(honest6)?, 1_790_000_240_000)?,
    honest6_restamped: checkpoint(5, honest, 6, zero, 1_790_000_000_001)?,
    honest8: checkpoint(6, honest, 8, checkpoint_hash(honest6)?, 1_790_000_060_000)?,
    forked6: forked6,
    forked8: checkpoint(6, forked, 8, checkpoint_hash(forked6)?, 1_790_000_060_000)?,
    rollback_high: rollback_high,
    rollback_low: checkpoint(8, honest, 6, checkpoint_hash(rollback_high)?, 1_790_000_180_000)?
  })
end

fn attest(witness :: String, value :: TransparencyCheckpoint) -> WitnessAttestation!String do
  let key = if witness == "witness-a" do
    signer(161)?
  else if witness == "witness-b" do
    signer(178)?
  else
    signer(195)?
  end
  sign_witness(witness, key.private_key, value)
end

fn evidence(kind :: Int,
  first :: TransparencyCheckpoint,
  second :: Option<TransparencyCheckpoint>,
  attestations :: List<WitnessAttestation>) -> ForkEvidence!String do
  Ok(ForkEvidence {
    kind: kind,
    finder: seed(0)?,
    service_public_key: first.service_public_key,
    first: first,
    second: second,
    ring_index: 0,
    attestations: attestations,
    leaf_index: 0,
    first_path: List.new(),
    first_leaf: Bytes.empty(),
    second_path: List.new(),
    second_leaf: Bytes.empty()
  })
end

fn with_leaf(value :: ForkEvidence,
  first_leaves :: List<Bytes>,
  first_size :: Int,
  second_leaves :: List<Bytes>,
  second_size :: Int) -> ForkEvidence!String do
  Ok(%{value |
    leaf_index: 3,
    first_path: tlog_inclusion_path(1, tlog_list_oracle(1, first_leaves), 3, first_size)?,
    first_leaf: List.get(first_leaves, 3),
    second_path: tlog_inclusion_path(1, tlog_list_oracle(1, second_leaves), 3, second_size)?,
    second_leaf: List.get(second_leaves, 3)
  })
end

fn ring_of(value :: TransparencyCheckpoint, bitmap :: Int) -> ForkRingEntry!String do
  Ok(ForkRingEntry {
    sequence: value.sequence,
    tree_size: value.tree_size,
    root: value.tree_root,
    checkpoint_hash: checkpoint_hash(value)?,
    cosign_bitmap: bitmap
  })
end

struct Vector do
  name :: String
  description :: String
  evidence :: ForkEvidence
  ring_index :: Int
  ring :: Option<ForkRingEntry>
  valid :: Bool
  implicated :: List<String>
end

fn vector(name :: String,
  description :: String,
  value :: ForkEvidence,
  valid :: Bool,
  implicated :: List<String>) -> Vector do
  Vector {
    name: name,
    description: description,
    evidence: value,
    ring_index: 0,
    ring: None,
    valid: valid,
    implicated: implicated
  }
end

fn ringed(name :: String,
  description :: String,
  value :: ForkEvidence,
  index :: Int,
  entry :: ForkRingEntry,
  valid :: Bool,
  implicated :: List<String>) -> Vector do
  Vector {
    name: name,
    description: description,
    evidence: %{value | second: None, ring_index: index},
    ring_index: index,
    ring: Some(entry),
    valid: valid,
    implicated: implicated
  }
end

fn same_size(s :: Scene) -> ForkEvidence!String do
  evidence(1,
    s.honest6,
    Some(s.forked6),
    [
      attest("witness-a", s.honest6)?,
      attest("witness-b", s.honest6)?,
      attest("witness-c", s.honest6)?,
      attest("witness-a", s.forked6)?,
      attest("witness-b", s.forked6)?
    ])
end

fn contradiction(s :: Scene) -> ForkEvidence!String do
  let base = evidence(2,
    s.honest6,
    Some(s.forked8),
    [
      attest("witness-a", s.honest6)?,
      attest("witness-b", s.honest6)?,
      attest("witness-a", s.forked8)?,
      attest("witness-c", s.forked8)?
    ])?
  with_leaf(base, s.honest, 6, s.forked, 8)
end

fn valid_vectors(s :: Scene) -> List<Vector>!String do
  let rollback = evidence(3,
    s.rollback_high,
    Some(s.rollback_low),
    [
      attest("witness-b", s.rollback_high)?,
      attest("witness-c", s.rollback_high)?,
      attest("witness-b", s.rollback_low)?,
      attest("witness-c", s.rollback_low)?
    ])?
  let restamped = evidence(3,
    s.honest6,
    Some(s.honest6_restamped),
    [attest("witness-a", s.honest6)?, attest("witness-a", s.honest6_restamped)?])?
  let contradiction_value = contradiction(s)?
  let ring_contradiction = %{contradiction_value | attestations: [attest("witness-b", s.honest6)?]}
  let same_size_value = same_size(s)?
  Ok([
    vector("f1-same-size",
      "Same sequence and size, different roots; a and b signed both",
      same_size_value,
      true,
      ["witness-a", "witness-b"]),
    vector("f1-same-size-finder",
      "f1-same-size naming a finder address; its proof hash is unchanged",
      %{same_size_value | finder: seed(122)?},
      true,
      ["witness-a", "witness-b"]),
    vector("f1-no-attestations",
      "A fork only the directory signed: valid, nobody else implicated",
      %{same_size_value | attestations: []},
      true,
      []),
    vector("f2-contradiction",
      "Sizes 6 and 8 read leaf 3 differently; only a signed both",
      contradiction_value,
      true,
      ["witness-a"]),
    vector("f3-rollback",
      "Sequence 7 has size 8, sequence 8 has size 6; b and c signed both",
      rollback,
      true,
      ["witness-b", "witness-c"]),
    vector("f3-same-sequence",
      "Two different checkpoints at sequence 5 over the same root",
      restamped,
      true,
      ["witness-a"]),
    ringed("f1-ring",
      "f1 against anchor ring entry 17 whose cosign bitmap holds a and c",
      %{same_size_value |
        attestations: [attest("witness-a", s.honest6)?, attest("witness-b", s.honest6)?]
      },
      17,
      ring_of(s.forked6, 5)?,
      true,
      ["witness-a"]),
    ringed("f2-ring",
      "f2 against anchor ring entry 18 (the forked size 8) cosigned by b",
      ring_contradiction,
      18,
      ring_of(s.forked8, 2)?,
      true,
      ["witness-b"]),
    ringed("f3-ring",
      "f3 against anchor ring entry 19 (sequence 8, size 6) cosigned by everyone",
      %{rollback | attestations: [attest("witness-c", s.rollback_high)?]},
      19,
      ring_of(s.rollback_low, 7)?,
      true,
      ["witness-c"])
  ])
end

fn invalid_vectors(s :: Scene) -> List<Vector>!String do
  let forked6 = s.forked6
  let tampered_second = %{forked6 | signature: flipped(forked6.signature, 0)?}
  let same_size_value = same_size(s)?
  let other_service = signer(82)?
  let contradiction_value = contradiction(s)?
  let bad_path = replaced_path(contradiction_value.first_path)?
  let honest_pair = with_leaf(evidence(2, s.honest6, Some(s.honest8), [])?,
    s.honest,
    6,
    s.honest,
    8)?
  Ok([
    vector("honest-f1-resigned",
      "An unchanged tree re-signed at the next sequence is not a fork",
      evidence(1,
        s.honest6,
        Some(s.honest6_later),
        [attest("witness-a", s.honest6)?, attest("witness-a", s.honest6_later)?])?,
      false,
      []),
    vector("honest-f3-extension",
      "A later honest checkpoint of the same log (sequence and size both grow)",
      evidence(3, s.honest6, Some(s.honest8), [])?,
      false,
      []),
    vector("honest-f2-same-leaf",
      "Leaf 3 reads the same at sizes 6 and 8 of the honest log",
      honest_pair,
      false,
      []),
    ringed("honest-f3-ring",
      "The honest size-8 checkpoint anchored at ring entry 20",
      evidence(3, s.honest6, None, [])?,
      20,
      ring_of(s.honest8, 7)?,
      false,
      []),
    vector("tampered-signature",
      "f1-same-size with the second checkpoint's service signature altered",
      %{same_size_value | second: Some(tampered_second)},
      false,
      []),
    vector("tampered-path",
      "f2-contradiction with a changed audit path hash",
      %{contradiction_value | first_path: bad_path},
      false,
      []),
    vector("wrong-service-key",
      "f1-same-size naming a service key that is not the log's",
      %{same_size_value | service_public_key: other_service.public_key.bytes},
      false,
      []),
    vector("wrong-kind",
      "The f2 pair (sizes 6 and 8) claimed as kind 1",
      evidence(1, s.honest6, Some(s.forked8), [])?,
      false,
      [])
  ])
end

fn replaced_path(values :: List<Bytes>) -> List<Bytes>!String do
  Ok([flipped(List.get(values, 0), 31)?] ++ List.drop(values, 1))
end

fn outcome(value :: Vector, log :: ForkLog) -> List<String>!String do
  fork_verify(value.evidence, log, value.ring)
end

fn verdicts() -> Bool!String do
  let s = scene()?
  for value in valid_vectors(s)? do
    case outcome(value, s.log) do
      Ok(ids) -> assert(ids == value.implicated)
      Err(error) -> do
        println(value.name <> ": " <> error)
        assert(false)
      end
    end
    let encoded = fork_encode(value.evidence)?
    let decoded = fork_decode(encoded)?
    assert(Bytes.secure_equals(fork_encode(decoded)?, encoded))
    assert(fork_verify(decoded, s.log, value.ring)? == value.implicated)
  end
  for value in invalid_vectors(s)? do
    case outcome(value, s.log) do
      Ok(_) -> do
        println(value.name <> " was accepted")
        assert(false)
      end
      Err(_) -> nil
    end
  end
  Ok(true)
end

test("real forks of each kind are accepted, honest pairs and tampered proofs refused") do
  case verdicts() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn per_kind() -> Bool!String do
  let s = scene()?
  let one = same_size(s)?
  assert(fork_same_size(one, s.log, None)? == ["witness-a", "witness-b"])
  assert(fork_rollback(one, s.log, None)? == ["witness-a", "witness-b"])
  case fork_contradiction(one, s.log, None) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  let two = contradiction(s)?
  assert(fork_contradiction(two, s.log, None)? == ["witness-a"])
  case fork_same_size(two, s.log, None) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "not_a_fork")
  end
  case fork_verify(%{one | second: None, ring_index: 3}, s.log, None) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "fork_ring_entry_required")
  end
  assert(fork_kind_between(s.honest6, s.forked6)? == 1)
  assert(fork_kind_between(s.rollback_high, s.rollback_low)? == 3)
  assert(fork_kind_between(s.honest6, s.honest6_restamped)? == 3)
  assert(fork_kind_between(s.honest6, s.forked8)? == 0)
  assert(fork_kind_between(s.honest6, s.honest8)? == 0)
  assert(fork_kind_between(s.honest6, s.honest6)? == 0)
  Ok(true)
end

test("each fork check returns the implicated witnesses or refuses a non-fork") do
  case per_kind() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn codec_rules() -> Bool!String do
  let s = scene()?
  let base = same_size(s)?
  let plain = fork_encode(base)?
  let named = fork_encode(%{base | finder: seed(122)?})?
  assert(Bytes.length(plain) == 258 + 188 + 1 + 5 * (1 + 9 + 96))
  assert(!Bytes.secure_equals(plain, named))
  assert(Bytes.secure_equals(fork_proof_hash(plain)?, fork_proof_hash(named)?))
  let other = fork_encode(%{base | kind: 3})?
  assert(!Bytes.secure_equals(fork_proof_hash(plain)?, fork_proof_hash(other)?))
  for bad in non_canonical(plain)? do
    case fork_decode(Tuple.second(bad)) do
      Ok(_) -> do
        println(Tuple.first(bad) <> " decoded")
        assert(false)
      end
      Err(_) -> nil
    end
  end
  let seventeen = for index in 0..17 do
    attest("witness-a", s.honest6)?
  end
  case fork_encode(%{base | attestations: seventeen}) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  let ring = fork_encode(%{base | second: None, ring_index: 4_294_967_295})?
  assert(Bytes.length(ring) == 258 + 4 + 1 + 5 * (1 + 9 + 96))
  assert(fork_decode(ring)?.ring_index == 4_294_967_295)
  Ok(true)
end

fn non_canonical(plain :: Bytes) -> List<(String, Bytes)>!String do
  let trailing = joined([plain, seed(0)?])?
  Ok([
    ("trailing-byte", trailing),
    ("unknown-kind", replaced_byte(plain, 4, 4)?),
    ("kind-zero", replaced_byte(plain, 4, 0)?),
    ("bad-form", replaced_byte(plain, 257, 2)?),
    ("too-many-attestations", replaced_byte(plain, 446, 17)?),
    ("version-two", replaced_byte(plain, 0, 2)?),
    ("truncated",
      case Bytes.slice(plain, 0, Bytes.length(plain) - 1) do
        Ok(value) -> value
        Err(_) -> Bytes.empty()
      end)
  ])
end

test("the proof hash ignores the finder, and non-canonical encodings are refused") do
  case codec_rules() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn json_string(text :: String) -> String do
  "\"" <> text <> "\""
end

fn json_bool(value :: Bool) -> String do
  if value do
    "true"
  else
    "false"
  end
end

fn json_strings(values :: List<String>) -> String do
  "[" <> String.join(List.map(values, fn value -> json_string(value) end), ", ") <> "]"
end

fn witness_json(key :: WitnessKey, seed_byte :: Int) -> String!String do
  Ok("    {\"witness_id\": "
    <> json_string(key.witness_id)
    <> ", \"seed\": "
    <> json_string(Bytes.to_hex(seed(seed_byte)?))
    <> ", \"public_key\": "
    <> json_string(Bytes.to_hex(key.public_key))
    <> "}")
end

fn ring_json(value :: Vector) -> String do
  case value.ring do
    None -> "null"
    Some(entry) -> "{\"ring_index\": "
      <> Int.to_string(value.ring_index)
      <> ", \"sequence\": "
      <> json_string(U64.to_string(entry.sequence))
      <> ", \"tree_size\": "
      <> json_string(U64.to_string(entry.tree_size))
      <> ", \"root\": "
      <> json_string(Bytes.to_hex(entry.root))
      <> ", \"checkpoint_hash\": "
      <> json_string(Bytes.to_hex(entry.checkpoint_hash))
      <> ", \"cosign_bitmap\": "
      <> Int.to_string(entry.cosign_bitmap)
      <> "}"
  end
end

fn log_json(log :: ForkLog) -> String!String do
  let witnesses = [
    witness_json(List.get(log.witnesses, 0), 161)?,
    witness_json(List.get(log.witnesses, 1), 178)?,
    witness_json(List.get(log.witnesses, 2), 195)?
  ]
  Ok("  \"log\": {\n    \"service_seed\": "
    <> json_string(Bytes.to_hex(seed(81)?))
    <> ",\n    \"service_public_key\": "
    <> json_string(Bytes.to_hex(log.service_public_key))
    <> ",\n    \"witnesses\": [\n"
    <> String.join(List.map(witnesses, fn line -> "  " <> line end), ",\n")
    <> "\n    ]\n  },\n")
end

fn vector_json(name :: String,
  description :: String,
  kind :: Int,
  frk :: Bytes,
  decodes :: Bool,
  valid :: Bool,
  implicated :: List<String>,
  ring :: String,
  log :: ForkLog) -> String!String do
  let proof_hash = if decodes do
    Bytes.to_hex(fork_proof_hash(frk)?)
  else
    ""
  end
  let finder = case Bytes.slice(frk, 5, 32) do
    Ok(value) -> Bytes.to_hex(value)
    Err(_) -> ""
  end
  Ok("{\n  \"name\": "
    <> json_string(name)
    <> ",\n  \"description\": "
    <> json_string(description)
    <> ",\n  \"kind\": "
    <> Int.to_string(kind)
    <> ",\n  \"decodes\": "
    <> json_bool(decodes)
    <> ",\n  \"valid\": "
    <> json_bool(valid)
    <> ",\n"
    <> log_json(log)?
    <> "  \"ring\": "
    <> ring
    <> ",\n  \"frk\": "
    <> json_string(Bytes.to_hex(frk))
    <> ",\n  \"finder\": "
    <> json_string(finder)
    <> ",\n  \"proof_hash\": "
    <> json_string(proof_hash)
    <> ",\n  \"implicated\": "
    <> json_strings(implicated)
    <> "\n}\n")
end

fn fixtures() -> List<(String, String)>!String do
  let s = scene()?
  let judged = for value in valid_vectors(s)? ++ invalid_vectors(s)? do
    (value.name,
      vector_json(value.name,
        value.description,
        value.evidence.kind,
        fork_encode(value.evidence)?,
        true,
        value.valid,
        value.implicated,
        ring_json(value),
        s.log)?)
  end
  let malformed = for bad in non_canonical(fork_encode(same_size(s)?)?)? do
    ("malformed-" <> Tuple.first(bad),
      vector_json("malformed-" <> Tuple.first(bad),
        "f1-same-size bytes made non-canonical (" <> Tuple.first(bad) <> "); must not decode",
        1,
        Tuple.second(bad),
        false,
        false,
        [],
        "null",
        s.log)?)
  end
  Ok(judged ++ malformed)
end

fn fixture_dir() -> String do
  let candidates = [
    Env.get("MESSENGER_FRK_FIXTURE_DIR", ""),
    "mesh-private-messenger/tests/fixtures/frk",
    "../mesh-private-messenger/tests/fixtures/frk",
    "tests/fixtures/frk",
    "../../tests/fixtures/frk"
  ]
  case List.find(candidates, fn dir -> dir != "" && File.exists(dir <> "/f1-same-size.json") end) do
    Some(dir) -> dir
    None -> ""
  end
end

fn golden() -> Bool!String do
  let write_dir = Env.get("MESSENGER_FRK_FIXTURE_WRITE", "")
  let values = fixtures()?
  if write_dir != "" do
    for pair in values do
      File.write(write_dir <> "/" <> Tuple.first(pair) <> ".json", Tuple.second(pair))?
    end
    Ok(true)
  else
    let dir = fixture_dir()
    if dir == "" do
      Err("FRK fixtures not found; set MESSENGER_FRK_FIXTURE_DIR")
    else
      for pair in values do
        let stored = File.read(dir <> "/" <> Tuple.first(pair) <> ".json")?
        if stored != Tuple.second(pair) do
          println("stale fixture: " <> Tuple.first(pair))
          assert(false)
        else
          nil
        end
      end
      Ok(true)
    end
  end
end

test("the FRK vectors the judge replays match what this code produces") do
  case golden() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
