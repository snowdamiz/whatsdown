from Api.Binary import (
  consistency_request,
  inclusion_request,
  resolve_devices_request,
  submit_witness_request,
  witnesses_request
)
from Api.WitnessNetwork import (
  anchor_request,
  health_request,
  leaf_request,
  leaves_request,
  push_witnesses_request,
  registry_request,
  submit_anchor_request,
  submit_cosignature_request,
  witnesses_at_request,
  witnesses_v2_request
)
from Storage.Transparency import checkpoint_note, create_checkpoint, latest_checkpoint
from Storage.TransparencyWitnesses import (
  RegistryWitness,
  transparency_registry_from_json,
  transparency_registry_upsert_on_connection,
  transparency_seed_registry
)
from Tests.MailboxSupport import register_test_mailbox
from Tests.TransparencySupport import (
  transparency_test_append,
  transparency_test_attest,
  transparency_test_bytes,
  transparency_test_reset,
  transparency_test_scalar,
  transparency_test_set,
  transparency_test_witness_key
)
from Transparency.Client import transparency_verify_evidence_v2
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
  transparency_encode_cosignatures,
  transparency_encode_leaf_query,
  transparency_encode_lookup_v2,
  transparency_encode_tree_query_v2
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  checkpoint_hash,
  sign_witness
)
from Transparency.Note import NoteCheckpoint, note_cosign, note_open_checkpoint
from Transparency.Tree import tlog_leaf, tlog_verify_consistency, tlog_verify_inclusion
from Transparency.Wire import (
  TransparencyLookup,
  decode_witnesses,
  encode_checkpoint,
  encode_witnesses
)

fn database() -> PoolHandle!String do
  Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)
end

fn origin() -> String do
  "morseapp.io/log/main"
end

fn log_seed() -> Bytes!String do
  Bytes.from_hex(Env.get("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX", ""))
end

fn keys(seed :: Int) -> SigningKeyPair!String do
  case Crypto.signing_from_seed(transparency_test_bytes(seed, 32)) do
    Err(_) -> Err("witness key failed")
    Ok(value)
  end
end

fn body_text(value :: Bytes) -> String!String do
  Bytes.to_utf8(value)
end

fn witness(witness_id :: String,
  public_key :: Bytes,
  status :: String,
  software :: String,
  c2sp_name :: String,
  push_url :: String) -> RegistryWitness do
  RegistryWitness {
    witness_id: witness_id,
    public_key: public_key,
    operator: if String.starts_with(witness_id, "witness-") do
      "Morse"
    else
      "Outside operator"
    end,
    status: status,
    software: software,
    push_url: push_url,
    morse_run: String.starts_with(witness_id, "witness-"),
    c2sp_name: c2sp_name
  }
end

fn upsert(pool :: PoolHandle, entry :: RegistryWitness) -> Result<(), String> do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> transparency_registry_upsert_on_connection(conn, entry) end)
end

fn refused(result :: Result<(), String>) -> Bool do
  case result do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn json_field(body :: Bytes, key :: String) -> Json!String do
  Json.object_get(Json.parse(body_text(body)?)?, key)
end

# Witnesses move from shadow to pinned to retired; a key stays with its ID for
# good and a retired witness never returns. Only Morse's witnesses is a normal
# registry.

fn registry_proof() -> Bool!String do
  let pool = database()?
  transparency_test_reset(pool)?
  transparency_seed_registry(pool)?
  let only_morse = json_field(registry_request(pool).body, "witnesses")?
  assert(Json.array_length(only_morse)? == 2)
  assert(Json.as_string(Json.object_get(Json.array_get(only_morse, 0)?, "operator")?)? == "Morse")
  assert(Json.as_bool(Json.object_get(Json.array_get(only_morse, 0)?, "morse_run")?)?)
  # The jobs Worker's list holds every non-retired entry, the default
  # legacy-seeded witness-a and witness-b included: Morse-run, Mesh software, no
  # C2SP push URL. It asks them to sign through their configured /attest.
  let pushed = body_text(push_witnesses_request(pool).body)?
  assert(Json.array_length(json_field(push_witnesses_request(pool).body, "witnesses")?)? == 2)
  assert(String.contains(pushed, "\"witness_id\":\"witness-a\"")
    && String.contains(pushed, "\"witness_id\":\"witness-b\"")
    && String.contains(pushed,
      "\"software\":\"mesh\",\"morse_run\":true,\"c2sp_name\":null,\"push_url\":null"))
  let outside = keys(71)?
  let parsed = transparency_registry_from_json("[{\"witness_id\":\"outside-1\",\"public_key\":\""
    <> Bytes.to_hex(outside.public_key.bytes)
    <> "\",\"operator\":\"Example Org\",\"status\":\"shadow\",\"software\":\"c2sp\",\"c2sp_name\":\"witness.example.org\",\"push_url\":\"https://witness.example.org/add-checkpoint\"}]")?
  assert(List.length(parsed) == 1 && !List.head(parsed).morse_run)
  upsert(pool, List.head(parsed))?
  assert(Json.array_length(json_field(push_witnesses_request(pool).body, "witnesses")?)? == 3)
  let promoted = %{List.head(parsed) | status: "pinned"}
  upsert(pool, promoted)?
  assert(transparency_test_scalar(pool,
    "SELECT status AS value FROM transparency_witness_registry WHERE witness_id = 'outside-1'")? == "pinned")
  # A new key under the same ID is refused; so is a second ID for one key.
  assert(refused(upsert(pool, %{promoted | public_key: keys(72)?.public_key.bytes})))
  assert(refused(upsert(pool, %{promoted | witness_id: "outside-2"})))
  upsert(pool, %{promoted | status: "retired"})?
  assert(transparency_test_scalar(pool,
    "SELECT concat(status, ':', (retired_at IS NOT NULL)::text) AS value FROM transparency_witness_registry WHERE witness_id = 'outside-1'")? == "retired:true")
  upsert(pool, %{promoted | status: "retired"})?
  assert(refused(upsert(pool, promoted)))
  assert(Json.array_length(json_field(push_witnesses_request(pool).body, "witnesses")?)? == 2)
  assert(Json.array_length(json_field(registry_request(pool).body, "witnesses")?)? == 3)
  # Invalid entries are refused before they reach the table.
  let incomplete = case transparency_registry_from_json("[{\"witness_id\":\"x\"}]") do
    Err(_) -> true
    Ok(_) -> false
  end
  assert(incomplete)
  assert(refused(upsert(pool,
    witness("Bad ID", keys(73)?.public_key.bytes, "shadow", "mesh", "", ""))))
  assert(refused(upsert(pool,
    witness("no-name", keys(74)?.public_key.bytes, "shadow", "c2sp", "", ""))))
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("the registry moves witnesses between states and never revives a retired one") do
  case registry_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn statement_status(pool :: PoolHandle,
  witness_id :: String,
  seed :: Int,
  checkpoint :: TransparencyCheckpoint,
  compact :: Bool) -> Int!String do
  let key = keys(seed)?
  let statement = sign_witness(witness_id, key.private_key, checkpoint)?
  let frame = if compact do
    transparency_encode_cosignatures([
      WitnessCosignature {
        kind: 1,
        witness_id: witness_id,
        checkpoint_hash: statement.checkpoint_hash,
        timestamp: 0,
        signature: statement.signature
      }
    ])?
  else
    encode_witnesses([statement])?
  end
  Ok(submit_witness_request(pool, frame).status)
end

fn register_many(pool :: PoolHandle, index :: Int) -> Result<(), String> do
  if index >= 16 do
    Ok(nil)
  else
    let status = if index < 9 do
      "pinned"
    else
      "shadow"
    end
    upsert(pool,
      witness("fan-#{index}", keys(100 + index)?.public_key.bytes, status, "mesh", "", ""))?
    register_many(pool, index + 1)
  end
end

fn submit_many(pool :: PoolHandle,
  checkpoint :: TransparencyCheckpoint,
  index :: Int) -> Bool!String do
  if index >= 16 do
    Ok(true)
  else
    let stored = statement_status(pool,
      "fan-#{index}",
      100 + index,
      checkpoint,
      index % 2 == 0)? == 201
    Ok(stored && submit_many(pool, checkpoint, index + 1)?)
  end
end

# Attestations fan in from 16 witnesses of any status. Each is one per
# request, verified against the current checkpoint and the registry key.

fn fan_in_proof() -> Bool!String do
  let pool = database()?
  transparency_test_reset(pool)?
  register_many(pool, 0)?
  transparency_test_append(pool,
    transparency_test_bytes(4, 32),
    transparency_test_set("dave", 1, [41], [])?)?
  let checkpoint = create_checkpoint(pool, log_seed()?)?
  assert(submit_many(pool, checkpoint, 0)?)
  assert(statement_status(pool, "fan-3", 103, checkpoint, false)? == 200)
  assert(statement_status(pool, "fan-3", 103, checkpoint, true)? == 200)
  # Unknown, wrongly keyed and retired witnesses are refused.
  assert(statement_status(pool, "stranger", 99, checkpoint, false)? == 400)
  assert(statement_status(pool, "fan-4", 99, checkpoint, false)? == 400)
  upsert(pool, witness("fan-15", keys(115)?.public_key.bytes, "retired", "mesh", "", ""))?
  assert(statement_status(pool, "fan-15", 115, checkpoint, false)? == 400)
  # A different stored attestation for the same witness is a conflict.
  Pool.execute(pool,
    "UPDATE witness_signatures SET signature = sha512('other'::bytea) WHERE witness_id = 'fan-2'",
    [])?
  assert(statement_status(pool, "fan-2", 102, checkpoint, false)? == 409)
  # Two statements in one request, and C2SP kinds in a binary frame, are refused.
  let key = keys(100)?
  let statement = sign_witness("fan-0", key.private_key, checkpoint)?
  assert(submit_witness_request(pool, encode_witnesses([statement, statement])?).status == 400)
  assert(submit_witness_request(pool,
    transparency_encode_cosignatures([
      WitnessCosignature {
        kind: 2,
        witness_id: "fan-0",
        checkpoint_hash: Bytes.empty(),
        timestamp: 1,
        signature: statement.signature
      }
    ])?).status == 400)
  # KTW v2 serves at most 16: pinned first, retired never.
  let served = transparency_decode_cosignatures(witnesses_v2_request(pool).body)?
  assert(List.length(served) == 15)
  let pinned = for index in 0..9 do
    "fan-#{index}"
  end
  assert(List.all(List.take(served, 9),
    fn value -> List.any(pinned, fn id -> id == value.witness_id end) end))
  assert(!List.any(served, fn value -> value.witness_id == "fan-15" end))
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("attestations fan in from 16 witnesses, pinned ones served first") do
  case fan_in_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

# An anchored checkpoint's attestations stay readable by sequence after the
# directory moves on, so the cosign crank still finds signatures that arrived
# after its last look; a checkpoint the directory does not hold is 404.

fn attestations_by_sequence_proof() -> Bool!String do
  let pool = database()?
  transparency_test_reset(pool)?
  upsert(pool, witness("fan-0", keys(100)?.public_key.bytes, "pinned", "mesh", "", ""))?
  transparency_test_append(pool,
    transparency_test_bytes(5, 32),
    transparency_test_set("erin", 1, [51], [])?)?
  let first = create_checkpoint(pool, log_seed()?)?
  assert(statement_status(pool, "fan-0", 100, first, true)? == 201)
  transparency_test_append(pool,
    transparency_test_bytes(6, 32),
    transparency_test_set("fred", 1, [61], [])?)?
  let second = create_checkpoint(pool, log_seed()?)?
  assert(U64.compare(first.sequence, second.sequence) < 0)
  let earlier = witnesses_at_request(pool, U64.to_string(first.sequence))
  assert(earlier.status == 200)
  let served = transparency_decode_cosignatures(earlier.body)?
  assert(List.length(served) == 1)
  assert(Bytes.secure_equals(List.head(served).checkpoint_hash, checkpoint_hash(first)?))
  assert(List.length(transparency_decode_cosignatures(witnesses_v2_request(pool).body)?) == 0)
  assert(witnesses_at_request(pool, "999999").status == 404)
  assert(witnesses_at_request(pool, "01").status == 400)
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("an anchored checkpoint's attestations are served by sequence after the directory moves on") do
  case attestations_by_sequence_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn now_ms() -> U64!String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn now_seconds() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now()) / 1000
end

fn lookup(pool :: PoolHandle,
  username :: String,
  previous :: Int) -> TransparencyEvidenceV2!String do
  let answer = resolve_devices_request(pool,
    transparency_encode_lookup_v2(TransparencyLookup {
      username: username,
      previous_tree_size: previous
    })?)
  assert(answer.status == 200)
  transparency_decode_evidence_v2(answer.body)
end

fn opened_note(pool :: PoolHandle) -> NoteCheckpoint!String do
  let note = case checkpoint_note(pool, origin(), log_seed()?)? do
    None -> Err("no checkpoint note")
    Some(value) -> Ok(value)
  end?
  let log_key = case Crypto.signing_from_seed(log_seed()?) do
    Err(_) -> Err("log key failed")
    Ok(value)
  end?
  note_open_checkpoint(note, origin(), log_key.public_key.bytes)
end

# A C2SP witness cosigns the checkpoint note; the directory stores its
# cosignature and serves it as a kind-2 attestation with the RFC 6962 view of
# the looked-up leaf, which a phone pinning that witness counts.

fn c2sp_proof() -> Bool!String do
  let pool = database()?
  transparency_test_reset(pool)?
  transparency_seed_registry(pool)?
  let c2sp = keys(81)?
  upsert(pool,
    witness("c2sp-1", c2sp.public_key.bytes, "pinned", "c2sp", "witness.example.org", ""))?
  let _device = register_test_mailbox(pool, "erin", transparency_test_bytes(51, 32))?
  transparency_test_append(pool,
    transparency_test_bytes(5, 32),
    transparency_test_set("frank", 1, [61], [])?)?
  # With no C2SP cosignature the evidence carries no C2SP view.
  let plain = lookup(pool, "erin", 0)?
  assert(Bytes.length(plain.c2sp_root) == 0 && List.length(plain.c2sp_path) == 0)
  let opened = opened_note(pool)?
  assert(opened.tree_size == 2)
  let stamp = now_seconds()
  let line = note_cosign(opened.body,
    "witness.example.org",
    c2sp.private_key,
    c2sp.public_key.bytes,
    stamp)?
  assert(submit_cosignature_request(pool, line, now_seconds()).status == 201)
  assert(submit_cosignature_request(pool, line, now_seconds()).status == 200)
  let older = note_cosign(opened.body,
    "witness.example.org",
    c2sp.private_key,
    c2sp.public_key.bytes,
    stamp - 5)?
  assert(submit_cosignature_request(pool, older, now_seconds()).status == 409)
  # Tampered lines, lines from unregistered keys and lines from the future are
  # refused.
  let stranger = keys(82)?
  assert(submit_cosignature_request(pool,
    note_cosign(opened.body,
      "witness.example.org",
      stranger.private_key,
      stranger.public_key.bytes,
      stamp)?,
    now_seconds()).status == 400)
  assert(submit_cosignature_request(pool,
    note_cosign(opened.body <> "x\n",
      "witness.example.org",
      c2sp.private_key,
      c2sp.public_key.bytes,
      stamp)?,
    now_seconds()).status == 400)
  assert(submit_cosignature_request(pool,
    note_cosign(opened.body,
      "witness.example.org",
      c2sp.private_key,
      c2sp.public_key.bytes,
      stamp + 3600)?,
    now_seconds()).status == 400)
  assert(transparency_test_attest(pool, "witness-a", latest(pool)?)? == 201)
  let evidence = lookup(pool, "erin", 0)?
  assert(List.length(evidence.witnesses) == 2)
  assert(List.any(evidence.witnesses,
    fn value -> value.kind == 2 && value.witness_id == "c2sp-1" end))
  assert(Bytes.length(evidence.c2sp_root) == 32
    && Bytes.secure_equals(evidence.c2sp_root, opened.root))
  let witness_a = transparency_test_witness_key("witness-a")?
  let trusted = [
    WitnessKey { witness_id: "witness-a", public_key: witness_a.public_key.bytes },
    WitnessKey { witness_id: "c2sp-1", public_key: c2sp.public_key.bytes }
  ]
  let log_key = case Crypto.signing_from_seed(log_seed()?) do
    Err(_) -> Err("log key failed")
    Ok(value)
  end?
  let service_key = SigningPublicKey { bytes: log_key.public_key.bytes }
  assert(transparency_verify_evidence_v2(evidence,
    service_key,
    trusted,
    2,
    origin(),
    Bytes.empty(),
    now_ms()?)?)
  # Version 1 clients see only the Morse statement; a version 2 inclusion
  # query answers the compact path of the same lookup.
  assert(List.length(decode_witnesses(witnesses_request(pool).body)?) == 1)
  let included = transparency_decode_inclusion_v2(inclusion_request(pool,
    transparency_encode_lookup_v2(TransparencyLookup {
      username: "erin",
      previous_tree_size: 0
    })?).body)?
  assert(included.leaf_index == evidence.inclusion.leaf_index
    && List.length(included.path) == List.length(evidence.inclusion.path))
  # Without the C2SP origin pinned, the kind-2 attestation counts for nothing.
  assert(!transparency_verify_evidence_v2(evidence,
    service_key,
    trusted,
    2,
    "-",
    Bytes.empty(),
    now_ms()?)?)
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

fn latest(pool :: PoolHandle) -> TransparencyCheckpoint!String do
  case latest_checkpoint(pool)? do
    None -> Err("no checkpoint")
    Some(value) -> Ok(value)
  end
end

test("C2SP cosignatures are stored and served as dual-inclusion attestations") do
  case c2sp_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn health(pool :: PoolHandle) -> Json!String do
  let answer = health_request(pool)
  assert(answer.status == 200)
  Json.parse(body_text(answer.body)?)
end

fn threshold_met(pool :: PoolHandle) -> Bool!String do
  Json.as_bool(Json.object_get(health(pool)?, "threshold_met")?)
end

# With three pinned witnesses k is 2: the report says the threshold is met at
# 2 signatures and not at 0 or 1. No anchors is a normal state.

fn health_proof() -> Bool!String do
  let pool = database()?
  transparency_test_reset(pool)?
  assert(!threshold_met(pool)?)
  transparency_seed_registry(pool)?
  upsert(pool, witness("witness-c", keys(91)?.public_key.bytes, "pinned", "mesh", "", ""))?
  transparency_test_append(pool,
    transparency_test_bytes(6, 32),
    transparency_test_set("gina", 1, [71], [])?)?
  let checkpoint = create_checkpoint(pool, log_seed()?)?
  let report = health(pool)?
  assert(!Json.as_bool(Json.object_get(report, "threshold_met")?)?)
  assert(Json.as_int(Json.object_get(report, "threshold")?)? == 2)
  assert(Json.is_null(Json.object_get(report, "anchor_lag_seconds")?))
  assert(Json.is_null(Json.object_get(Json.array_get(Json.object_get(report, "witnesses")?, 0)?,
    "last_signature_age_seconds")?))
  assert(transparency_test_attest(pool, "witness-a", checkpoint)? == 201)
  assert(!threshold_met(pool)?)
  assert(statement_status(pool, "witness-c", 91, checkpoint, false)? == 201)
  assert(threshold_met(pool)?)
  let ages = Json.object_get(health(pool)?, "witnesses")?
  assert(Json.as_int(Json.object_get(Json.array_get(ages, 0)?,
    "last_signature_age_seconds")?)? >= 0)
  # A shadow witness never counts toward the threshold.
  transparency_test_reset(pool)?
  transparency_seed_registry(pool)?
  upsert(pool, witness("shadow-1", keys(92)?.public_key.bytes, "shadow", "mesh", "", ""))?
  transparency_test_append(pool,
    transparency_test_bytes(6, 32),
    transparency_test_set("gina", 1, [71], [])?)?
  let next = create_checkpoint(pool, log_seed()?)?
  assert(statement_status(pool, "shadow-1", 92, next, false)? == 201)
  assert(transparency_test_attest(pool, "witness-a", next)? == 201)
  assert(!threshold_met(pool)?)
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("health reports the threshold for the current checkpoint") do
  case health_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn anchor_body(sequence :: Int, size :: Int, hash :: Bytes, signature :: String) -> String do
  "{\"sequence\":"
    <> Int.to_string(sequence)
    <> ",\"tree_size\":"
    <> Int.to_string(size)
    <> ",\"checkpoint_hash\":\""
    <> Bytes.to_hex(hash)
    <> "\",\"ring_index\":17,\"tx_signature\":\""
    <> signature
    <> "\",\"slot\":123456789}"
end

fn anchors_proof() -> Bool!String do
  let pool = database()?
  transparency_test_reset(pool)?
  transparency_test_append(pool,
    transparency_test_bytes(7, 32),
    transparency_test_set("hana", 1, [81], [])?)?
  let checkpoint = create_checkpoint(pool, log_seed()?)?
  let hash = checkpoint_hash(checkpoint)?
  let signature = "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"
  assert(anchor_request(pool, "1").status == 404)
  assert(submit_anchor_request(pool, anchor_body(1, 1, hash, signature)).status == 201)
  assert(submit_anchor_request(pool, anchor_body(1, 1, hash, signature)).status == 200)
  assert(submit_anchor_request(pool,
    anchor_body(1,
      1,
      hash,
      "4VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW")).status == 409)
  assert(submit_anchor_request(pool, anchor_body(1, 2, hash, signature)).status == 409)
  assert(submit_anchor_request(pool, anchor_body(9, 1, hash, signature)).status == 404)
  assert(submit_anchor_request(pool, anchor_body(1, 1, hash, "not base58 0OIl")).status == 400)
  assert(submit_anchor_request(pool, "{").status == 400)
  let found = anchor_request(pool, "1")
  assert(found.status == 200)
  let record = Json.parse(body_text(found.body)?)?
  assert(Json.as_int(Json.object_get(record, "ring_index")?)? == 17)
  assert(Json.as_string(Json.object_get(record, "checkpoint_hash")?)? == Bytes.to_hex(hash))
  assert(Json.as_int(Json.object_get(record, "slot")?)? == 123456789)
  assert(Json.as_string(Json.object_get(record,
    "checkpoint")?)? == Bytes.to_hex(encode_checkpoint(checkpoint)?))
  assert(anchor_request(pool, "01").status == 400)
  let report = health(pool)?
  assert(Json.as_int(Json.object_get(report, "anchor_lag_seconds")?)? == 0)
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("anchor records are checked against their checkpoint and served") do
  case anchors_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn append_many(pool :: PoolHandle, count :: Int, index :: Int) -> Result<(), String> do
  if index >= count do
    Ok(nil)
  else
    transparency_test_append(pool,
      transparency_test_bytes(8, 32),
      transparency_test_set("ivan", index + 1, [90 + index % 5], [])?)?
    append_many(pool, count, index + 1)
  end
end

fn tree_proof() -> Bool!String do
  let pool = database()?
  transparency_test_reset(pool)?
  append_many(pool, 5, 0)?
  let small = create_checkpoint(pool, log_seed()?)?
  append_many(pool, 13, 5)?
  let large = create_checkpoint(pool, log_seed()?)?
  let morse = transparency_decode_consistency_v2(consistency_request(pool,
    transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
      old_size: 5,
      new_size: 0,
      tree: 1
    })?).body)?
  assert(morse.new_size == 13)
  assert(tlog_verify_consistency(1, 5, 13, morse.path, small.tree_root, large.tree_root))
  let rfc = transparency_decode_consistency_v2(consistency_request(pool,
    transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
      old_size: 5,
      new_size: 13,
      tree: 2
    })?).body)?
  assert(List.length(rfc.path) > 0 && List.length(rfc.path) == List.length(morse.path))
  assert(consistency_request(pool,
    transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
      old_size: 5,
      new_size: 14,
      tree: 1
    })?).status == 400)
  let leaves = leaves_request(pool, "0", "1024")
  assert(leaves.status == 200 && Bytes.length(leaves.body) == 13 * 32)
  assert(Bytes.length(leaves_request(pool, "12", "5").body) == 32)
  assert(leaves_request(pool, "0", "1025").status == 400)
  assert(leaves_request(pool, "0", "0").status == 400)
  assert(leaves_request(pool, "-1", "3").status == 400)
  let seventh = case Bytes.slice(leaves.body, 7 * 32, 32) do
    Err(_) -> Err("slice failed")
    Ok(value)
  end?
  let morse_leaf = transparency_decode_leaf_proof(leaf_request(pool,
    transparency_encode_leaf_query(TransparencyLeafQuery {
      leaf_index: 7,
      tree_size: 13,
      tree: 1
    })?).body)?
  assert(Bytes.secure_equals(morse_leaf.leaf_hash, seventh))
  assert(tlog_verify_inclusion(1, seventh, 7, 13, morse_leaf.inclusion.path, large.tree_root))
  let rfc_leaf = transparency_decode_leaf_proof(leaf_request(pool,
    transparency_encode_leaf_query(TransparencyLeafQuery {
      leaf_index: 7,
      tree_size: 13,
      tree: 2
    })?).body)?
  let opened = opened_note(pool)?
  assert(tlog_verify_inclusion(2,
    tlog_leaf(2, seventh)?,
    7,
    13,
    rfc_leaf.inclusion.path,
    opened.root))
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("tree queries answer compact proofs in both trees and raw leaves") do
  case tree_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
