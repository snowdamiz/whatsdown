##! The witness-network routes: the C2SP view of the log, the registry, anchors,
##! tree queries for witnesses and monitors, C2SP cosignature submission, and
##! the health report. Each answers a BinaryResult; JSON bodies are UTF-8.

from Api.Binary import BinaryResult, attestation_status, transparency_log_origin
from Storage.Transparency import (
  attestations_for_checkpoint,
  configured_checkpoint_note,
  latest_checkpoint,
  store_cosignatures,
  transparency_checkpoint_at_on_connection,
  transparency_leaf_proof,
  transparency_leaves
)
from Storage.TransparencyPruning import transparency_last_pruning
from Storage.TransparencyWitnesses import (
  AnchorLag,
  AnchorRecord,
  AttestationWrite,
  WitnessHealth,
  transparency_anchor,
  transparency_anchor_from_json,
  transparency_anchor_json,
  transparency_anchor_lag_on_connection,
  transparency_registry,
  transparency_registry_json,
  transparency_store_anchor_on_connection,
  transparency_witness_health_on_connection
)
from Runtime.Registry import get_pool
from Transparency.Codec import tcodec_decimal
from Transparency.CompactWire import (
  transparency_decode_leaf_query,
  transparency_encode_cosignatures,
  transparency_encode_leaf_proof
)
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash
from Transparency.Wire import encode_checkpoint

fn empty(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

fn text(status :: Int, body :: String) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.from_utf8(body) }
end

## GET /v1/transparency/checkpoint.note: the current checkpoint as a C2SP
## signed note (text/plain), 404 before the first checkpoint.

pub fn checkpoint_note_request(pool :: PoolHandle) -> BinaryResult do
  case transparency_log_origin() do
    Err(_) -> empty(500)
    Ok(origin) -> case configured_checkpoint_note(pool, origin) do
      Err(_) -> empty(500)
      Ok(None) -> empty(404)
      Ok(Some(note)) -> text(200, note)
    end
  end
end

## GET /v1/transparency/witnesses with Accept: application/x-morse-attestation-v2:
## KTW v2, both kinds, pinned witnesses first, then shadow, newest first.

pub fn witnesses_v2_request(pool :: PoolHandle) -> BinaryResult do
  case latest_checkpoint(pool) do
    Err(_) -> empty(500)
    Ok(None) -> empty(404)
    Ok(Some(checkpoint)) -> encoded_attestations(pool, checkpoint)
  end
end

fn encoded_attestations(pool :: PoolHandle, checkpoint :: TransparencyCheckpoint) -> BinaryResult do
  case attestations_for_checkpoint(pool, checkpoint.sequence) do
    Err(_) -> empty(500)
    Ok(values) -> case transparency_encode_cosignatures(values) do
      Err(_) -> empty(500)
      Ok(encoded) -> BinaryResult { status: 200, body: encoded }
    end
  end
end

## GET /v1/transparency/witnesses/{sequence}: KTW v2 for that checkpoint, as
## the plain route serves the current one. The cosign crank reads an anchored
## checkpoint's attestations here after the directory has moved on; 404 once
## the checkpoint is gone (pruned, or never issued).

pub fn witnesses_at_request(pool :: PoolHandle, sequence :: String) -> BinaryResult do
  case tcodec_decimal(sequence) do
    Err(_) -> empty(400)
    Ok(value) -> case Repo.transaction(pool,
      fn(conn :: borrow PgConn) -> transparency_checkpoint_at_on_connection(conn, value) end) do
      Err(_) -> empty(500)
      Ok(None) -> empty(404)
      Ok(Some(checkpoint)) -> encoded_attestations(pool, checkpoint)
    end
  end
end

pub fn handle_transparency_witnesses_at(request :: Request) -> Response do
  let result = case Request.param(request, "sequence") do
    None -> empty(400)
    Some(sequence) -> witnesses_at_request(get_pool(), sequence)
  end
  HTTP.response_bytes(result.status, result.body)
end

fn cosignature_status(writes :: List<AttestationWrite>) -> Int do
  let statuses = List.map(writes, fn write -> attestation_status(write) end)
  if List.any(statuses, fn status -> status == 409 end) do
    409
  else if List.any(statuses, fn status -> status == 201 end) do
    201
  else
    200
  end
end

## POST /v1/transparency/witnesses as text/x-c2sp-cosignature: one or more
## cosignature lines on the current checkpoint's note.

pub fn submit_cosignature_request(pool :: PoolHandle,
  body :: String,
  now_seconds :: Int) -> BinaryResult do
  case transparency_log_origin() do
    Err(_) -> empty(500)
    Ok(origin) -> case store_cosignatures(pool, body, origin, now_seconds) do
      Err(_) -> empty(400)
      Ok(writes) -> empty(cosignature_status(writes))
    end
  end
end

## GET /v1/transparency/registry.

pub fn registry_request(pool :: PoolHandle) -> BinaryResult do
  case transparency_registry(pool) do
    Err(_) -> empty(500)
    Ok(entries) -> text(200, transparency_registry_json(entries, false))
  end
end

## GET /internal/v1/transparency/push-witnesses: every shadow and pinned entry,
## with its push_url (the C2SP add-checkpoint endpoint, or null). The jobs
## Worker asks the Morse-run Mesh entries it has an /attest URL for to sign,
## and pushes checkpoints to the C2SP entries with a push_url.

pub fn push_witnesses_request(pool :: PoolHandle) -> BinaryResult do
  case transparency_registry(pool) do
    Err(_) -> empty(500)
    Ok(entries) -> text(200,
      transparency_registry_json(List.filter(entries, fn entry -> entry.status != "retired" end),
        true))
  end
end

# Anchored checkpoints are never pruned, so the record can carry the KTK
# itself: a monitor then proves a mismatch from this answer alone.

fn anchored_checkpoint_hex(pool :: PoolHandle, record :: AnchorRecord) -> String!String do
  let found = Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> transparency_checkpoint_at_on_connection(conn,
      record.sequence) end)?
  case found do
    None -> Err("anchored checkpoint missing")
    Some(checkpoint) -> Ok(Bytes.to_hex(encode_checkpoint(checkpoint)?))
  end
end

## GET /v1/transparency/anchor/{sequence}: 404 when not anchored. Carries the
## anchored checkpoint (KTK, hex) as "checkpoint".

pub fn anchor_request(pool :: PoolHandle, sequence :: String) -> BinaryResult do
  case tcodec_decimal(sequence) do
    Err(_) -> empty(400)
    Ok(value) -> case transparency_anchor(pool, value) do
      Err(_) -> empty(500)
      Ok(None) -> empty(404)
      Ok(Some(record)) -> case anchored_checkpoint_hex(pool, record) do
        Err(_) -> empty(500)
        Ok(checkpoint) -> text(200, transparency_anchor_json(record, checkpoint))
      end
    end
  end
end

fn anchor_matches(checkpoint :: TransparencyCheckpoint, record :: AnchorRecord) -> Bool!String do
  Ok(U64.to_int(checkpoint.tree_size)? == record.tree_size
    && Bytes.secure_equals(checkpoint_hash(checkpoint)?, record.checkpoint_hash))
end

fn anchor_on_connection(conn :: borrow PgConn, record :: AnchorRecord) -> Int!String do
  case transparency_checkpoint_at_on_connection(conn, record.sequence)? do
    None -> Ok(404)
    Some(checkpoint) -> if anchor_matches(checkpoint, record)? do
      Ok(attestation_status(transparency_store_anchor_on_connection(conn, record)?))
    else
      Ok(409)
    end
  end
end

## POST /internal/v1/transparency/anchors: the jobs Worker's record of an
## anchoring transaction. 201 stored, 200 already stored, 404 no such
## checkpoint, 409 it names another checkpoint or contradicts a stored record.

pub fn submit_anchor_request(pool :: PoolHandle, body :: String) -> BinaryResult do
  case transparency_anchor_from_json(body) do
    Err(_) -> empty(400)
    Ok(record) -> case Repo.transaction(pool,
      fn(conn :: borrow PgConn) -> anchor_on_connection(conn, record) end) do
      Err(_) -> empty(500)
      Ok(status) -> empty(status)
    end
  end
end

## POST /v1/transparency/leaf: KTP v2 in, KTL v2 out.

pub fn leaf_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case transparency_decode_leaf_query(body) do
    Err(_) -> empty(400)
    Ok(query) -> case transparency_leaf_proof(pool,
      query.tree,
      query.leaf_index,
      query.tree_size) do
      Err(_) -> empty(400)
      Ok(proof) -> case transparency_encode_leaf_proof(proof) do
        Err(_) -> empty(500)
        Ok(encoded) -> BinaryResult { status: 200, body: encoded }
      end
    end
  end
end

## GET /v1/transparency/leaves?start=S&count=C: up to C (1-1024) Morse leaf
## hashes from index S, 32 bytes each; fewer past the end of the log.

pub fn leaves_request(pool :: PoolHandle, start :: String, count :: String) -> BinaryResult do
  case (tcodec_decimal(start), tcodec_decimal(count)) do
    (Ok(first), Ok(total)) -> if total < 1 || total > 1024 do
      empty(400)
    else
      case transparency_leaves(pool, first, total) do
        Err(_) -> empty(500)
        Ok(hashes) -> BinaryResult { status: 200, body: hashes }
      end
    end
    _ -> empty(400)
  end
end

fn json_age(seconds :: Int) -> String do
  if seconds < 0 do
    "null"
  else
    Int.to_string(seconds)
  end
end

fn witness_json(value :: WitnessHealth) -> String do
  "{\"witness_id\":"
    <> Json.encode_string(value.witness_id)
    <> ",\"status\":"
    <> Json.encode_string(value.status)
    <> ",\"morse_run\":"
    <> Json.encode_bool(value.morse_run)
    <> ",\"signed_current\":"
    <> Json.encode_bool(value.signed_current)
    <> ",\"last_signature_age_seconds\":"
    <> json_age(value.last_signature_age)
    <> "}"
end

struct HealthView do
  witnesses :: List<WitnessHealth>
  anchor :: AnchorLag
end

fn health_view(conn :: borrow PgConn, sequence :: U64) -> HealthView!String do
  Ok(HealthView {
    witnesses: transparency_witness_health_on_connection(conn, sequence)?,
    anchor: transparency_anchor_lag_on_connection(conn)?
  })
end

## Whether the pinned registry entries' strict majority attested the current
## checkpoint: k = n / 2 + 1 of the n pinned; false with none pinned.

pub fn transparency_threshold_met(witnesses :: List<WitnessHealth>) -> Bool do
  let pinned = List.filter(witnesses, fn value -> value.status == "pinned" end)
  let signed = List.filter(pinned, fn value -> value.signed_current end)
  List.length(pinned) > 0 && List.length(signed) >= List.length(pinned) / 2 + 1
end

fn health_json(checkpoint :: Option<TransparencyCheckpoint>,
  view :: HealthView,
  last_pruning :: String) -> String do
  let (sequence, size, current) = case checkpoint do
    None -> ("null", "null", false)
    Some(value) -> (U64.to_string(value.sequence), U64.to_string(value.tree_size), true)
  end
  let pinned = List.filter(view.witnesses, fn value -> value.status == "pinned" end)
  let lag = if view.anchor.anchored do
    Int.to_string(view.anchor.lag_seconds)
  else
    "null"
  end
  let pruning = if String.length(last_pruning) == 0 do
    "null"
  else
    Json.encode_string(last_pruning)
  end
  "{\"status\":\"ok\",\"checkpoint_sequence\":"
    <> sequence
    <> ",\"tree_size\":"
    <> size
    <> ",\"pinned\":"
    <> Int.to_string(List.length(pinned))
    <> ",\"threshold\":"
    <> Int.to_string(List.length(pinned) / 2 + 1)
    <> ",\"threshold_met\":"
    <> Json.encode_bool(current && transparency_threshold_met(view.witnesses))
    <> ",\"witnesses\":["
    <> String.join(List.map(view.witnesses, fn value -> witness_json(value) end), ",")
    <> "],\"anchor_lag_seconds\":"
    <> lag
    <> ",\"last_anchor_age_seconds\":"
    <> json_age(view.anchor.last_anchor_age_seconds)
    <> ",\"last_pruning_day\":"
    <> pruning
    <> "}"
end

fn health_report(pool :: PoolHandle) -> String!String do
  let checkpoint = latest_checkpoint(pool)?
  let sequence = case checkpoint do
    None -> U64.parse("0")?
    Some(value) -> value.sequence
  end
  let view = Repo.transaction(pool, fn(conn :: borrow PgConn) -> health_view(conn, sequence) end)?
  Ok(health_json(checkpoint, view, transparency_last_pruning(pool)?))
end

## GET /health: 200 with the witness report while the database answers, 503
## otherwise. threshold_met is for the current checkpoint.

pub fn health_request(pool :: PoolHandle) -> BinaryResult do
  case health_report(pool) do
    Err(_) -> text(503, "{\"status\":\"unavailable\"}")
    Ok(body) -> text(200, body)
  end
end
