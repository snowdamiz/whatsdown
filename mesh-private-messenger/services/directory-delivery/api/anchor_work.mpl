from Api.Binary import BinaryResult
from Storage.Transparency import latest_checkpoint_for, historical_checkpoint_on_connection
from Storage.TransparencyLog import witness_table
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  checkpoint_hash
)
from Transparency.Wire import encode_checkpoint
from Transparency.AnchorWrite import (
  AnchorInstructionPair,
  anchor_post_instructions,
  anchor_cosign_instructions
)
from Transparency.AnchorWitnessSet import AnchorWitnessSet, AnchorWitness, decode_anchor_witness_set

fn empty(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

fn quoted(bytes :: Bytes) -> String do
  Json.encode_string(Bytes.to_hex(bytes))
end

fn checkpoint_fields(checkpoint :: TransparencyCheckpoint) -> String!String do
  Ok("\"checkpoint\":"
    <> quoted(encode_checkpoint(checkpoint)?)
    <> ",\"checkpoint_hash\":"
    <> quoted(checkpoint_hash(checkpoint)?)
    <> ",\"version\":"
    <> Int.to_string(checkpoint.version)
    <> ",\"sequence\":"
    <> Json.encode_string(U64.to_string(checkpoint.sequence))
    <> ",\"tree_size\":"
    <> Json.encode_string(U64.to_string(checkpoint.tree_size))
    <> ",\"timestamp_ms\":"
    <> Json.encode_string(U64.to_string(checkpoint.timestamp))
    <> ",\"root\":"
    <> quoted(checkpoint.tree_root)
    <> ",\"service_key\":"
    <> quoted(checkpoint.service_public_key))
end

fn instruction_fields(pair :: AnchorInstructionPair) -> String do
  "\"ed25519\":" <> quoted(pair.ed25519) <> ",\"instruction\":" <> quoted(pair.judge)
end

fn candidate(checkpoint :: TransparencyCheckpoint) -> String!String do
  let pair = anchor_post_instructions(checkpoint, checkpoint.service_public_key, 0)?
  Ok("{" <> checkpoint_fields(checkpoint)? <> "," <> instruction_fields(pair) <> "}")
end

pub fn anchor_candidate_request_for(pool :: PoolHandle, version :: Int) -> BinaryResult do
  if version != 1 && version != 2 do
    return empty(400)
  end
  case latest_checkpoint_for(pool, version) do
    Err(_) -> empty(503)
    Ok(None) -> empty(404)
    Ok(Some(value)) -> case candidate(value) do
      Err(_) -> empty(503)
      Ok(document) -> BinaryResult { status: 200, body: Bytes.from_utf8(document) }
    end
  end
end

struct CosignQuery do
  version :: Int
  sequence :: U64
  ring_index :: Int
  set :: AnchorWitnessSet
end

fn narrow(bytes :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_be(bytes, offset) do
    Err(_) -> Err("invalid_anchor_work")
    Ok(value)
  end
end

fn decode_query(bytes :: Bytes) -> CosignQuery!String do
  if Bytes.length(bytes) != 2768 || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "01415751" do
    return Err("invalid_anchor_work")
  end
  let sequence = case Bytes.read_u64_be(bytes, 6) do
    Err(_) -> return Err("invalid_anchor_work")
    Ok(value) -> value
  end
  let value = CosignQuery {
    version: narrow(bytes, 4)?,
    sequence: sequence,
    ring_index: narrow(bytes, 14)?,
    set: decode_anchor_witness_set(Bytes.slice(bytes, 16, 2752)?)?
  }
  if (value.version != 1 && value.version != 2)
    || value.ring_index >= 4096
    || U64.compare(sequence, U64.parse("0")?) == 0 do
    Err("invalid_anchor_work")
  else
    Ok(value)
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid_anchor_signature_row")
  end
end

fn cosign(conn :: borrow PgConn,
  checkpoint :: TransparencyCheckpoint,
  witness :: AnchorWitness,
  ring_index :: Int,
  witness_index :: Int) -> Option<String>!String do
  # The authenticated chain generation, not today's registry, identifies a
  # historical signer. Never relabel an old slot after a registry rotation.
  let rows = Pg.query_values(conn,
    "SELECT checkpoint_hash, signature FROM "
      <> witness_table(checkpoint.version)?
      <> " WHERE checkpoint_sequence = $1::bigint AND witness_id = $2::text AND witness_public_key = $3",
    [
      Text(U64.to_string(checkpoint.sequence)),
      Text(witness.witness_id),
      Binary(witness.public_key)
    ])?
  if List.length(rows) == 0 do
    return Ok(None)
  end
  let row = List.head(rows)
  let attestation = WitnessAttestation {
    witness_id: witness.witness_id,
    checkpoint_hash: binary(Map.get(row, "checkpoint_hash"))?,
    signature: binary(Map.get(row, "signature"))?
  }
  let pair = case anchor_cosign_instructions(checkpoint,
    attestation,
    WitnessKey { witness_id: witness.witness_id, public_key: witness.public_key },
    ring_index,
    witness_index,
    0) do
    Err(_) -> return Ok(None)
    Ok(value) -> value
  end
  Ok(Some("{\"witness_index\":"
    <> Int.to_string(witness_index)
    <> ","
    <> instruction_fields(pair)
    <> "}"))
end

fn cosigns(conn :: borrow PgConn, query :: CosignQuery) -> Option<String>!String do
  let checkpoint = case historical_checkpoint_on_connection(conn, query.version, query.sequence)? do
    None -> return Ok(None)
    Some(value) -> value
  end
  # A forged stored checkpoint cannot become a prepared transaction even when
  # no witness has signed it yet.
  anchor_post_instructions(checkpoint, checkpoint.service_public_key, 0)?
  let values = for index in 0..List.length(query.set.witnesses) do
    cosign(conn, checkpoint, List.get(query.set.witnesses, index), query.ring_index, index)?
  end
  let present = List.flat_map(values,
    fn(value) do
      case value do
        Some(text) -> [text]
        None -> []
      end
    end)
  Ok(Some("{"
    <> checkpoint_fields(checkpoint)?
    <> ",\"log_id\":"
    <> quoted(query.set.log_id)
    <> ",\"generation\":"
    <> Int.to_string(query.set.generation)
    <> ",\"ring_index\":"
    <> Int.to_string(query.ring_index)
    <> ",\"cosigns\":["
    <> String.join(present, ",")
    <> "]}"))
end

pub fn anchor_cosign_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  let query = case decode_query(body) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case Repo.transaction(pool, fn(conn :: borrow PgConn) do cosigns(conn, query) end) do
    Err(_) -> empty(503)
    Ok(None) -> empty(404)
    Ok(Some(document)) -> BinaryResult { status: 200, body: Bytes.from_utf8(document) }
  end
end
