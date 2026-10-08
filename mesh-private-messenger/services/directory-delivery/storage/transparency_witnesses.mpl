##! The witness registry and the attestations stored for each checkpoint.
##!
##! Any non-retired registry entry may attest: shadow entries are stored and
##! served but pinned by no release, so phones ignore them. Morse software signs
##! Morse statements (kind 1); C2SP software cosigns the checkpoint note (kind 2)
##! under its key name. Anchors record where each checkpoint went on-chain.

from Transparency.CompactWire import WitnessCosignature
from Transparency.Merkle import WitnessAttestation

pub struct RegistryWitness do
  witness_id :: String
  public_key :: Bytes
  operator :: String
  status :: String
  software :: String
  push_url :: String
  morse_run :: Bool
  c2sp_name :: String
end

pub type AttestationWrite do
  AttestationStored
  AttestationDuplicate
  AttestationConflict
end deriving(Eq, Debug)

pub struct WitnessHealth do
  witness_id :: String
  status :: String
  morse_run :: Bool
  last_signature_age :: Int
  signed_current :: Bool
end

pub struct AnchorRecord do
  sequence :: Int
  tree_size :: Int
  checkpoint_hash :: Bytes
  ring_index :: Int
  tx_signature :: String
  slot :: Int
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid witness row")
  end
end

fn optional_text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    Null -> Ok("")
    _ -> Err("invalid witness row")
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid witness row")
  end
end

fn integer(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    None -> Err("invalid witness integer")
    Some(output) -> Ok(output)
  end
end

fn json_field(value :: Json, key :: String) -> Option<Json> do
  case Json.object_get(value, key) do
    Err(_) -> None
    Ok(field) -> if Json.is_null(field) do
      None
    else
      Some(field)
    end
  end
end

fn json_text(value :: Json, key :: String) -> String!String do
  case json_field(value, key) do
    None -> Err("witness registry entry needs #{key}")
    Some(field) -> Json.as_string(field)
  end
end

fn json_optional_text(value :: Json, key :: String) -> String!String do
  case json_field(value, key) do
    None -> Ok("")
    Some(field) -> Json.as_string(field)
  end
end

fn public_key(hex :: String) -> Bytes!String do
  case Bytes.from_hex(hex) do
    Ok(value) -> if Bytes.length(value) == 32 && Bytes.to_hex(value) == hex do
      Ok(value)
    else
      Err("invalid witness public key")
    end
    Err(_) -> Err("invalid witness public key")
  end
end

fn registry_entry(value :: Json) -> RegistryWitness!String do
  let operator = json_text(value, "operator")?
  let morse_run = case json_field(value, "morse_run") do
    None -> Ok(operator == "Morse")
    Some(field) -> Json.as_bool(field)
  end?
  Ok(RegistryWitness {
    witness_id: json_text(value, "witness_id")?,
    public_key: public_key(json_text(value, "public_key")?)?,
    operator: operator,
    status: json_text(value, "status")?,
    software: json_text(value, "software")?,
    push_url: json_optional_text(value, "push_url")?,
    morse_run: morse_run,
    c2sp_name: json_optional_text(value, "c2sp_name")?
  })
end

## Parses MESSENGER_WITNESS_REGISTRY: a JSON array of registry entries
## (witness_id, public_key hex, operator, status, software, and optionally
## push_url, morse_run, c2sp_name). The database checks the rest.

pub fn transparency_registry_from_json(input :: String) -> List<RegistryWitness>!String do
  let root = Json.parse(input)?
  let count = Json.array_length(root)?
  if count > 64 do
    Err("witness registry too large")
  else
    Ok(for index in 0..count do
      registry_entry(Json.array_get(root, index)?)?
    end)
  end
end

fn legacy_witness(witness_id :: String, name :: String) -> List<RegistryWitness>!String do
  let hex = Env.get(name, "")
  if String.length(hex) == 0 do
    Ok(List.new())
  else
    Ok([
      RegistryWitness {
        witness_id: witness_id,
        public_key: public_key(hex)?,
        operator: "Morse",
        status: "pinned",
        software: "mesh",
        push_url: "",
        morse_run: true,
        c2sp_name: ""
      }
    ])
  end
end

## What the environment asks the registry to hold: the legacy witness-a and
## witness-b keys (Morse, pinned), then MESSENGER_WITNESS_REGISTRY, which wins.

pub fn transparency_configured_registry() -> List<RegistryWitness>!String do
  let writes = Env.get("MORSE_REGISTRY_WRITES", "on")
  if writes != "on" && writes != "off" do
    Err("MORSE_REGISTRY_WRITES must be on or off")
  else
    Ok(legacy_witness("witness-a", "MESSENGER_WITNESS_A_PUBLIC_KEY_HEX")?
      ++ legacy_witness("witness-b", "MESSENGER_WITNESS_B_PUBLIC_KEY_HEX")?
      ++ transparency_registry_from_json(Env.get("MESSENGER_WITNESS_REGISTRY", "[]"))?)
  end
end

fn unchanged_retirement(conn :: borrow PgConn, entry :: RegistryWitness) -> Bool!String do
  let rows = Pg.query_values(conn,
    "SELECT witness_id FROM transparency_witness_registry WHERE witness_id = $1 AND status = 'retired' AND public_key = $2",
    [Text(entry.witness_id), Binary(entry.public_key)])?
  Ok(entry.status == "retired" && List.length(rows) == 1)
end

## Adds an entry or moves it between shadow and pinned, or retires it. A
## witness keeps its key for good, and a retired one never comes back.

pub fn transparency_registry_upsert_on_connection(conn :: borrow PgConn,
  entry :: RegistryWitness) -> Result<(), String> do
  let rows = Pg.query_values(conn,
    "INSERT INTO transparency_witness_registry (witness_id, public_key, operator, status, software, push_url, morse_run, c2sp_name, retired_at) VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7::boolean, NULLIF($8, ''), CASE WHEN $4 = 'retired' THEN now() END) ON CONFLICT (witness_id) DO UPDATE SET operator = EXCLUDED.operator, status = EXCLUDED.status, software = EXCLUDED.software, push_url = EXCLUDED.push_url, morse_run = EXCLUDED.morse_run, c2sp_name = EXCLUDED.c2sp_name, retired_at = EXCLUDED.retired_at WHERE transparency_witness_registry.status <> 'retired' AND transparency_witness_registry.public_key = EXCLUDED.public_key RETURNING witness_id",
    [
      Text(entry.witness_id),
      Binary(entry.public_key),
      Text(entry.operator),
      Text(entry.status),
      Text(entry.software),
      Text(entry.push_url),
      Text(if entry.morse_run do
        "true"
      else
        "false"
      end),
      Text(entry.c2sp_name)
    ])?
  if List.length(rows) == 1 || unchanged_retirement(conn, entry)? do
    Ok(nil)
  else
    Err("witness registry conflict for #{entry.witness_id}")
  end
end

fn upsert_all(conn :: borrow PgConn,
  entries :: List<RegistryWitness>,
  index :: Int) -> Int!String do
  if index >= List.length(entries) do
    Ok(index)
  else
    transparency_registry_upsert_on_connection(conn, List.get(entries, index))?
    upsert_all(conn, entries, index + 1)
  end
end

## Seeds the registry from the environment at startup, unless
## MORSE_REGISTRY_WRITES is off (the registry is then frozen).

pub fn transparency_seed_registry(pool :: PoolHandle) -> Int!String do
  let entries = transparency_configured_registry()?
  if Env.get("MORSE_REGISTRY_WRITES", "on") == "off" do
    Ok(0)
  else
    Repo.transaction(pool, fn(conn :: borrow PgConn) -> upsert_all(conn, entries, 0) end)
  end
end

fn registry_rows(rows :: List<Map<String, DbValue>>) -> List<RegistryWitness>!String do
  Ok(for row in rows do
    RegistryWitness {
      witness_id: text(Map.get(row, "witness_id"))?,
      public_key: binary(Map.get(row, "public_key"))?,
      operator: text(Map.get(row, "operator"))?,
      status: text(Map.get(row, "status"))?,
      software: text(Map.get(row, "software"))?,
      push_url: optional_text(Map.get(row, "push_url"))?,
      morse_run: text(Map.get(row, "morse_run"))? == "true",
      c2sp_name: optional_text(Map.get(row, "c2sp_name"))?
    }
  end)
end

fn registry_columns() -> String do
  "SELECT witness_id, public_key, operator, status, software, push_url, morse_run::text AS morse_run, c2sp_name FROM transparency_witness_registry"
end

## Every entry, retired ones included, in the order they were added.

pub fn transparency_registry(pool :: PoolHandle) -> List<RegistryWitness>!String do
  registry_rows(Pool.query_values(pool,
    registry_columns() <> " ORDER BY added_at, witness_id",
    [])?)
end

## Entries the jobs Worker pushes checkpoints to: shadow or pinned, with a URL.

pub fn transparency_push_witnesses(pool :: PoolHandle) -> List<RegistryWitness>!String do
  registry_rows(Pool.query_values(pool,
    registry_columns()
      <> " WHERE status IN ('shadow', 'pinned') AND push_url IS NOT NULL ORDER BY witness_id",
    [])?)
end

pub fn transparency_registry_witness_on_connection(conn :: borrow PgConn,
  witness_id :: String) -> Option<RegistryWitness>!String do
  let found = registry_rows(Pg.query_values(conn,
    registry_columns() <> " WHERE witness_id = $1 AND status <> 'retired'",
    [Text(witness_id)])?)?
  case found do
    [entry] -> Ok(Some(entry))
    _ -> Ok(None)
  end
end

pub fn transparency_c2sp_witnesses_on_connection(conn :: borrow PgConn) -> List<RegistryWitness>!String do
  registry_rows(Pg.query_values(conn,
    registry_columns()
      <> " WHERE status <> 'retired' AND software = 'c2sp' AND c2sp_name IS NOT NULL ORDER BY witness_id",
    [])?)
end

fn json_nullable(value :: String) -> String do
  if String.length(value) == 0 do
    "null"
  else
    Json.encode_string(value)
  end
end

fn registry_json_entry(entry :: RegistryWitness, with_push_url :: Bool) -> String do
  let push = if with_push_url do
    ",\"push_url\":" <> json_nullable(entry.push_url)
  else
    ""
  end
  "{\"witness_id\":"
    <> Json.encode_string(entry.witness_id)
    <> ",\"public_key\":"
    <> Json.encode_string(Bytes.to_hex(entry.public_key))
    <> ",\"operator\":"
    <> Json.encode_string(entry.operator)
    <> ",\"status\":"
    <> Json.encode_string(entry.status)
    <> ",\"software\":"
    <> Json.encode_string(entry.software)
    <> ",\"morse_run\":"
    <> Json.encode_bool(entry.morse_run)
    <> ",\"c2sp_name\":"
    <> json_nullable(entry.c2sp_name)
    <> push
    <> "}"
end

## {"witnesses":[...]}; push_url only on the internal list.

pub fn transparency_registry_json(entries :: List<RegistryWitness>,
  with_push_url :: Bool) -> String do
  "{\"witnesses\":["
    <> String.join(List.map(entries, fn entry -> registry_json_entry(entry, with_push_url) end),
      ",")
    <> "]}"
end

fn attestation_rows(conn :: borrow PgConn,
  checkpoint_sequence :: U64,
  with_cosignatures :: Bool) -> List<Map<String, DbValue>>!String do
  Pg.query_values(conn,
    "SELECT signature.witness_id, signature.checkpoint_hash, signature.signature, COALESCE(signature.cosigned_at::text, '') AS cosigned_at FROM witness_signatures AS signature JOIN transparency_witness_registry AS registry ON registry.witness_id = signature.witness_id AND registry.public_key = signature.witness_public_key WHERE signature.checkpoint_sequence = $1::bigint AND registry.status <> 'retired' AND ($2::boolean OR signature.cosigned_at IS NULL) ORDER BY registry.status = 'pinned' DESC, signature.observed_at DESC, signature.witness_id LIMIT 16",
    [
      Text(U64.to_string(checkpoint_sequence)),
      Text(if with_cosignatures do
        "true"
      else
        "false"
      end)
    ])
end

## At most 16 attestations for a checkpoint, of both kinds: pinned witnesses
## first, then shadow ones, newest first.

fn cosignature_row(row :: Map<String, DbValue>) -> WitnessCosignature!String do
  let stamp = text(Map.get(row, "cosigned_at"))?
  let cosigned = String.length(stamp) > 0
  let timestamp = if cosigned do
    integer(Map.get(row, "cosigned_at"))?
  else
    0
  end
  let digest = if cosigned do
    Bytes.empty()
  else
    binary(Map.get(row, "checkpoint_hash"))?
  end
  Ok(WitnessCosignature {
    kind: if cosigned do
      2
    else
      1
    end,
    witness_id: text(Map.get(row, "witness_id"))?,
    checkpoint_hash: digest,
    timestamp: timestamp,
    signature: binary(Map.get(row, "signature"))?
  })
end

pub fn transparency_attestations_on_connection(conn :: borrow PgConn,
  checkpoint_sequence :: U64) -> List<WitnessCosignature>!String do
  let rows = attestation_rows(conn, checkpoint_sequence, true)?
  Ok(for row in rows do
    cosignature_row(row)?
  end)
end

## The Morse statements only, as KTW v1 carries them.

pub fn transparency_statements_on_connection(conn :: borrow PgConn,
  checkpoint_sequence :: U64) -> List<WitnessAttestation>!String do
  let rows = attestation_rows(conn, checkpoint_sequence, false)?
  Ok(for row in rows do
    WitnessAttestation {
      witness_id: text(Map.get(row, "witness_id"))?,
      checkpoint_hash: binary(Map.get(row, "checkpoint_hash"))?,
      signature: binary(Map.get(row, "signature"))?
    }
  end)
end

fn stamp_text(cosigned_at :: Int) -> String do
  if cosigned_at < 0 do
    ""
  else
    Int.to_string(cosigned_at)
  end
end

## Stores one verified attestation. cosigned_at is the C2SP cosignature time,
## or -1 for a Morse statement. The same attestation again is a duplicate; a
## later C2SP cosignature replaces an earlier one; anything else is a conflict.

pub fn transparency_store_attestation_on_connection(conn :: borrow PgConn,
  checkpoint_sequence :: U64,
  witness :: RegistryWitness,
  checkpoint_hash :: Bytes,
  signature :: Bytes,
  cosigned_at :: Int) -> AttestationWrite!String do
  let sequence = U64.to_string(checkpoint_sequence)
  let changed = Pg.execute_values(conn,
    "INSERT INTO witness_signatures (checkpoint_sequence, witness_id, witness_public_key, checkpoint_hash, signature, cosigned_at) VALUES ($1::bigint, $2, $3, $4, $5, NULLIF($6, '')::bigint) ON CONFLICT DO NOTHING",
    [
      Text(sequence),
      Text(witness.witness_id),
      Binary(witness.public_key),
      Binary(checkpoint_hash),
      Binary(signature),
      Text(stamp_text(cosigned_at))
    ])?
  if changed == 1 do
    return Ok(AttestationStored)
  end
  let same = Pg.query_values(conn,
    "SELECT witness_id FROM witness_signatures WHERE checkpoint_sequence = $1::bigint AND witness_id = $2 AND witness_public_key = $3 AND checkpoint_hash = $4 AND signature = $5 AND cosigned_at IS NOT DISTINCT FROM NULLIF($6, '')::bigint",
    [
      Text(sequence),
      Text(witness.witness_id),
      Binary(witness.public_key),
      Binary(checkpoint_hash),
      Binary(signature),
      Text(stamp_text(cosigned_at))
    ])?
  if List.length(same) == 1 do
    return Ok(AttestationDuplicate)
  end
  if cosigned_at < 0 do
    return Ok(AttestationConflict)
  end
  let replaced = Pg.execute_values(conn,
    "UPDATE witness_signatures SET checkpoint_hash = $4, signature = $5, cosigned_at = $6::bigint, observed_at = now() WHERE checkpoint_sequence = $1::bigint AND witness_id = $2 AND witness_public_key = $3 AND cosigned_at < $6::bigint",
    [
      Text(sequence),
      Text(witness.witness_id),
      Binary(witness.public_key),
      Binary(checkpoint_hash),
      Binary(signature),
      Text(Int.to_string(cosigned_at))
    ])?
  if replaced == 1 do
    Ok(AttestationStored)
  else
    Ok(AttestationConflict)
  end
end

## Each non-retired witness: whether it attested the given checkpoint, and
## seconds since its last stored attestation (-1 when none is kept).

pub fn transparency_witness_health_on_connection(conn :: borrow PgConn,
  checkpoint_sequence :: U64) -> List<WitnessHealth>!String do
  let rows = Pg.query_values(conn,
    "SELECT registry.witness_id, registry.status, registry.morse_run::text AS morse_run, COALESCE(floor(extract(epoch FROM now() - max(signature.observed_at)))::bigint, -1)::text AS age, COALESCE(bool_or(signature.checkpoint_sequence = $1::bigint), false)::text AS signed_current FROM transparency_witness_registry AS registry LEFT JOIN witness_signatures AS signature ON signature.witness_id = registry.witness_id AND signature.witness_public_key = registry.public_key WHERE registry.status <> 'retired' GROUP BY registry.witness_id, registry.status, registry.morse_run ORDER BY registry.status = 'pinned' DESC, registry.witness_id",
    [Text(U64.to_string(checkpoint_sequence))])?
  Ok(for row in rows do
    WitnessHealth {
      witness_id: text(Map.get(row, "witness_id"))?,
      status: text(Map.get(row, "status"))?,
      morse_run: text(Map.get(row, "morse_run"))? == "true",
      last_signature_age: integer(Map.get(row, "age"))?,
      signed_current: text(Map.get(row, "signed_current"))? == "true"
    }
  end)
end

## Stores an anchor record the caller has checked against its checkpoint.

pub fn transparency_store_anchor_on_connection(conn :: borrow PgConn,
  record :: AnchorRecord) -> AttestationWrite!String do
  let values = [
    Text(Int.to_string(record.sequence)),
    Text(Int.to_string(record.tree_size)),
    Binary(record.checkpoint_hash),
    Text(Int.to_string(record.ring_index)),
    Text(record.tx_signature),
    Text(Int.to_string(record.slot))
  ]
  let changed = Pg.execute_values(conn,
    "INSERT INTO transparency_anchors (checkpoint_sequence, tree_size, checkpoint_hash, ring_index, tx_signature, slot) VALUES ($1::bigint, $2::bigint, $3, $4::integer, $5, $6::bigint) ON CONFLICT DO NOTHING",
    values)?
  if changed == 1 do
    Ok(AttestationStored)
  else
    let same = Pg.query_values(conn,
      "SELECT checkpoint_sequence FROM transparency_anchors WHERE checkpoint_sequence = $1::bigint AND tree_size = $2::bigint AND checkpoint_hash = $3 AND ring_index = $4::integer AND tx_signature = $5 AND slot = $6::bigint",
      values)?
    if List.length(same) == 1 do
      Ok(AttestationDuplicate)
    else
      Ok(AttestationConflict)
    end
  end
end

pub fn transparency_anchor(pool :: PoolHandle, sequence :: Int) -> Option<AnchorRecord>!String do
  let rows = Pool.query_values(pool,
    "SELECT checkpoint_sequence::text AS sequence, tree_size::text AS tree_size, checkpoint_hash, ring_index::text AS ring_index, tx_signature, slot::text AS slot FROM transparency_anchors WHERE checkpoint_sequence = $1::bigint",
    [Text(Int.to_string(sequence))])?
  case rows do
    [row] -> Ok(Some(AnchorRecord {
      sequence: integer(Map.get(row, "sequence"))?,
      tree_size: integer(Map.get(row, "tree_size"))?,
      checkpoint_hash: binary(Map.get(row, "checkpoint_hash"))?,
      ring_index: integer(Map.get(row, "ring_index"))?,
      tx_signature: text(Map.get(row, "tx_signature"))?,
      slot: integer(Map.get(row, "slot"))?
    }))
    _ -> Ok(None)
  end
end

pub fn transparency_anchor_json(record :: AnchorRecord, checkpoint_hex :: String) -> String do
  "{\"sequence\":"
    <> Int.to_string(record.sequence)
    <> ",\"tree_size\":"
    <> Int.to_string(record.tree_size)
    <> ",\"checkpoint_hash\":"
    <> Json.encode_string(Bytes.to_hex(record.checkpoint_hash))
    <> ",\"ring_index\":"
    <> Int.to_string(record.ring_index)
    <> ",\"tx_signature\":"
    <> Json.encode_string(record.tx_signature)
    <> ",\"slot\":"
    <> Int.to_string(record.slot)
    <> ",\"checkpoint\":"
    <> Json.encode_string(checkpoint_hex)
    <> "}"
end

fn json_int(value :: Json, key :: String) -> Int!String do
  case json_field(value, key) do
    None -> Err("anchor record needs #{key}")
    Some(field) -> Json.as_int(field)
  end
end

fn base58_signature(value :: String) -> Bool do
  let bytes = Bytes.to_list(Bytes.from_utf8(value))
  List.length(bytes) >= 32
    && List.length(bytes) <= 128
    && List.all(bytes,
      fn byte -> (byte >= 49 && byte <= 57)
        || (byte >= 65 && byte <= 90 && byte != 73 && byte != 79)
        || (byte >= 97 && byte <= 122 && byte != 108) end)
end

## Parses the jobs Worker's anchor record: {"sequence","tree_size",
## "checkpoint_hash" (hex),"ring_index","tx_signature","slot"}.

pub fn transparency_anchor_from_json(input :: String) -> AnchorRecord!String do
  let root = Json.parse(input)?
  let hash = case Bytes.from_hex(json_text(root, "checkpoint_hash")?) do
    Ok(value)
    Err(_) -> Err("invalid anchor checkpoint hash")
  end?
  let record = AnchorRecord {
    sequence: json_int(root, "sequence")?,
    tree_size: json_int(root, "tree_size")?,
    checkpoint_hash: hash,
    ring_index: json_int(root, "ring_index")?,
    tx_signature: json_text(root, "tx_signature")?,
    slot: json_int(root, "slot")?
  }
  if record.sequence < 1
    || record.tree_size < 1
    || Bytes.length(record.checkpoint_hash) != 32
    || record.ring_index < 0
    || record.ring_index > 4095
    || record.slot < 0
    || !base58_signature(record.tx_signature) do
    Err("invalid anchor record")
  else
    Ok(record)
  end
end

pub struct AnchorLag do
  anchored :: Bool
  lag_seconds :: Int
  last_anchor_age_seconds :: Int
end

## anchored is false while nothing was ever anchored. lag_seconds is how long
## the oldest checkpoint beyond the newest anchored size has waited (0 when
## every checkpoint's size is anchored).

pub fn transparency_anchor_lag_on_connection(conn :: borrow PgConn) -> AnchorLag!String do
  let rows = Pg.query_values(conn,
    "SELECT (SELECT count(*) FROM transparency_anchors)::text AS anchors, COALESCE(floor(extract(epoch FROM now() - (SELECT max(posted_at) FROM transparency_anchors)))::bigint, -1)::text AS last_age, COALESCE(floor(extract(epoch FROM now() - (SELECT min(created_at) FROM transparency_checkpoints WHERE tree_size > (SELECT max(tree_size) FROM transparency_anchors))))::bigint, 0)::text AS lag",
    [])?
  case rows do
    [row] -> Ok(AnchorLag {
      anchored: integer(Map.get(row, "anchors"))? > 0,
      lag_seconds: integer(Map.get(row, "lag"))?,
      last_anchor_age_seconds: integer(Map.get(row, "last_age"))?
    })
    _ -> Err("anchor lag failed")
  end
end
