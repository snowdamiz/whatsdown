from Transparency.Merkle import WitnessKey
from Storage.TransparencyLog import cutover_phase, checkpoint_table, witness_table, anchor_table

pub struct RegisteredWitness do
  key :: WitnessKey
  software :: String
  note_name :: String
  push_url :: String
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid witness registry row")
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid witness registry row")
  end
end

pub fn registered_witness(conn :: borrow PgConn, id :: String) -> Option<WitnessKey>!String do
  case registered_profile(conn, id)? do
    None -> Ok(None)
    Some(value) -> Ok(Some(value.key))
  end
end

pub fn registered_profile(conn :: borrow PgConn,
  id :: String) -> Option<RegisteredWitness>!String do
  let rows = Pg.query_values(conn,
    "SELECT public_key, software, COALESCE(note_name, '') AS note_name, COALESCE(push_url, '') AS push_url FROM transparency_witness_registry WHERE witness_id = $1 AND status <> 'retired' FOR SHARE",
    [Text(id)])?
  if List.length(rows) == 0 do
    Ok(None)
  else
    let row = List.head(rows)
    Ok(Some(RegisteredWitness {
      key: WitnessKey { witness_id: id, public_key: binary(Map.get(row, "public_key"))? },
      software: text(Map.get(row, "software"))?,
      note_name: text(Map.get(row, "note_name"))?,
      push_url: text(Map.get(row, "push_url"))?
    }))
  end
end

fn bootstrap_key(name :: String) -> Bytes!String do
  let encoded = Env.get(name, "")
  let key = Bytes.from_hex(encoded)?
  if Bytes.length(key) != 32 || Bytes.to_hex(key) != encoded do
    Err("invalid bootstrap witness key")
  else
    Ok(key)
  end
end

fn bootstrap_push(name :: String, fallback :: String) -> String!String do
  let configured = Env.get(name, "")
  if configured == "" do
    Ok(fallback)
  else
    let origin = Http.url_origin(configured)?
    if !String.starts_with(origin, "https://")
      || (configured != origin && configured != origin <> "/") do
      Err("invalid bootstrap witness URL")
    else
      Ok(origin <> "/attest")
    end
  end
end

pub fn bootstrap_witness_registry(pool :: PoolHandle) -> Result<(), String> do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365486)", [])?
      if List.length(Pg.query(conn,
        "SELECT witness_id FROM transparency_witness_registry LIMIT 1",
        [])?) > 0 do
        return Ok(nil)
      end
      let a = bootstrap_key("MESSENGER_WITNESS_A_PUBLIC_KEY_HEX")?
      let b = bootstrap_key("MESSENGER_WITNESS_B_PUBLIC_KEY_HEX")?
      if Bytes.secure_equals(a, b) do
        return Err("duplicate bootstrap witness keys")
      end
      Pg.execute_values(conn,
        "INSERT INTO transparency_witness_registry (witness_id, public_key, operator, status, software, push_url, morse_run) VALUES ('witness-a', $1, 'Morse', 'pinned', 'mesh', $3, true), ('witness-b', $2, 'Morse', 'pinned', 'mesh', $4, true)",
        [
          Binary(a),
          Binary(b),
          Text(bootstrap_push("WITNESS_A_URL", "https://witness-a.internal/attest")?),
          Text(bootstrap_push("WITNESS_B_URL", "https://witness-b.internal/attest")?)
        ])?
      Ok(nil)
    end)
end

pub fn public_witness_registry(pool :: PoolHandle) -> String!String do
  let rows = Pool.query_values(pool,
    "SELECT witness_id, encode(public_key, 'hex') AS public_key, operator, status, software FROM transparency_witness_registry ORDER BY witness_id LIMIT 1025",
    [])?
  if List.length(rows) > 1024 do
    return Err("witness registry capacity exceeded")
  end
  let encoded = for row in rows do
    "{\"witness_id\":"
      <> Json.encode_string(text(Map.get(row, "witness_id"))?)
      <> ",\"public_key\":"
      <> Json.encode_string(text(Map.get(row, "public_key"))?)
      <> ",\"operator\":"
      <> Json.encode_string(text(Map.get(row, "operator"))?)
      <> ",\"status\":"
      <> Json.encode_string(text(Map.get(row, "status"))?)
      <> ",\"software\":"
      <> Json.encode_string(text(Map.get(row, "software"))?)
      <> "}"
  end
  Ok("{\"witnesses\":[" <> String.join(encoded, ",") <> "]}")
end

pub fn push_witness_registry(pool :: PoolHandle) -> String!String do
  let rows = Pool.query_values(pool,
    "SELECT witness_id, push_url, software FROM transparency_witness_registry WHERE status <> 'retired' AND push_url IS NOT NULL AND ((morse_run AND software = 'mesh') OR (software = 'c2sp' AND note_name IS NOT NULL)) ORDER BY witness_id LIMIT 257",
    [])?
  if List.length(rows) > 256 do
    return Err("witness push capacity exceeded")
  end
  let encoded = for row in rows do
    "{\"witness_id\":"
      <> Json.encode_string(text(Map.get(row, "witness_id"))?)
      <> ",\"push_url\":"
      <> Json.encode_string(text(Map.get(row, "push_url"))?)
      <> ",\"software\":"
      <> Json.encode_string(text(Map.get(row, "software"))?)
      <> "}"
  end
  Ok("{\"witnesses\":[" <> String.join(encoded, ",") <> "]}")
end

fn number(row :: Map<String, DbValue>, field :: String) -> Int!String do
  case String.to_int(text(Map.get(row, field))?) do
    Some(value) -> Ok(value)
    None -> Err("invalid witness health row")
  end
end

# Fixed SQL fragments shared by evidence and health, using aliases s and r.
pub fn signature_policy_sql(version :: Int) -> String!String do
  if version == 1 do
    Ok("r.software = 'mesh' AND octet_length(s.signature) = 64")
  else if version == 2 do
    Ok("((r.software = 'mesh' AND octet_length(s.signature) = 64) OR (r.software = 'c2sp' AND r.note_name IS NOT NULL AND octet_length(s.signature) = 72 AND s.cosigned_at_ms BETWEEN floor(extract(epoch from now()) * 1000)::bigint - 300000 AND floor(extract(epoch from now()) * 1000)::bigint + 60000))")
  else
    Err("invalid transparency log version")
  end
end

pub fn witness_health(pool :: PoolHandle) -> String!String do
  let phase = Repo.transaction(pool, fn(conn :: borrow PgConn) -> cutover_phase(conn) end)?
  let version = if phase == "active" do
    2
  else
    1
  end
  let signatures = witness_table(version)?
  let checkpoints = checkpoint_table(version)?
  let accepted = signature_policy_sql(version)?
  let anchor_age = "(SELECT CASE WHEN max(posted_at) IS NULL THEN NULL ELSE GREATEST(0, floor(extract(epoch from now() - max(posted_at)) * 1000)::bigint)::text END FROM "
    <> anchor_table(version)?
    <> ")"
  let rows = Pool.query_values(pool,
    "SELECT (SELECT count(*) FROM transparency_witness_registry WHERE status = 'pinned')::text AS pins, (SELECT count(*) FROM "
      <> signatures
      <> " s JOIN transparency_witness_registry r ON r.witness_id = s.witness_id AND r.public_key = s.witness_public_key WHERE r.status = 'pinned' AND s.checkpoint_sequence = c.sequence AND "
      <> accepted
      <> ")::text AS signatures, COALESCE(c.sequence::text, 'null') AS sequence, COALESCE((floor(extract(epoch from now()) * 1000)::bigint - c.timestamp_ms)::text, 'null') AS age, COALESCE("
      <> anchor_age
      <> ", 'null') AS anchor_age FROM (SELECT 1) singleton LEFT JOIN LATERAL (SELECT sequence, timestamp_ms FROM "
      <> checkpoints
      <> " ORDER BY sequence DESC LIMIT 1) c ON true",
    [])?
  let summary = List.head(rows)
  let pins = number(summary, "pins")?
  let count = number(summary, "signatures")?
  let threshold = pins / 2 + 1
  let age = text(Map.get(summary, "age"))?
  let fresh = case String.to_int(age) do
    None -> false
    Some(value) -> value >= -60000 && value <= 300000
  end
  let met = pins >= 1
    && pins <= 16
    && count >= threshold
    && fresh
    && (phase == "legacy" || phase == "active")
  let witnesses = Pool.query_values(pool,
    "SELECT r.witness_id, r.status, COALESCE(CASE WHEN max(s.observed_at) IS NULL THEN NULL ELSE GREATEST(0, floor(extract(epoch from now() - max(s.observed_at)) * 1000)::bigint)::text END, 'null') AS age FROM transparency_witness_registry r LEFT JOIN "
      <> signatures
      <> " s ON s.witness_id = r.witness_id AND s.witness_public_key = r.public_key AND "
      <> accepted
      <> " GROUP BY r.witness_id ORDER BY r.witness_id LIMIT 1025",
    [])?
  if List.length(witnesses) > 1024 do
    return Err("witness registry capacity exceeded")
  end
  let encoded = for row in witnesses do
    "{\"witness_id\":"
      <> Json.encode_string(text(Map.get(row, "witness_id"))?)
      <> ",\"status\":"
      <> Json.encode_string(text(Map.get(row, "status"))?)
      <> ",\"last_signature_age_ms\":"
      <> text(Map.get(row, "age"))?
      <> "}"
  end
  Ok("{\"threshold_met\":"
    <> (if met do
      "true"
    else
      "false"
    end)
    <> ",\"threshold\":#{threshold},\"pinned\":#{pins},\"valid_signatures\":#{count}"
    <> ",\"log_version\":#{version},\"phase\":"
    <> Json.encode_string(phase)
    <> ",\"checkpoint_sequence\":"
    <> text(Map.get(summary, "sequence"))?
    <> ",\"checkpoint_age_ms\":"
    <> age
    <> ",\"anchor_lag_ms\":"
    <> text(Map.get(summary, "anchor_age"))?
    <> ",\"witnesses\":["
    <> String.join(encoded, ",")
    <> "]}")
end
