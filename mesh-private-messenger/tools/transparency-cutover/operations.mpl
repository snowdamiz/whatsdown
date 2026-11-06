from Storage.TransparencyCutover import (
  begin_cutover_on_connection,
  accept_legacy_seal_on_connection,
  copy_cutover_batch_on_connection
)
from Storage.TransparencyLog import legacy_seal, cutover_phase
from Storage.TransparencyTree import tree_size_for
from Transparency.Config import SecurityConfig, decode_security_config, pinned_legacy_witness_keys
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  verify_checkpoint
)
from Transparency.Wire import encode_checkpoint

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(value) -> Ok(value)
    _ -> Err("invalid stored witness signature")
  end
end

fn configured_signer(config :: SecurityConfig) -> SigningKeyPair!String do
  let material = case Env.get_secret_hex("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX") do
    Err(_) -> return Err("invalid transparency signing seed")
    Ok(value) -> value
  end
  let pair = case Crypto.signing_from_secret(material) do
    Err(_) -> return Err("invalid transparency signing seed")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(pair.public_key.bytes, config.service_public_key) do
    Err("cutover signing key differs from release policy")
  else
    Ok(pair)
  end
end

fn accept(conn :: borrow PgConn, config :: SecurityConfig) -> Result<(), String> do
  let seal = case legacy_seal(conn)? do
    None -> return Err("transparency_cutover_not_started")
    Some(value) -> value
  end
  if !verify_checkpoint(seal, SigningPublicKey { bytes: config.service_public_key })? do
    return Err("legacy seal differs from release policy")
  end
  let keys = pinned_legacy_witness_keys(config)
  let signatures = List.flatten(for key in keys do
    let rows = Pg.query_values(conn,
      "SELECT checkpoint_hash, signature FROM witness_signatures WHERE checkpoint_sequence = $1::bigint AND witness_id = $2 AND witness_public_key = $3",
      [Text(U64.to_string(seal.sequence)), Text(key.witness_id), Binary(key.public_key)])?
    for row in rows do
      WitnessAttestation {
        witness_id: key.witness_id,
        checkpoint_hash: binary(Map.get(row, "checkpoint_hash"))?,
        signature: binary(Map.get(row, "signature"))?
      }
    end
  end)
  accept_legacy_seal_on_connection(conn, signatures, keys, config.legacy_threshold)
end

fn status(conn :: borrow PgConn) -> String!String do
  let phase = cutover_phase(conn)?
  let seal = case legacy_seal(conn)? do
    None -> "null"
    Some(value) -> Json.encode_string(Bytes.to_hex(encode_checkpoint(value)?))
  end
  let rows = Pg.query(conn, "SELECT copied_through::text FROM transparency_log_cutover", [])?
  let cursor = if List.length(rows) == 0 do
    "0"
  else
    Map.get(List.head(rows), "copied_through")
  end
  let size = tree_size_for(conn, 2)?
  Ok("{\"phase\":"
    <> Json.encode_string(phase)
    <> ",\"copied_through\":#{cursor},\"rfc_tree_size\":#{size},\"legacy_checkpoint_hex\":"
    <> seal
    <> "}")
end

pub fn run_action(pool :: PoolHandle,
  action :: String,
  limit :: Int,
  frame :: String) -> String!String do
  if (action != "status" && action != "prepare" && action != "accept" && action != "resume")
    || limit < 1
    || limit > 100 do
    return Err("invalid cutover action")
  end
  if action == "status" do
    return Repo.transaction(pool, fn(conn :: borrow PgConn) -> status(conn) end)
  end
  let config = decode_security_config(Bytes.from_utf8(frame))?
  if (config.version != 3 && config.version != 4 && config.version != 5)
    || config.log_version != 2 do
    return Err("cutover requires a version-3, version-4 or version-5 release policy")
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
      if action == "accept" do
        accept(conn, config)?
      else
        let pair = configured_signer(config)?
        if action == "prepare" do
          begin_cutover_on_connection(conn, pair.private_key, pair.public_key.bytes)?
          nil
        else
          copy_cutover_batch_on_connection(conn, limit, pair.private_key, pair.public_key.bytes)?
          nil
        end
        nil
      end
      status(conn)
    end)
end
