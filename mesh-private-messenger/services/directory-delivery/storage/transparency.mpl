from Transparency.Merkle import ConsistencyProof, InclusionProof, TransparencyCheckpoint, checkpoint_hash, consistency_proof, inclusion_proof, leaf_hash, sign_checkpoint

fn binary(value :: DbValue) -> Bytes ! String do
  case value do
    Binary( bytes) -> Ok(bytes)
    _ -> Err("invalid transparency row")
  end
end

fn text(value :: DbValue) -> String ! String do
  case value do
    Text( output) -> Ok(output)
    _ -> Err("invalid transparency row")
  end
end

fn integer(value :: DbValue) -> Int ! String do
  case String.to_int(text(value) ?) do
    None -> Err("invalid transparency integer")
    Some( output) -> Ok(output)
  end
end

fn wide(value :: DbValue) -> U64 ! String do
  U64.parse(text(value) ?)
end

fn int_wide(value :: Int) -> U64 ! String do
  U64.parse(Int.to_string(value))
end

fn zero_hash() -> Bytes ! String do
  case Bytes.repeat(0, 32) do
    Err( _) -> Err("transparency allocation failed")
    Ok( value) -> Ok(value)
  end
end

fn account_commitment(account_id :: Bytes) -> Bytes ! String do
  if Bytes.length(account_id) != 32 do
    Err("invalid transparency account")
  else
    case Bytes.concat(Bytes.from_utf8("mesh-msg/v1/transparency-account"), account_id) do
      Err( _) -> Err("transparency allocation failed")
      Ok( value) -> Ok(Crypto.sha256(value))
    end
  end
end

pub fn append_entry_on_connection(conn :: borrow PgConn,
account_id :: Bytes,
entry_bytes :: Bytes) -> Int ! String do
  let commitment = account_commitment(account_id) ?
  let hash = leaf_hash(entry_bytes) ?
  let rows = Pg.query_values(conn,
  "INSERT INTO transparency_entries (account_commitment, entry_bytes, leaf_hash) VALUES ($1, $2, $3) RETURNING sequence::text",
  [Binary(commitment), Binary(entry_bytes), Binary(hash)]) ?
  if List.length(rows) != 1 do
    Err("transparency append failed")
  else
    integer(Map.get(List.head(rows), "sequence"))
  end
end

fn hashes(rows :: List < Map < String, DbValue > >,
index :: Int,
output :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(rows) do
    Ok(output)
  else
    hashes(rows,
    index + 1,
    List.append(output, binary(Map.get(List.get(rows, index), "leaf_hash")) ?))
  end
end

fn all_hashes_on_connection(conn :: borrow PgConn) -> List < Bytes > ! String do
  let rows = Pg.query_values(conn,
  "SELECT leaf_hash FROM transparency_entries ORDER BY sequence LIMIT 4097",
  []) ?
  if List.length(rows) > 4096 do
    Err("transparency log exceeds proof ceiling")
  else
    hashes(rows, 0, List.new())
  end
end

fn checkpoint_from_row(row :: Map < String, DbValue >) -> TransparencyCheckpoint ! String do
  Ok(TransparencyCheckpoint {
    version : 1,
    sequence : wide(Map.get(row, "sequence")) ?,
    tree_size : wide(Map.get(row, "tree_size")) ?,
    tree_root : binary(Map.get(row, "tree_root")) ?,
    previous_checkpoint_hash : binary(Map.get(row, "previous_checkpoint_hash")) ?,
    timestamp : wide(Map.get(row, "timestamp_ms")) ?,
    service_public_key : binary(Map.get(row, "service_public_key")) ?,
    signature : binary(Map.get(row, "service_signature")) ?
  })
end

fn checkpoint_rows(conn :: borrow PgConn) -> List < Map < String, DbValue > > ! String do
  Pg.query_values(conn,
  "SELECT sequence::text, tree_size::text, tree_root, previous_checkpoint_hash, timestamp_ms::text, service_public_key, service_signature FROM transparency_checkpoints ORDER BY sequence DESC LIMIT 1 FOR UPDATE",
  [])
end

fn current_time() -> U64 ! String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn create_checkpoint_on_connection(conn :: borrow PgConn,
signing_seed :: Bytes) -> TransparencyCheckpoint ! String do
  let _ = Pg.query_values(conn, "SELECT pg_advisory_xact_lock(1835365485)", []) ?
  let leaf_hashes = all_hashes_on_connection(conn) ?
  if List.length(leaf_hashes) == 0 do
    Err("transparency log is empty")
  else
    let previous_rows = checkpoint_rows(conn) ?
    if List.length(previous_rows) > 0 && U64.to_int(wide(Map.get(List.head(previous_rows),
    "tree_size")) ?) ? == List.length(leaf_hashes) do
      checkpoint_from_row(List.head(previous_rows))
    else
      let previous = if List.length(previous_rows) == 0 do
        None
      else
        Some(checkpoint_from_row(List.head(previous_rows)) ?)
      end
      let sequence = case previous do
        None -> int_wide(1)
        Some( value) -> U64.add(value.sequence, int_wide(1) ?)
      end ?
      let previous_hash = case previous do
        None -> zero_hash()
        Some( value) -> checkpoint_hash(value)
      end ?
      let signer = case Crypto.signing_from_seed(signing_seed) do
        Err( _) -> Err("invalid transparency signing seed")
        Ok( value) -> Ok(value)
      end ?
      let checkpoint = sign_checkpoint(signer.private_key,
      signer.public_key.bytes,
      sequence,
      leaf_hashes,
      previous_hash,
      current_time() ?) ?
      let changed = Pg.execute_values(conn,
      "INSERT INTO transparency_checkpoints (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature) VALUES ($1::bigint, $2::bigint, $3, $4, $5::bigint, $6, $7)",
      [Text(U64.to_string(checkpoint.sequence)), Text(U64.to_string(checkpoint.tree_size)), Binary(checkpoint.tree_root), Binary(checkpoint.previous_checkpoint_hash), Text(U64.to_string(checkpoint.timestamp)), Binary(checkpoint.service_public_key), Binary(checkpoint.signature)]) ?
      if changed == 1 do
        Ok(checkpoint)
      else
        Err("transparency checkpoint insert failed")
      end
    end
  end
end

pub fn create_checkpoint(pool :: PoolHandle,
signing_seed :: Bytes) -> TransparencyCheckpoint ! String do
  Repo.transaction(pool,
  fn (conn :: borrow PgConn) -> create_checkpoint_on_connection(conn, signing_seed) end)
end

pub fn entry_count(pool :: PoolHandle) -> Int ! String do
  let rows = Pool.query_values(pool, "SELECT count(*)::text AS count FROM transparency_entries", []) ?
  if List.length(rows) != 1 do
    Err("transparency count failed")
  else
    integer(Map.get(List.head(rows), "count"))
  end
end

pub fn inclusion_for_account(pool :: PoolHandle, account_id :: Bytes) -> InclusionProof ! String do
  let commitment = account_commitment(account_id) ?
  let positions = Pool.query_values(pool,
  "SELECT (SELECT count(*) FROM transparency_entries AS earlier WHERE earlier.sequence < current.sequence)::text AS leaf_index FROM transparency_entries AS current WHERE account_commitment = $1 ORDER BY sequence DESC LIMIT 1",
  [Binary(commitment)]) ?
  if List.length(positions) != 1 do
    Err("transparency entry not found")
  else
    let rows = Pool.query_values(pool,
    "SELECT leaf_hash FROM transparency_entries ORDER BY sequence LIMIT 4097",
    []) ?
    if List.length(rows) > 4096 do
      Err("transparency log exceeds proof ceiling")
    else
      inclusion_proof(hashes(rows, 0, List.new()) ?, integer(Map.get(List.head(positions), "leaf_index")) ?)
    end
  end
end

pub fn consistency_from(pool :: PoolHandle, old_tree_size :: Int) -> ConsistencyProof ! String do
  if old_tree_size < 0 || old_tree_size > 4096 do
    Err("invalid consistency size")
  else
    let old_rows = Pool.query_values(pool,
    "SELECT leaf_hash FROM transparency_entries ORDER BY sequence LIMIT $1::bigint",
    [Text(Int.to_string(old_tree_size))]) ?
    let new_rows = Pool.query_values(pool,
    "SELECT leaf_hash FROM transparency_entries ORDER BY sequence LIMIT 4097",
    []) ?
    if List.length(new_rows) > 4096 || List.length(old_rows) != old_tree_size do
      Err("invalid consistency size")
    else
      consistency_proof(hashes(old_rows, 0, List.new()) ?, hashes(new_rows, 0, List.new()) ?)
    end
  end
end
