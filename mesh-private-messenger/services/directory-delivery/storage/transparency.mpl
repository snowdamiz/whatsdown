import RuntimeJobs
from Transparency.Merkle import ConsistencyProof, InclusionProof, TransparencyCheckpoint, WitnessAttestation, WitnessKey, checkpoint_hash, consistency_proof, inclusion_proof, leaf_hash, sign_checkpoint, verify_witnesses
from Transparency.Wire import account_lookup_id, TransparencyEvidence

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid transparency row")
  end
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid transparency row")
  end
end

fn integer(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    None -> Err("invalid transparency integer")
    Some(output) -> Ok(output)
  end
end

fn wide(value :: DbValue) -> U64!String do
  U64.parse(text(value)?)
end

fn int_wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn zero_hash() -> Bytes!String do
  case Bytes.repeat(0, 32) do
    Err(_) -> Err("transparency allocation failed")
    Ok(value)
  end
end

fn account_commitment(account_id :: Bytes) -> Bytes!String do
  if Bytes.length(account_id) != 32 do
    Err("invalid transparency account")
  else
    case Bytes.concat(Bytes.from_utf8("mesh-msg/v1/transparency-account"), account_id) do
      Err(_) -> Err("transparency allocation failed")
      Ok(value) -> Ok(Crypto.sha256(value))
    end
  end
end

# Proofs carry every leaf commitment, which lets a client check any earlier
# checkpoint against its cached view offline, and bounds the log. Registration
# is anonymous, so that bound has to fail safe: an append past it used to
# succeed and then make every lookup fail for every account.
#
# Appends now stop at the ceiling, and new accounts stop earlier. A flood can
# close registration; it cannot take the directory down, and existing accounts
# keep the reserved room to link, rotate, and above all revoke devices.

pub fn transparency_proof_ceiling() -> Int do
  4096
end

pub fn transparency_new_account_ceiling() -> Int do
  3584
end

fn log_size_on_connection(conn :: borrow PgConn) -> Int!String do
  let rows = Pg.query_values(conn, "SELECT count(*)::text AS count FROM transparency_entries", [])?
  if List.length(rows) != 1 do
    Err("transparency count failed")
  else
    integer(Map.get(List.head(rows), "count"))
  end
end

pub fn append_entry_on_connection(conn :: borrow PgConn,
  account_id :: Bytes,
  entry_bytes :: Bytes,
  new_account :: Bool) -> Int!String do
  let commitment = account_commitment(account_id)?
  let hash = leaf_hash(entry_bytes)?
  Pg.query_values(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  let ceiling = if new_account do
    transparency_new_account_ceiling()
  else
    transparency_proof_ceiling()
  end
  if log_size_on_connection(conn)? >= ceiling do
    return Err("transparency_log_full")
  end
  let rows = Pg.query_values(conn,
    "INSERT INTO transparency_entries (account_commitment, entry_bytes, leaf_hash) VALUES ($1, $2, $3) RETURNING sequence::text",
    [Binary(commitment), Binary(entry_bytes), Binary(hash)])?
  if List.length(rows) != 1 do
    Err("transparency append failed")
  else
    integer(Map.get(List.head(rows), "sequence"))
  end
end

## A deleted account's leaves stay, since every proof covers the whole tree.
## The entries behind them name the account and its devices, and go with it.

pub fn forget_account_entries_on_connection(conn :: borrow PgConn, account_id :: Bytes) -> Result<(), String> do
  Pg.execute_values(conn,
    "UPDATE transparency_entries SET entry_bytes = NULL WHERE account_commitment = $1",
    [Binary(account_commitment(account_id)?)])?
  Ok(nil)
end

fn hashes(rows :: List<Map<String, DbValue>>, index :: Int, output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(rows) do
    Ok(output)
  else
    hashes(rows,
      index + 1,
      List.append(output, binary(Map.get(List.get(rows, index), "leaf_hash"))?))
  end
end

fn all_hashes_on_connection(conn :: borrow PgConn) -> List<Bytes>!String do
  let rows = Pg.query_values(conn,
    "SELECT leaf_hash FROM transparency_entries ORDER BY sequence LIMIT 4097",
    [])?
  if List.length(rows) > 4096 do
    Err("transparency log exceeds proof ceiling")
  else
    hashes(rows, 0, List.new())
  end
end

fn checkpoint_from_row(row :: Map<String, DbValue>) -> TransparencyCheckpoint!String do
  Ok(TransparencyCheckpoint {
    version: 1,
    sequence: wide(Map.get(row, "sequence"))?,
    tree_size: wide(Map.get(row, "tree_size"))?,
    tree_root: binary(Map.get(row, "tree_root"))?,
    previous_checkpoint_hash: binary(Map.get(row, "previous_checkpoint_hash"))?,
    timestamp: wide(Map.get(row, "timestamp_ms"))?,
    service_public_key: binary(Map.get(row, "service_public_key"))?,
    signature: binary(Map.get(row, "service_signature"))?
  })
end

fn checkpoint_rows(conn :: borrow PgConn) -> List<Map<String, DbValue>>!String do
  Pg.query_values(conn,
    "SELECT sequence::text, tree_size::text, tree_root, previous_checkpoint_hash, timestamp_ms::text, service_public_key, service_signature FROM transparency_checkpoints ORDER BY transparency_checkpoints.sequence DESC LIMIT 1 FOR UPDATE",
    [])
end

fn prefix(values :: List<Bytes>, count :: Int, index :: Int, output :: List<Bytes>) -> List<Bytes> do
  if index >= count do
    output
  else
    prefix(values, count, index + 1, List.append(output, List.get(values, index)))
  end
end

fn witness_values(rows :: List<Map<String, DbValue>>,
  index :: Int,
  output :: List<WitnessAttestation>) -> List<WitnessAttestation>!String do
  if index >= List.length(rows) do
    Ok(output)
  else
    let row = List.get(rows, index)
    witness_values(rows,
      index + 1,
      List.append(output,
        WitnessAttestation {
          witness_id: text(Map.get(row, "witness_id"))?,
          checkpoint_hash: binary(Map.get(row, "checkpoint_hash"))?,
          signature: binary(Map.get(row, "signature"))?
        }))
  end
end

fn witnesses_on_connection(conn :: borrow PgConn, checkpoint_sequence :: U64) -> List<WitnessAttestation>!String do
  let rows = Pg.query_values(conn,
    "SELECT witness_id, checkpoint_hash, signature FROM witness_signatures WHERE checkpoint_sequence = $1::bigint ORDER BY witness_id",
    [Text(U64.to_string(checkpoint_sequence))])?
  witness_values(rows, 0, List.new())
end

fn current_time() -> U64!String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn configured_signer() -> SigningKeyPair!String do
  let material = case Env.get_secret_hex("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX") do
    Err(_) -> Err("invalid transparency signing seed")
    Ok(value)
  end?
  case Crypto.signing_from_secret(material) do
    Err(_) -> Err("invalid transparency signing seed")
    Ok(signer)
  end
end

pub fn validate_signing_config() -> Result<(), String> do
  let _signer = configured_signer()?
  Ok(nil)
end

fn checkpoint_recent(value :: TransparencyCheckpoint, now :: U64) -> Bool do
  case U64.to_int(value.timestamp) do
    Err(_) -> false
    Ok(stamp) -> case U64.to_int(now) do
      Err(_) -> false
      Ok(current) -> current >= stamp && current - stamp < 240000
    end
  end
end

fn create_checkpoint_on_connection(conn :: borrow PgConn,
  signing_key :: borrow SigningPrivateKey,
  signing_public_key :: Bytes) -> TransparencyCheckpoint!String do
  Pg.query_values(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  let leaf_hashes = all_hashes_on_connection(conn)?
  if List.length(leaf_hashes) == 0 do
    Err("transparency log is empty")
  else
    let previous_rows = checkpoint_rows(conn)?
    if List.length(previous_rows) > 0 && U64.to_int(wide(Map.get(List.head(previous_rows),
      "tree_size"))?)? == List.length(leaf_hashes) && checkpoint_recent(checkpoint_from_row(List.head(previous_rows))?,
      current_time()?) do
      checkpoint_from_row(List.head(previous_rows))
    else
      let previous = if List.length(previous_rows) == 0 do
        None
      else
        Some(checkpoint_from_row(List.head(previous_rows))?)
      end
      let sequence = case previous do
        None -> int_wide(1)
        Some(value) -> U64.add(value.sequence, int_wide(1)?)
      end?
      let previous_hash = case previous do
        None -> zero_hash()
        Some(value) -> checkpoint_hash(value)
      end?
      let checkpoint = sign_checkpoint(signing_key,
        signing_public_key,
        sequence,
        leaf_hashes,
        previous_hash,
        current_time()?)?
      let changed = Pg.execute_values(conn,
        "INSERT INTO transparency_checkpoints (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature) VALUES ($1::bigint, $2::bigint, $3, $4, $5::bigint, $6, $7)",
        [
          Text(U64.to_string(checkpoint.sequence)),
          Text(U64.to_string(checkpoint.tree_size)),
          Binary(checkpoint.tree_root),
          Binary(checkpoint.previous_checkpoint_hash),
          Text(U64.to_string(checkpoint.timestamp)),
          Binary(checkpoint.service_public_key),
          Binary(checkpoint.signature)
        ])?
      if changed == 1 do
        RuntimeJobs.notify(conn, "witness")?
        Ok(checkpoint)
      else
        Err("transparency checkpoint insert failed")
      end
    end
  end
end

fn create_checkpoint_from_seed_on_connection(conn :: borrow PgConn, signing_seed :: Bytes) -> TransparencyCheckpoint!String do
  let signer = case Crypto.signing_from_seed(signing_seed) do
    Err(_) -> Err("invalid transparency signing seed")
    Ok(value)
  end?
  create_checkpoint_on_connection(conn, signer.private_key, signer.public_key.bytes)
end

fn create_configured_checkpoint_on_connection(conn :: borrow PgConn) -> TransparencyCheckpoint!String do
  let signer = configured_signer()?
  create_checkpoint_on_connection(conn, signer.private_key, signer.public_key.bytes)
end

pub fn create_checkpoint(pool :: PoolHandle, signing_seed :: Bytes) -> TransparencyCheckpoint!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> create_checkpoint_from_seed_on_connection(conn, signing_seed) end)
end

pub fn create_configured_checkpoint(pool :: PoolHandle) -> TransparencyCheckpoint!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> create_configured_checkpoint_on_connection(conn) end)
end

pub fn entry_count(pool :: PoolHandle) -> Int!String do
  let rows = Pool.query_values(pool, "SELECT count(*)::text AS count FROM transparency_entries", [])?
  if List.length(rows) != 1 do
    Err("transparency count failed")
  else
    integer(Map.get(List.head(rows), "count"))
  end
end

pub fn inclusion_for_account(pool :: PoolHandle, account_id :: Bytes) -> InclusionProof!String do
  let commitment = account_commitment(account_id)?
  let positions = Pool.query_values(pool,
    "SELECT (SELECT count(*) FROM transparency_entries AS earlier WHERE earlier.sequence < current.sequence)::text AS leaf_index FROM transparency_entries AS current WHERE account_commitment = $1 ORDER BY sequence DESC LIMIT 1",
    [Binary(commitment)])?
  if List.length(positions) != 1 do
    Err("transparency entry not found")
  else
    let rows = Pool.query_values(pool,
      "SELECT leaf_hash FROM transparency_entries ORDER BY sequence LIMIT 4097",
      [])?
    if List.length(rows) > 4096 do
      Err("transparency log exceeds proof ceiling")
    else
      inclusion_proof(hashes(rows, 0, List.new())?,
        integer(Map.get(List.head(positions), "leaf_index"))?)
    end
  end
end

pub fn consistency_from(pool :: PoolHandle, old_tree_size :: Int) -> ConsistencyProof!String do
  if old_tree_size < 0 || old_tree_size > 4096 do
    Err("invalid consistency size")
  else
    let old_rows = Pool.query_values(pool,
      "SELECT leaf_hash FROM transparency_entries ORDER BY sequence LIMIT $1::bigint",
      [Text(Int.to_string(old_tree_size))])?
    let new_rows = Pool.query_values(pool,
      "SELECT leaf_hash FROM transparency_entries ORDER BY sequence LIMIT 4097",
      [])?
    if List.length(new_rows) > 4096 || List.length(old_rows) != old_tree_size do
      Err("invalid consistency size")
    else
      consistency_proof(hashes(old_rows, 0, List.new())?, hashes(new_rows, 0, List.new())?)
    end
  end
end

pub fn latest_checkpoint(pool :: PoolHandle) -> Option<TransparencyCheckpoint>!String do
  let rows = Pool.query_values(pool,
    "SELECT sequence::text, tree_size::text, tree_root, previous_checkpoint_hash, timestamp_ms::text, service_public_key, service_signature FROM transparency_checkpoints ORDER BY transparency_checkpoints.sequence DESC LIMIT 1",
    [])?
  if List.length(rows) == 0 do
    Ok(None)
  else
    Ok(Some(checkpoint_from_row(List.head(rows))?))
  end
end

pub fn witnesses_for_checkpoint(pool :: PoolHandle, checkpoint_sequence :: U64) -> List<WitnessAttestation>!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> witnesses_on_connection(conn, checkpoint_sequence) end)
end

fn evidence_on_connection(conn :: borrow PgConn,
  username :: String,
  old_tree_size :: Int,
  signing_key :: borrow SigningPrivateKey,
  signing_public_key :: Bytes) -> TransparencyEvidence!String do
  let checkpoint = create_checkpoint_on_connection(conn, signing_key, signing_public_key)?
  let all = all_hashes_on_connection(conn)?
  if old_tree_size < 0 || old_tree_size > List.length(all) do
    Err("invalid consistency size")
  else
    let accounts = Pg.query_values(conn,
      "SELECT account_id FROM messenger_accounts WHERE username = $1",
      [Text(username)])?
    if List.length(accounts) != 1 do
      Err("transparency entry not found")
    else
      let positions = Pg.query_values(conn,
        "SELECT entry_bytes, (SELECT count(*) FROM transparency_entries AS earlier WHERE earlier.sequence < current.sequence)::text AS leaf_index FROM transparency_entries AS current WHERE account_commitment = $1 ORDER BY sequence DESC LIMIT 1",
        [Binary(account_commitment(binary(Map.get(List.head(accounts), "account_id"))?)?)])?
      if List.length(positions) != 1 do
        Err("transparency entry not found")
      else
        let position = List.head(positions)
        Ok(TransparencyEvidence {
          entry_bytes: binary(Map.get(position, "entry_bytes"))?,
          inclusion: inclusion_proof(all, integer(Map.get(position, "leaf_index"))?)?,
          consistency: consistency_proof(prefix(all, old_tree_size, 0, List.new()), all)?,
          checkpoint: checkpoint,
          witnesses: witnesses_on_connection(conn, checkpoint.sequence)?
        })
      end
    end
  end
end

fn evidence_from_seed_on_connection(conn :: borrow PgConn,
  username :: String,
  old_tree_size :: Int,
  signing_seed :: Bytes) -> TransparencyEvidence!String do
  let signer = case Crypto.signing_from_seed(signing_seed) do
    Err(_) -> Err("invalid transparency signing seed")
    Ok(value)
  end?
  evidence_on_connection(conn, username, old_tree_size, signer.private_key, signer.public_key.bytes)
end

fn configured_evidence_on_connection(conn :: borrow PgConn,
  username :: String,
  old_tree_size :: Int) -> TransparencyEvidence!String do
  let signer = configured_signer()?
  evidence_on_connection(conn, username, old_tree_size, signer.private_key, signer.public_key.bytes)
end

pub fn evidence_for_username(pool :: PoolHandle,
  username :: String,
  old_tree_size :: Int,
  signing_seed :: Bytes) -> TransparencyEvidence!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> evidence_from_seed_on_connection(conn,
      username,
      old_tree_size,
      signing_seed) end)
end

pub fn configured_evidence_for_username(pool :: PoolHandle,
  username :: String,
  old_tree_size :: Int) -> TransparencyEvidence!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> configured_evidence_on_connection(conn, username, old_tree_size) end)
end

fn store_witness_on_connection(conn :: borrow PgConn,
  attestation :: WitnessAttestation,
  trusted :: WitnessKey) -> Result<(), String> do
  let rows = checkpoint_rows(conn)?
  if List.length(rows) != 1 do
    Err("transparency checkpoint not found")
  else
    let checkpoint = checkpoint_from_row(List.head(rows))?
    if attestation.witness_id != trusted.witness_id || !verify_witnesses(checkpoint,
      [attestation],
      [trusted],
      1)? do
      Err("invalid witness attestation")
    else
      let changed = Pg.execute_values(conn,
        "INSERT INTO witness_signatures (checkpoint_sequence, witness_id, witness_public_key, checkpoint_hash, signature) VALUES ($1::bigint, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        [
          Text(U64.to_string(checkpoint.sequence)),
          Text(attestation.witness_id),
          Binary(trusted.public_key),
          Binary(attestation.checkpoint_hash),
          Binary(attestation.signature)
        ])?
      if changed == 1 do
        Ok(nil)
      else
        let existing = Pg.query_values(conn,
          "SELECT witness_id FROM witness_signatures WHERE checkpoint_sequence = $1::bigint AND witness_id = $2 AND witness_public_key = $3 AND checkpoint_hash = $4 AND signature = $5",
          [
            Text(U64.to_string(checkpoint.sequence)),
            Text(attestation.witness_id),
            Binary(trusted.public_key),
            Binary(attestation.checkpoint_hash),
            Binary(attestation.signature)
          ])?
        if List.length(existing) == 1 do
          Ok(nil)
        else
          Err("witness conflict")
        end
      end
    end
  end
end

pub fn store_witness(pool :: PoolHandle, attestation :: WitnessAttestation, trusted :: WitnessKey) -> Result<(), String> do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> store_witness_on_connection(conn, attestation, trusted) end)
end

pub fn transparency_username(pool :: PoolHandle, reference :: String) -> Option<String>!String do
  let account_id = account_lookup_id(reference)?
  if Bytes.length(account_id) == 0 do
    Ok(Some(reference))
  else
    let rows = Pool.query_values(pool,
      "SELECT username FROM messenger_accounts WHERE account_id = $1",
      [Binary(account_id)])?
    if List.length(rows) == 0 do
      Ok(None)
    else
      Ok(Some(text(Map.get(List.head(rows), "username"))?))
    end
  end
end
