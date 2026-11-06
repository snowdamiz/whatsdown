from Transparency.C2sp import (
  sign_checkpoint_note,
  SignedCheckpointNote,
  decode_signature_lines,
  note_key_id,
  verified_cosignature
)
from Transparency.Client import checkpoint_fresh_at
from Storage.TransparencyLog import (
  writable_log_version,
  legacy_seal,
  checkpoint_table,
  witness_table,
  cutover_phase
)
from Storage.WitnessRegistry import RegisteredWitness, registered_profile, signature_policy_sql
import RuntimeJobs
from Storage.TransparencyRecords import (
  entry_bytes_on_connection,
  store_entry_records,
  forget_records_on_connection
)
from Storage.TransparencyTree import (
  append_tree_leaf_for,
  tree_root_for,
  tree_size_for,
  tree_consistency_for,
  tree_inclusion_for,
  tree_consistency,
  tree_inclusion,
  tree_size
)
from Transparency.Merkle import (
  ConsistencyProof,
  InclusionProof,
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  checkpoint_hash,
  consistency_proof,
  inclusion_proof,
  leaf_hash_for,
  sign_tree_checkpoint_for,
  verify_witnesses,
  verify_witnesses_at
)
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

# Keep legacy output until the compact-capable native clients have shipped.
# Every append maintains the incremental tree, regardless of output mode.
pub fn compact_proofs_enabled() -> Bool do
  Env.get("MORSE_COMPACT_PROOFS", "off") == "on"
end

fn use_compact(tree_size :: Int) -> Bool do
  # Crossing the legacy wire bound makes compact proofs mandatory. Rolling
  # back a flag must never make a committed tree unreadable or unappendable.
  compact_proofs_enabled() || tree_size > 4096
end

pub fn transparency_proof_ceiling() -> Int do
  if compact_proofs_enabled() do
    4294967295
  else
    4096
  end
end

pub fn transparency_new_account_ceiling() -> Int do
  if compact_proofs_enabled() do
    4294966783
  else
    3584
  end
end

pub fn append_entry_on_connection(conn :: borrow PgConn,
  account_id :: Bytes,
  entry_bytes :: Bytes,
  new_account :: Bool) -> Int!String do
  let commitment = account_commitment(account_id)?
  Pg.query_values(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  let version = writable_log_version(conn)?
  let hash = leaf_hash_for(version, entry_bytes)?
  let index = tree_size_for(conn, version)?
  let maximum = if version == 2 || use_compact(index) do
    4294967295
  else
    4096
  end
  let ceiling = if new_account do
    maximum - 512
  else
    maximum
  end
  if index >= ceiling do
    return Err("transparency_log_full")
  end
  let rows = Pg.query_values(conn,
    "INSERT INTO transparency_entries (account_commitment, entry_bytes, leaf_hash, leaf_index, log_version) VALUES ($1, $2, $3, $4::bigint, $5::smallint) RETURNING sequence::text",
    [
      Binary(commitment),
      Binary(entry_bytes),
      Binary(hash),
      Text(Int.to_string(index)),
      Text(Int.to_string(version))
    ])?
  if List.length(rows) != 1 do
    Err("transparency append failed")
  else
    let sequence = integer(Map.get(List.head(rows), "sequence"))?
    store_entry_records(conn, sequence, entry_bytes, hash)?
    append_tree_leaf_for(conn, version, index, hash)?
    Ok(sequence)
  end
end

## A deleted account's leaves stay, since every proof covers the whole tree.
## The entries behind them name the account and its devices, and go with it.

pub fn forget_account_entries_on_connection(conn :: borrow PgConn,
  account_id :: Bytes) -> Result<(), String> do
  forget_records_on_connection(conn, account_commitment(account_id)?)
end

fn hashes(rows :: List<Map<String, DbValue>>,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
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
    "SELECT leaf_hash FROM transparency_entries WHERE log_version = 1 ORDER BY sequence LIMIT 4097",
    [])?
  if List.length(rows) > 4096 do
    Err("transparency log exceeds proof ceiling")
  else
    hashes(rows, 0, List.new())
  end
end

fn checkpoint_from_row(version :: Int,
  row :: Map<String, DbValue>) -> TransparencyCheckpoint!String do
  Ok(TransparencyCheckpoint {
    version: version,
    sequence: wide(Map.get(row, "sequence"))?,
    tree_size: wide(Map.get(row, "tree_size"))?,
    tree_root: binary(Map.get(row, "tree_root"))?,
    previous_checkpoint_hash: binary(Map.get(row, "previous_checkpoint_hash"))?,
    timestamp: wide(Map.get(row, "timestamp_ms"))?,
    service_public_key: binary(Map.get(row, "service_public_key"))?,
    signature: binary(Map.get(row, "service_signature"))?
  })
end

fn checkpoint_rows(conn :: borrow PgConn, version :: Int) -> List<Map<String, DbValue>>!String do
  Pg.query_values(conn,
    "SELECT sequence::text, tree_size::text, tree_root, previous_checkpoint_hash, timestamp_ms::text, service_public_key, service_signature FROM "
      <> checkpoint_table(version)?
      <> " ORDER BY "
      <> checkpoint_table(version)?
      <> ".sequence DESC LIMIT 1 FOR UPDATE",
    [])
end

fn prefix(values :: List<Bytes>,
  count :: Int,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes> do
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

fn witnesses_on_connection(conn :: borrow PgConn,
  version :: Int,
  checkpoint_sequence :: U64) -> List<WitnessAttestation>!String do
  let rows = Pg.query_values(conn,
    "SELECT s.witness_id, s.checkpoint_hash, s.signature FROM "
      <> witness_table(version)?
      <> " s JOIN transparency_witness_registry r ON r.witness_id = s.witness_id AND r.public_key = s.witness_public_key WHERE s.checkpoint_sequence = $1::bigint AND r.status <> 'retired' AND "
      <> signature_policy_sql(version)?
      <> " ORDER BY CASE r.status WHEN 'pinned' THEN 0 ELSE 1 END, r.added_at DESC, r.witness_id LIMIT 16",
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

pub fn create_checkpoint_for_on_connection(conn :: borrow PgConn,
  version :: Int,
  signing_key :: borrow SigningPrivateKey,
  signing_public_key :: Bytes) -> TransparencyCheckpoint!String do
  Pg.query_values(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  checkpoint_table(version)?
  if version == 1 do
    case legacy_seal(conn)? do
      Some(value) -> return Ok(value)
      None -> nil
    end
  else if cutover_phase(conn)? != "active" do
    return Err("transparency_v2_not_active")
  end
  let count = tree_size_for(conn, version)?
  if count == 0 do
    Err("transparency log is empty")
  else
    let previous_rows = checkpoint_rows(conn, version)?
    if List.length(previous_rows) > 0
      && U64.to_int(wide(Map.get(List.head(previous_rows), "tree_size"))?)? == count
      && checkpoint_recent(checkpoint_from_row(version, List.head(previous_rows))?,
        current_time()?) do
      checkpoint_from_row(version, List.head(previous_rows))
    else
      let previous = if List.length(previous_rows) == 0 do
        None
      else
        Some(checkpoint_from_row(version, List.head(previous_rows))?)
      end
      case previous do
        Some(value) -> if !Bytes.secure_equals(value.service_public_key, signing_public_key)
          || U64.compare(current_time()?, value.timestamp) < 0 do
          return Err("transparency checkpoint continuity failed")
        end
        None -> nil
      end
      let sequence = case previous do
        None -> int_wide(1)
        Some(value) -> U64.add(value.sequence, int_wide(1)?)
      end?
      let previous_hash = case previous do
        None -> zero_hash()
        Some(value) -> checkpoint_hash(value)
      end?
      let checkpoint = sign_tree_checkpoint_for(version,
        signing_key,
        signing_public_key,
        sequence,
        int_wide(count)?,
        tree_root_for(conn, version, count)?,
        previous_hash,
        current_time()?)?
      let changed = Pg.execute_values(conn,
        "INSERT INTO "
          <> checkpoint_table(version)?
          <> " (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature) VALUES ($1::bigint, $2::bigint, $3, $4, $5::bigint, $6, $7)",
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

fn create_checkpoint_on_connection(conn :: borrow PgConn,
  signing_key :: borrow SigningPrivateKey,
  signing_public_key :: Bytes) -> TransparencyCheckpoint!String do
  Pg.query_values(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  create_checkpoint_for_on_connection(conn,
    writable_log_version(conn)?,
    signing_key,
    signing_public_key)
end

fn create_checkpoint_from_seed_on_connection(conn :: borrow PgConn,
  signing_seed :: Bytes) -> TransparencyCheckpoint!String do
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

pub fn create_checkpoint(pool :: PoolHandle,
  signing_seed :: Bytes) -> TransparencyCheckpoint!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> create_checkpoint_from_seed_on_connection(conn, signing_seed) end)
end

pub fn create_configured_checkpoint(pool :: PoolHandle) -> TransparencyCheckpoint!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> create_configured_checkpoint_on_connection(conn) end)
end

pub fn entry_count(pool :: PoolHandle) -> Int!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> tree_size(conn) end)
end

pub fn inclusion_for_account(pool :: PoolHandle, account_id :: Bytes) -> InclusionProof!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> inclusion_on_connection(conn, account_id) end)
end

fn inclusion_on_connection(conn :: borrow PgConn, account_id :: Bytes) -> InclusionProof!String do
  let commitment = account_commitment(account_id)?
  let positions = Pg.query_values(conn,
    "SELECT leaf_index::text FROM transparency_entries WHERE account_commitment = $1 AND log_version = 1 ORDER BY sequence DESC LIMIT 1",
    [Binary(commitment)])?
  if List.length(positions) != 1 do
    Err("transparency entry not found")
  else
    let index = integer(Map.get(List.head(positions), "leaf_index"))?
    let count = tree_size(conn)?
    if use_compact(count) do
      tree_inclusion(conn, index, count)
    else
      inclusion_proof(all_hashes_on_connection(conn)?, index)
    end
  end
end

pub fn consistency_from(pool :: PoolHandle, old_tree_size :: Int) -> ConsistencyProof!String do
  if use_compact(entry_count(pool)?) do
    return Repo.transaction(pool,
      fn(conn :: borrow PgConn) -> tree_consistency(conn, old_tree_size, tree_size(conn)?) end)
  end
  if old_tree_size < 0 || old_tree_size > 4096 do
    Err("invalid consistency size")
  else
    let old_rows = Pool.query_values(pool,
      "SELECT leaf_hash FROM transparency_entries WHERE log_version = 1 ORDER BY sequence LIMIT $1::bigint",
      [Text(Int.to_string(old_tree_size))])?
    let new_rows = Pool.query_values(pool,
      "SELECT leaf_hash FROM transparency_entries WHERE log_version = 1 ORDER BY sequence LIMIT 4097",
      [])?
    if List.length(new_rows) > 4096 || List.length(old_rows) != old_tree_size do
      Err("invalid consistency size")
    else
      consistency_proof(hashes(old_rows, 0, List.new())?, hashes(new_rows, 0, List.new())?)
    end
  end
end

pub fn consistency_between(pool :: PoolHandle,
  old_tree_size :: Int,
  new_tree_size :: Int) -> ConsistencyProof!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> tree_consistency(conn, old_tree_size, new_tree_size) end)
end

fn latest_on_connection(conn :: borrow PgConn,
  version :: Int) -> Option<TransparencyCheckpoint>!String do
  checkpoint_table(version)?
  if version == 1 do
    case legacy_seal(conn)? do
      Some(value) -> return Ok(Some(value))
      None -> nil
    end
  else if cutover_phase(conn)? != "active" do
    return Ok(None)
  end
  let rows = checkpoint_rows(conn, version)?
  if List.length(rows) == 0 do
    Ok(None)
  else
    Ok(Some(checkpoint_from_row(version, List.head(rows))?))
  end
end

pub fn latest_checkpoint_for(pool :: PoolHandle,
  version :: Int) -> Option<TransparencyCheckpoint>!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> latest_on_connection(conn, version) end)
end

pub fn latest_checkpoint(pool :: PoolHandle) -> Option<TransparencyCheckpoint>!String do
  latest_checkpoint_for(pool, 1)
end

# Exact retained history is public even after a log is sealed. Never poll or
# mint a checkpoint here: the caller is verifying a specific anchor commitment.
pub fn historical_checkpoint_for(pool :: PoolHandle,
  version :: Int,
  sequence :: U64) -> Option<TransparencyCheckpoint>!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do historical_checkpoint_on_connection(conn, version, sequence) end)
end

pub fn historical_checkpoint_on_connection(conn :: borrow PgConn,
  version :: Int,
  sequence :: U64) -> Option<TransparencyCheckpoint>!String do
  let table = checkpoint_table(version)?
  if U64.compare(sequence, U64.parse("9223372036854775807")?) > 0 do
    return Ok(None)
  end
  let rows = Pg.query_values(conn,
    "SELECT sequence::text, tree_size::text, tree_root, previous_checkpoint_hash, timestamp_ms::text, service_public_key, service_signature FROM "
      <> table
      <> " WHERE sequence = $1::bigint",
    [Text(U64.to_string(sequence))])?
  if List.length(rows) == 0 do
    Ok(None)
  else
    Ok(Some(checkpoint_from_row(version, List.head(rows))?))
  end
end

pub fn witnesses_for_checkpoint_for(pool :: PoolHandle,
  version :: Int,
  checkpoint_sequence :: U64) -> List<WitnessAttestation>!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> witnesses_on_connection(conn, version, checkpoint_sequence) end)
end

pub fn witnesses_for_checkpoint(pool :: PoolHandle,
  checkpoint_sequence :: U64) -> List<WitnessAttestation>!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> witnesses_on_connection(conn, 1, checkpoint_sequence) end)
end

fn evidence_on_connection(conn :: borrow PgConn,
  version :: Int,
  username :: String,
  old_tree_size :: Int,
  signing_key :: borrow SigningPrivateKey,
  signing_public_key :: Bytes) -> TransparencyEvidence!String do
  let checkpoint = create_checkpoint_for_on_connection(conn,
    version,
    signing_key,
    signing_public_key)?
  let count = U64.to_int(checkpoint.tree_size)?
  if old_tree_size < 0 || old_tree_size > count do
    Err("invalid consistency size")
  else
    let accounts = Pg.query_values(conn,
      "SELECT account_id FROM messenger_accounts WHERE username = $1",
      [Text(username)])?
    if List.length(accounts) != 1 do
      Err("transparency entry not found")
    else
      let positions = Pg.query_values(conn,
        "SELECT sequence::text, leaf_index::text FROM transparency_entries WHERE account_commitment = $1 AND log_version = $2::smallint ORDER BY sequence DESC LIMIT 1",
        [
          Binary(account_commitment(binary(Map.get(List.head(accounts), "account_id"))?)?),
          Text(Int.to_string(version))
        ])?
      if List.length(positions) != 1 do
        Err("transparency entry not found")
      else
        let position = List.head(positions)
        let index = integer(Map.get(position, "leaf_index"))?
        let (inclusion, consistency) = if version == 2 || use_compact(count) do
          (tree_inclusion_for(conn, version, index, count)?,
            tree_consistency_for(conn, version, old_tree_size, count)?)
        else
          let all = all_hashes_on_connection(conn)?
          (inclusion_proof(all, index)?,
            consistency_proof(prefix(all, old_tree_size, 0, List.new()), all)?)
        end
        Ok(TransparencyEvidence {
          entry_bytes: entry_bytes_on_connection(conn, integer(Map.get(position, "sequence"))?)?,
          inclusion: inclusion,
          consistency: consistency,
          checkpoint: checkpoint,
          witnesses: witnesses_on_connection(conn, version, checkpoint.sequence)?
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
  evidence_on_connection(conn,
    1,
    username,
    old_tree_size,
    signer.private_key,
    signer.public_key.bytes)
end

fn configured_evidence_on_connection(conn :: borrow PgConn,
  version :: Int,
  username :: String,
  old_tree_size :: Int) -> TransparencyEvidence!String do
  let signer = configured_signer()?
  evidence_on_connection(conn,
    version,
    username,
    old_tree_size,
    signer.private_key,
    signer.public_key.bytes)
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
    fn(conn :: borrow PgConn) -> configured_evidence_on_connection(conn,
      1,
      username,
      old_tree_size) end)
end

pub fn configured_evidence_for_username_for(pool :: PoolHandle,
  version :: Int,
  username :: String,
  old_tree_size :: Int) -> TransparencyEvidence!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> configured_evidence_on_connection(conn,
      version,
      username,
      old_tree_size) end)
end

pub fn consistency_between_for(pool :: PoolHandle,
  version :: Int,
  old_tree_size :: Int,
  new_tree_size :: Int) -> ConsistencyProof!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      if version == 2 && cutover_phase(conn)? != "active" do
        return Err("transparency_v2_not_active")
      end
      tree_consistency_for(conn, version, old_tree_size, new_tree_size)
    end)
end

fn store_witness_on_connection(conn :: borrow PgConn,
  version :: Int,
  attestation :: WitnessAttestation,
  trusted :: WitnessKey) -> Result<(), String> do
  let rows = checkpoint_rows(conn, version)?
  if List.length(rows) != 1 do
    Err("transparency checkpoint not found")
  else
    let checkpoint = checkpoint_from_row(version, List.head(rows))?
    let now = current_time()?
    if attestation.witness_id != trusted.witness_id
      || !verify_witnesses(checkpoint, [attestation], [trusted], 1)?
      || (version == 2
        && (!checkpoint_fresh_at(checkpoint.timestamp, now)
          || !verify_witnesses_at(checkpoint, [attestation], [trusted], 1, now)?)) do
      Err("invalid witness attestation")
    else
      let changed = if version == 2 do
        store_rfc_signature(conn, checkpoint.sequence, attestation, trusted)?
      else
        Pg.execute_values(conn,
          "INSERT INTO "
            <> witness_table(version)?
            <> " (checkpoint_sequence, witness_id, witness_public_key, checkpoint_hash, signature) VALUES ($1::bigint, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
          [
            Text(U64.to_string(checkpoint.sequence)),
            Text(attestation.witness_id),
            Binary(trusted.public_key),
            Binary(attestation.checkpoint_hash),
            Binary(attestation.signature)
          ])?
      end
      if changed == 1 do
        Ok(nil)
      else
        let existing = Pg.query_values(conn,
          "SELECT witness_id FROM "
            <> witness_table(version)?
            <> " WHERE checkpoint_sequence = $1::bigint AND witness_id = $2 AND witness_public_key = $3 AND checkpoint_hash = $4 AND signature = $5",
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

fn store_rfc_signature(conn :: borrow PgConn,
  sequence :: U64,
  attestation :: WitnessAttestation,
  trusted :: WitnessKey) -> Int!String do
  let stamp = if Bytes.length(attestation.signature) == 72 do
    let seconds = case Bytes.read_u64_be(attestation.signature, 0) do
      Err(_) -> return Err("invalid witness timestamp")
      Ok(value) -> U64.to_int(value)?
    end
    Text(Int.to_string(seconds * 1000))
  else
    Null
  end
  Pg.execute_values(conn,
    "INSERT INTO witness_v2_signatures (checkpoint_sequence, witness_id, witness_public_key, checkpoint_hash, signature, cosigned_at_ms) VALUES ($1::bigint, $2, $3, $4, $5, $6::bigint) ON CONFLICT (checkpoint_sequence, witness_id) DO UPDATE SET signature = EXCLUDED.signature, cosigned_at_ms = EXCLUDED.cosigned_at_ms, observed_at = now() WHERE witness_v2_signatures.witness_public_key = EXCLUDED.witness_public_key AND witness_v2_signatures.checkpoint_hash = EXCLUDED.checkpoint_hash AND octet_length(witness_v2_signatures.signature) = 72 AND octet_length(EXCLUDED.signature) = 72 AND EXCLUDED.cosigned_at_ms >= COALESCE(witness_v2_signatures.cosigned_at_ms, 0)",
    [
      Text(U64.to_string(sequence)),
      Text(attestation.witness_id),
      Binary(trusted.public_key),
      Binary(attestation.checkpoint_hash),
      Binary(attestation.signature),
      stamp
    ])
end

pub fn store_witness(pool :: PoolHandle,
  attestation :: WitnessAttestation,
  trusted :: WitnessKey) -> Result<(), String> do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> store_witness_on_connection(conn, 1, attestation, trusted) end)
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

pub fn store_registered_witness(pool :: PoolHandle,
  attestation :: WitnessAttestation) -> Result<(), String> do
  store_registered_witness_for(pool, 1, attestation)
end

pub fn store_registered_witness_for(pool :: PoolHandle,
  version :: Int,
  attestation :: WitnessAttestation) -> Result<(), String> do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      if version == 2 && cutover_phase(conn)? != "active" do
        return Err("transparency_v2_not_active")
      end
      case registered_profile(conn, attestation.witness_id)? do
        None -> Err("untrusted witness")
        Some(trusted) -> if trusted.software != "mesh"
          || Bytes.length(attestation.signature) != 64 do
          Err("witness signature algorithm mismatch")
        else
          store_witness_on_connection(conn, version, attestation, trusted.key)
        end
      end
    end)
end

# Called after a standard add-checkpoint response. Re-read and lock the active
# registry row here: retirement or key/name replacement during HTTP must win.
pub fn store_c2sp_response(pool :: PoolHandle,
  id :: String,
  checkpoint :: TransparencyCheckpoint,
  response :: Bytes) -> Result<(), String> do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      if checkpoint.version != 2 || cutover_phase(conn)? != "active" do
        return Err("transparency_v2_not_active")
      end
      let trusted = case registered_profile(conn, id)? do
        None -> return Err("untrusted witness")
        Some(value) -> value
      end
      if trusted.software != "c2sp" do
        return Err("witness signature algorithm mismatch")
      end
      let signature = verified_cosignature(SignedCheckpointNote {
          checkpoint: checkpoint,
          signatures: decode_signature_lines(response)?
        },
        trusted.note_name,
        SigningPublicKey { bytes: trusted.key.public_key })?
      store_witness_on_connection(conn,
        2,
        WitnessAttestation {
          witness_id: id,
          checkpoint_hash: checkpoint_hash(checkpoint)?,
          signature: signature
        },
        trusted.key)
    end)
end

# Public signature-only submissions identify a registered key by its exact
# note name and algorithm-specific key ID. The current checkpoint is local;
# neither a caller-provided checkpoint nor a supplied trust key is accepted.
pub fn store_current_c2sp_response(pool :: PoolHandle, response :: Bytes) -> Result<(), String> do
  if Bytes.length(response) > 365 do
    return Err("invalid C2SP submission")
  end
  let signatures = decode_signature_lines(response)?
  if List.length(signatures) != 1 || Bytes.length(List.head(signatures).signature) != 72 do
    return Err("invalid C2SP submission")
  end
  let signature = List.head(signatures)
  let checkpoint = case latest_checkpoint_for(pool, 2)? do
    None -> return Err("transparency checkpoint not found")
    Some(value) -> value
  end
  let rows = Pool.query_values(pool,
    "SELECT witness_id, public_key FROM transparency_witness_registry WHERE note_name = $1 AND software = 'c2sp' AND status <> 'retired' ORDER BY witness_id LIMIT 17",
    [Text(signature.name)])?
  if List.length(rows) > 16 do
    return Err("ambiguous C2SP name")
  end
  for row in rows do
    let key = binary(Map.get(row, "public_key"))?
    if Bytes.secure_equals(note_key_id(signature.name, 4, key)?, signature.key_id) do
      # A four-byte ID is a selector, not proof of key equality. A collision
      # cannot let one registered key hide another key's valid signature.
      case store_c2sp_response(pool, text(Map.get(row, "witness_id"))?, checkpoint, response) do
        Ok(_) -> return Ok(nil)
        Err(_) -> nil
      end
    end
  end
  Err("invalid C2SP submission")
end

fn polled_on_connection(conn :: borrow PgConn,
  version :: Int) -> Option<TransparencyCheckpoint>!String do
  Pg.query_values(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  checkpoint_table(version)?
  if version == 1 do
    case legacy_seal(conn)? do
      Some(value) -> return Ok(Some(value))
      None -> nil
    end
  else if cutover_phase(conn)? != "active" do
    return Ok(None)
  end
  case latest_on_connection(conn, version)? do
    Some(checkpoint) -> if checkpoint_recent(checkpoint, current_time()?) do
      return Ok(Some(checkpoint))
    end
    None -> nil
  end
  if tree_size_for(conn, version)? == 0 do
    Ok(None)
  else
    let signer = configured_signer()?
    Ok(Some(create_checkpoint_for_on_connection(conn,
      version,
      signer.private_key,
      signer.public_key.bytes)?))
  end
end

# Polling keeps an idle writable log fresh. A sealed legacy log always returns
# its exact seal, including after expiry; a v1 URL can never return a v2 log.
pub fn polled_checkpoint_for(pool :: PoolHandle,
  version :: Int) -> Option<TransparencyCheckpoint>!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> polled_on_connection(conn, version) end)
end

pub fn polled_checkpoint(pool :: PoolHandle) -> Option<TransparencyCheckpoint>!String do
  polled_checkpoint_for(pool, 1)
end

pub fn configured_checkpoint_note(pool :: PoolHandle) -> Bytes!String do
  let checkpoint = case polled_checkpoint_for(pool, 2)? do
    None -> return Err("transparency_v2_not_active")
    Some(value) -> value
  end
  configured_note_for(checkpoint)
end

pub fn configured_note_for(checkpoint :: TransparencyCheckpoint) -> Bytes!String do
  let signer = configured_signer()?
  sign_checkpoint_note(checkpoint, signer.private_key)
end
