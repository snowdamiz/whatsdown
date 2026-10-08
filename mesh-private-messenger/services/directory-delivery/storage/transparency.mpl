import RuntimeJobs
from Storage.TransparencyTree import (
  dtree_append_on_connection,
  dtree_consistency_on_connection,
  dtree_inclusion_on_connection,
  dtree_root_on_connection,
  dtree_size_on_connection,
  dtree_view_on_connection
)
from Storage.TransparencyWitnesses import (
  AttestationWrite,
  RegistryWitness,
  transparency_attestations_on_connection,
  transparency_c2sp_witnesses_on_connection,
  transparency_registry_witness_on_connection,
  transparency_statements_on_connection,
  transparency_store_attestation_on_connection
)
from Transparency.Codec import tcodec_join
from Transparency.CompactWire import (
  CompactConsistency,
  CompactInclusion,
  TransparencyEvidenceV2,
  TransparencyLeafProof,
  WitnessCosignature
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
  leaf_hash,
  transparency_sign_checkpoint_root,
  verify_witnesses
)
from Transparency.Note import (
  NoteCosignature,
  note_checkpoint_body,
  note_read_cosignatures,
  note_sign
)
from Transparency.Wire import account_lookup_id, encode_checkpoint, TransparencyEvidence

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

# The log has no ceiling: proofs are compact RFC 9162 paths built from stored
# nodes, so appends and proofs cost O(log n). Registration is still limited by
# proof of work.
#
# Version 1 clients still get full-list proofs, which only fit while the log
# holds at most this many leaves; above it their lookups fail closed.

fn v1_ceiling() -> Int do
  4096
end

## Appends one entry (a device set) at the next leaf index, stores its device
## records once each, and completes the tree nodes it closes, all in the
## caller's transaction. Returns the entry's sequence.

pub fn append_entry_on_connection(conn :: borrow PgConn,
  account_id :: Bytes,
  entry_bytes :: Bytes) -> Int!String do
  let commitment = account_commitment(account_id)?
  let hash = leaf_hash(entry_bytes)?
  Pg.query_values(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  let index = dtree_size_on_connection(conn)?
  # The parts must reassemble to the exact entry, or nothing is stored.
  let rows = Pg.query_values(conn,
    "WITH parts AS (SELECT header, records, trailer FROM transparency_entry_parts($2) WHERE header || COALESCE((SELECT string_agg(int4send(octet_length(record)) || record, ''::bytea ORDER BY ordinal) FROM unnest(records) WITH ORDINALITY AS listed (record, ordinal)), ''::bytea) || trailer = $2), stored AS (INSERT INTO transparency_device_records (record_hash, record_bytes) SELECT sha256(listed.record), listed.record FROM parts, unnest(parts.records) AS listed (record) ON CONFLICT DO NOTHING) INSERT INTO transparency_entries (account_commitment, leaf_hash, leaf_index, entry_header, record_hashes, entry_trailer) SELECT $1, $3, $4::bigint, parts.header, ARRAY(SELECT sha256(listed.record) FROM unnest(parts.records) WITH ORDINALITY AS listed (record, ordinal) ORDER BY listed.ordinal), parts.trailer FROM parts RETURNING sequence::text",
    [Binary(commitment), Binary(entry_bytes), Binary(hash), Text(Int.to_string(index))])?
  if List.length(rows) != 1 do
    Err("transparency append failed")
  else
    dtree_append_on_connection(conn, index, hash)?
    integer(Map.get(List.head(rows), "sequence"))
  end
end

## A deleted account's leaves stay, since every proof covers the whole tree.
## The entries behind them name the account and its devices, and go with it,
## as do its device records.

pub fn forget_account_entries_on_connection(conn :: borrow PgConn,
  account_id :: Bytes) -> Result<(), String> do
  let commitment = account_commitment(account_id)?
  Pg.execute_values(conn,
    "DELETE FROM transparency_device_records AS record USING (SELECT DISTINCT unnest(record_hashes) AS record_hash FROM transparency_entries WHERE account_commitment = $1) AS forgotten WHERE record.record_hash = forgotten.record_hash AND NOT EXISTS (SELECT 1 FROM transparency_entries AS other WHERE other.account_commitment <> $1 AND other.record_hashes @> ARRAY[record.record_hash])",
    [Binary(commitment)])?
  Pg.execute_values(conn,
    "UPDATE transparency_entries SET entry_bytes = NULL, entry_header = NULL, record_hashes = NULL, entry_trailer = NULL, pruned_at = COALESCE(pruned_at, now()) WHERE account_commitment = $1",
    [Binary(commitment)])?
  Ok(nil)
end

# The canonical bytes of a stored entry, checked against its leaf hash.

fn stored_entry_bytes(row :: Map<String, DbValue>) -> Bytes!String do
  let bytes = case Map.get(row, "entry_bytes") do
    Binary(value) -> Ok(value)
    _ -> Err("transparency entry pruned")
  end?
  if !Bytes.secure_equals(leaf_hash(bytes)?, binary(Map.get(row, "leaf_hash"))?) do
    Err("transparency entry does not match its leaf")
  else
    Ok(bytes)
  end
end

fn entry_columns() -> String do
  "SELECT COALESCE(entry_bytes, transparency_entry_rebuild(entry_header, record_hashes, entry_trailer)) AS entry_bytes, leaf_hash, leaf_index::text AS leaf_index FROM transparency_entries"
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

# Every leaf hash, for version 1 full-list proofs only.

fn all_hashes_on_connection(conn :: borrow PgConn) -> List<Bytes>!String do
  let rows = Pg.query_values(conn,
    "SELECT leaf_hash FROM transparency_entries ORDER BY leaf_index LIMIT 4097",
    [])?
  if List.length(rows) > v1_ceiling() do
    Err("transparency_v1_ceiling")
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

## The latest checkpoint, locked against a concurrent refresh.

pub fn transparency_current_checkpoint_on_connection(conn :: borrow PgConn) -> Option<TransparencyCheckpoint>!String do
  case checkpoint_rows(conn)? do
    [row] -> Ok(Some(checkpoint_from_row(row)?))
    _ -> Ok(None)
  end
end

pub fn transparency_checkpoint_at_on_connection(conn :: borrow PgConn,
  sequence :: Int) -> Option<TransparencyCheckpoint>!String do
  let rows = Pg.query_values(conn,
    "SELECT sequence::text, tree_size::text, tree_root, previous_checkpoint_hash, timestamp_ms::text, service_public_key, service_signature FROM transparency_checkpoints WHERE sequence = $1::bigint",
    [Text(Int.to_string(sequence))])?
  case rows do
    [row] -> Ok(Some(checkpoint_from_row(row)?))
    _ -> Ok(None)
  end
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
  let size = dtree_size_on_connection(conn)?
  if size == 0 do
    Err("transparency log is empty")
  else
    let previous_rows = checkpoint_rows(conn)?
    if List.length(previous_rows) > 0
      && U64.to_int(wide(Map.get(List.head(previous_rows), "tree_size"))?)? == size
      && checkpoint_recent(checkpoint_from_row(List.head(previous_rows))?, current_time()?) do
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
      # The root comes from the stored right-edge nodes, never from the leaves.
      let checkpoint = transparency_sign_checkpoint_root(signing_key,
        signing_public_key,
        sequence,
        int_wide(size)?,
        dtree_root_on_connection(conn, 1, size)?,
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

## Leaves in the log.

pub fn entry_count(pool :: PoolHandle) -> Int!String do
  let rows = Pool.query_values(pool,
    "SELECT COALESCE(max(leaf_index) + 1, 0)::text AS count FROM transparency_entries",
    [])?
  case rows do
    [row] -> integer(Map.get(row, "count"))
    _ -> Err("transparency count failed")
  end
end

fn latest_entry_on_connection(conn :: borrow PgConn,
  commitment :: Bytes) -> Map<String, DbValue>!String do
  let rows = Pg.query_values(conn,
    entry_columns() <> " WHERE account_commitment = $1 ORDER BY sequence DESC LIMIT 1",
    [Binary(commitment)])?
  case rows do
    [row] -> Ok(row)
    _ -> Err("transparency entry not found")
  end
end

fn account_entry_on_connection(conn :: borrow PgConn,
  username :: String) -> Map<String, DbValue>!String do
  let accounts = Pg.query_values(conn,
    "SELECT account_id FROM messenger_accounts WHERE username = $1",
    [Text(username)])?
  case accounts do
    [account] -> latest_entry_on_connection(conn,
      account_commitment(binary(Map.get(account, "account_id"))?)?)
    _ -> Err("transparency entry not found")
  end
end

fn v1_inclusion_on_connection(conn :: borrow PgConn,
  account_id :: Bytes) -> InclusionProof!String do
  let row = latest_entry_on_connection(conn, account_commitment(account_id)?)?
  inclusion_proof(all_hashes_on_connection(conn)?, integer(Map.get(row, "leaf_index"))?)
end

## A version 1 (full-list) inclusion proof; only while the log fits one.

pub fn inclusion_for_account(pool :: PoolHandle, account_id :: Bytes) -> InclusionProof!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> v1_inclusion_on_connection(conn, account_id) end)
end

fn v1_consistency_on_connection(conn :: borrow PgConn,
  old_tree_size :: Int) -> ConsistencyProof!String do
  let all = all_hashes_on_connection(conn)?
  if old_tree_size < 0 || old_tree_size > List.length(all) do
    Err("invalid consistency size")
  else
    consistency_proof(prefix(all, old_tree_size, 0, List.new()), all)
  end
end

## A version 1 (full-list) consistency proof to the whole log; only while the
## log fits one.

pub fn consistency_from(pool :: PoolHandle, old_tree_size :: Int) -> ConsistencyProof!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> v1_consistency_on_connection(conn, old_tree_size) end)
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

## Morse statements for a checkpoint, as KTW v1 carries them.

pub fn witnesses_for_checkpoint(pool :: PoolHandle,
  checkpoint_sequence :: U64) -> List<WitnessAttestation>!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> transparency_statements_on_connection(conn,
      checkpoint_sequence) end)
end

## Attestations of both kinds for a checkpoint, as KTW v2 carries them.

pub fn attestations_for_checkpoint(pool :: PoolHandle,
  checkpoint_sequence :: U64) -> List<WitnessCosignature>!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> transparency_attestations_on_connection(conn,
      checkpoint_sequence) end)
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
    let row = account_entry_on_connection(conn, username)?
    Ok(TransparencyEvidence {
      entry_bytes: stored_entry_bytes(row)?,
      inclusion: inclusion_proof(all, integer(Map.get(row, "leaf_index"))?)?,
      consistency: consistency_proof(prefix(all, old_tree_size, 0, List.new()), all)?,
      checkpoint: checkpoint,
      witnesses: transparency_statements_on_connection(conn, checkpoint.sequence)?
    })
  end
end

fn c2sp_view_on_connection(conn :: borrow PgConn,
  witnesses :: List<WitnessCosignature>,
  index :: Int,
  size :: Int) -> (Bytes, List<Bytes>)!String do
  if List.any(witnesses, fn value -> value.kind == 2 end) do
    dtree_view_on_connection(conn, 2, index, size)
  else
    Ok((Bytes.empty(), List.new()))
  end
end

fn evidence_v2_on_connection(conn :: borrow PgConn,
  username :: String,
  old_tree_size :: Int,
  signing_key :: borrow SigningPrivateKey,
  signing_public_key :: Bytes) -> TransparencyEvidenceV2!String do
  let checkpoint = create_checkpoint_on_connection(conn, signing_key, signing_public_key)?
  let size = U64.to_int(checkpoint.tree_size)?
  if old_tree_size < 0 || old_tree_size > size do
    Err("invalid consistency size")
  else
    let row = account_entry_on_connection(conn, username)?
    let index = integer(Map.get(row, "leaf_index"))?
    let witnesses = transparency_attestations_on_connection(conn, checkpoint.sequence)?
    let (c2sp_root, c2sp_path) = c2sp_view_on_connection(conn, witnesses, index, size)?
    Ok(TransparencyEvidenceV2 {
      entry_bytes: stored_entry_bytes(row)?,
      inclusion: CompactInclusion {
        leaf_index: index,
        tree_size: size,
        path: dtree_inclusion_on_connection(conn, 1, index, size)?
      },
      consistency: CompactConsistency {
        old_size: old_tree_size,
        new_size: size,
        path: dtree_consistency_on_connection(conn, 1, old_tree_size, size)?
      },
      checkpoint: checkpoint,
      witnesses: witnesses,
      c2sp_root: c2sp_root,
      c2sp_path: c2sp_path
    })
  end
end

fn seeded_signer(signing_seed :: Bytes) -> SigningKeyPair!String do
  case Crypto.signing_from_seed(signing_seed) do
    Err(_) -> Err("invalid transparency signing seed")
    Ok(value)
  end
end

fn evidence_from_seed_on_connection(conn :: borrow PgConn,
  username :: String,
  old_tree_size :: Int,
  signing_seed :: Bytes) -> TransparencyEvidence!String do
  let signer = seeded_signer(signing_seed)?
  evidence_on_connection(conn, username, old_tree_size, signer.private_key, signer.public_key.bytes)
end

fn configured_evidence_on_connection(conn :: borrow PgConn,
  username :: String,
  old_tree_size :: Int) -> TransparencyEvidence!String do
  let signer = configured_signer()?
  evidence_on_connection(conn, username, old_tree_size, signer.private_key, signer.public_key.bytes)
end

fn evidence_v2_from_seed_on_connection(conn :: borrow PgConn,
  username :: String,
  old_tree_size :: Int,
  signing_seed :: Bytes) -> TransparencyEvidenceV2!String do
  let signer = seeded_signer(signing_seed)?
  evidence_v2_on_connection(conn,
    username,
    old_tree_size,
    signer.private_key,
    signer.public_key.bytes)
end

fn configured_evidence_v2_on_connection(conn :: borrow PgConn,
  username :: String,
  old_tree_size :: Int) -> TransparencyEvidenceV2!String do
  let signer = configured_signer()?
  evidence_v2_on_connection(conn,
    username,
    old_tree_size,
    signer.private_key,
    signer.public_key.bytes)
end

## Version 1 evidence (full lists): only while the log holds at most 4,096
## leaves; above it this fails with "transparency_v1_ceiling".

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
      username,
      old_tree_size) end)
end

## Version 2 evidence: compact proofs, attestations of both kinds, and the
## RFC 6962 view of the same leaf whenever a C2SP cosignature is included.

pub fn evidence_v2_for_username(pool :: PoolHandle,
  username :: String,
  old_tree_size :: Int,
  signing_seed :: Bytes) -> TransparencyEvidenceV2!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> evidence_v2_from_seed_on_connection(conn,
      username,
      old_tree_size,
      signing_seed) end)
end

pub fn configured_evidence_v2_for_username(pool :: PoolHandle,
  username :: String,
  old_tree_size :: Int) -> TransparencyEvidenceV2!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> configured_evidence_v2_on_connection(conn,
      username,
      old_tree_size) end)
end

fn current_checkpoint(conn :: borrow PgConn) -> TransparencyCheckpoint!String do
  case transparency_current_checkpoint_on_connection(conn)? do
    None -> Err("transparency checkpoint not found")
    Some(value) -> Ok(value)
  end
end

fn statement_on_connection(conn :: borrow PgConn,
  attestation :: WitnessAttestation) -> AttestationWrite!String do
  let checkpoint = current_checkpoint(conn)?
  let witness = case transparency_registry_witness_on_connection(conn, attestation.witness_id)? do
    Some(entry) -> if entry.software == "mesh" do
      Ok(entry)
    else
      Err("invalid witness attestation")
    end
    None -> Err("invalid witness attestation")
  end?
  let trusted = WitnessKey { witness_id: witness.witness_id, public_key: witness.public_key }
  if !verify_witnesses(checkpoint, [attestation], [trusted], 1)? do
    Err("invalid witness attestation")
  else
    transparency_store_attestation_on_connection(conn,
      checkpoint.sequence,
      witness,
      attestation.checkpoint_hash,
      attestation.signature,
      -1)
  end
end

## Stores a Morse statement on the current checkpoint from any non-retired
## Morse-software registry entry. Err when it does not verify.

pub fn store_witness(pool :: PoolHandle,
  attestation :: WitnessAttestation) -> AttestationWrite!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> statement_on_connection(conn, attestation) end)
end

## The C2SP checkpoint body (tlog-checkpoint plus the morse-checkpoint
## extension line) of a checkpoint: its size, the RFC 6962 root at that size,
## and the whole KTK.

pub fn transparency_note_body_on_connection(conn :: borrow PgConn,
  checkpoint :: TransparencyCheckpoint,
  origin :: String) -> String!String do
  let size = U64.to_int(checkpoint.tree_size)?
  note_checkpoint_body(origin,
    size,
    dtree_root_on_connection(conn, 2, size)?,
    encode_checkpoint(checkpoint)?)
end

fn note_on_connection(conn :: borrow PgConn,
  origin :: String,
  signing_key :: borrow SigningPrivateKey,
  signing_public_key :: Bytes) -> Option<String>!String do
  case transparency_current_checkpoint_on_connection(conn)? do
    None -> Ok(None)
    Some(checkpoint) -> Ok(Some(note_sign(transparency_note_body_on_connection(conn,
        checkpoint,
        origin)?,
      origin,
      signing_key,
      signing_public_key)?))
  end
end

fn configured_note_on_connection(conn :: borrow PgConn,
  origin :: String) -> Option<String>!String do
  let signer = configured_signer()?
  note_on_connection(conn, origin, signer.private_key, signer.public_key.bytes)
end

fn seeded_note_on_connection(conn :: borrow PgConn,
  origin :: String,
  signing_seed :: Bytes) -> Option<String>!String do
  let signer = seeded_signer(signing_seed)?
  note_on_connection(conn, origin, signer.private_key, signer.public_key.bytes)
end

## The current checkpoint as a C2SP signed note, signed by the log's service
## key under the origin's key name. None before the first checkpoint.

pub fn checkpoint_note(pool :: PoolHandle,
  origin :: String,
  signing_seed :: Bytes) -> Option<String>!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> seeded_note_on_connection(conn, origin, signing_seed) end)
end

pub fn configured_checkpoint_note(pool :: PoolHandle, origin :: String) -> Option<String>!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> configured_note_on_connection(conn, origin) end)
end

fn newest_cosignature(values :: List<NoteCosignature>) -> Option<NoteCosignature> do
  List.reduce(values,
    None,
    fn best, value -> case best do
      None -> Some(value)
      Some(current) -> if value.timestamp > current.timestamp do
        Some(value)
      else
        Some(current)
      end
    end end)
end

fn cosignatures_on_connection(conn :: borrow PgConn,
  checkpoint :: TransparencyCheckpoint,
  digest :: Bytes,
  body :: String,
  response :: String,
  latest_seconds :: Int,
  witnesses :: List<RegistryWitness>,
  index :: Int,
  output :: List<AttestationWrite>) -> List<AttestationWrite>!String do
  if index >= List.length(witnesses) do
    Ok(output)
  else
    let witness = List.get(witnesses, index)
    let verified = note_read_cosignatures(response, witness.c2sp_name, witness.public_key, body)?
    let next = case newest_cosignature(verified) do
      None -> Ok(output)
      Some(value) -> if value.timestamp > latest_seconds do
        Err("cosignature from the future")
      else
        Ok(List.append(output,
          transparency_store_attestation_on_connection(conn,
            checkpoint.sequence,
            witness,
            digest,
            value.signature,
            value.timestamp)?))
      end
    end?
    cosignatures_on_connection(conn,
      checkpoint,
      digest,
      body,
      response,
      latest_seconds,
      witnesses,
      index + 1,
      next)
  end
end

fn c2sp_on_connection(conn :: borrow PgConn,
  response :: String,
  origin :: String,
  now_seconds :: Int) -> List<AttestationWrite>!String do
  let checkpoint = current_checkpoint(conn)?
  let written = cosignatures_on_connection(conn,
    checkpoint,
    checkpoint_hash(checkpoint)?,
    transparency_note_body_on_connection(conn, checkpoint, origin)?,
    response,
    now_seconds + 60,
    transparency_c2sp_witnesses_on_connection(conn)?,
    0,
    List.new())?
  if List.length(written) == 0 do
    Err("no cosignature from a registered witness")
  else
    Ok(written)
  end
end

## Stores C2SP cosignature lines on the current checkpoint's note, one per
## registered C2SP witness they verify under. Err when none does, or when a
## line under a registered key fails to verify.

pub fn store_cosignatures(pool :: PoolHandle,
  response :: String,
  origin :: String,
  now_seconds :: Int) -> List<AttestationWrite>!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> c2sp_on_connection(conn, response, origin, now_seconds) end)
end

fn tree_size_checked(conn :: borrow PgConn, size :: Int) -> Int!String do
  if size < 0 || size > dtree_size_on_connection(conn)? do
    Err("invalid tree size")
  else
    Ok(size)
  end
end

fn consistency_v2_on_connection(conn :: borrow PgConn,
  tree :: Int,
  old_size :: Int,
  new_size :: Int) -> CompactConsistency!String do
  let size = tree_size_checked(conn, new_size)?
  if old_size < 0 || old_size > size do
    Err("invalid tree size")
  else
    Ok(CompactConsistency {
      old_size: old_size,
      new_size: size,
      path: dtree_consistency_on_connection(conn, tree, old_size, size)?
    })
  end
end

## A compact consistency proof in either tree, between any two sizes the log
## has reached.

pub fn transparency_consistency_v2(pool :: PoolHandle,
  tree :: Int,
  old_size :: Int,
  new_size :: Int) -> CompactConsistency!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> consistency_v2_on_connection(conn, tree, old_size, new_size) end)
end

fn leaf_proof_on_connection(conn :: borrow PgConn,
  tree :: Int,
  index :: Int,
  size :: Int) -> TransparencyLeafProof!String do
  let checked = tree_size_checked(conn, size)?
  let rows = Pg.query_values(conn,
    "SELECT leaf_hash FROM transparency_entries WHERE leaf_index = $1::bigint",
    [Text(Int.to_string(index))])?
  case rows do
    [row] -> Ok(TransparencyLeafProof {
      leaf_hash: binary(Map.get(row, "leaf_hash"))?,
      inclusion: CompactInclusion {
        leaf_index: index,
        tree_size: checked,
        path: dtree_inclusion_on_connection(conn, tree, index, checked)?
      }
    })
    _ -> Err("invalid tree size")
  end
end

## The Morse leaf hash at an index and its inclusion path in either tree.

pub fn transparency_leaf_proof(pool :: PoolHandle,
  tree :: Int,
  index :: Int,
  size :: Int) -> TransparencyLeafProof!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> leaf_proof_on_connection(conn, tree, index, size) end)
end

## Up to `count` Morse leaf hashes from `start`, concatenated.

pub fn transparency_leaves(pool :: PoolHandle, start :: Int, count :: Int) -> Bytes!String do
  let rows = Pool.query_values(pool,
    "SELECT leaf_hash FROM transparency_entries WHERE leaf_index >= $1::bigint AND leaf_index < $1::bigint + $2::bigint ORDER BY leaf_index",
    [Text(Int.to_string(start)), Text(Int.to_string(count))])?
  tcodec_join(hashes(rows, 0, List.new())?)
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
