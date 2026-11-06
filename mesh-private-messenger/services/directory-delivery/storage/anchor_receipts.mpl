from Storage.TransparencyLog import checkpoint_table, anchor_table
from Storage.Transparency import historical_checkpoint_on_connection
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash
from Transparency.AnchorReceipt import AnchorReceipt, encode_anchor_receipt

pub type AnchorReceiptWrite do
  ReceiptCreated
  ReceiptUnchanged
  ReceiptMissing
  ReceiptConflict
end

fn wide(value :: DbValue) -> U64!String do
  case value do
    Text(text) -> U64.parse(text)
    _ -> Err("invalid_anchor_receipt_row")
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid_anchor_receipt_row")
  end
end

fn signature(value :: DbValue) -> Bytes!String do
  case value do
    Text(text) -> Bytes.from_base58(text)
    _ -> Err("invalid_anchor_receipt_row")
  end
end

fn from_row(version :: Int, row :: Map<String, DbValue>) -> AnchorReceipt!String do
  let value = AnchorReceipt {
    log_version: version,
    sequence: wide(Map.get(row, "checkpoint_sequence"))?,
    tree_size: wide(Map.get(row, "tree_size"))?,
    checkpoint_hash: binary(Map.get(row, "checkpoint_hash"))?,
    ring_index: U64.to_int(wide(Map.get(row, "ring_index"))?)?,
    transaction_signature: signature(Map.get(row, "tx_signature"))?,
    slot: wide(Map.get(row, "slot"))?
  }
  encode_anchor_receipt(value)?
  Ok(value)
end

fn read_receipt(conn :: borrow PgConn,
  version :: Int,
  sequence :: U64) -> Option<AnchorReceipt>!String do
  let table = anchor_table(version)?
  if U64.compare(sequence, U64.parse("9223372036854775807")?) > 0 do
    return Ok(None)
  end
  let rows = Pg.query_values(conn,
    "SELECT checkpoint_sequence::text, tree_size::text, checkpoint_hash, ring_index::text, tx_signature, slot::text FROM "
      <> table
      <> " WHERE checkpoint_sequence = $1::bigint",
    [Text(U64.to_string(sequence))])?
  if List.length(rows) == 0 do
    Ok(None)
  else
    Ok(Some(from_row(version, List.head(rows))?))
  end
end

pub fn load_anchor_receipt(pool :: PoolHandle,
  version :: Int,
  sequence :: U64) -> Option<AnchorReceipt>!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) do read_receipt(conn, version, sequence) end)
end

fn same_anchor(left :: AnchorReceipt, right :: AnchorReceipt) -> Bool do
  left.log_version == right.log_version
    && U64.compare(left.sequence, right.sequence) == 0
    && U64.compare(left.tree_size, right.tree_size) == 0
    && Bytes.secure_equals(left.checkpoint_hash, right.checkpoint_hash)
    && left.ring_index == right.ring_index
    && U64.compare(left.slot, right.slot) == 0
end

fn record(conn :: borrow PgConn, receipt :: AnchorReceipt) -> AnchorReceiptWrite!String do
  # Hold the checkpoint against pruning and serialize competing receipts for
  # this exact log/sequence. The FK then protects it after this transaction.
  let locked = Pg.query(conn,
    "SELECT sequence::text FROM "
      <> checkpoint_table(receipt.log_version)?
      <> " WHERE sequence = $1::bigint FOR UPDATE",
    [U64.to_string(receipt.sequence)])?
  if List.length(locked) == 0 do
    return Ok(ReceiptMissing)
  end
  let checkpoint = case historical_checkpoint_on_connection(conn,
    receipt.log_version,
    receipt.sequence)? do
    None -> return Ok(ReceiptMissing)
    Some(value) -> value
  end
  if U64.compare(checkpoint.tree_size, receipt.tree_size) != 0
    || !Bytes.secure_equals(checkpoint_hash(checkpoint)?, receipt.checkpoint_hash) do
    return Ok(ReceiptConflict)
  end
  case read_receipt(conn, receipt.log_version, receipt.sequence)? do
    Some(previous) -> return Ok(if same_anchor(previous, receipt) do
      ReceiptUnchanged
    else
      ReceiptConflict
    end)
    None -> nil
  end
  Pg.execute_values(conn,
    "INSERT INTO "
      <> anchor_table(receipt.log_version)?
      <> " (checkpoint_sequence, tree_size, checkpoint_hash, ring_index, tx_signature, slot) VALUES ($1::bigint, $2::bigint, $3, $4::integer, $5::text, $6::bigint)",
    [
      Text(U64.to_string(receipt.sequence)),
      Text(U64.to_string(receipt.tree_size)),
      Binary(receipt.checkpoint_hash),
      Text(Int.to_string(receipt.ring_index)),
      Text(Bytes.to_base58(receipt.transaction_signature)),
      Text(U64.to_string(receipt.slot))
    ])?
  Ok(ReceiptCreated)
end

# Only the bearer-authenticated chain writer calls this after finalized chain
# confirmation. These coordinates never confer chain trust on public readers.
pub fn store_anchor_receipt(pool :: PoolHandle,
  receipt :: AnchorReceipt) -> AnchorReceiptWrite!String do
  encode_anchor_receipt(receipt)?
  if U64.compare(receipt.sequence, U64.parse("9223372036854775807")?) > 0
    || U64.compare(receipt.slot, U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_anchor_receipt")
  end
  Repo.transaction(pool, fn(conn :: borrow PgConn) do record(conn, receipt) end)
end
