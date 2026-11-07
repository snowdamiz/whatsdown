from Storage.OutboxGuard import OutboxBasis, record_matches, require_outbox_basis
from Storage.Blobs import put_blob
from Storage.Records import with_record_transaction, put_blobs, delete_blobs, delete_blob

pub struct OutboxSettlementSnapshot do
  profile :: Bytes
  index :: Bytes
  postage :: Bytes
  delivery :: Bytes
  guarded_labels :: List<String>
  guarded_blobs :: List<Bytes>
end

fn guards_match(database :: SqliteConn,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Bool!String do
  for index in 0..List.length(labels) do
    if !record_matches(database, List.get(labels, index), List.get(blobs, index))? do
      return Ok(false)
    end
  end
  Ok(true)
end

## A late edge response cannot replace a concurrently extended index, settle
## paid-owned frames or recreate caches after account erasure/replacement.
## Empty optional snapshots mean the corresponding record must still be absent.
pub fn commit_outbox_settlement(path :: String,
  before :: OutboxSettlementSnapshot,
  next_index :: Bytes,
  labels :: List<String>,
  blobs :: List<Bytes>,
  removed :: List<String>) -> Result<(), String> do
  if Bytes.length(before.profile) == 0
    || Bytes.length(before.index) == 0
    || List.length(labels) != List.length(blobs)
    || List.length(before.guarded_labels) != List.length(before.guarded_blobs)
    || List.any(labels, fn(label) -> label != "delivery/v1" end)
    || List.any(removed,
      fn(label) -> label == "profile/v1"
        || label == "outbox/v1"
        || label == "postage-queue/v1"
        || label == "delivery/v1" end) do
    return Err("invalid_outbox_commit")
  end
  with_record_transaction(path,
    fn(database) do
      require_outbox_basis(database,
        OutboxBasis {
          profile: before.profile,
          index: before.index,
          postage: before.postage,
          delivery: before.delivery
        })?
      if !guards_match(database, before.guarded_labels, before.guarded_blobs)? do
        return Err("outbox_state_changed")
      end
      if Bytes.length(next_index) == 0 do
        delete_blob(database, "outbox/v1")?
      else
        put_blob(database, "outbox/v1", next_index)?
      end
      put_blobs(database, labels, blobs, 0)?
      delete_blobs(database, removed, 0)
    end)
end
