from Storage.Blobs import blob_record_hash
from Storage.Records import with_record_transaction, put_blobs

# Check both the movement journal CAS and the selected-bounty custody record in
# the same SQLite write. Account erasure cannot race an in-flight first insert.
pub fn store_bounty_transfer_snapshot(path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>,
  previous :: Bytes,
  selected :: Bytes) -> Result<(), String> do
  if List.length(labels) == 0
    || List.length(labels) != List.length(blobs)
    || Bytes.length(selected) == 0 do
    return Err("invalid_bounty_transfer_snapshot")
  end
  with_record_transaction(path,
    fn(database) do
      Sqlite.execute(database, "PRAGMA busy_timeout = 1000", [])?
      let hash = blob_record_hash(database, List.head(labels))?
      let guard = blob_record_hash(database, "fork-bounty/v1")?
      let count = if Bytes.length(previous) == 0 do
        Sqlite.execute_values(database,
          "INSERT INTO encrypted_blobs (record_hash, ciphertext) SELECT ?, ? WHERE EXISTS (SELECT 1 FROM encrypted_blobs WHERE record_hash = ? AND ciphertext = ?) ON CONFLICT(record_hash) DO NOTHING",
          [Text(hash), Binary(List.head(blobs)), Text(guard), Binary(selected)])?
      else
        Sqlite.execute_values(database,
          "UPDATE encrypted_blobs SET ciphertext = ? WHERE record_hash = ? AND ciphertext = ? AND EXISTS (SELECT 1 FROM encrypted_blobs WHERE record_hash = ? AND ciphertext = ?)",
          [Binary(List.head(blobs)), Text(hash), Binary(previous), Text(guard), Binary(selected)])?
      end
      if count != 1 do
        return Err("local_state_changed")
      end
      put_blobs(database, labels, blobs, 1)
    end)
end
