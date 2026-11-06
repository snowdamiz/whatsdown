from Storage.Blobs import blob_record_hash

## Test fault injection must address the current keyed row, not a legacy digest.
pub fn fixture_record_hash(path :: String, label :: String) -> String!String do
  let database = Sqlite.open(path)?
  let result = blob_record_hash(database, label)
  Sqlite.close(database)
  result
end
