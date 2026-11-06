from Storage.Blobs import blob_record_hash
from Mobile.CreditState import credit_record_id
from Storage.Credits import CreditWalletIdentity, CreditWalletSnapshot, credit_wallet_label
from Storage.Records import with_record_transaction

# Couple the first durable part insert to the exact wallet snapshot that allowed
# staging. A concurrent cancellation/cleanup changes the manifest, so an old
# encryption result cannot recreate a part after the cleanup cursor passed it.
pub fn insert_credit_attachment_part(path :: String,
  who :: CreditWalletIdentity,
  before :: CreditWalletSnapshot,
  nonce :: Bytes,
  index :: Int,
  sealed :: Bytes) -> Result<(), String> do
  if !credit_record_id(nonce)
    || index < 0
    || index >= 8192
    || Bytes.length(before.previous) == 0
    || Bytes.length(sealed) < 1
    || Bytes.length(sealed) > 70000 do
    return Err("invalid_credit_attachment_part")
  end
  with_record_transaction(path,
    fn(database) do
      let wallet_hash = blob_record_hash(database, credit_wallet_label(who))?
      let part_hash = blob_record_hash(database,
        "#{credit_wallet_label(who)}/attachment-part/#{Bytes.to_hex(nonce)}/#{index}")?
      Sqlite.execute(database, "PRAGMA busy_timeout = 1000", [])?
      let changed = Sqlite.execute_values(database,
        "INSERT INTO encrypted_blobs (record_hash, ciphertext) SELECT ?, ? WHERE EXISTS (SELECT 1 FROM encrypted_blobs WHERE record_hash = ? AND ciphertext = ?) ON CONFLICT(record_hash) DO NOTHING",
        [Text(part_hash), Binary(sealed), Text(wallet_hash), Binary(before.previous)])?
      if changed == 1 do
        Ok(nil)
      else
        Err("local_state_changed")
      end
    end)
end
