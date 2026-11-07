##! Canonical protected backup identity projection; current custody is checked by the caller.
from Backups.TextArchive import BackupTextArchive, decode_text_archive
from Backups.ContentArchive import BackupContentArchive, decode_content_archive

pub struct BackupPayloadIdentity do
  backup_id :: Bytes
  owner_account :: Bytes
  owner_authorization_key :: Bytes
  service_realm :: Bytes
  created_at :: U64
  outgoing_groups_owned :: Bool
end

fn text_identity(archive :: BackupTextArchive) -> BackupPayloadIdentity do
  BackupPayloadIdentity {
    backup_id: archive.backup_id,
    owner_account: archive.owner_account,
    owner_authorization_key: archive.owner_authorization_key,
    service_realm: archive.service_realm,
    created_at: archive.created_at,
    outgoing_groups_owned: List.all(archive.scopes,
      fn(scope) -> scope.kind != 2
        || List.all(scope.entries,
          fn(record) -> record.direction != 1
            || Bytes.secure_equals(record.sender_account, archive.owner_account) end) end)
  }
end

fn content_identity(archive :: BackupContentArchive) -> BackupPayloadIdentity do
  BackupPayloadIdentity {
    backup_id: archive.backup_id,
    owner_account: archive.owner_account,
    owner_authorization_key: archive.owner_authorization_key,
    service_realm: archive.service_realm,
    created_at: archive.created_at,
    outgoing_groups_owned: List.all(archive.scopes,
      fn(scope) -> scope.kind != 2
        || List.all(scope.entries,
          fn(record) -> record.direction != 1
            || Bytes.secure_equals(record.sender_account, archive.owner_account) end) end)
  }
end

pub fn backup_payload_identity(payload :: Plaintext<Bytes>) -> Result<Plaintext<BackupPayloadIdentity>, String> do
  if Bytes.length(payload) < 4 || Bytes.length(payload) > 16777216 do
    return Err("invalid_backup_archive")
  end
  let magic = case Bytes.slice(payload, 0, 4) do
    Err(_) -> return Err("invalid_backup_archive")
    Ok(value) -> Bytes.to_hex(value)
  end
  if magic == "014d5441" do
    case decode_text_archive(payload) do
      Err(_) -> Err("invalid_backup_archive")
      Ok(archive) -> Ok(text_identity(archive))
    end
  else if magic == "014d4341" do
    case decode_content_archive(payload) do
      Err(_) -> Err("invalid_backup_archive")
      Ok(archive) -> Ok(content_identity(archive))
    end
  else
    Err("invalid_backup_archive")
  end
end
