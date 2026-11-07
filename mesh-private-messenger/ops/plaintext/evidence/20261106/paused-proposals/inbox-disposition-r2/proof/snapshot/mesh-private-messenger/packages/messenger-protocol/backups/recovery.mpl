from Backups.Protocol import BackupError

## The display code is user-held recovery material. Show it during creation only;
## never log, persist or upload it. Returning it does not enforce UI erasure.
pub fn create_backup_recovery() -> (SecretBytes, String)!BackupError do
  case RecoveryCode.generate() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

## Import the canonical recovery code directly into an opaque secret owner.
pub fn open_backup_recovery(code :: String) -> SecretBytes!BackupError do
  case RecoveryCode.parse(code) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end
