from Transparency.Merkle import TransparencyCheckpoint
from Transparency.Wire import decode_checkpoint, encode_checkpoint

pub fn read_local_checkpoint(path :: String) -> Option<TransparencyCheckpoint>!String do
  if !File.exists(path) do
    return Ok(None)
  end
  if File.size(path)? != 252 do
    return Err("invalid cached witness checkpoint")
  end
  let text = File.read(path)?
  let bytes = Bytes.from_base64(text)?
  if Bytes.to_base64(bytes) != text do
    return Err("invalid cached witness checkpoint")
  end
  let checkpoint = decode_checkpoint(bytes)?
  if !Bytes.secure_equals(encode_checkpoint(checkpoint)?, bytes) do
    return Err("invalid cached witness checkpoint")
  end
  Ok(Some(checkpoint))
end

fn parent(path :: String) -> String do
  let parts = String.split(path, "/")
  if List.length(parts) <= 1 do
    "."
  else
    let prefix = String.join(for index in 0..(List.length(parts) - 1) do
        List.get(parts, index)
      end,
      "/")
    if prefix == "" do
      "/"
    else
      prefix
    end
  end
end

fn same_checkpoint(left :: Option<TransparencyCheckpoint>,
  right :: Option<TransparencyCheckpoint>) -> Bool!String do
  case (left, right) do
    (None, None) -> Ok(true)
    (Some(a), Some(b)) -> Ok(Bytes.secure_equals(encode_checkpoint(a)?, encode_checkpoint(b)?))
    _ -> Ok(false)
  end
end

fn replace_locked(path :: String,
  previous :: Option<TransparencyCheckpoint>,
  value :: TransparencyCheckpoint) -> Result<(), String> do
  if !same_checkpoint(read_local_checkpoint(path)?, previous)? do
    return Err("witness checkpoint changed concurrently")
  end
  let temporary = path <> ".pending"
  File.write(temporary, Bytes.to_base64(encode_checkpoint(value)?))?
  File.sync(temporary)?
  File.rename(temporary, path)?
  File.sync(parent(path))
end

fn with_lock(path :: String, operation :: Fun() -> Result<(), String>) -> Result<(), String> do
  # SQLite supplies an inter-process lock with automatic release on a crash.
  # No protocol state is in this sidecar. Never unlink it while writers run:
  # all writers must lock the same inode before comparing and replacing.
  let lock = Sqlite.open(path <> ".lock")?
  let result = case Sqlite.execute(lock, "BEGIN IMMEDIATE", []) do
    Err(error)
    Ok(_) -> operation()
  end
  let released = Sqlite.rollback(lock)
  Sqlite.close(lock)
  case result do
    Err(error)
    Ok(_) -> released
  end
end

pub fn save_local_checkpoint(path :: String,
  previous :: Option<TransparencyCheckpoint>,
  value :: TransparencyCheckpoint) -> Result<(), String> do
  with_lock(path, fn() do replace_locked(path, previous, value) end)
end

pub fn save_local_evidence(path :: String, evidence :: String) -> Result<(), String> do
  if String.length(evidence) > 2048 do
    return Err("witness evidence too large")
  end
  with_lock(path,
    fn() do
      if File.exists(path) do
        return Ok(nil)
      end
      let temporary = path <> ".pending"
      File.write(temporary, evidence)?
      File.sync(temporary)?
      File.rename(temporary, path)?
      File.sync(parent(path))
    end)
end
