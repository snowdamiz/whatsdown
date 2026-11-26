##! The witness's continuity state: the last checkpoint it signed. A file
##! state is replaced crash-safely (a temporary file, File.sync, then
##! File.rename over the old one) after a compare-and-swap check that the file
##! still holds what this process read. An http(s) state is a checkpoint store
##! that takes If-Match (the Cloudflare witnesses). A halt marker beside a file
##! state stops all signing until an operator restores continuity.

from Transparency.Merkle import TransparencyCheckpoint
from Transparency.Wire import decode_checkpoint, encode_checkpoint

fn remote(path :: String) -> Bool do
  String.starts_with(path, "http://") || String.starts_with(path, "https://")
end

fn read_remote(path :: String) -> Option<TransparencyCheckpoint>!String do
  let request = Http.build(:get, path)
    |> Http.header("Accept-Encoding", "identity")
    |> Http.timeout(10000)
    |> Http.max_response_bytes(4096)
  let response = Http.send(request)?
  if response.status == 404 do
    Ok(None)
  else if response.status == 200 do
    Ok(Some(decode_checkpoint(response.body_bytes)?))
  else
    Err("witness checkpoint read failed")
  end
end

fn read_local(path :: String) -> Option<TransparencyCheckpoint>!String do
  if !File.exists(path) do
    Ok(None)
  else
    case File.read(path) do
      Err(_) -> Err("witness checkpoint read failed")
      Ok(encoded) -> case Bytes.from_base64(String.trim(encoded)) do
        Err(_) -> Err("invalid cached witness checkpoint")
        Ok(bytes) -> Ok(Some(decode_checkpoint(bytes)?))
      end
    end
  end
end

pub fn witness_state_read(path :: String) -> Option<TransparencyCheckpoint>!String do
  if remote(path) do
    read_remote(path)
  else
    read_local(path)
  end
end

pub fn witness_state_exists(path :: String) -> Bool!String do
  if remote(path) do
    case read_remote(path)? do
      None -> Ok(false)
      Some(_) -> Ok(true)
    end
  else
    Ok(File.exists(path))
  end
end

fn encoded_state(value :: Option<TransparencyCheckpoint>) -> Bytes!String do
  case value do
    None -> Ok(Bytes.empty())
    Some(checkpoint) -> encode_checkpoint(checkpoint)
  end
end

fn same_state(left :: Option<TransparencyCheckpoint>,
  right :: Option<TransparencyCheckpoint>) -> Bool!String do
  Ok(Bytes.secure_equals(encoded_state(left)?, encoded_state(right)?))
end

# A per-process temporary name in the same directory, so the rename stays on
# one filesystem and two instances sharing the volume never share a temp file.

fn temporary_path(path :: String) -> String!String do
  case Crypto.random_bytes(8) do
    Err(_) -> Err("witness temporary name failed")
    Ok(suffix) -> Ok("#{path}.tmp-#{Bytes.to_hex(suffix)}")
  end
end

fn write_synced(path :: String, contents :: String) -> String!String do
  let temporary = temporary_path(path)?
  case File.write(temporary, contents) do
    Err(_) -> Err("witness file write failed")
    Ok(_) -> case File.sync(temporary) do
      Err(_) -> do
        File.delete(temporary)
        Err("witness file sync failed")
      end
      Ok(_) -> Ok(temporary)
    end
  end
end

fn replace(temporary :: String, path :: String) -> Result<(), String> do
  case File.rename(temporary, path) do
    Err(_) -> do
      File.delete(temporary)
      Err("witness file rename failed")
    end
    Ok(_) -> Ok(nil)
  end
end

# Writes contents so a crash leaves either the old file or the new one.

pub fn witness_write_atomic(path :: String, contents :: String) -> Result<(), String> do
  replace(write_synced(path, contents)?, path)
end

fn write_remote(path :: String,
  expected :: Option<TransparencyCheckpoint>,
  value :: TransparencyCheckpoint) -> Result<(), String> do
  let if_match = case expected do
    None -> "none"
    Some(prior) -> Bytes.to_hex(Crypto.sha256(encode_checkpoint(prior)?))
  end
  let request = Http.build(:put, path)
    |> Http.header("Accept-Encoding", "identity")
    |> Http.header("If-Match", if_match)
    |> Http.body_bytes(encode_checkpoint(value)?)
    |> Http.timeout(10000)
    |> Http.max_response_bytes(1024)
  let response = Http.send(request)?
  if response.status == 204 do
    Ok(nil)
  else
    Err("witness checkpoint write failed")
  end
end

# ponytail: the check and the rename are two steps, not one atomic operation
# across processes. The runbook runs one instance at a time (the standby starts
# after the primary stops), so the window only matters for an operator error;
# add a rename-token lock if active/active standbys are ever supported.

fn write_local(path :: String,
  expected :: Option<TransparencyCheckpoint>,
  value :: TransparencyCheckpoint) -> Result<(), String> do
  let temporary = write_synced(path, Bytes.to_base64(encode_checkpoint(value)?))?
  let unchanged = case read_local(path) do
    Err(error)
    Ok(current) -> same_state(current, expected)
  end
  case unchanged do
    Ok(true) -> replace(temporary, path)
    Ok(false) -> do
      File.delete(temporary)
      Err("witness state changed underneath this instance")
    end
    Err(error) -> do
      File.delete(temporary)
      Err(error)
    end
  end
end

# Replaces the state with value only if it still holds expected (None: no
# state yet). Callers commit before they release a signature.

pub fn witness_state_write(path :: String,
  expected :: Option<TransparencyCheckpoint>,
  value :: TransparencyCheckpoint) -> Result<(), String> do
  if remote(path) do
    write_remote(path, expected, value)
  else
    write_local(path, expected, value)
  end
end

pub fn witness_halt_path(state_path :: String) -> String do
  "#{state_path}.halted"
end

# The halt marker's text, or None. A checkpoint store (http state) keeps no
# marker: the Cloudflare witnesses run once per call and stop at the error.

pub fn witness_halted(state_path :: String) -> Option<String>!String do
  let marker = witness_halt_path(state_path)
  if remote(state_path) || !File.exists(marker) do
    Ok(None)
  else
    case File.read(marker) do
      Err(_) -> Err("witness halt marker unreadable")
      Ok(text) -> Ok(Some(text))
    end
  end
end

pub fn witness_halt(state_path :: String, text :: String) -> Result<(), String> do
  if remote(state_path) do
    Ok(nil)
  else
    witness_write_atomic(witness_halt_path(state_path), text)
  end
end

pub fn witness_clear_halt(state_path :: String) -> Result<(), String> do
  let marker = witness_halt_path(state_path)
  if remote(state_path) || !File.exists(marker) do
    Ok(nil)
  else
    case File.delete(marker) do
      Err(_) -> Err("witness halt marker could not be removed")
      Ok(_) -> Ok(nil)
    end
  end
end
