##! Bounded opaque-part file I/O and storage path validation.

import File

pub fn maximum_part_bytes() -> Int = 65608

pub fn maximum_object_bytes() -> Int = 16795830

pub fn maximum_part_index() -> Int = 8192

## The bytes an object of `part_count` parts may hold: the shared 16 MiB
## ceiling up to 257 parts; above that a paid attachment bucket, exactly its
## 514-byte manifest and full 65,576-byte chunks (opaque-object-wire-v1.md,
## "Large objects").

pub fn object_bytes_limit(part_count :: Int) -> Int do
  if part_count <= 257 do
    maximum_object_bytes()
  else
    514 + (part_count - 1) * 65576
  end
end

## The one size each part of a large object may have.

pub fn large_part_size(part_index :: Int) -> Int do
  if part_index == 0 do
    514
  else
    65576
  end
end

fn valid_root(root :: String) -> Bool do
  String.length(root) > 1
    && String.length(root) <= 4096
    && (String.starts_with(root, "/") || remote(root))
    && !String.ends_with(root, "/")
    && !String.contains(root, "/../")
    && !String.ends_with(root, "/..")
    && !String.contains(root, "/./")
    && !String.ends_with(root, "/.")
end

fn remote(path :: String) -> Bool do
  String.starts_with(path, "http://") || String.starts_with(path, "https://")
end

pub fn validate_paths(database_path :: String, root :: String) -> Result<(), String> do
  if !(String.starts_with(database_path, "postgres://")
    || String.starts_with(database_path, "postgresql://"))
    || String.length(database_path) > 4096
    || !valid_root(root) do
    Err("invalid object storage configuration")
  else if remote(root) do
    Ok(nil)
  else if !File.exists(root) do
    Err("invalid object storage configuration")
  else
    case File.size(root) do
      Ok(_) -> Err("object storage root is not a directory")
      Err(_) -> Ok(nil)
    end
  end
end

pub fn part_path(root :: String, object_id :: Bytes, part_index :: Int) -> String!String do
  if !valid_root(root)
    || Bytes.length(object_id) != 32
    || part_index < 0
    || part_index > maximum_part_index() do
    Err("invalid object part path")
  else
    Ok(root <> "/" <> Bytes.to_hex(object_id) <> "." <> Int.to_string(part_index))
  end
end

pub fn remove_file(path :: String) -> Result<(), String> do
  if remote(path) do
    let request = Http.build(:delete, path)
      |> Http.header("Accept-Encoding", "identity")
      |> Http.timeout(10000)
      |> Http.max_response_bytes(1024)
    let response = Http.send(request)?
    if response.status == 204 || response.status == 404 do
      Ok(nil)
    else
      Err("object deletion unavailable")
    end
  else if File.exists(path) do
    File.delete(path)
  else
    Ok(nil)
  end
end

pub fn write_part_file(path :: String, body :: Bytes) -> Result<(), String> do
  let length = Bytes.length(body)
  if length <= 0 || length > maximum_part_bytes() do
    Err("invalid object part size")
  else if remote(path) do
    let request = Http.build(:put, path)
      |> Http.body_bytes(body)
      |> Http.header("Accept-Encoding", "identity")
      |> Http.timeout(10000)
      |> Http.max_response_bytes(1024)
    let response = Http.send(request)?
    if response.status == 200 || response.status == 201 do
      Ok(nil)
    else
      Err("object part write unavailable")
    end
  else if length <= 65536 do
    File.write_bytes(path, 0, body, true)
  else
    File.write_bytes(path, 0, Bytes.slice(body, 0, 65536)?, true)?
    File.write_bytes(path, 65536, Bytes.slice(body, 65536, length - 65536)?, false)
  end
end

fn append_part_tail(head :: Bytes, path :: String, expected_size :: Int) -> Option<Bytes> do
  case File.read_bytes(path, 65536, expected_size - 65536) do
    Err(_) -> None
    Ok(tail) -> if Bytes.length(head) != 65536 || Bytes.length(tail) != expected_size - 65536 do
      None
    else
      case Bytes.concat(head, tail) do
        Err(_) -> None
        Ok(body) -> Some(body)
      end
    end
  end
end

pub fn read_part_file(path :: String, expected_size :: Int) -> Option<Bytes> do
  if remote(path) do
    if expected_size <= 0 || expected_size > maximum_part_bytes() do
      return None
    end
    let result = Http.build(:get, path)
      |> Http.header("Accept-Encoding", "identity")
      |> Http.timeout(10000)
      |> Http.max_response_bytes(expected_size + 1)
      |> Http.send()
    return case result do
      Err(_) -> None
      Ok(response) -> if response.status == 200
        && Bytes.length(response.body_bytes) == expected_size do
        Some(response.body_bytes)
      else
        None
      end
    end
  end
  case File.size(path) do
    Err(_) -> return None
    Ok(size) -> if size != expected_size do
      return None
    end
  end
  if expected_size > 0 && expected_size <= maximum_part_bytes() do
    if expected_size <= 65536 do
      case File.read_bytes(path, 0, expected_size) do
        Err(_) -> None
        Ok(body) -> if Bytes.length(body) == expected_size do
          Some(body)
        else
          None
        end
      end
    else
      case File.read_bytes(path, 0, 65536) do
        Err(_) -> None
        Ok(head) -> append_part_tail(head, path, expected_size)
      end
    end
  else
    None
  end
end

# Remote storage removes every part of an object in one request, so a 8,193-part
# object is gone in a few storage calls rather than one per part.

fn remove_remote_parts(root :: String,
  object_id :: Bytes,
  part_count :: Int) -> Result<(), String> do
  let response = Http.build(:delete, root <> "/" <> Bytes.to_hex(object_id))
    |> Http.header("X-Part-Count", Int.to_string(part_count))
    |> Http.header("Accept-Encoding", "identity")
    |> Http.timeout(30000)
    |> Http.max_response_bytes(1024)
    |> Http.send()?
  if response.status == 204 do
    Ok(nil)
  else
    Err("object deletion unavailable")
  end
end

pub fn remove_parts(root :: String,
  object_id :: Bytes,
  part_count :: Int,
  index :: Int) -> Result<(), String> do
  if index >= part_count do
    Ok(nil)
  else if remote(root) do
    if Bytes.length(object_id) != 32 || part_count > maximum_part_index() + 1 do
      Err("invalid object part path")
    else
      remove_remote_parts(root, object_id, part_count)
    end
  else
    remove_file(part_path(root, object_id, index)?)?
    remove_parts(root, object_id, part_count, index + 1)
  end
end
