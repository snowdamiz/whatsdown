from Store.Files import (
  part_path,
  read_part_file,
  remove_file,
  remove_parts,
  validate_paths,
  write_part_file
)

fn proof() -> Result<(), String> do
  let root = Env.get("MESSENGER_OBJECT_TEST_STORAGE_ROOT", "")
  validate_paths("postgres://configured", root)?
  let id = case Crypto.random_bytes(32) do
    Err(_) -> Err("random allocation failed")
    Ok(value)
  end?
  let path = part_path(root, id, 0)?
  let body = case Bytes.repeat(42, 65608) do
    Err(_) -> Err("byte allocation failed")
    Ok(value)
  end?
  write_part_file(path, body)?
  write_part_file(path, body)?
  case write_part_file(path, Bytes.from_utf8("changed")) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  case read_part_file(path, 65608) do
    None -> assert(false)
    Some(stored) -> assert(Bytes.secure_equals(stored, body))
  end
  remove_file(path)?
  case read_part_file(path, 65608) do
    None -> nil
    Some(_) -> assert(false)
  end
  # A 512 MiB attachment's parts go in one request.
  let last = part_path(root, id, 8192)?
  write_part_file(path, body)?
  write_part_file(last, body)?
  remove_parts(root, id, 8193, 0)?
  for removed in [path, last] do
    case read_part_file(removed, 65608) do
      None -> nil
      Some(_) -> assert(false)
    end
  end
  Ok(nil)
end

test("remote opaque parts preserve exact bytes and reject changed replays") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
