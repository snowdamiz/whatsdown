from Witness.State import read_local_checkpoint, save_local_checkpoint
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash, sign_checkpoint
from Transparency.Wire import encode_checkpoint

fn proof() -> Bool!String do
  let pair = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("test signer failed")
  end
  let path = "/tmp/morse-witness-state-#{Bytes.to_hex(pair.public_key.bytes)}"
  let zero = Bytes.from_hex(String.join(for _ in 0..32 do
      "00"
    end,
    ""))?
  let first = sign_checkpoint(pair.private_key,
    pair.public_key.bytes,
    U64.parse("1")?,
    [],
    zero,
    U64.parse("1000")?)?
  let next = sign_checkpoint(pair.private_key,
    pair.public_key.bytes,
    U64.parse("2")?,
    [],
    checkpoint_hash(first)?,
    U64.parse("1001")?)?
  save_local_checkpoint(path, None, first)?
  save_local_checkpoint(path, Some(first), next)?
  case save_local_checkpoint(path, Some(first), first) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case save_local_checkpoint(path, None, first) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let cached = case read_local_checkpoint(path)? do
    Some(value) -> value
    None -> return Err("missing state")
  end
  assert(Bytes.secure_equals(encode_checkpoint(cached)?, encode_checkpoint(next)?))
  assert(!File.exists(path <> ".pending"))
  File.write(path, "corrupt")?
  case save_local_checkpoint(path, Some(next), first) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  assert(File.read(path)? == "corrupt")
  File.delete(path)?
  if File.exists(path <> ".lock") do
    File.delete(path <> ".lock")?
  end
  Ok(true)
end

test("witness state replacement refuses stale writers and preserves corrupt evidence") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
