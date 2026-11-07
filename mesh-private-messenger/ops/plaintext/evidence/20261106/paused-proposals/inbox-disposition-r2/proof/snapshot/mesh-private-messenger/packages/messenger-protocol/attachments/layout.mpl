# No file-sized byte values: both hosts and services derive the same bounded
# part layout from one public size. Part0 is the encrypted manifest.
pub fn large_attachment_chunks(plaintext_size :: Int) -> Int!String do
  if plaintext_size <= 16777216 || plaintext_size > 536870912 do
    return Err("invalid_large_attachment_size")
  end
  Ok((plaintext_size + 65535) / 65536)
end

pub fn large_attachment_part_bytes(plaintext_size :: Int, part_index :: Int) -> Int!String do
  let count = large_attachment_chunks(plaintext_size)?
  if part_index < 1 || part_index > count do
    return Err("invalid_large_attachment_part")
  end
  let plaintext = if part_index == count do
    plaintext_size - (count - 1) * 65536
  else
    65536
  end
  # ACH header/index/nonce/vector length plus AEAD tag.
  Ok(plaintext + 40)
end

pub fn large_attachment_total_bytes(plaintext_size :: Int, manifest_size :: Int) -> Int!String do
  let count = large_attachment_chunks(plaintext_size)?
  if manifest_size < 68 || manifest_size > 514 do
    return Err("invalid_large_attachment_manifest")
  end
  Ok(plaintext_size + count * 40 + manifest_size)
end

# New profile4 exposes only a64KiB capacity. Exact size remains in its EAM4.
pub fn attachment_bucket_capacity(plaintext_size :: Int) -> Int!String do
  if plaintext_size < 1 || plaintext_size > 536870912 do
    return Err("invalid_large_attachment_size")
  end
  Ok(((plaintext_size + 65535) / 65536) * 65536)
end

pub fn bucketed_large_attachment_chunks(capacity :: Int) -> Int!String do
  if capacity <= 16777216 || capacity > 536870912 || capacity % 65536 != 0 do
    return Err("invalid_large_attachment_size")
  end
  Ok(capacity / 65536)
end

pub fn bucketed_large_attachment_part_bytes(capacity :: Int, part_index :: Int) -> Int!String do
  let count = bucketed_large_attachment_chunks(capacity)?
  if part_index < 1 || part_index > count do
    return Err("invalid_large_attachment_part")
  end
  Ok(65576)
end

pub fn bucketed_large_attachment_total_bytes(capacity :: Int, manifest_size :: Int) -> Int!String do
  let count = bucketed_large_attachment_chunks(capacity)?
  if manifest_size != 514 do
    return Err("invalid_large_attachment_manifest")
  end
  Ok(capacity + count * 40 + 514)
end
