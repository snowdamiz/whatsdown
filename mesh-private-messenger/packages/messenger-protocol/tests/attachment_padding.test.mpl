from Attachments.Protocol import (
  AttachmentError,
  AttachmentManifest,
  attachment_credit_cost,
  attachment_padded_size,
  generate_attachment_id,
  generate_attachment_key,
  open_chunk,
  open_manifest,
  seal_chunk,
  seal_manifest
)

fn check(value :: Bool, message :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(message)
  end
end

fn bytes(result :: Result<Bytes, BytesError>) -> Bytes!String do
  case result do
    Err(_) -> Err("byte operation failed")
    Ok(value)
  end
end

fn new_key() -> SecretBytes!String do
  case generate_attachment_key() do
    Err(_) -> Err("key generation failed")
    Ok(value)
  end
end

fn repeated(value :: Int, count :: Int) -> Bytes!String do
  bytes(Bytes.repeat(value, count))
end

fn slice(input :: Bytes, offset :: Int, length :: Int) -> Bytes!String do
  Bytes.slice(input, offset, length)
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts,
    Ok(Bytes.empty()),
    fn(output, part) do
      case output do
        Err(error)
        Ok(value) -> Bytes.concat(value, part)
      end
    end)
end

fn u32(value :: Int) -> Bytes!String do
  bytes(Bytes.write_u32_be(U64.parse(Int.to_string(value))?))
end

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn protocol(value :: Result<Bytes, AttachmentError>, message :: String) -> Bytes!String do
  case value do
    Err(_) -> Err(message)
    Ok(output)
  end
end

fn opened_manifest(value :: Result<AttachmentManifest, AttachmentError>,
  message :: String) -> AttachmentManifest!String do
  case value do
    Err(_) -> Err(message)
    Ok(output)
  end
end

fn chunk_count(size :: Int) -> Int do
  (attachment_padded_size(size) + 65535) / 65536
end

fn padded_manifest(attachment_id :: Bytes, size :: Int) -> AttachmentManifest!String do
  Ok(AttachmentManifest {
    version: 2,
    attachment_id: attachment_id,
    chunk_size: 65536,
    chunk_count: chunk_count(size),
    plaintext_size: size,
    filename: Bytes.from_utf8("field-notes.txt"),
    mime_type: Bytes.from_utf8("text/plain"),
    expires_at: wide("4102444800000")?
  })
end

# Every size maps to its bucket: the ladder starts at one chunk, has four steps
# per doubling, never pads by more than a quarter above one chunk, and ends at
# the 512 MiB ceiling. Between two rungs every size pads to the upper one, and
# costs what the rung costs.

fn walk_ladder(previous :: Int, rungs :: Int) -> Int!String do
  if previous >= 536870912 do
    Ok(rungs)
  else
    let next = attachment_padded_size(previous + 1)
    check(next > previous && attachment_padded_size(next) == next,
      "bucket #{next} is not a fixed point")?
    check(attachment_padded_size((previous + 1 + next) / 2) == next,
      "a size between #{previous} and #{next} left its bucket")?
    check(next % 16384 == 0 && 4 * next <= 5 * (previous + 1),
      "bucket #{next} pads #{previous + 1} by more than a quarter")?
    check(attachment_credit_cost(previous + 1) == attachment_credit_cost(next),
      "sizes in bucket #{next} cost different credits")?
    walk_ladder(next, rungs + 1)
  end
end

fn ladder_proof() -> Result<(), String> do
  let table = [
    (1, 65536),
    (65536, 65536),
    (65537, 81920),
    (81920, 81920),
    (81921, 98304),
    (131073, 163840),
    (196609, 229376),
    (262145, 327680),
    (524289, 655360),
    (10000000, 10485760),
    (16777215, 16777216),
    (16777216, 16777216),
    (16777217, 20971520),
    (33554432, 33554432),
    (33554433, 41943040),
    (41943040, 41943040),
    (536870911, 536870912),
    (536870912, 536870912)
  ]
  for (size, bucket) in table do
    check(attachment_padded_size(size) == bucket, "size #{size} did not pad to #{bucket}")?
  end
  check(walk_ladder(65536, 1)? == 53, "the ladder does not have 53 buckets")
end

# Files up to 16 MiB are free; above that each bucket costs one credit per 16
# MiB it holds beyond the first (plan §6.10): the 20 buckets from 20 MiB to 512
# MiB, in MiB and credits.

fn cost_proof() -> Result<(), String> do
  check(attachment_credit_cost(1) == 0 && attachment_credit_cost(16777216) == 0,
    "a file of at most 16 MiB costs credits")?
  let rungs = [
    (20, 1),
    (24, 1),
    (28, 1),
    (32, 1),
    (40, 2),
    (48, 2),
    (56, 3),
    (64, 3),
    (80, 4),
    (96, 5),
    (112, 6),
    (128, 7),
    (160, 9),
    (192, 11),
    (224, 13),
    (256, 15),
    (320, 19),
    (384, 23),
    (448, 27),
    (512, 31)
  ]
  for (mebibytes, credits) in rungs do
    let size = mebibytes * 1048576
    check(attachment_padded_size(size) == size, "#{mebibytes} MiB is not a bucket")?
    check(attachment_credit_cost(size) == credits,
      "#{mebibytes} MiB did not cost #{credits} credits")?
  end
  check(attachment_credit_cost(16777217) == 1, "a byte over 16 MiB is free")?
  check(attachment_credit_cost(40000000) == 2, "a 40 MB video does not cost 2 credits")
end

test("files over 16 MiB cost one credit per extra 16 MiB of their bucket") do
  case cost_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("every attachment size pads to its bucket") do
  case ladder_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

# Seal every chunk of a file the way a sender does, then open them the way a
# receiver does: each chunk on the wire has its padded length, and the opened
# chunks join to exactly the original bytes.

fn chunk_data(data :: Bytes, index :: Int) -> Bytes!String do
  let offset = index * 65536
  let size = Bytes.length(data)
  if offset >= size do
    Ok(Bytes.empty())
  else
    slice(data, offset, Math.min(65536, size - offset))
  end
end

fn open_chunks(key :: borrow SecretBytes,
  manifest :: AttachmentManifest,
  data :: Bytes,
  index :: Int,
  output :: Bytes) -> Bytes!String do
  if index >= manifest.chunk_count do
    Ok(output)
  else
    let sealed = protocol(seal_chunk(key, manifest, index, chunk_data(data, index)?),
      "chunk seal #{index}")?
    let stored = Math.min(65536, attachment_padded_size(manifest.plaintext_size) - index * 65536)
    check(Bytes.length(sealed) == stored + 40, "chunk #{index} is not its padded length")?
    let opened = protocol(open_chunk(key, manifest, index, sealed), "chunk open #{index}")?
    open_chunks(key, manifest, data, index + 1, Bytes.concat(output, opened)?)
  end
end

# Blocks of 4,099 bytes that each hold their own index, so a chunk opened out of
# place or cut at the wrong length changes the joined bytes.

fn pattern(size :: Int, block :: Int, output :: Bytes) -> Bytes!String do
  let remaining = size - Bytes.length(output)
  if remaining <= 0 do
    Ok(output)
  else
    let piece = repeated(block % 251, Math.min(4099, remaining))?
    pattern(size, block + 1, Bytes.concat(output, piece)?)
  end
end

fn round_trip(key :: borrow SecretBytes, size :: Int) -> Result<(), String> do
  let manifest = padded_manifest(protocol(generate_attachment_id(), "id")?, size)?
  let wire = protocol(seal_manifest(key, manifest), "manifest seal #{size}")?
  check(Bytes.length(wire) == 514, "encrypted manifest is not 514 bytes")?
  let opened = opened_manifest(open_manifest(key, wire), "manifest open #{size}")?
  check(opened.version == 2 && opened.plaintext_size == size, "manifest changed")?
  let plaintext = pattern(size, 0, Bytes.empty())?
  let joined = open_chunks(key, opened, plaintext, 0, Bytes.empty())?
  check(Bytes.secure_equals(joined, plaintext), "padding was not stripped exactly for #{size}")
end

fn manifest_refused(value :: Result<Bytes, AttachmentError>,
  message :: String) -> Result<(), String> do
  case value do
    Err(InvalidManifest) -> Ok(nil)
    _ -> Err(message)
  end
end

fn size_refused(value :: Result<Bytes, AttachmentError>, message :: String) -> Result<(), String> do
  case value do
    Err(InvalidChunkSize) -> Ok(nil)
    _ -> Err(message)
  end
end

fn padding_refused(value :: Result<Bytes, AttachmentError>,
  message :: String) -> Result<(), String> do
  case value do
    Err(InvalidPadding) -> Ok(nil)
    _ -> Err(message)
  end
end

fn round_trip_proof() -> Result<(), String> do
  let key = new_key()?
  round_trip(key, 1000)?
  round_trip(key, 70000)?
  round_trip(key, 524289)?
  let short = padded_manifest(protocol(generate_attachment_id(), "id")?, 524289)?
  manifest_refused(seal_manifest(key, %{short | chunk_count: 9}),
    "a manifest without its padding chunks was sealed")?
  manifest_refused(seal_manifest(key, %{short | chunk_size: 32768, chunk_count: 20}),
    "a padded manifest with another chunk size was sealed")?
  let small = padded_manifest(protocol(generate_attachment_id(), "id")?, 70000)?
  size_refused(seal_chunk(key, small, 1, repeated(1, 16384)?),
    "a sender passed the padding itself")?
  Secret.destroy(key)
  Ok(nil)
end

# The largest bucket is 8,192 chunks. A file one byte over 20 MiB pads to 24
# MiB: its last byte is chunk 320 and chunks 321 to 383 are padding alone.

fn index_refused(value :: Result<Bytes, AttachmentError>,
  message :: String) -> Result<(), String> do
  case value do
    Err(InvalidChunkIndex) -> Ok(nil)
    _ -> Err(message)
  end
end

fn large_proof() -> Result<(), String> do
  let key = new_key()?
  let largest = padded_manifest(protocol(generate_attachment_id(), "id")?, 536870912)?
  check(largest.chunk_count == 8192, "512 MiB is not 8,192 chunks")?
  let opened = opened_manifest(open_manifest(key,
      protocol(seal_manifest(key, largest), "largest manifest seal")?),
    "largest manifest open")?
  let full = repeated(6, 65536)?
  let last = protocol(seal_chunk(key, opened, 8191, full), "last chunk seal")?
  check(Bytes.secure_equals(protocol(open_chunk(key, opened, 8191, last), "last chunk open")?,
      full),
    "the last of 8,192 chunks changed")?
  index_refused(seal_chunk(key, opened, 8192, full), "a chunk past 8,192 was sealed")?
  manifest_refused(seal_manifest(key, %{largest | plaintext_size: 536870913, chunk_count: 10240}),
    "a file over 512 MiB was sealed")?
  manifest_refused(seal_manifest(key,
      %{largest | version: 1, plaintext_size: 16842752, chunk_count: 257}),
    "a version 1 manifest over 256 chunks was sealed")?
  let odd = padded_manifest(protocol(generate_attachment_id(), "id")?, 20971521)?
  check(odd.chunk_count == 384, "20 MiB and a byte is not 384 chunks")?
  let tail = protocol(seal_chunk(key, odd, 320, repeated(8, 1)?), "tail chunk seal")?
  check(Bytes.secure_equals(protocol(open_chunk(key, odd, 320, tail), "tail open")?,
      repeated(8, 1)?),
    "the file's last byte did not come back")?
  let padding = protocol(seal_chunk(key, odd, 383, Bytes.empty()), "padding chunk seal")?
  check(Bytes.length(padding) == 65576
      && Bytes.length(protocol(open_chunk(key, odd, 383, padding), "padding open")?) == 0,
    "a padding-only chunk of a large file is not a full empty chunk")?
  Secret.destroy(key)
  Ok(nil)
end

test("files up to 512 MiB seal to 8,192 chunks, and nothing larger") do
  case large_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("padded attachments round trip and strip their padding exactly") do
  case round_trip_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

# A dishonest sender holds the key, so it can seal anything. Build its manifests
# and chunks by hand, straight from attachment-wire-v1.md, and check the
# receiver refuses every padding that isn't the canonical one.

fn aead_key(secret :: borrow SecretBytes, attachment_id :: Bytes) -> AeadKey!String do
  let material = case Crypto.hkdf_sha256(secret,
    attachment_id,
    Bytes.from_utf8("mesh-msg/v1/attachment-key"),
    32) do
    Err(_) -> Err("key derivation failed")
    Ok(value)
  end?
  case Crypto.aead_key(material) do
    Err(_) -> Err("key derivation failed")
    Ok(value)
  end
end

fn seal_raw(key :: borrow AeadKey, aad :: Bytes, plaintext :: Bytes) -> Bytes!String do
  let nonce = case Crypto.random_bytes(12) do
    Err(_) -> Err("nonce generation failed")
    Ok(value)
  end?
  let ciphertext = case Crypto.aead_seal(key, nonce, aad, plaintext) do
    Err(_) -> Err("sealing failed")
    Ok(value)
  end?
  Bytes.concat(nonce, join([u32(Bytes.length(ciphertext))?, ciphertext])?)
end

fn manifest_bytes(attachment_id :: Bytes,
  chunk_count :: Int,
  size :: Int,
  padding :: Bytes) -> Bytes!String do
  let filename = Bytes.from_utf8("field-notes.txt")
  let mime_type = Bytes.from_utf8("text/plain")
  join([
    bytes(Bytes.from_list([2]))?,
    Bytes.from_utf8("AMF"),
    attachment_id,
    u32(65536)?,
    u32(chunk_count)?,
    u32(size)?,
    bytes(Bytes.write_u64_be(wide("4102444800000")?))?,
    u32(Bytes.length(filename))?,
    filename,
    u32(Bytes.length(mime_type))?,
    mime_type,
    padding
  ])
end

fn sealed_manifest(key :: borrow AeadKey,
  attachment_id :: Bytes,
  plaintext :: Bytes) -> Bytes!String do
  let aad = join([Bytes.from_utf8("mesh-msg/v1/attachment-manifest"), attachment_id])?
  join([
    bytes(Bytes.from_list([1]))?,
    Bytes.from_utf8("EAM"),
    attachment_id,
    seal_raw(key, aad, plaintext)?
  ])
end

fn sealed_chunk(key :: borrow AeadKey,
  manifest :: Bytes,
  index :: Int,
  plaintext :: Bytes) -> Bytes!String do
  let aad = join([
    Bytes.from_utf8("mesh-msg/v1/attachment-chunk"),
    Crypto.sha256(manifest),
    u32(index)?
  ])?
  join([
    bytes(Bytes.from_list([1]))?,
    Bytes.from_utf8("ACH"),
    u32(index)?,
    seal_raw(key, aad, plaintext)?
  ])
end

fn refused_manifest(secret :: borrow SecretBytes,
  wire :: Bytes,
  message :: String) -> Result<(), String> do
  case open_manifest(secret, wire) do
    Err(InvalidManifest) -> Ok(nil)
    _ -> Err(message)
  end
end

fn tamper_proof() -> Result<(), String> do
  let secret = new_key()?
  let attachment_id = protocol(generate_attachment_id(), "id")?
  let key = aead_key(secret, attachment_id)?
  # 70,000 bytes pad to 81,920: chunk 1 holds 4,464 bytes and 11,920 zeros.
  let zeros = repeated(0, 446 - 64 - 15 - 10)?
  let canonical = manifest_bytes(attachment_id, 2, 70000, zeros)?
  check(Bytes.length(canonical) == 446, "hand-built manifest is not 446 bytes")?
  let opened = opened_manifest(open_manifest(secret,
      sealed_manifest(key, attachment_id, canonical)?),
    "the hand-built manifest does not follow the wire document")?
  let data = repeated(9, 4464)?
  let honest = sealed_chunk(key, canonical, 1, join([data, repeated(0, 11920)?])?)?
  check(Bytes.secure_equals(protocol(open_chunk(secret, opened, 1, honest), "honest chunk")?, data),
    "the hand-built chunk did not open to its data")?
  let marked = join([slice(zeros, 0, Bytes.length(zeros) - 1)?, bytes(Bytes.from_list([1]))?])?
  refused_manifest(secret,
    sealed_manifest(key, attachment_id, manifest_bytes(attachment_id, 2, 70000, marked)?)?,
    "a manifest with nonzero padding opened")?
  refused_manifest(secret,
    sealed_manifest(key,
      attachment_id,
      manifest_bytes(attachment_id, 2, 70000, slice(zeros, 0, 10)?)?)?,
    "a manifest shorter than 446 bytes opened")?
  refused_manifest(secret,
    sealed_manifest(key, attachment_id, manifest_bytes(attachment_id, 3, 70000, zeros)?)?,
    "a manifest claiming an extra padding chunk opened")?
  let heavy = sealed_chunk(key, canonical, 1, join([data, repeated(0, 11921)?])?)?
  size_refused(open_chunk(secret, opened, 1, heavy),
    "a chunk with one byte too much padding opened")?
  let light = sealed_chunk(key, canonical, 1, join([data, repeated(0, 11919)?])?)?
  size_refused(open_chunk(secret, opened, 1, light),
    "a chunk with one byte too little padding opened")?
  let dirty = join([data, repeated(0, 11919)?, bytes(Bytes.from_list([7]))?])?
  padding_refused(open_chunk(secret, opened, 1, sealed_chunk(key, canonical, 1, dirty)?),
    "a chunk with nonzero padding opened")?
  Secret.destroy(secret)
  Ok(nil)
end

test("receivers refuse padding a dishonest sender changed") do
  case tamper_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
