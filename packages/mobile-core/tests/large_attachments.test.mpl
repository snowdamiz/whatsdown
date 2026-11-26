import File
from Credits.CreditFrames import credits_detach
from Credits.CreditToken import CreditToken, credits_encode_token
from Mobile.Codec import current_time
from MobileCore import (
  attachment_open_chunk_export,
  attachment_prepare_export,
  attachment_seal_chunk_export,
  create_account_export
)
from Objects.Grant import decode_grant, verify_grant
from Tests.GroupLifecycleWire import group_vectors, output_list
from Tests.Support import database_path, read_u32, repeated, write_u32

# Files over 16 MiB (attachment-wire-v1.md "Large files"): the host passes the
# credit tokens the file's bucket costs, and moves the file one chunk at a time.
# The hosts read and write the file itself (apps/mobile attachment-io); here the
# host is the test, handing the core each chunk as it would read it.

fn ensure(value :: Bool, error :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(error)
  end
end

# Tokens as the device's credits hold them; the core only frames them, and the
# directory's tests check real ones against the spent set.

fn tokens(count :: Int) -> Bytes!String do
  if count <= 0 do
    Ok(Bytes.empty())
  else
    let token = credits_encode_token(CreditToken {
      nonce: repeated(count, 32)?,
      challenge_digest: repeated(2, 32)?,
      token_key_id: repeated(3, 32)?,
      authenticator: repeated(4, 256)?
    })?
    Bytes.concat(token, tokens(count - 1)?)
  end
end

fn prepare(path :: String, size :: Int, credits :: Int) -> List<Bytes>!String do
  let request = [
    Bytes.from_utf8(path),
    Bytes.from_utf8("launch-film.mov"),
    Bytes.from_utf8("video/quicktime"),
    write_u32(size)?,
    write_u32(1)?
  ]
  let with_credits = if credits == 0 do
    request
  else
    request ++ [tokens(credits)?]
  end
  output_list(attachment_prepare_export(group_vectors(with_credits)?)?)
end

fn refused(path :: String, size :: Int, credits :: Int, expected :: String) -> Result<(), String> do
  case prepare(path, size, credits) do
    Ok(_) -> Err("#{size} bytes with #{credits} credits was prepared")
    Err(error) -> ensure(error == expected, "#{size} bytes with #{credits} credits: #{error}")
  end
end

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

# A 40 MB video pads to 40 MiB and costs 2 credits; its grant is those two
# tokens bound to the OGR of its 641 parts. 16 MiB is still free.

fn credits_proof(path :: String) -> Result<(), String> do
  refused(path, 17000001, 0, "attachment_credits_required")?
  refused(path, 40000000, 1, "attachment_credits_required")?
  refused(path, 40000000, 3, "invalid_attachment_credits")?
  refused(path, 16777216, 1, "invalid_attachment_credits")?
  refused(path, 536870913, 31, "attachment_too_large")?
  let video = prepare(path, 40000000, 2)?
  ensure(read_u32(List.get(video, 7))? == 640, "a 40 MB video is not 640 chunks")?
  let (frame, ogr) = credits_detach(List.get(video, 3))?
  let paid = case frame do
    None -> Err("the 40 MB grant carried no credits")
    Some(value) -> Ok(value)
  end?
  ensure(List.length(paid.tokens) == 2, "the 40 MB grant did not carry 2 credits")?
  ensure(decode_grant(ogr)?.part_count == 641, "the 40 MB grant is not 641 parts")?
  ensure(verify_grant(ogr, current_time()?, wide("150000")?, wide("518400000")?, 1)?,
    "the paid grant's work did not verify")?
  let free = prepare(path, 16777216, 0)?
  ensure(Bytes.length(List.get(free, 3)) == 124, "a 16 MiB grant is not a plain OGR")?
  ensure(decode_grant(List.get(free, 3))?.part_count == 257, "a 16 MiB grant is not 257 parts")?
  let largest = prepare(path, 536870912, 31)?
  ensure(read_u32(List.get(largest, 7))? == 8192, "512 MiB is not 8,192 chunks")
end

# The host reads the file one chunk at a time, has the core seal it, and opens
# it again the way a receiver does: the core never holds more than one chunk.
# Each chunk of the file holds its own index, so one out of place shows.

fn file_chunk(size :: Int, index :: Int) -> Bytes!String do
  let offset = index * 65536
  if offset >= size do
    Ok(Bytes.empty())
  else
    repeated(index % 251, Math.min(65536, size - offset))
  end
end

fn chunk_request(path :: String,
  reference :: Bytes,
  index :: Int,
  payload :: Bytes) -> Bytes!String do
  group_vectors([Bytes.from_utf8(path), reference, write_u32(index)?, payload])
end

fn stream(path :: String,
  size :: Int,
  reference :: Bytes,
  chunks :: Int,
  index :: Int,
  received :: Int) -> Int!String do
  if index >= chunks do
    Ok(received)
  else
    let chunk = file_chunk(size, index)?
    let sealed = attachment_seal_chunk_export(chunk_request(path, reference, index, chunk)?)?
    ensure(Bytes.length(sealed) == 65576, "chunk #{index} left the bucket's size")?
    let opened = attachment_open_chunk_export(chunk_request(path, reference, index, sealed)?)?
    ensure(Bytes.secure_equals(opened, chunk), "chunk #{index} did not round trip")?
    stream(path, size, reference, chunks, index + 1, received + Bytes.length(opened))
  end
end

# 17,000,001 bytes pad to 20 MiB: 320 chunks, the last 60 of them padding alone.

fn stream_proof(path :: String) -> Result<(), String> do
  let size = 17000001
  let prepared = prepare(path, size, 1)?
  let chunks = read_u32(List.get(prepared, 7))?
  ensure(chunks == 320, "17,000,001 bytes are not 320 chunks")?
  let received = stream(path, size, List.get(prepared, 0), chunks, 0, 0)?
  ensure(received == size, "the streamed file came back a different size")
end

fn proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("large-attachments")?
  create_account_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("erin")])?)?
  credits_proof(path)?
  stream_proof(path)?
  File.delete(path)?
  Ok(nil)
end

test("files over 16 MiB are prepared with the credits their bucket costs and stream a chunk at a time") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
