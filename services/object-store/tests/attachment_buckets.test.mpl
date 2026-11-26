from Attachments.Protocol import (
  AttachmentError,
  AttachmentManifest,
  attachment_padded_size,
  generate_attachment_id,
  generate_attachment_key,
  seal_chunk,
  seal_manifest
)
from Credits.CreditFrames import (
  CreditRedemption,
  credits_attach,
  credits_decode_redeem,
  credits_encode_redemption
)
from Credits.CreditToken import CreditToken, credits_encode_token
from Objects.Grant import ObjectControl, encode_complete, encode_delete, encode_grant, mint_grant
from Privacy.CreditEdge import CreditEdgeResult
from Store.Service import complete, delete_object, grant_with_credits, initialize, put_part

# What the object store records for an attachment is all it learns about the
# file's size. A sender pads to a bucket (attachment wire version 2), so files of
# different sizes in one bucket must leave identical rows.

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

# Large objects are tens of MiB: keep them off a small system disk.

fn root() -> String do
  Env.get("MESSENGER_OBJECT_TEST_ROOT", "/tmp")
end

fn repeated(value :: Int, count :: Int) -> Bytes do
  case Bytes.repeat(value, count) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn token(seed :: Int) -> Bytes!String do
  credits_encode_token(CreditToken {
    nonce: repeated(seed, 32),
    challenge_digest: repeated(2, 32),
    token_key_id: repeated(3, 32),
    authenticator: repeated(4, 256)
  })
end

fn tokens(first :: Int, count :: Int) -> List<Bytes>!String do
  if count <= 0 do
    Ok([])
  else
    Ok([token(first)?] ++ tokens(first + 1, count - 1)?)
  end
end

# Stands in for the core's redeem route, whose own checks run in the
# directory's credits tests: a file redemption of the frame's credits.

fn core(request :: Bytes) -> CreditEdgeResult!String do
  let (action, frame) = credits_decode_redeem(request)?
  if action != 4 do
    Err("the store redeemed for another action")
  else
    Ok(CreditEdgeResult {
      status: 201,
      body: credits_encode_redemption(CreditRedemption {
        redemption_id: repeated(5, 16),
        credits: List.length(frame.tokens)
      })?
    })
  end
end

fn never(_request :: Bytes) -> CreditEdgeResult!String do
  Err("the store asked the core to redeem")
end

fn answering(status :: Int) -> Fun(Bytes) -> CreditEdgeResult!String do
  fn _request -> Ok(CreditEdgeResult { status: status, body: Bytes.empty() }) end
end

fn random_32() -> Bytes!String do
  case Crypto.random_bytes(32) do
    Err(_) -> Err("random value generation failed")
    Ok(value)
  end
end

fn sealed(value :: Result<Bytes, AttachmentError>) -> Bytes!String do
  case value do
    Err(_) -> Err("attachment sealing failed")
    Ok(output)
  end
end

fn chunk_data(size :: Int, index :: Int) -> Bytes!String do
  let remaining = size - index * 65536
  if remaining <= 0 do
    Ok(Bytes.empty())
  else
    case Bytes.repeat((index + 1) % 251, Math.min(65536, remaining)) do
      Err(_) -> Err("test byte allocation failed")
      Ok(value)
    end
  end
end

fn upload_chunks(database_path :: String,
  secret :: borrow SecretBytes,
  manifest :: AttachmentManifest,
  object_id :: Bytes,
  upload :: Bytes,
  index :: Int) -> Result<(), String> do
  if index >= manifest.chunk_count do
    Ok(nil)
  else
    let body = sealed(seal_chunk(secret,
      manifest,
      index,
      chunk_data(manifest.plaintext_size, index)?))?
    if put_part(database_path,
      root(),
      object_id,
      index + 1,
      upload,
      body,
      wide("100001")?).status != 201 do
      Err("chunk #{index} was refused")
    else
      upload_chunks(database_path, secret, manifest, object_id, upload, index + 1)
    end
  end
end

fn store_attachment(database_path :: String, size :: Int, filename :: String) -> Bytes!String do
  Ok(store_paid_attachment(database_path, size, filename, 0)?.object_id)
end

# A file above 16 MiB carries the credits its bucket costs in front of its grant.

fn store_paid_attachment(database_path :: String,
  size :: Int,
  filename :: String,
  credits :: Int) -> ObjectControl!String do
  let secret = case generate_attachment_key() do
    Err(_) -> Err("attachment key generation failed")
    Ok(value)
  end?
  let manifest = AttachmentManifest {
    version: 2,
    attachment_id: sealed(generate_attachment_id())?,
    chunk_size: 65536,
    chunk_count: (attachment_padded_size(size) + 65535) / 65536,
    plaintext_size: size,
    filename: Bytes.from_utf8(filename),
    mime_type: Bytes.from_utf8("application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    expires_at: wide("700000")?
  }
  let object_id = random_32()?
  let upload = random_32()?
  let ogr = encode_grant(mint_grant(object_id,
    manifest.chunk_count + 1,
    wide("700000")?,
    wide("200000")?,
    upload,
    random_32()?,
    4)?)?
  let request = if credits == 0 do
    ogr
  else
    credits_attach(tokens(size % 200, credits)?, ogr)?
  end
  if grant_with_credits(database_path,
    root(),
    request,
    wide("100000")?,
    wide("300000")?,
    4,
    core).status != 201 do
    return Err("grant was refused")
  end
  let first = sealed(seal_manifest(secret, manifest))?
  if put_part(database_path, root(), object_id, 0, upload, first, wide("100001")?).status != 201 do
    return Err("manifest was refused")
  end
  upload_chunks(database_path, secret, manifest, object_id, upload, 0)?
  Secret.destroy(secret)
  let control = ObjectControl { object_id: object_id, capability: upload }
  if complete(database_path, root(), encode_complete(control)?, wide("100002")?).status != 200 do
    Err("completion was refused")
  else
    Ok(control)
  end
end

# Everything the store keeps about one object's size: its part count, its
# total, and each part's length.

fn stored_sizes(database_path :: String, object_id :: Bytes) -> String!String do
  let database = Pg.connect(database_path)?
  let rows = Pg.query_values(database,
    "SELECT concat(object.part_count, ':', object.total_bytes, ':', string_agg(part.size::text, ',' ORDER BY part.part_index)) AS sizes FROM objects AS object JOIN object_parts AS part ON part.object_id = object.object_id WHERE object.object_id = $1 GROUP BY object.part_count, object.total_bytes",
    [Binary(object_id)])
  Pg.close(database)
  case rows? do
    [row] -> case Map.get(row, "sizes") do
      Text(value) -> Ok(value)
      _ -> Err("stored sizes were not text")
    end
    _ -> Err("stored object was not found")
  end
end

fn proof() -> Result<(), String> do
  let database_path = Env.get("MESSENGER_STORAGE_TEST_DATABASE_URL", "")
  initialize(database_path, root())?
  # 70,000 and 81,920 bytes share the 81,920-byte bucket; 81,921 is in the next.
  # The filenames differ in length too, and the sealed manifest hides that.
  let low = stored_sizes(database_path, store_attachment(database_path, 70000, "a")?)?
  let full = stored_sizes(database_path,
    store_attachment(database_path, 81920, "quarterly-report-final-v3.docx")?)?
  let next = stored_sizes(database_path, store_attachment(database_path, 81921, "b")?)?
  let tiny = stored_sizes(database_path, store_attachment(database_path, 1, "c")?)?
  if low != "3:82514:514,65576,16424" do
    Err("a 70,000-byte file left #{low}")
  else if full != low do
    Err("two files in one bucket left different rows: #{low} and #{full}")
  else if next != "3:98898:514,65576,32808" do
    Err("an 81,921-byte file left #{next}")
  else if tiny != "2:66090:514,65576" do
    Err("a one-byte file left #{tiny}")
  else
    Ok(nil)
  end
end

test("the object store records only an attachment's size bucket") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn repeated_sizes(output :: String, count :: Int) -> String do
  if count <= 0 do
    output
  else
    repeated_sizes(output <> ",65576", count - 1)
  end
end

# 17,000,000 and 20,971,520 bytes share the 20 MiB bucket, which costs one
# credit: 320 full chunks after the manifest, whatever the file's size.

fn large_proof() -> Result<(), String> do
  let database_path = Env.get("MESSENGER_STORAGE_TEST_DATABASE_URL", "")
  initialize(database_path, root())?
  let small = store_paid_attachment(database_path, 17000000, "a", 1)?
  let large = store_paid_attachment(database_path, 20971520, "holiday-2026-full-length.mov", 1)?
  let low = stored_sizes(database_path, small.object_id)?
  let full = stored_sizes(database_path, large.object_id)?
  for control in [small, large] do
    delete_object(database_path, root(), encode_delete(control)?, wide("100003")?)
  end
  let expected = repeated_sizes("321:20984834:514", 320)
  if low != expected do
    Err("a 17,000,000-byte file left #{String.slice(low, 0, 40)}")
  else if full != low do
    Err("two large files in one bucket left different rows")
  else
    Ok(nil)
  end
end

test("the object store records only a large attachment's bucket too") do
  case large_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn ask(database_path :: String,
  request :: Bytes,
  redeem :: Fun(Bytes) -> CreditEdgeResult!String) -> Int!String do
  Ok(grant_with_credits(database_path,
    root(),
    request,
    wide("100000")?,
    wide("300000")?,
    4,
    redeem).status)
end

fn grant_request(object_id :: Bytes, upload :: Bytes, parts :: Int) -> Bytes!String do
  encode_grant(mint_grant(object_id,
    parts,
    wide("700000")?,
    wide("200000")?,
    upload,
    random_32()?,
    4)?)
end

fn check(value :: Bool, message :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(message)
  end
end

fn absent(database_path :: String, object_id :: Bytes, upload :: Bytes) -> Bool!String do
  let control = encode_complete(ObjectControl { object_id: object_id, capability: upload })?
  Ok(complete(database_path, root(), control, wide("100002")?).status == 404)
end

# A 20 MiB grant costs 1 credit and a 40 MiB grant 2. The core redeems a frame
# once; a missing or short frame never reaches it, a spent one (the core's 409)
# grants nothing, and an exact replay of a granted request answers from the
# store. Up to 16 MiB nothing changes.

fn paid_grant_proof() -> Result<(), String> do
  let database_path = Env.get("MESSENGER_STORAGE_TEST_DATABASE_URL", "")
  initialize(database_path, root())?
  let upload = random_32()?
  let twenty_id = random_32()?
  let twenty = grant_request(twenty_id, upload, 321)?
  check(ask(database_path, twenty, never)? == 402, "a 20 MiB grant without credits passed")?
  check(absent(database_path, twenty_id, upload)?, "a refused grant left an object")?
  let paid = credits_attach(tokens(1, 1)?, twenty)?
  check(ask(database_path, paid, core)? == 201, "a 20 MiB grant with 1 credit failed")?
  check(ask(database_path, paid, never)? == 200, "a replayed grant was redeemed again")?
  let forty_id = random_32()?
  let forty = grant_request(forty_id, upload, 641)?
  check(ask(database_path, credits_attach(tokens(2, 1)?, forty)?, never)? == 402,
    "a 40 MiB grant with 1 credit passed")?
  check(ask(database_path, credits_attach(tokens(2, 2)?, forty)?, answering(409))? == 409,
    "a spent frame was granted")?
  check(ask(database_path, credits_attach(tokens(2, 2)?, forty)?, answering(422))? == 422,
    "a frame of forged tokens was granted")?
  check(absent(database_path, forty_id, upload)?, "a refused 40 MiB grant left an object")?
  check(ask(database_path, credits_attach(tokens(2, 2)?, forty)?, core)? == 201,
    "a 40 MiB grant with 2 credits failed")?
  check(ask(database_path, grant_request(random_32()?, upload, 257)?, never)? == 201,
    "a 16 MiB grant asked for credits")?
  check(ask(database_path,
      credits_attach(tokens(9, 1)?, grant_request(random_32()?, upload, 257)?)?,
      never)? == 201,
    "credits on a free grant were spent")?
  let moved = Bytes.concat(Bytes.slice(paid, 0, 391)?, forty)?
  check(ask(database_path, moved, never)? == 400, "a frame moved to another grant was accepted")?
  # The paid object takes exactly its bucket's parts.
  check(put_part(database_path,
      root(),
      twenty_id,
      0,
      upload,
      repeated(1, 513),
      wide("100001")?).status == 400,
    "a short manifest part was stored")?
  check(put_part(database_path,
      root(),
      twenty_id,
      1,
      upload,
      repeated(1, 65608),
      wide("100001")?).status == 400,
    "an oversized chunk part was stored")?
  check(put_part(database_path,
      root(),
      twenty_id,
      321,
      upload,
      repeated(1, 65576),
      wide("100001")?).status == 404,
    "a part past the bucket was stored")?
  check(put_part(database_path,
      root(),
      twenty_id,
      320,
      upload,
      repeated(1, 65576),
      wide("100001")?).status == 201,
    "the last part of a 20 MiB object was refused")?
  let control = encode_complete(ObjectControl { object_id: twenty_id, capability: upload })?
  check(complete(database_path, root(), control, wide("100002")?).status == 409,
    "an incomplete large object completed")
end

test("grants above 16 MiB need the credits their bucket costs, redeemed once") do
  case paid_grant_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
