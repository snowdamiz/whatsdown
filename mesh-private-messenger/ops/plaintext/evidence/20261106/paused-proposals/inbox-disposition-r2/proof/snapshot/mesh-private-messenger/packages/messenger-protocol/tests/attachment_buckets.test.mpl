from Attachments.Protocol import (
  AttachmentManifest,
  AttachmentError,
  generate_attachment_key,
  seal_manifest,
  open_manifest,
  seal_bound_chunk,
  open_bound_chunk
)

fn bytes(value :: Int, count :: Int) -> Bytes!AttachmentError do
  case Bytes.repeat(value, count) do
    Err(_) -> Err(InvalidManifest)
    Ok(output)
  end
end

fn exact(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "synthetic public attachment size-bucket fixture equality only; no application disclosure")
end

fn opened_equals(result :: Result<Plaintext<Bytes>, AttachmentError>,
  expected :: Bytes) -> Plaintext<Bool> do
  case result do
    Ok(value) -> Bytes.secure_equals(value, expected)
    Err(_) -> false
  end
end

fn proof() -> Bool!AttachmentError do
  let key = generate_attachment_key()?
  let expires = case U64.parse("4102444800000") do
    Err(_) -> return Err(InvalidManifest)
    Ok(value) -> value
  end
  for size in [1, 65535, 65536, 65537, 16777216, 16777217, 536870911, 536870912] do
    let count = (size + 65535) / 65536
    let manifest = AttachmentManifest {
      version: 4,
      attachment_id: bytes(17, 32)?,
      chunk_size: 65536,
      chunk_count: count,
      plaintext_size: size,
      filename: Bytes.empty(),
      mime_type: Bytes.from_utf8("x"),
      expires_at: expires
    }
    let encrypted = seal_manifest(key, manifest)?
    assert(Bytes.length(encrypted) == 514)
    let long = seal_manifest(key,
      %{manifest | filename: bytes(110, 255)?, mime_type: bytes(109, 127)?})?
    assert(Bytes.length(long) == 514)
    let opened = open_manifest(key, encrypted)?
    assert(opened.version == 4 && opened.plaintext_size == size && opened.chunk_count == count)
    let length = size - (count - 1) * 65536
    let input = bytes(31, length)?
    let chunk = seal_bound_chunk(key, encrypted, count - 1, input)?
    assert(Bytes.length(chunk) == 65576)
    assert(Bytes.get(chunk, 0) == Ok(4))
    assert(exact(opened_equals(open_bound_chunk(key, encrypted, count - 1, chunk), input)))
    # A different exact encrypted manifest (even same metadata) is not reusable.
    assert(exact(Result.is_err(open_bound_chunk(key, long, count - 1, chunk))))
    assert(exact(Result.is_err(open_bound_chunk(key, encrypted, count, chunk))))
    assert(Result.is_err(seal_bound_chunk(key, encrypted, count - 1, Bytes.empty())))
  end
  Secret.destroy(key)
  Ok(true)
end

test("bucket profile4 fixes manifest and final chunk lengths while returning only exact file bytes") do
  case proof() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end
