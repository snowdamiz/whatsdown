from Attachments.Protocol import AttachmentError, AttachmentManifest, generate_attachment_id, generate_attachment_key, open_chunk, open_manifest, seal_chunk, seal_manifest

fn repeated(value :: Int, count :: Int) -> Bytes!AttachmentError do
  case Bytes.repeat(value, count) do
    Err(_) -> Err(InvalidManifest)
    Ok(output)
  end
end

fn wide(value :: String) -> U64!AttachmentError do
  case U64.parse(value) do
    Err(_) -> Err(InvalidManifest)
    Ok(output)
  end
end

fn tamper_last_byte(input :: Bytes) -> Bytes!AttachmentError do
  let length = Bytes.length(input)
  let last = case Bytes.get(input, length - 1) do
    Err(_) -> Err(InvalidChunk)
    Ok(value)
  end?
  let prefix = case Bytes.slice(input, 0, length - 1) do
    Err(_) -> Err(InvalidChunk)
    Ok(value)
  end?
  let replacement = if last == 120 do
    Bytes.from_utf8("y")
  else
    Bytes.from_utf8("x")
  end
  case Bytes.concat(prefix, replacement) do
    Err(_) -> Err(InvalidChunk)
    Ok(value)
  end
end

fn attachment_proof() -> Bool!AttachmentError do
  let key = generate_attachment_key()?
  let attachment_id = generate_attachment_id()?
  assert(Bytes.length(attachment_id) == 32)
  let manifest = AttachmentManifest {
    version: 1,
    attachment_id: attachment_id,
    chunk_size: 16,
    chunk_count: 2,
    plaintext_size: 21,
    filename: Bytes.from_utf8("field-notes.txt"),
    mime_type: Bytes.from_utf8("text/plain"),
    expires_at: wide("4102444800000")?
  }
  let manifest_wire = seal_manifest(key, manifest)?
  assert(Bytes.length(manifest_wire) <= 514)
  let opened_manifest = open_manifest(key, manifest_wire)?
  assert(Bytes.secure_equals(opened_manifest.attachment_id, manifest.attachment_id))
  assert(opened_manifest.chunk_size == 16 && opened_manifest.chunk_count == 2 && opened_manifest.plaintext_size == 21)
  assert(U64.compare(opened_manifest.expires_at, manifest.expires_at) == 0)
  assert(Bytes.secure_equals(opened_manifest.filename, manifest.filename))
  assert(Bytes.secure_equals(opened_manifest.mime_type, manifest.mime_type))
  let first = Bytes.from_utf8("0123456789abcdef")
  let second = Bytes.from_utf8("final")
  let first_wire = seal_chunk(key, opened_manifest, 0, first)?
  let second_wire = seal_chunk(key, opened_manifest, 1, second)?
  assert(Bytes.secure_equals(open_chunk(key, opened_manifest, 0, first_wire)?, first))
  assert(Bytes.secure_equals(open_chunk(key, opened_manifest, 1, second_wire)?, second))
  case open_chunk(key, opened_manifest, 0, tamper_last_byte(first_wire)?) do
    Err(AuthenticationRejected) -> assert(true)
    _ -> assert(false)
  end
  case open_chunk(key, opened_manifest, 1, first_wire) do
    Err(InvalidChunkIndex) -> assert(true)
    _ -> assert(false)
  end
  case seal_chunk(key, opened_manifest, 1, Bytes.from_utf8("not-final")) do
    Err(InvalidChunkSize) -> assert(true)
    _ -> assert(false)
  end
  Secret.destroy(key)
  Ok(true)
end

test("attachment manifest and two chunks round trip within canonical bounds") do
  case attachment_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
