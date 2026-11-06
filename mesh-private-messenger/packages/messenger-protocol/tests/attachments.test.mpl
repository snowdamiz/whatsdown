from Tests.LegacyAttachmentFixture import (
  LegacyAttachmentManifest,
  copy_legacy_fixture_manifest,
  legacy_fixture_chunk
)
from Attachments.Protocol import (
  AttachmentError,
  AttachmentManifest,
  generate_attachment_id,
  generate_attachment_key,
  open_chunk,
  open_manifest,
  seal_manifest
)

fn public_legacy_metadata(value :: AttachmentManifest) -> LegacyAttachmentManifest do
  declassify(copy_legacy_fixture_manifest(value),
    "synthetic public legacy attachment fixture metadata only; no application disclosure")
end

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

fn fixture_only(value :: Plaintext<Bool>) -> Bool do
  declassify(value, "synthetic public attachment fixture equality only; no application disclosure")
end

fn opened_equals(result :: Result<Plaintext<Bytes>, AttachmentError>,
  expected :: Bytes) -> Plaintext<Bool> do
  case result do
    Ok(value) -> Bytes.secure_equals(value, expected)
    Err(_) -> false
  end
end

fn rejected_as(result :: Result<Plaintext<Bytes>, AttachmentError>,
  expected :: Int) -> Plaintext<Bool> do
  case result do
    Err(AuthenticationRejected) -> expected == 1
    Err(InvalidChunkIndex) -> expected == 2
    Err(InvalidChunkSize) -> expected == 3
    _ -> false
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
  assert(opened_manifest.chunk_size == 16
    && opened_manifest.chunk_count == 2
    && opened_manifest.plaintext_size == 21)
  assert(U64.compare(opened_manifest.expires_at, manifest.expires_at) == 0)
  assert(fixture_only(Bytes.secure_equals(opened_manifest.filename, manifest.filename)))
  assert(fixture_only(Bytes.secure_equals(opened_manifest.mime_type, manifest.mime_type)))
  let first = Bytes.from_utf8("0123456789abcdef")
  let second = Bytes.from_utf8("final")
  let first_wire = legacy_fixture_chunk(key, public_legacy_metadata(opened_manifest), 0, first)?
  let second_wire = legacy_fixture_chunk(key, public_legacy_metadata(opened_manifest), 1, second)?
  assert(fixture_only(opened_equals(open_chunk(key, opened_manifest, 0, first_wire), first)))
  assert(fixture_only(opened_equals(open_chunk(key, opened_manifest, 1, second_wire), second)))
  assert(fixture_only(rejected_as(open_chunk(key,
      opened_manifest,
      0,
      tamper_last_byte(first_wire)?),
    1)))
  assert(fixture_only(rejected_as(open_chunk(key, opened_manifest, 1, first_wire), 2)))
  assert(fixture_only(rejected_as(legacy_fixture_chunk(key,
      public_legacy_metadata(opened_manifest),
      1,
      Bytes.from_utf8("not-final")),
    3)))
  Secret.destroy(key)
  Ok(true)
end

test("attachment manifest and two chunks round trip within canonical bounds") do
  case attachment_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
