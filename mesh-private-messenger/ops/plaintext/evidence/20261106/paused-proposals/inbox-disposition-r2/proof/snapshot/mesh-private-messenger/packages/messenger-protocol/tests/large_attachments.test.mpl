from Tests.LegacyAttachmentFixture import (
  LegacyAttachmentManifest,
  copy_legacy_fixture_manifest,
  legacy_fixture_chunk
)
from Attachments.Protocol import (
  AttachmentError,
  AttachmentManifest,
  generate_attachment_key,
  open_chunk,
  open_manifest,
  seal_manifest
)

fn public_legacy_metadata(value :: AttachmentManifest) -> LegacyAttachmentManifest do
  declassify(copy_legacy_fixture_manifest(value),
    "synthetic public legacy attachment fixture metadata only; no application disclosure")
end

fn bytes(value :: Int, count :: Int) -> Bytes!AttachmentError do
  case Bytes.repeat(value, count) do
    Err(_) -> Err(InvalidManifest)
    Ok(output)
  end
end

fn exact(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "synthetic public large attachment fixture equality only; no application disclosure")
end

fn opened_equals(result :: Result<Plaintext<Bytes>, AttachmentError>,
  expected :: Bytes) -> Plaintext<Bool> do
  case result do
    Ok(value) -> Bytes.secure_equals(value, expected)
    Err(_) -> false
  end
end

fn opened_length(result :: Result<Plaintext<Bytes>, AttachmentError>,
  expected :: Int) -> Plaintext<Bool> do
  case result do
    Ok(value) -> Bytes.length(value) == expected
    Err(_) -> false
  end
end

fn proof() -> Bool!AttachmentError do
  let key = generate_attachment_key()?
  let expiry = case U64.parse("4102444800000") do
    Err(_) -> return Err(InvalidManifest)
    Ok(value) -> value
  end
  let manifest = AttachmentManifest {
    version: 2,
    attachment_id: bytes(11, 32)?,
    chunk_size: 65536,
    chunk_count: 257,
    plaintext_size: 16777217,
    filename: Bytes.from_utf8("large.bin"),
    mime_type: Bytes.from_utf8("application/octet-stream"),
    expires_at: expiry
  }
  let encoded = seal_manifest(key, manifest)?
  assert(Bytes.length(encoded) <= 514)
  let opened = open_manifest(key, encoded)?
  assert(opened.version == 2 && opened.chunk_count == 257 && opened.plaintext_size == 16777217)
  let final = legacy_fixture_chunk(key, public_legacy_metadata(opened), 256, bytes(29, 1)?)?
  assert(Bytes.length(final) == 41)
  assert(exact(opened_equals(open_chunk(key, opened, 256, final), bytes(29, 1)?)))
  let maximum = %{manifest | plaintext_size: 536870912, chunk_count: 8192}
  let last = legacy_fixture_chunk(key, public_legacy_metadata(maximum), 8191, bytes(31, 65536)?)?
  assert(Bytes.length(last) == 65576)
  assert(exact(opened_length(open_chunk(key, maximum, 8191, last), 65536)))
  assert(Result.is_err(legacy_fixture_chunk(key,
    public_legacy_metadata(maximum),
    8192,
    bytes(1, 1)?)))
  assert(Result.is_err(seal_manifest(key, %{maximum | plaintext_size: 536870913})))
  assert(Result.is_err(seal_manifest(key, %{maximum | chunk_count: 8193})))
  assert(Result.is_err(seal_manifest(key, %{manifest | version: 1})))
  assert(Result.is_err(seal_manifest(key,
    %{manifest | plaintext_size: 16777216, chunk_count: 256})))
  assert(Result.is_err(seal_manifest(key, %{manifest | chunk_size: 65535})))
  # A v2 public frame cannot be relabeled as legacy v1. Authentication and
  # per-version limits remain independent; every actor input stays <=64KiB.
  let legacy = %{manifest | version: 1, plaintext_size: 65536, chunk_count: 1}
  assert(exact(Result.is_err(open_chunk(key, legacy, 0, last))))
  Secret.destroy(key)
  Ok(true)
end

test("large attachment v2 streams bounded chunks through 512MiB without widening legacy v1") do
  case proof() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end
