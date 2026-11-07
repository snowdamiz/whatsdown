from Attachments.Protocol import (
  AttachmentManifest,
  AttachmentError,
  generate_attachment_key,
  generate_attachment_id,
  seal_manifest,
  open_manifest
)

fn wide(text :: String) -> U64!AttachmentError do
  case U64.parse(text) do
    Err(_) -> Err(InvalidManifest)
    Ok(value)
  end
end

fn repeat(value :: Int, count :: Int) -> Bytes!AttachmentError do
  case Bytes.repeat(value, count) do
    Err(_) -> Err(InvalidManifest)
    Ok(value)
  end
end

fn invalid(value :: Result<Bytes, AttachmentError>) -> Bool do
  case value do
    Err(InvalidManifest) -> true
    _ -> false
  end
end

fn fixture_only(value :: Plaintext<Bool>) -> Bool do
  declassify(value, "synthetic public manifest fixture equality only; no application disclosure")
end

fn opened_header_matches(result :: Result<AttachmentManifest, AttachmentError>,
  expected :: AttachmentManifest) -> Plaintext<Bool> do
  case result do
    Ok(value) -> value.version == expected.version
      && value.plaintext_size == expected.plaintext_size
    Err(_) -> false
  end
end

fn opened_filename_matches(result :: Result<AttachmentManifest, AttachmentError>,
  expected :: AttachmentManifest) -> Plaintext<Bool> do
  case result do
    Ok(value) -> Bytes.secure_equals(value.filename, expected.filename)
    Err(_) -> false
  end
end

fn opened_mime_matches(result :: Result<AttachmentManifest, AttachmentError>,
  expected :: AttachmentManifest) -> Plaintext<Bool> do
  case result do
    Ok(value) -> Bytes.secure_equals(value.mime_type, expected.mime_type)
    Err(_) -> false
  end
end

fn manifest_seal_proof() -> Bool!AttachmentError do
  let key = generate_attachment_key()?
  let id = generate_attachment_id()?
  let first = AttachmentManifest {
    version: 1,
    attachment_id: id,
    chunk_size: 16,
    chunk_count: 1,
    plaintext_size: 8,
    filename: repeat(97, 255)?,
    mime_type: repeat(98, 127)?,
    expires_at: wide("4102444800000")?
  }
  for manifest in [
    first,
    %{first | version: 2, chunk_size: 65536, chunk_count: 8192, plaintext_size: 536870912}
  ] do
    let wire = seal_manifest(key, manifest)?
    let actual_version = case Bytes.get(wire, 0) do
      Err(_) -> return Err(InvalidManifest)
      Ok(value) -> value
    end
    assert(actual_version == manifest.version)
    let opened = open_manifest(key, wire)
    assert(fixture_only(opened_header_matches(opened, manifest)))
    assert(fixture_only(opened_filename_matches(opened, manifest)))
    assert(fixture_only(opened_mime_matches(opened, manifest)))
  end
  for manifest in [
    %{first | filename: repeat(97, 256)?},
    %{first | mime_type: Bytes.empty()},
    %{first | mime_type: repeat(98, 128)?},
    %{first | attachment_id: repeat(1, 31)?},
    # Raw encryption would fail its HKDF salt bound; original admission wins.
    %{first | attachment_id: repeat(1, 65537)?},
    %{first | version: 3},
    %{first | version: 2}
  ] do
    assert(invalid(seal_manifest(key, manifest)))
  end
  Ok(true)
end

test("private manifest admission cannot publish encrypted fallback and legacy formats still open") do
  case manifest_seal_proof() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end
