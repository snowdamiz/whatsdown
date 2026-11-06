from Attachments.Protocol import AttachmentManifest, AttachmentError, seal_manifest, open_manifest

fn value(filename :: Plaintext<Bytes>, mime :: Plaintext<Bytes>) -> AttachmentManifest!String do
  Ok(AttachmentManifest {
    version: 1,
    attachment_id: Result.unwrap_or(Bytes.repeat(9, 32), Bytes.empty()),
    chunk_size: 16,
    chunk_count: 1,
    plaintext_size: 1,
    filename: filename,
    mime_type: mime,
    expires_at: U64.parse("4102444800000")?
  })
end

fn accepted(key :: borrow SecretBytes,
  filename :: Plaintext<Bytes>,
  mime :: Plaintext<Bytes>,
  size :: Int) -> Bool do
  let manifest = case value(filename, mime) do
    Err(_) -> return false
    Ok(value) -> value
  end
  case seal_manifest(key, manifest) do
    Err(_) -> false
    Ok(wire) -> case open_manifest(key, wire) do
      Err(_) -> false
      Ok(opened) -> Bytes.length(wire) == size
        && Bytes.secure_equals(opened.filename, filename)
        && Bytes.secure_equals(opened.mime_type, mime)
    end
  end
end

fn rejected(key :: borrow SecretBytes,
  filename :: Plaintext<Bytes>,
  mime :: Plaintext<Bytes>) -> Bool do
  let manifest = case value(filename, mime) do
    Err(_) -> return false
    Ok(value) -> value
  end
  case seal_manifest(key, manifest) do
    Err(InvalidManifest) -> true
    _ -> false
  end
end

fn boundaries() -> Bool do
  let key = case Secret.random(32) do
    Err(_) -> return false
    Ok(key) -> key
  end
  let filename = Result.unwrap_or(Bytes.repeat(110, 255), Bytes.empty())
  let mime = Result.unwrap_or(Bytes.repeat(97, 127), Bytes.empty())
  let valid = accepted(key, filename, mime, 514)
    && accepted(key, Bytes.empty(), Bytes.from_utf8("x"), 133)
    && rejected(key, Result.unwrap_or(Bytes.repeat(110, 256), Bytes.empty()), mime)
    && rejected(key, filename, Bytes.empty())
    && rejected(key, filename, Result.unwrap_or(Bytes.repeat(97, 128), Bytes.empty()))
  Secret.destroy(key)
  valid
end

test("reviewed manifest framing preserves exact bounds and encrypted metadata round trips") do
  assert(declassify(boundaries(),
    "synthetic attachment framing boundary fixture equality only; no application disclosure"))
end
