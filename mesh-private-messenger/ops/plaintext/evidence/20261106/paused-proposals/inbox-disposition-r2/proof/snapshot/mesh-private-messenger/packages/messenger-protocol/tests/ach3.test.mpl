from Tests.LegacyAttachmentFixture import (
  LegacyAttachmentManifest,
  copy_legacy_fixture_manifest,
  legacy_fixture_chunk
)
from Attachments.Protocol import (
  AttachmentError,
  AttachmentManifest,
  generate_attachment_key,
  generate_attachment_id,
  seal_manifest,
  open_chunk,
  seal_bound_chunk,
  open_bound_chunk,
  validate_large_attachment_part
)

fn public_legacy_metadata(value :: AttachmentManifest) -> LegacyAttachmentManifest do
  declassify(copy_legacy_fixture_manifest(value),
    "synthetic public legacy attachment fixture metadata only; no application disclosure")
end

fn wide(value :: String) -> U64!AttachmentError do
  case U64.parse(value) do
    Err(_) -> Err(InvalidManifest)
    Ok(parsed)
  end
end

fn fixture_manifest() -> AttachmentManifest!AttachmentError do
  let id = generate_attachment_id()?
  Ok(AttachmentManifest {
    version: 1,
    attachment_id: id,
    chunk_size: 16,
    chunk_count: 1,
    plaintext_size: 7,
    filename: Bytes.from_utf8("fixture.txt"),
    mime_type: Bytes.from_utf8("text/plain"),
    expires_at: wide("4102444800000")?
  })
end

fn ciphertext_commitment() -> Bool!AttachmentError do
  let secret = generate_attachment_key()?
  let manifest = fixture_manifest()?
  let first = seal_manifest(secret, manifest)?
  let second = seal_manifest(secret, manifest)?
  assert(!Bytes.secure_equals(first, second))
  let wire = seal_bound_chunk(secret, first, 0, Bytes.from_utf8("payload"))?
  assert(fixture_only(opened(open_bound_chunk(secret, first, 0, wire))))
  # The exact EAM ciphertext identity is part of ACH3's authentication.
  # Re-encrypting identical clear metadata must not substitute that identity.
  assert(fixture_only(rejected(open_bound_chunk(secret, second, 0, wire))))
  Ok(true)
end

test("ACH3 binds the exact encrypted manifest even when clear metadata is identical") do
  case ciphertext_commitment() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end

fn fixture_only(value :: Plaintext<Bool>) -> Bool do
  declassify(value, "synthetic public ACH3 fixture equality only; no application disclosure")
end

fn opened(result :: Result<Plaintext<Bytes>, AttachmentError>) -> Plaintext<Bool> do
  Result.is_ok(result)
end

fn rejected(result :: Result<Plaintext<Bytes>, AttachmentError>) -> Plaintext<Bool> do
  Result.is_err(result)
end

fn opened_equals(result :: Result<Plaintext<Bytes>, AttachmentError>,
  expected :: Bytes) -> Plaintext<Bool> do
  case result do
    Ok(value) -> Bytes.secure_equals(value, expected)
    Err(_) -> false
  end
end

fn append(left :: Bytes, right :: Bytes) -> Bytes!AttachmentError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(InvalidChunk)
    Ok(value)
  end
end

fn byte(value :: Int) -> Bytes!AttachmentError do
  case Bytes.from_list([value]) do
    Err(_) -> Err(InvalidChunk)
    Ok(encoded)
  end
end

fn slice(value :: Bytes, offset :: Int, count :: Int) -> Bytes!AttachmentError do
  case Bytes.slice(value, offset, count) do
    Err(_) -> Err(InvalidChunk)
    Ok(output)
  end
end

fn get(value :: Bytes, index :: Int) -> Int!AttachmentError do
  case Bytes.get(value, index) do
    Err(_) -> Err(InvalidChunk)
    Ok(output)
  end
end

fn replace(value :: Bytes,
  offset :: Int,
  count :: Int,
  replacement :: Bytes) -> Bytes!AttachmentError do
  append(append(slice(value, 0, offset)?, replacement)?,
    slice(value, offset + count, Bytes.length(value) - offset - count)?)
end

fn tamper(value :: Bytes, offset :: Int) -> Bytes!AttachmentError do
  let prior = get(value, offset)?
  replace(value,
    offset,
    1,
    byte(if prior == 0 do
      1
    else
      0
    end)?)
end

fn encoded_index(value :: String) -> Bytes!AttachmentError do
  case Bytes.write_u32_be(wide(value)?) do
    Err(_) -> Err(InvalidChunk)
    Ok(output)
  end
end

fn metadata_and_index_binding() -> Bool!AttachmentError do
  let secret = generate_attachment_key()?
  let wrong_secret = generate_attachment_key()?
  let manifest = %{fixture_manifest()? | chunk_count: 2, plaintext_size: 32}
  let envelope = seal_manifest(secret, manifest)?
  let first = Bytes.from_utf8("0123456789abcdef")
  let second = Bytes.from_utf8("fedcba9876543210")
  let zero = seal_bound_chunk(secret, envelope, 0, first)?
  let one = seal_bound_chunk(secret, envelope, 1, second)?
  assert(get(zero, 0)? == 3 && Bytes.length(zero) == 56)
  assert(fixture_only(opened_equals(open_bound_chunk(secret, envelope, 0, zero), first)))
  assert(fixture_only(opened_equals(open_bound_chunk(secret, envelope, 1, one), second)))
  assert(fixture_only(rejected(open_bound_chunk(secret, envelope, 1, zero))))
  # Equal chunk sizes ensure changing only the index must fail AEAD, not size checks.
  assert(fixture_only(rejected(open_bound_chunk(secret,
    envelope,
    1,
    replace(zero, 4, 4, encoded_index("1")?)?))))
  let other_name = seal_manifest(secret, %{manifest | filename: Bytes.from_utf8("other.txt")})?
  let other_mime = seal_manifest(secret, %{manifest | mime_type: Bytes.from_utf8("text/csv")})?
  let other_expiry = seal_manifest(secret, %{manifest | expires_at: wide("4102444800001")?})?
  let other_id = seal_manifest(secret, %{manifest | attachment_id: generate_attachment_id()?})?
  for changed in [other_name, other_mime, other_expiry, other_id] do
    assert(fixture_only(rejected(open_bound_chunk(secret, changed, 0, zero))))
  end
  assert(fixture_only(rejected(open_bound_chunk(wrong_secret, envelope, 0, zero))))
  assert(fixture_only(rejected(seal_bound_chunk(wrong_secret, envelope, 0, first))))
  assert(fixture_only(rejected(open_bound_chunk(secret, envelope, 0, tamper(zero, 8)?))))
  assert(fixture_only(rejected(open_bound_chunk(secret, envelope, 0, tamper(zero, 55)?))))
  assert(fixture_only(rejected(seal_bound_chunk(secret, envelope, 0, Bytes.from_utf8("short")))))
  Ok(true)
end

test("ACH3 rejects metadata substitution, same-size chunk swaps and changed authentication") do
  case metadata_and_index_binding() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end

fn version_and_framing() -> Bool!AttachmentError do
  let secret = generate_attachment_key()?
  let manifest = fixture_manifest()?
  let envelope = seal_manifest(secret, manifest)?
  let payload = Bytes.from_utf8("payload")
  let legacy = legacy_fixture_chunk(secret, public_legacy_metadata(manifest), 0, payload)?
  let current = seal_bound_chunk(secret, envelope, 0, payload)?
  assert(get(legacy, 0)? == 1 && get(current, 0)? == 3)
  assert(fixture_only(opened_equals(open_bound_chunk(secret, envelope, 0, legacy), payload)))
  assert(fixture_only(rejected(open_chunk(secret, manifest, 0, current))))
  for version in [0, 1, 2, 4, 255] do
    assert(fixture_only(rejected(open_bound_chunk(secret,
      envelope,
      0,
      replace(current, 0, 1, byte(version)?)?))))
  end
  assert(fixture_only(rejected(open_bound_chunk(secret,
    envelope,
    0,
    replace(legacy, 0, 1, byte(3)?)?))))
  assert(fixture_only(rejected(open_bound_chunk(secret,
    envelope,
    0,
    replace(current, 1, 3, Bytes.from_utf8("EAM"))?))))
  assert(fixture_only(rejected(open_bound_chunk(secret, envelope, 0, append(current, byte(0)?)?))))
  assert(fixture_only(rejected(open_bound_chunk(secret,
    envelope,
    0,
    slice(current, 0, Bytes.length(current) - 1)?))))
  assert(fixture_only(rejected(open_bound_chunk(secret, envelope, 0, Bytes.empty()))))
  # ACH3 support must not silently accept EAM3 or malformed manifest envelopes.
  assert(fixture_only(rejected(seal_bound_chunk(secret,
    replace(envelope, 0, 1, byte(3)?)?,
    0,
    payload))))
  assert(fixture_only(rejected(open_bound_chunk(secret,
    replace(envelope, 0, 1, byte(3)?)?,
    0,
    current))))
  assert(fixture_only(rejected(open_bound_chunk(secret, append(envelope, byte(0)?)?, 0, current))))
  assert(fixture_only(rejected(open_bound_chunk(secret,
    tamper(envelope, Bytes.length(envelope) - 1)?,
    0,
    current))))
  Ok(true)
end

test("ACH3 keeps legacy reads while refusing version, magic, truncation and trailing confusion") do
  case version_and_framing() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end

fn bounded_large_chunks() -> Bool!AttachmentError do
  let secret = generate_attachment_key()?
  let manifest = %{fixture_manifest()? |
    version: 2,
    chunk_size: 65536,
    chunk_count: 8192,
    plaintext_size: 536870912
  }
  let envelope = seal_manifest(secret, manifest)?
  let payload = case Bytes.repeat(7, 65536) do
    Err(_) -> return Err(InvalidChunk)
    Ok(value) -> value
  end
  let legacy = legacy_fixture_chunk(secret, public_legacy_metadata(manifest), 8191, payload)?
  let current = seal_bound_chunk(secret, envelope, 8191, payload)?
  assert(get(legacy, 0)? == 2 && get(current, 0)? == 3)
  assert(Bytes.length(legacy) == 65576 && Bytes.length(current) == 65576)
  # Object stores admit only bounded public framing. Recipients separately
  # authenticate the exact encrypted manifest and chunk bytes.
  assert(validate_large_attachment_part(manifest.attachment_id,
    manifest.plaintext_size,
    Bytes.length(envelope),
    Crypto.sha256(envelope),
    8192,
    legacy)?)
  assert(validate_large_attachment_part(manifest.attachment_id,
    manifest.plaintext_size,
    Bytes.length(envelope),
    Crypto.sha256(envelope),
    8192,
    current)?)
  assert(!validate_large_attachment_part(manifest.attachment_id,
    manifest.plaintext_size,
    Bytes.length(envelope),
    Crypto.sha256(envelope),
    8191,
    current)?)
  assert(fixture_only(opened_equals(open_bound_chunk(secret, envelope, 8191, legacy), payload)))
  assert(fixture_only(opened_equals(open_bound_chunk(secret, envelope, 8191, current), payload)))
  assert(fixture_only(rejected(open_bound_chunk(secret,
    envelope,
    8191,
    replace(legacy, 0, 1, byte(3)?)?))))
  assert(fixture_only(rejected(open_bound_chunk(secret,
    envelope,
    8191,
    replace(current, 0, 1, byte(2)?)?))))
  assert(fixture_only(rejected(seal_bound_chunk(secret, envelope, -1, payload))))
  assert(fixture_only(rejected(seal_bound_chunk(secret, envelope, 8192, payload))))
  assert(fixture_only(rejected(open_bound_chunk(secret, envelope, 8192, current))))
  let oversized = case Bytes.repeat(7, 65537) do
    Err(_) -> return Err(InvalidChunk)
    Ok(value) -> value
  end
  assert(fixture_only(rejected(seal_bound_chunk(secret, envelope, 8191, oversized))))
  Ok(true)
end

test("ACH3 preserves 64KiB frame and 512MiB index bounds without file-sized buffers") do
  case bounded_large_chunks() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end

fn raw_primitive_oracle() -> Bool!AttachmentError do
  let secret = generate_attachment_key()?
  let manifest = fixture_manifest()?
  let envelope = seal_manifest(secret, manifest)?
  let wire = seal_bound_chunk(secret, envelope, 0, Bytes.from_utf8("payload"))?
  # Decode the documented offsets directly, independently of the chunk decoder.
  assert(Bytes.secure_equals(slice(wire, 0, 4)?, append(byte(3)?, Bytes.from_utf8("ACH"))?))
  assert(Bytes.secure_equals(slice(wire, 4, 4)?, encoded_index("0")?))
  let nonce = slice(wire, 8, 12)?
  let ciphertext = slice(wire, 24, Bytes.length(wire) - 24)?
  let material = case Crypto.hkdf_sha256(secret,
    manifest.attachment_id,
    Bytes.from_utf8("mesh-msg/v3/attachment-key"),
    32) do
    Err(error) -> return Err(CryptoFailure(error))
    Ok(value) -> value
  end
  let key = case Crypto.aead_key(material) do
    Err(error) -> return Err(CryptoFailure(error))
    Ok(value) -> value
  end
  let aad = append(append(Bytes.from_utf8("mesh-msg/v3/attachment-chunk"),
      Crypto.sha256(envelope))?,
    encoded_index("0")?)?
  let plaintext = case Crypto.aead_open(key, nonce, aad, ciphertext) do
    Err(error) -> return Err(CryptoFailure(error))
    Ok(value) -> value
  end
  assert(Bytes.secure_equals(plaintext, Bytes.from_utf8("payload")))
  let wrong_domain = append(append(Bytes.from_utf8("mesh-msg/v2/attachment-chunk"),
      Crypto.sha256(envelope))?,
    encoded_index("0")?)?
  assert(Result.is_err(Crypto.aead_open(key, nonce, wrong_domain, ciphertext)))
  Ok(true)
end

test("ACH3 wire offsets, KDF and exact ciphertext AAD match the raw public primitives") do
  case raw_primitive_oracle() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end
