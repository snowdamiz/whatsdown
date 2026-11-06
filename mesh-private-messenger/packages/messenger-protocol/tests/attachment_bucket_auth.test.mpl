from Attachments.Protocol import (
  AttachmentError,
  AttachmentManifest,
  generate_attachment_key,
  seal_manifest,
  open_manifest,
  seal_bound_chunk,
  open_bound_chunk
)

fn joined(parts :: List<Bytes>) -> Bytes!String do
  case Bytes.concat_many(parts, 70000) do
    Err(_) -> Err("fixture_join_failed")
    Ok(value)
  end
end

fn u32(value :: Int) -> Bytes!String do
  case Bytes.write_u32_be(U64.parse(Int.to_string(value))?) do
    Err(_) -> Err("fixture_integer_failed")
    Ok(value)
  end
end

fn repeated(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("fixture_bytes_failed")
    Ok(value)
  end
end

fn octet(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("fixture_byte_failed")
    Ok(value)
  end
end

fn wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("fixture_integer_failed")
    Ok(value)
  end
end

fn exact(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "synthetic public padded attachment authentication fixture equality only; no application disclosure")
end

fn protocol_bytes(value :: Result<Bytes, AttachmentError>) -> Bytes!String do
  case value do
    Err(_) -> Err("fixture_protocol_failed")
    Ok(value)
  end
end

fn key_for(secret :: borrow SecretBytes, id :: Bytes, version :: Int) -> AeadKey!String do
  let material = case Crypto.hkdf_sha256(secret,
    id,
    Bytes.from_utf8("mesh-msg/v#{version}/attachment-key"),
    32) do
    Err(_) -> return Err("fixture_key_failed")
    Ok(value) -> value
  end
  case Crypto.aead_key(material) do
    Err(_) -> Err("fixture_key_failed")
    Ok(value)
  end
end

fn sealed(key :: borrow AeadKey,
  nonce :: Bytes,
  aad :: Bytes,
  plaintext :: Bytes) -> Bytes!String do
  case Crypto.aead_seal(key, nonce, aad, plaintext) do
    Err(_) -> Err("fixture_seal_failed")
    Ok(value)
  end
end

fn manifest_wire(secret :: borrow SecretBytes, id :: Bytes, bad_tail :: Bool) -> Bytes!String do
  let prefix = joined([
    Bytes.from_hex("04414d46")?,
    id,
    u32(65536)?,
    u32(1)?,
    u32(1)?,
    wide(U64.parse("4102444800000")?)?,
    u32(1)?,
    Bytes.from_utf8("a"),
    u32(1)?,
    Bytes.from_utf8("x")
  ])?
  let body = joined([
    prefix,
    repeated(0, 445 - Bytes.length(prefix))?,
    octet(if bad_tail do
      1
    else
      0
    end)?
  ])?
  let nonce = repeated(61, 12)?
  let key = key_for(secret, id, 4)?
  let ciphertext = sealed(key,
    nonce,
    joined([Bytes.from_utf8("mesh-msg/v4/attachment-manifest"), id])?,
    body)?
  joined([Bytes.from_hex("0445414d")?, id, nonce, u32(Bytes.length(ciphertext))?, ciphertext])
end

fn chunk_wire(secret :: borrow SecretBytes,
  id :: Bytes,
  manifest :: Bytes,
  version :: Int,
  bad_tail :: Bool) -> Bytes!String do
  let body = joined([
    octet(31)?,
    repeated(0, 65534)?,
    octet(if bad_tail do
      1
    else
      0
    end)?
  ])?
  let nonce = repeated(62, 12)?
  let key = key_for(secret, id, version)?
  let aad = joined([
    Bytes.from_utf8("mesh-msg/v#{version}/attachment-chunk"),
    Crypto.sha256(manifest),
    u32(0)?
  ])?
  let ciphertext = sealed(key, nonce, aad, body)?
  joined([
    octet(version)?,
    Bytes.from_utf8("ACH"),
    u32(0)?,
    nonce,
    u32(Bytes.length(ciphertext))?,
    ciphertext
  ])
end

fn chunk_equals(value :: Result<Plaintext<Bytes>, AttachmentError>,
  expected :: Bytes) -> Plaintext<Bool> do
  case value do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, expected)
  end
end

fn raw_equals(value :: Result<Plaintext<Bytes>, CryptoError>,
  expected :: Bytes) -> Plaintext<Bool> do
  case value do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, expected)
  end
end

fn proof() -> Bool!String do
  let secret = case generate_attachment_key() do
    Err(_) -> return Err("fixture_key_failed")
    Ok(value) -> value
  end
  let id = repeated(17, 32)?
  let wire = manifest_wire(secret, id, false)?
  assert(Bytes.length(wire) == 514)
  let opened = case open_manifest(secret, wire) do
    Err(_) -> return Err("fixture_manifest_failed")
    Ok(value) -> value
  end
  assert(opened.version == 4 && opened.plaintext_size == 1)
  assert(exact(Result.is_err(open_manifest(secret, manifest_wire(secret, id, true)?))))
  let chunk = chunk_wire(secret, id, wire, 4, false)?
  assert(exact(chunk_equals(open_bound_chunk(secret, wire, 0, chunk), octet(31)?)))
  # Authenticated but noncanonical tail padding must not produce file bytes.
  assert(exact(Result.is_err(open_bound_chunk(secret,
    wire,
    0,
    chunk_wire(secret, id, wire, 4, true)?))))
  # A key holder cannot downgrade a new manifest to an otherwise valid ACH3.
  assert(exact(Result.is_err(open_bound_chunk(secret,
    wire,
    0,
    chunk_wire(secret, id, wire, 3, false)?))))
  let own = protocol_bytes(seal_bound_chunk(secret, wire, 0, octet(31)?))?
  assert(Bytes.length(own) == 65576)
  let key = key_for(secret, id, 4)?
  let nonce = Bytes.slice(own, 8, 12)?
  let aad = joined([Bytes.from_utf8("mesh-msg/v4/attachment-chunk"), Crypto.sha256(wire), u32(0)?])?
  assert(exact(raw_equals(Crypto.aead_open(key, nonce, aad, Bytes.slice(own, 24, 65552)?),
    joined([octet(31)?, repeated(0, 65535)?])?)))
  Secret.destroy(secret)
  Ok(true)
end

test("profile4 wire uses independent v4 primitives and rejects authenticated noncanonical padding and downgrade") do
  case proof() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end
