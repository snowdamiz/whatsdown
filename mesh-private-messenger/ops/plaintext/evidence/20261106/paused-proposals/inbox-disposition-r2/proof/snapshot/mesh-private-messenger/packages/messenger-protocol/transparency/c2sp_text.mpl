# C2SP v1.1.0 Ed25519 checkpoint profile. This module operates on canonical
# checkpoint bytes to keep note serialization independent of the Merkle and
# wire modules. Its callers authenticate the KTK service signature separately.

pub fn checkpoint_origin() -> String do
  "morseapp.io/log/main/v2"
end

fn wide_at(input :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(input, offset) do
    Err(_) -> Err("invalid_c2sp_integer")
    Ok(value)
  end
end

pub fn checkpoint_note_text(checkpoint :: Bytes) -> String!String do
  if Bytes.length(checkpoint) != 188
    || !Bytes.secure_equals(Bytes.slice(checkpoint, 0, 4)?, Bytes.from_hex("024b544b")?) do
    return Err("invalid_c2sp_checkpoint")
  end
  let size = wide_at(checkpoint, 12)?
  if U64.compare(size, U64.parse("4294967295")?) > 0 do
    return Err("invalid_c2sp_checkpoint")
  end
  let root = Bytes.slice(checkpoint, 20, 32)?
  if U64.compare(size, U64.parse("0")?) == 0
    && !Bytes.secure_equals(root, Crypto.sha256(Bytes.empty())) do
    return Err("invalid_c2sp_empty_root")
  end
  Ok(checkpoint_origin()
    <> "\n"
    <> U64.to_string(size)
    <> "\n"
    <> Bytes.to_base64(root)
    <> "\nmorse-checkpoint "
    <> Bytes.to_base64(checkpoint)
    <> "\n")
end

pub fn verify_checkpoint_cosignature(checkpoint :: Bytes,
  cosignature :: Bytes,
  public_key :: SigningPublicKey) -> Bool!String do
  if Bytes.length(cosignature) != 72 || Bytes.length(public_key.bytes) != 32 do
    return Ok(false)
  end
  let note = case checkpoint_note_text(checkpoint) do
    Err(_) -> return Ok(false)
    Ok(value) -> value
  end
  let seconds = wide_at(cosignature, 0)?
  let text = "cosignature/v1\ntime " <> U64.to_string(seconds) <> "\n" <> note
  let signature = Signature { bytes: Bytes.slice(cosignature, 8, 64)? }
  case Crypto.verify(public_key, Bytes.from_utf8(text), signature) do
    Err(_) -> Ok(false)
    Ok(value)
  end
end

# Freshness is deliberately separate from cryptographic verification: fork
# evidence must remain verifiable after a checkpoint's authorization window.
pub fn cosignature_fresh_at(cosignature :: Bytes, now_ms :: U64) -> Bool!String do
  if Bytes.length(cosignature) != 72 do
    return Ok(false)
  end
  let signed_ms = case U64.multiply(wide_at(cosignature, 0)?, U64.parse("1000")?) do
    Err(_) -> return Ok(false)
    Ok(value) -> value
  end
  if U64.compare(signed_ms, now_ms) > 0 do
    Ok(U64.compare(U64.subtract(signed_ms, now_ms)?, U64.parse("60000")?) <= 0)
  else
    Ok(U64.compare(U64.subtract(now_ms, signed_ms)?, U64.parse("300000")?) <= 0)
  end
end
