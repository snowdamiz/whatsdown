from Transparency.C2spText import (
  checkpoint_origin,
  checkpoint_note_text,
  verify_checkpoint_cosignature
)
from Transparency.Merkle import TransparencyCheckpoint, verify_checkpoint
from Transparency.Wire import encode_checkpoint, decode_checkpoint

pub struct NoteSignature do
  name :: String
  key_id :: Bytes
  signature :: Bytes
end

pub struct SignedCheckpointNote do
  checkpoint :: TransparencyCheckpoint
  signatures :: List<NoteSignature>
end

fn valid_name(value :: String) -> Bool do
  let bytes = Bytes.from_utf8(value)
  if Bytes.length(bytes) < 1
    || Bytes.length(bytes) > 255
    || String.contains(value, "+")
    || Regex.is_match(~r/\s/, value) do
    return false
  end
  for index in 0..Bytes.length(bytes) do
    case Bytes.get(bytes, index) do
      Err(_) -> return false
      Ok(value) -> if value < 32 do
        return false
      end
    end
  end
  true
end

pub fn note_key_id(name :: String, algorithm :: Int, public_key :: Bytes) -> Bytes!String do
  if !valid_name(name) || (algorithm != 1 && algorithm != 4) || Bytes.length(public_key) != 32 do
    return Err("invalid_c2sp_key")
  end
  let tag = if algorithm == 1 do
    Bytes.from_hex("01")?
  else
    Bytes.from_hex("04")?
  end
  let input = Bytes.concat(Bytes.from_utf8(name <> "\n"), Bytes.concat(tag, public_key)?)?
  Bytes.slice(Crypto.sha256(input), 0, 4)
end

pub fn signature_line(name :: String,
  algorithm :: Int,
  public_key :: Bytes,
  signature :: Bytes) -> String!String do
  if (algorithm == 1 && Bytes.length(signature) != 64)
    || (algorithm == 4 && Bytes.length(signature) != 72) do
    return Err("invalid_c2sp_signature")
  end
  let payload = Bytes.concat(note_key_id(name, algorithm, public_key)?, signature)?
  Ok("— " <> name <> " " <> Bytes.to_base64(payload) <> "\n")
end

pub fn sign_checkpoint_note(checkpoint :: TransparencyCheckpoint,
  signing_key :: borrow SigningPrivateKey) -> Bytes!String do
  let public_key = SigningPublicKey { bytes: checkpoint.service_public_key }
  if !verify_checkpoint(checkpoint, public_key)? do
    return Err("invalid_c2sp_checkpoint_signature")
  end
  let text = checkpoint_note_text(encode_checkpoint(checkpoint)?)?
  let signature = case Crypto.sign(signing_key, Bytes.from_utf8(text)) do
    Err(_) -> return Err("c2sp_note_signing_failed")
    Ok(value) -> value
  end
  let bound = case Crypto.verify(public_key, Bytes.from_utf8(text), signature) do
    Err(_) -> false
    Ok(value) -> value
  end
  if !bound do
    return Err("c2sp_note_signing_key_mismatch")
  end
  Ok(Bytes.from_utf8(text
    <> "\n"
    <> signature_line(checkpoint_origin(), 1, public_key.bytes, signature.bytes)?))
end

fn base64(value :: String) -> Bytes!String do
  let bytes = Bytes.from_base64(value)?
  if Bytes.to_base64(bytes) != value do
    Err("noncanonical_c2sp_base64")
  else
    Ok(bytes)
  end
end

fn valid_signatures(values :: List<NoteSignature>) -> Bool do
  if List.length(values) < 1 || List.length(values) > 16 do
    return false
  end
  for index in 0..List.length(values) do
    let value = List.get(values, index)
    if !valid_name(value.name)
      || Bytes.length(value.key_id) != 4
      || Bytes.length(value.signature) < 1
      || Bytes.length(value.signature) > 8192 do
      return false
    end
    for prior in 0..index do
      let other = List.get(values, prior)
      if other.name == value.name && Bytes.secure_equals(other.key_id, value.key_id) do
        return false
      end
    end
  end
  true
end

# This accepts unknown algorithms as bounded opaque signatures. Verification
# selects the exact trusted name and algorithm-specific ID, never an ID alone.
pub fn decode_signature_lines(input :: Bytes) -> List<NoteSignature>!String do
  if Bytes.length(input) > 196608 do
    return Err("c2sp_note_too_large")
  end
  let text = Bytes.to_utf8(input)?
  if !String.ends_with(text, "\n") do
    return Err("invalid_c2sp_signature_lines")
  end
  let lines = String.split(text, "\n")
  if List.length(lines) < 2 || List.length(lines) > 17 do
    return Err("invalid_c2sp_signature_count")
  end
  let values = for index in 0..(List.length(lines) - 1) do
    let fields = String.split(List.get(lines, index), " ")
    if List.length(fields) != 3 || List.head(fields) != "—" do
      return Err("invalid_c2sp_signature_line")
    end
    let payload = base64(List.get(fields, 2))?
    if Bytes.length(payload) < 5 || Bytes.length(payload) > 8196 do
      return Err("invalid_c2sp_signature_size")
    end
    NoteSignature {
      name: List.get(fields, 1),
      key_id: Bytes.slice(payload, 0, 4)?,
      signature: Bytes.slice(payload, 4, Bytes.length(payload) - 4)?
    }
  end
  if !valid_signatures(values) do
    Err("invalid_c2sp_signatures")
  else
    Ok(values)
  end
end

# The Morse profile has exactly one extension line. Rejecting additional text
# prevents a verifier from accidentally checking a reconstructed, different note.
pub fn decode_checkpoint_note(input :: Bytes) -> SignedCheckpointNote!String do
  if Bytes.length(input) > 196608 do
    return Err("c2sp_note_too_large")
  end
  let parts = String.split(Bytes.to_utf8(input)?, "\n\n")
  if List.length(parts) != 2 do
    return Err("invalid_c2sp_note")
  end
  let lines = String.split(List.head(parts), "\n")
  if List.length(lines) != 4 do
    return Err("invalid_c2sp_checkpoint_text")
  end
  let extension = String.split(List.get(lines, 3), " ")
  if List.length(extension) != 2 || List.head(extension) != "morse-checkpoint" do
    return Err("invalid_c2sp_checkpoint_extension")
  end
  let wire = base64(List.get(extension, 1))?
  let checkpoint = decode_checkpoint(wire)?
  if checkpoint_note_text(wire)? != List.head(parts) <> "\n"
    || !Bytes.secure_equals(encode_checkpoint(checkpoint)?, wire) do
    return Err("inconsistent_c2sp_checkpoint")
  end
  Ok(SignedCheckpointNote {
    checkpoint: checkpoint,
    signatures: decode_signature_lines(Bytes.from_utf8(List.get(parts, 1)))?
  })
end

pub fn verify_checkpoint_note(note :: SignedCheckpointNote,
  trusted_log :: SigningPublicKey) -> Bool!String do
  if !valid_signatures(note.signatures) || !verify_checkpoint(note.checkpoint, trusted_log)? do
    return Ok(false)
  end
  let id = note_key_id(checkpoint_origin(), 1, trusted_log.bytes)?
  let text = Bytes.from_utf8(checkpoint_note_text(encode_checkpoint(note.checkpoint)?)?)
  for value in note.signatures do
    if value.name == checkpoint_origin() && Bytes.secure_equals(value.key_id, id) do
      if Bytes.length(value.signature) != 64 do
        return Ok(false)
      end
      return case Crypto.verify(trusted_log, text, Signature { bytes: value.signature }) do
        Err(_) -> Ok(false)
        Ok(valid)
      end
    end
  end
  Ok(false)
end

# Callers additionally verify the log signature and authorization freshness.
pub fn verified_cosignature(note :: SignedCheckpointNote,
  name :: String,
  trusted_witness :: SigningPublicKey) -> Bytes!String do
  if !valid_signatures(note.signatures) do
    return Err("invalid_c2sp_signatures")
  end
  let id = note_key_id(name, 4, trusted_witness.bytes)?
  let wire = encode_checkpoint(note.checkpoint)?
  for value in note.signatures do
    if value.name == name && Bytes.secure_equals(value.key_id, id) do
      if !verify_checkpoint_cosignature(wire, value.signature, trusted_witness)? do
        return Err("invalid_c2sp_cosignature")
      end
      return Ok(value.signature)
    end
  end
  Err("missing_c2sp_cosignature")
end
