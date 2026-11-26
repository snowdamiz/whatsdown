##! The C2SP view of the key log: a tlog-checkpoint note over the RFC 6962
##! tree of Morse leaf hashes, signed by the log with a signed-note Ed25519
##! signature (type 0x01), cosigned by witnesses with tlog-cosignature v1
##! (type 0x04), and pushed with the tlog-witness add-checkpoint request.

from Transparency.Codec import tcodec_decimal, tcodec_join, tcodec_u64, tcodec_u8
from Transparency.Tree import tlog_size_limit

pub struct NoteCheckpoint do
  body :: String
  origin :: String
  tree_size :: Int
  root :: Bytes
  checkpoint_bytes :: Bytes
end

pub struct NoteCosignature do
  timestamp :: Int
  signature :: Bytes
end

struct SignatureLine do
  name :: String
  key_id :: Bytes
  signature :: Bytes
end

# Key names and origins: 1-255 bytes of printable ASCII without space or '+'
# (the specs forbid spaces and '+'; Morse also keeps them ASCII).

fn valid_name(name :: String) -> Bool do
  let bytes = Bytes.to_list(Bytes.from_utf8(name))
  List.length(bytes) > 0
    && List.length(bytes) <= 255
    && List.all(bytes, fn byte -> byte > 32 && byte < 127 && byte != 43 end)
end

fn slice(value :: Bytes, start :: Int, length :: Int) -> Bytes!String do
  case Bytes.slice(value, start, length) do
    Err(_) -> Err("invalid note")
    Ok(output)
  end
end

pub fn note_key_id(name :: String, signature_type :: Int, public_key :: Bytes) -> Bytes!String do
  if !valid_name(name) || Bytes.length(public_key) != 32 do
    Err("invalid note key")
  else
    let digest = Crypto.sha256(tcodec_join([
      Bytes.from_utf8(name <> "\n"),
      tcodec_u8(signature_type)?,
      public_key
    ])?)
    slice(digest, 0, 4)
  end
end

# <name>+<hex key ID>+<base64(type || public key)>, as witnessctl add-key takes it.

pub fn note_verifier_key(name :: String,
  signature_type :: Int,
  public_key :: Bytes) -> String!String do
  let key_id = note_key_id(name, signature_type, public_key)?
  let material = tcodec_join([tcodec_u8(signature_type)?, public_key])?
  Ok(name <> "+" <> Bytes.to_hex(key_id) <> "+" <> Bytes.to_base64(material))
end

pub fn note_checkpoint_body(origin :: String,
  tree_size :: Int,
  root :: Bytes,
  checkpoint_bytes :: Bytes) -> String!String do
  if !valid_name(origin)
    || tree_size < 0
    || tree_size >= tlog_size_limit()
    || Bytes.length(root) != 32
    || Bytes.length(checkpoint_bytes) != 188 do
    Err("invalid checkpoint note")
  else
    Ok(origin
      <> "\n"
      <> Int.to_string(tree_size)
      <> "\n"
      <> Bytes.to_base64(root)
      <> "\nmorse-checkpoint "
      <> Bytes.to_base64(checkpoint_bytes)
      <> "\n")
  end
end

fn signature_line(name :: String, value :: Bytes) -> String do
  "— " <> name <> " " <> Bytes.to_base64(value) <> "\n"
end

fn signed(signing_key :: borrow SigningPrivateKey,
  public_key :: Bytes,
  message :: Bytes) -> Bytes!String do
  let signature = case Crypto.sign(signing_key, message) do
    Err(_) -> Err("note signing failed")
    Ok(value)
  end?
  case Crypto.verify(SigningPublicKey { bytes: public_key }, message, signature) do
    Ok(true) -> Ok(signature.bytes)
    _ -> Err("note signing failed")
  end
end

# A signed note: the body (ending in a newline), a blank line, then the
# Ed25519 note signature of the log under key name `name`.

pub fn note_sign(body :: String,
  name :: String,
  signing_key :: borrow SigningPrivateKey,
  public_key :: Bytes) -> String!String do
  if !String.ends_with(body, "\n") || String.contains(body, "\n\n") do
    Err("invalid note")
  else
    let key_id = note_key_id(name, 1, public_key)?
    let signature = signed(signing_key, public_key, Bytes.from_utf8(body))?
    Ok(body <> "\n" <> signature_line(name, tcodec_join([key_id, signature])?))
  end
end

pub fn note_cosignature_message(timestamp :: Int, body :: String) -> Bytes!String do
  if timestamp < 0 do
    Err("invalid cosignature")
  else
    Ok(Bytes.from_utf8("cosignature/v1\ntime " <> Int.to_string(timestamp) <> "\n" <> body))
  end
end

# One tlog-cosignature v1 line: base64(key ID || u64 timestamp || signature).

pub fn note_cosign(body :: String,
  name :: String,
  signing_key :: borrow SigningPrivateKey,
  public_key :: Bytes,
  timestamp :: Int) -> String!String do
  let key_id = note_key_id(name, 4, public_key)?
  let signature = signed(signing_key, public_key, note_cosignature_message(timestamp, body)?)?
  Ok(signature_line(name, tcodec_join([key_id, tcodec_u64(timestamp)?, signature])?))
end

pub fn note_verify_cosignature(public_key :: Bytes,
  timestamp :: Int,
  signature :: Bytes,
  body :: String) -> Bool do
  if Bytes.length(public_key) != 32 || Bytes.length(signature) != 64 do
    false
  else
    case note_cosignature_message(timestamp, body) do
      Err(_) -> false
      Ok(message) -> case Crypto.verify(SigningPublicKey { bytes: public_key },
        message,
        Signature { bytes: signature }) do
        Ok(valid) -> valid
        Err(_) -> false
      end
    end
  end
end

fn canonical_base64(text :: String) -> Bytes!String do
  case Bytes.from_base64(text) do
    Err(_) -> Err("invalid note")
    Ok(value) -> if Bytes.to_base64(value) == text do
      Ok(value)
    else
      Err("invalid note")
    end
  end
end

fn parse_signature_line(line :: String) -> SignatureLine!String do
  let fields = String.split(String.slice(line, 2, String.length(line)), " ")
  if !String.starts_with(line, "— ") || List.length(fields) != 2 do
    Err("invalid note signature")
  else
    let name = List.get(fields, 0)
    let value = canonical_base64(List.get(fields, 1))?
    if !valid_name(name) || Bytes.length(value) < 5 do
      Err("invalid note signature")
    else
      Ok(SignatureLine {
        name: name,
        key_id: slice(value, 0, 4)?,
        signature: slice(value, 4, Bytes.length(value) - 4)?
      })
    end
  end
end

fn text_allowed(text :: String) -> Bool do
  List.all(Bytes.to_list(Bytes.from_utf8(text)), fn byte -> byte >= 32 || byte == 10 end)
end

# Signature lines each end in a newline; at most 64 are read.

fn signature_lines(block :: String) -> List<SignatureLine>!String do
  let lines = String.split(block, "\n")
  let count = List.length(lines) - 1
  if !String.ends_with(block, "\n") || count < 1 || count > 64 do
    Err("invalid note signature")
  else
    Ok(for index in 0..count do
      parse_signature_line(List.get(lines, index))?
    end)
  end
end

fn matching(lines :: List<SignatureLine>, name :: String, key_id :: Bytes) -> List<SignatureLine> do
  List.filter(lines, fn line -> line.name == name && Bytes.secure_equals(line.key_id, key_id) end)
end

fn log_signature_valid(line :: SignatureLine, log_key :: Bytes, body :: String) -> Bool do
  Bytes.length(line.signature) == 64
    && case Crypto.verify(SigningPublicKey { bytes: log_key },
      Bytes.from_utf8(body),
      Signature { bytes: line.signature }) do
      Ok(valid) -> valid
      Err(_) -> false
    end
end

fn extension_checkpoint(lines :: List<String>) -> Bytes!String do
  let found = List.filter(lines, fn line -> String.starts_with(line, "morse-checkpoint ") end)
  if List.length(found) == 0 do
    Ok(Bytes.empty())
  else if List.length(found) > 1 do
    Err("invalid checkpoint note")
  else
    let value = canonical_base64(String.slice(List.get(found, 0), 17, 1000))?
    if Bytes.length(value) != 188 do
      Err("invalid checkpoint note")
    else
      Ok(value)
    end
  end
end

fn parse_body(body :: String, origin :: String) -> NoteCheckpoint!String do
  let all = String.split(body, "\n")
  let lines = List.take(all, List.length(all) - 1)
  if List.length(lines) < 3
    || List.any(lines, fn line -> String.length(line) == 0 end)
    || List.get(lines, 0) != origin do
    Err("invalid checkpoint note")
  else
    let size = case tcodec_decimal(List.get(lines, 1)) do
      Err(_) -> Err("invalid checkpoint note")
      Ok(value)
    end?
    let root = canonical_base64(List.get(lines, 2))?
    if Bytes.length(root) != 32 do
      Err("invalid checkpoint note")
    else
      Ok(NoteCheckpoint {
        body: body,
        origin: origin,
        tree_size: size,
        root: root,
        checkpoint_bytes: extension_checkpoint(List.drop(lines, 3))?
      })
    end
  end
end

fn split_note(note :: String) -> (String, String)!String do
  let parts = String.split(note, "\n\n")
  let count = List.length(parts)
  if count < 2 || Bytes.length(Bytes.from_utf8(note)) > 16384 || !text_allowed(note) do
    Err("invalid note")
  else
    Ok((String.join(List.take(parts, count - 1), "\n\n") <> "\n", List.get(parts, count - 1)))
  end
end

# Opens a checkpoint note signed by the log key under the origin's key name.
# Unknown signatures are ignored; a failing signature from the log key rejects
# the note, as signed-note requires.

pub fn note_open_checkpoint(note :: String,
  origin :: String,
  log_key :: Bytes) -> NoteCheckpoint!String do
  let (body, block) = split_note(note)?
  let key_id = note_key_id(origin, 1, log_key)?
  let candidates = matching(signature_lines(block)?, origin, key_id)
  if List.length(candidates) == 0 do
    Err("checkpoint note unsigned")
  else if !List.all(candidates, fn line -> log_signature_valid(line, log_key, body) end) do
    Err("checkpoint note signature invalid")
  else
    parse_body(body, origin)
  end
end

fn cosignature_of(line :: SignatureLine,
  public_key :: Bytes,
  body :: String) -> NoteCosignature!String do
  if Bytes.length(line.signature) != 72 do
    Err("invalid cosignature")
  else
    let timestamp = case Bytes.read_u64_be(line.signature, 0) do
      Err(_) -> Err("invalid cosignature")
      Ok(wide) -> case U64.to_int(wide) do
        Err(_) -> Err("invalid cosignature")
        Ok(value)
      end
    end?
    let signature = slice(line.signature, 8, 64)?
    if note_verify_cosignature(public_key, timestamp, signature, body) do
      Ok(NoteCosignature { timestamp: timestamp, signature: signature })
    else
      Err("cosignature invalid")
    end
  end
end

# Reads an add-checkpoint response (one or more signature lines) and returns
# the witness's verified cosignatures over body. Lines from other keys are
# ignored; a line from this key that fails to verify is an error.

pub fn note_read_cosignatures(response :: String,
  name :: String,
  public_key :: Bytes,
  body :: String) -> List<NoteCosignature>!String do
  if !text_allowed(response) do
    Err("invalid note signature")
  else
    let key_id = note_key_id(name, 4, public_key)?
    let lines = matching(signature_lines(response)?, name, key_id)
    Ok(for line in lines do
      cosignature_of(line, public_key, body)?
    end)
  end
end

# tlog-witness add-checkpoint body: "old N", one base64 line per RFC 6962
# consistency-proof hash (at most 63), a blank line, then the signed note.

pub fn note_add_checkpoint_request(old_size :: Int,
  proof :: List<Bytes>,
  signed_note :: String) -> String!String do
  if old_size < 0
    || List.length(proof) > 63
    || (old_size == 0 && List.length(proof) > 0)
    || !List.all(proof, fn hash -> Bytes.length(hash) == 32 end) do
    Err("invalid add-checkpoint request")
  else
    let lines = List.map(proof, fn hash -> Bytes.to_base64(hash) <> "\n" end)
    Ok("old " <> Int.to_string(old_size) <> "\n" <> String.join(lines, "") <> "\n" <> signed_note)
  end
end
