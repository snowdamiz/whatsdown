from Transparency.Note import (
  note_add_checkpoint_request,
  note_checkpoint_body,
  note_cosign,
  note_cosignature_message,
  note_key_id,
  note_open_checkpoint,
  note_read_cosignatures,
  note_sign,
  note_verifier_key,
  note_verify_cosignature
)

fn signer(seed :: Int) -> SigningKeyPair!String do
  let bytes = case Bytes.repeat(seed, 32) do
    Err(_) -> Err("seed failed")
    Ok(value)
  end?
  case Crypto.signing_from_seed(bytes) do
    Err(_) -> Err("signing key failed")
    Ok(value)
  end
end

fn repeated(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("bytes failed")
    Ok(output)
  end
end

fn failed(result :: Result<String, String>) -> Bool do
  case result do
    Ok(_) -> false
    Err(_) -> true
  end
end

# The signed-note specification's own example: its verifier key and the
# signature it prints over "This is an example message.\n".

fn signed_note_example() -> Bool!String do
  let vkey = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
  let material = case Bytes.from_base64("AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k") do
    Err(_) -> Err("base64 failed")
    Ok(value)
  end?
  let public_key = case Bytes.slice(material, 1, 32) do
    Err(_) -> Err("slice failed")
    Ok(value)
  end?
  assert(Bytes.to_hex(note_key_id("example.com/foo", 1, public_key)?) == "530d903a")
  assert(note_verifier_key("example.com/foo", 1, public_key)? == vkey)
  let line = case Bytes.from_base64("Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=") do
    Err(_) -> Err("base64 failed")
    Ok(value)
  end?
  let signature = case Bytes.slice(line, 4, 64) do
    Err(_) -> Err("slice failed")
    Ok(value)
  end?
  let valid = case Crypto.verify(SigningPublicKey { bytes: public_key },
    Bytes.from_utf8("This is an example message.\n"),
    Signature { bytes: signature }) do
    Err(_) -> false
    Ok(value) -> value
  end
  assert(valid)
  Ok(true)
end

test("key IDs, verifier keys and signed text match the signed-note specification's example") do
  case signed_note_example() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn checkpoint_note() -> Bool!String do
  let log = signer(7)?
  let root = repeated(3, 32)?
  let ktk = repeated(1, 188)?
  let body = note_checkpoint_body("morseapp.io/log/main", 42, root, ktk)?
  assert(body == "morseapp.io/log/main\n42\n"
      <> Bytes.to_base64(root)
      <> "\nmorse-checkpoint "
      <> Bytes.to_base64(ktk)
      <> "\n")
  let note = note_sign(body, "morseapp.io/log/main", log.private_key, log.public_key.bytes)?
  let key_id = note_key_id("morseapp.io/log/main", 1, log.public_key.bytes)?
  assert(String.starts_with(note, body <> "\n— morseapp.io/log/main "))
  assert(String.ends_with(note, "\n"))
  let opened = note_open_checkpoint(note, "morseapp.io/log/main", log.public_key.bytes)?
  assert(opened.body == body && opened.tree_size == 42)
  assert(Bytes.secure_equals(opened.root, root)
    && Bytes.secure_equals(opened.checkpoint_bytes, ktk))
  let signature_value = case Bytes.from_base64(List.last(String.split(String.trim_end(note),
    " "))) do
    Err(_) -> Err("base64 failed")
    Ok(value)
  end?
  case Bytes.slice(signature_value, 0, 4) do
    Ok(prefix) -> assert(Bytes.secure_equals(prefix, key_id))
    Err(_) -> assert(false)
  end
  let other = signer(8)?
  let foreign = note_cosign(body,
    "witness.example/w1",
    other.private_key,
    other.public_key.bytes,
    1700000000)?
  let cosigned = note <> foreign
  assert(note_open_checkpoint(cosigned,
    "morseapp.io/log/main",
    log.public_key.bytes)?.tree_size == 42)
  Ok(true)
end

test("checkpoint notes carry origin, size, RFC 6962 root and the Morse checkpoint, signed by the log") do
  case checkpoint_note() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn opens(note :: String, origin :: String, key :: Bytes) -> Bool do
  case note_open_checkpoint(note, origin, key) do
    Ok(_) -> true
    Err(_) -> false
  end
end

fn hostile_notes() -> Bool!String do
  let log = signer(7)?
  let other = signer(9)?
  let origin = "morseapp.io/log/main"
  let root = repeated(3, 32)?
  let ktk = repeated(1, 188)?
  let body = note_checkpoint_body(origin, 42, root, ktk)?
  let note = note_sign(body, origin, log.private_key, log.public_key.bytes)?
  assert(opens(note, origin, log.public_key.bytes))
  assert(!opens(note, "morseapp.io/log/canary", log.public_key.bytes))
  assert(!opens(note, origin, other.public_key.bytes))
  assert(!opens(String.replace(note, "\n42\n", "\n43\n"), origin, log.public_key.bytes))
  let padded = note_sign(String.replace(body, "\n42\n", "\n042\n"),
    origin,
    log.private_key,
    log.public_key.bytes)?
  assert(!opens(padded, origin, log.public_key.bytes))
  let forged = note_sign(body, origin, other.private_key, other.public_key.bytes)?
  assert(!opens(forged, origin, log.public_key.bytes))
  let mismatched = body
    <> "\n— "
    <> origin
    <> " "
    <> Bytes.to_base64(Bytes.concat(note_key_id(origin, 1, log.public_key.bytes)?,
      repeated(0, 64)?)?)
    <> "\n"
  assert(!opens(mismatched, origin, log.public_key.bytes))
  assert(!opens(mismatched <> List.get(String.split(note, "\n\n"), 1),
    origin,
    log.public_key.bytes))
  assert(!opens(String.replace(note, "\n\n", "\n"), origin, log.public_key.bytes))
  assert(!opens(String.replace(note, "morse-checkpoint", "morse-checkpoint\t"),
    origin,
    log.public_key.bytes))
  assert(failed(note_checkpoint_body("morseapp.io/log main", 1, root, ktk)))
  assert(failed(note_checkpoint_body(origin, 1, root, repeated(1, 187)?)))
  assert(failed(note_sign("two\n\nparagraphs\n", origin, log.private_key, log.public_key.bytes)))
  Ok(true)
end

test("notes with a wrong origin, key, size, encoding or failing log signature are refused") do
  case hostile_notes() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn cosignatures() -> Bool!String do
  let witness = signer(11)?
  let other = signer(12)?
  let body = note_checkpoint_body("morseapp.io/log/main", 42, repeated(3, 32)?, repeated(1, 188)?)?
  let message = note_cosignature_message(1700000000, body)?
  assert(Bytes.secure_equals(message, Bytes.from_utf8("cosignature/v1\ntime 1700000000\n" <> body)))
  let line = note_cosign(body,
    "witness.example/w1",
    witness.private_key,
    witness.public_key.bytes,
    1700000000)?
  let decoded = case Bytes.from_base64(String.trim_end(List.get(String.split(line, " "), 2))) do
    Err(_) -> Err("base64 failed")
    Ok(value)
  end?
  assert(Bytes.length(decoded) == 76)
  let noise = note_cosign(body,
    "witness.example/w2",
    other.private_key,
    other.public_key.bytes,
    1700000001)?
  let read = note_read_cosignatures(noise <> line,
    "witness.example/w1",
    witness.public_key.bytes,
    body)?
  assert(List.length(read) == 1)
  let value = List.get(read, 0)
  assert(value.timestamp == 1700000000)
  assert(note_verify_cosignature(witness.public_key.bytes, 1700000000, value.signature, body))
  assert(!note_verify_cosignature(witness.public_key.bytes, 1700000001, value.signature, body))
  assert(!note_verify_cosignature(witness.public_key.bytes,
    1700000000,
    value.signature,
    String.replace(body, "\n42\n", "\n43\n")))
  let none = note_read_cosignatures(noise, "witness.example/w1", witness.public_key.bytes, body)?
  assert(List.length(none) == 0)
  let other_body = String.replace(body, "\n42\n", "\n43\n")
  case note_read_cosignatures(line, "witness.example/w1", witness.public_key.bytes, other_body) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  case note_read_cosignatures("— witness.example/w1 !!!\n",
    "witness.example/w1",
    witness.public_key.bytes,
    body) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  Ok(true)
end

test("cosignature/v1 lines sign the timestamped body and are read back by name and key ID") do
  case cosignatures() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn add_checkpoint_requests() -> Bool!String do
  let first = repeated(1, 32)?
  let second = repeated(2, 32)?
  let request = note_add_checkpoint_request(5, [first, second], "NOTE\n")?
  assert(request == "old 5\n"
      <> Bytes.to_base64(first)
      <> "\n"
      <> Bytes.to_base64(second)
      <> "\n\nNOTE\n")
  assert(note_add_checkpoint_request(0, [], "NOTE\n")? == "old 0\n\nNOTE\n")
  assert(failed(note_add_checkpoint_request(0, [first], "NOTE\n")))
  let too_many = for index in 0..64 do
    first
  end
  assert(failed(note_add_checkpoint_request(9, too_many, "NOTE\n")))
  assert(failed(note_add_checkpoint_request(9, [repeated(1, 31)?], "NOTE\n")))
  Ok(true)
end

test("add-checkpoint requests follow tlog-witness: old size, proof lines, blank line, note") do
  case add_checkpoint_requests() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
