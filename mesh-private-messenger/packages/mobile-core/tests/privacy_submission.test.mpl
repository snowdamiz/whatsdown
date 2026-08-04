import File
from MobileCore import privacy_submission_export
from Privacy.Edge import decode_privacy_submission, open_delivery_with_key, verify_submission
from Tests.Support import install_security_config, repeated

fn delivery_key_pair() -> X25519KeyPair ! String do
  let material = case Env.get_secret_hex("MESSENGER_DELIVERY_SEALING_SEED_HEX") do
    Err( _) -> Err("invalid test delivery seed")
    Ok( value) -> Ok(value)
  end ?
  case Crypto.x25519_from_secret(material) do
    Err( _) -> Err("test delivery key generation failed")
    Ok( value) -> Ok(value)
  end
end

fn signing_pair() -> SigningKeyPair ! String do
  case Crypto.signing_generate() do
    Err( _) -> Err("test signing key generation failed")
    Ok( value) -> Ok(value)
  end
end

fn fixture_outer() -> Bytes ! String do
  case Bytes.from_hex("014d5347000102030405060708090a0b0c0d0e0f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00010000018bcfe568000000010000000008a0a1a2a3a4a5a6a7") do
    Err( _) -> Err("invalid test outer envelope")
    Ok( value) -> Ok(value)
  end
end

fn now() -> U64 ! String do
  case U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()))) do
    Err( _) -> Err("test clock conversion failed")
    Ok( value) -> Ok(value)
  end
end

fn wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err( _) -> Err("test integer conversion failed")
    Ok( parsed) -> Ok(parsed)
  end
end

fn proof() -> Bool ! String do
  let pair = delivery_key_pair() ?
  let service_pair = signing_pair() ?
  let witness_a = signing_pair() ?
  let witness_b = signing_pair() ?
  assert(install_security_config(service_pair.public_key.bytes,
  witness_a.public_key.bytes,
  witness_b.public_key.bytes,
  pair.public_key.bytes,
  8))
  let outer = fixture_outer() ?
  let started_at = now() ?
  let submission = privacy_submission_export(outer) ?
  assert(verify_submission(submission, started_at, wide("600000") ?, 8) ?)
  let decoded = decode_privacy_submission(submission) ?
  assert(Bytes.secure_equals(open_delivery_with_key(decoded.sealed, pair.private_key) ?, outer))
  let output_path = Env.get("MESSENGER_M13_SUBMISSION_PATH", "")
  if String.length(output_path) > 0 do
    File.write_bytes(output_path, 0, submission, true) ?
  else
    nil
  end
  Ok(true)
end

fn config_frame(service_hex :: String,
witness_a_hex :: String,
witness_b_hex :: String,
delivery_hex :: String,
difficulty :: String) -> Bytes do
  Bytes.from_utf8("1\n" <> service_hex <> "\n" <> witness_a_hex <> "\n" <> witness_b_hex <> "\n" <> delivery_hex <> "\n" <> difficulty)
end

fn rejects_config(frame :: Bytes, outer :: Bytes) -> Bool ! String do
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame))
  case privacy_submission_export(outer) do
    Err( error) -> Ok(error == "invalid_messenger_configuration")
    Ok( _) -> Ok(false)
  end
end

fn config_validation_proof() -> Bool ! String do
  let outer = fixture_outer() ?
  case privacy_submission_export(outer) do
    Err( error) -> assert(error == "messenger_configuration_required")
    Ok( _) -> assert(false)
  end
  let service_pair = signing_pair() ?
  let witness_a = signing_pair() ?
  let witness_b = signing_pair() ?
  let delivery_pair = case Crypto.x25519_generate() do
    Err( _) -> Err("test delivery key generation failed")
    Ok( value) -> Ok(value)
  end ?
  let service_hex = Bytes.to_hex(service_pair.public_key.bytes)
  let first_witness = Bytes.to_hex(witness_a.public_key.bytes)
  let second_witness = Bytes.to_hex(witness_b.public_key.bytes)
  let delivery = Bytes.to_hex(delivery_pair.public_key.bytes)
  assert(rejects_config(config_frame("AB" <> String.slice(service_hex, 2, 64),
  first_witness,
  second_witness,
  delivery,
  "8"),
  outer) ?)
  assert(rejects_config(config_frame(service_hex, first_witness, first_witness, delivery, "8"),
  outer) ?)
  assert(rejects_config(config_frame(service_hex,
  first_witness,
  second_witness,
  Bytes.to_hex(repeated(0, 32) ?),
  "8"),
  outer) ?)
  assert(rejects_config(config_frame(service_hex, first_witness, second_witness, delivery, "0"),
  outer) ?)
  assert(rejects_config(config_frame(service_hex, first_witness, second_witness, delivery, "25"),
  outer) ?)
  assert(rejects_config(config_frame(service_hex, first_witness, second_witness, delivery, "08"),
  outer) ?)
  assert(rejects_config(Bytes.from_utf8("1\n" <> service_hex <> "\n" <> first_witness <> "\n" <> second_witness <> "\n" <> delivery <> "\n8\n"),
  outer) ?)
  Ok(true)
end

test("mobile privacy submission is canonical sealed delivery produced in Mesh") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end

test("mobile security config rejects missing and noncanonical native resources") do
  case config_validation_proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
