import File
from MobileCore import privacy_submission_export
from Privacy.Edge import decode_privacy_submission, open_delivery, verify_submission
from Tests.Support import append, vector

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn delivery_seed() -> Bytes ! String do
  case Bytes.from_hex(Env.get("MESSENGER_DELIVERY_SEALING_SEED_HEX",
  "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")) do
    Err( _) -> Err("invalid test delivery seed")
    Ok( value) -> Ok(value)
  end
end

fn key_pair(seed :: Bytes) -> X25519KeyPair ! String do
  case Crypto.x25519_from_seed(seed) do
    Err( _) -> Err("test delivery key generation failed")
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

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("test byte encoding failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn proof() -> Bool ! String do
  let seed = delivery_seed() ?
  let pair = key_pair(seed) ?
  let outer = fixture_outer() ?
  let request = join([vector(outer) ?, vector(pair.public_key.bytes) ?, vector(byte(8) ?) ?],
  0,
  Bytes.empty()) ?
  let started_at = now() ?
  let submission = privacy_submission_export(request) ?
  assert(verify_submission(submission, started_at, wide("600000") ?, 8) ?)
  let decoded = decode_privacy_submission(submission) ?
  assert(Bytes.secure_equals(open_delivery(decoded.sealed, seed) ?, outer))
  let output_path = Env.get("MESSENGER_M13_SUBMISSION_PATH", "")
  if String.length(output_path) > 0 do
    File.write_bytes(output_path, 0, submission, true) ?
  else
    nil
  end
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
