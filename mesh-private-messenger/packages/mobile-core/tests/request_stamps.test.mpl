import File
from MobileCore import create_account_export, directory_entry_export, register_request_export, resolve_request_export, transparency_lookup_export
from Privacy.Edge import RequestStamp, decode_stamped_request, verify_request_stamp
from Tests.Support import append, database_path, install_security_config, vector

fn request(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    request(values, index + 1, append(output, vector(List.get(values, index)) ?) ?)
  end
end

# The device mines at the difficulty its signed native configuration names (8
# here), which is what the directory will demand.

fn paid_for(label :: String, payload :: Bytes, stamp :: RequestStamp) -> Bool ! String do
  let now = U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()))) ?
  verify_request_stamp(label, payload, stamp, now, U64.parse("300000") ?, 8)
end

fn signing_pair() -> SigningKeyPair ! String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test signing key generation failed")
    Ok(value) -> Ok(value)
  end
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let service_pair = signing_pair() ?
  let witness_a = signing_pair() ?
  let witness_b = signing_pair() ?
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> Err("test delivery key generation failed")
    Ok(value) -> Ok(value)
  end ?
  assert(install_security_config(service_pair.public_key.bytes,
  witness_a.public_key.bytes,
  witness_b.public_key.bytes,
  delivery.public_key.bytes,
  8))
  let path = database_path("request-stamps") ?
  let _ = create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8("alice")],
  0,
  Bytes.empty()) ?) ?
  let register = "mesh-msg/v1/work/register"
  let resolve = "mesh-msg/v1/work/resolve"
  # Registration carries the unchanged directory entry inside paid work.
  let (register_stamp, entry) = decode_stamped_request(register_request_export(Bytes.from_utf8(path)) ?,
  36006) ?
  assert(Bytes.secure_equals(entry, directory_entry_export(Bytes.from_utf8(path)) ?))
  assert(paid_for(register, entry, register_stamp) ?)
  # So does a lookup, under its own endpoint's label.
  let lookup_request = request([Bytes.from_utf8(path), Bytes.from_utf8("bob")], 0, Bytes.empty()) ?
  let (resolve_stamp, lookup) = decode_stamped_request(resolve_request_export(lookup_request) ?, 76) ?
  assert(Bytes.secure_equals(lookup, transparency_lookup_export(lookup_request) ?))
  assert(paid_for(resolve, lookup, resolve_stamp) ?)
  # That work for one endpoint buys nothing at another is proved on fixed
  # inputs in the protocol's `privacy_edge.test.mpl`. Here the inputs are live,
  # and at this difficulty one stamp in 256 suits the other label by chance.
  File.delete(path) ?
  Ok(true)
end

test("anonymous directory requests leave the device wrapped in work for their own endpoint") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
