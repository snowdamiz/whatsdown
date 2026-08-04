import File
from MobileCore import create_account_export, directory_entry_export, transparency_lookup_export, verify_transparency_export
from Protocol.V1 import DeviceSet, decode_account_identity, decode_directory_entry, encode_device_set
from Tests.Support import append, database_path, install_security_config, repeated, vector
from Transparency.Merkle import consistency_proof, inclusion_proof, leaf_hash, sign_checkpoint, sign_witness
from Transparency.Wire import TransparencyEvidence, decode_transparency_lookup, encode_transparency_evidence

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err( _) -> Err("test integer conversion failed")
    Ok( parsed) -> Ok(parsed)
  end
end

fn signing_pair() -> SigningKeyPair ! String do
  case Crypto.signing_generate() do
    Err( _) -> Err("test signing key generation failed")
    Ok( value) -> Ok(value)
  end
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("transparency") ?
  let path_bytes = Bytes.from_utf8(path)
  let username_bytes = Bytes.from_utf8("alice")
  let account_request = append(vector(path_bytes) ?, vector(username_bytes) ?) ?
  let _ = create_account_export(account_request) ?
  let entry_bytes = directory_entry_export(Bytes.from_utf8(path)) ?
  let output_path = Env.get("MESSENGER_M13_DIRECTORY_ENTRY_PATH", "")
  if String.length(output_path) > 0 do
    File.write_bytes(output_path, 0, entry_bytes, true) ?
  else
    nil
  end
  let entry = case decode_directory_entry(entry_bytes) do
    Err( _) -> Err("directory entry decode failed")
    Ok( value) -> Ok(value)
  end ?
  let account = case decode_account_identity(entry.account_identity) do
    Err( _) -> Err("account identity decode failed")
    Ok( value) -> Ok(value)
  end ?
  let device_set = case encode_device_set(DeviceSet {
    version : 1,
    username : entry.username,
    account_identity : entry.account_identity,
    sequence : account.directory_sequence,
    devices : [entry],
    revoked_device_ids : List.new()
  }) do
    Err( _) -> Err("device set encode failed")
    Ok( value) -> Ok(value)
  end ?
  let leaves = [leaf_hash(device_set) ?]
  let service_pair = signing_pair() ?
  let witness_a = signing_pair() ?
  let witness_b = signing_pair() ?
  let delivery_pair = case Crypto.x25519_generate() do
    Err( _) -> Err("test delivery key generation failed")
    Ok( value) -> Ok(value)
  end ?
  assert(install_security_config(service_pair.public_key.bytes,
  witness_a.public_key.bytes,
  witness_b.public_key.bytes,
  delivery_pair.public_key.bytes,
  8))
  let checkpoint = sign_checkpoint(service_pair.private_key,
  service_pair.public_key.bytes,
  wide("1") ?,
  leaves,
  repeated(0, 32) ?,
  wide("1000") ?) ?
  let evidence = case encode_transparency_evidence(TransparencyEvidence {
    entry_bytes : device_set,
    inclusion : inclusion_proof(leaves, 0) ?,
    consistency : consistency_proof(List.new(), leaves) ?,
    checkpoint : checkpoint,
    witnesses : [sign_witness("witness-a", witness_a.private_key, checkpoint) ?, sign_witness("witness-b",
    witness_b.private_key,
    checkpoint) ?]
  }) do
    Err( _) -> Err("transparency evidence encode failed")
    Ok( value) -> Ok(value)
  end ?
  let path_vector = vector(path_bytes) ?
  let username_vector = vector(username_bytes) ?
  let evidence_vector = vector(evidence) ?
  let request = join([path_vector, username_vector, evidence_vector], 0, Bytes.empty()) ?
  assert(Bytes.secure_equals(verify_transparency_export(request) ?, device_set))
  case verify_transparency_export(request) do
    Err( error) -> assert(error == "transparency_verification_failed")
    Ok( _) -> assert(false)
  end
  let lookup_request = append(path_vector, username_vector) ?
  let lookup_bytes = transparency_lookup_export(lookup_request) ?
  let lookup_output_path = Env.get("MESSENGER_M13_TRANSPARENCY_LOOKUP_PATH", "")
  if String.length(lookup_output_path) > 0 do
    File.write_bytes(lookup_output_path, 0, lookup_bytes, true) ?
  else
    nil
  end
  let lookup = decode_transparency_lookup(lookup_bytes) ?
  assert(lookup.username == "alice")
  assert(lookup.previous_tree_size == 1)
  File.delete(path) ?
  Ok(true)
end

test("mobile transparency persists trusted checkpoints and rejects replay") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
