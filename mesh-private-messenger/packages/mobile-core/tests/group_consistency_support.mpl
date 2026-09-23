from Mobile.Codec import current_time
import File
from MobileCore import (
  create_account_export,
  directory_entry_export,
  group_add_export,
  group_create_export,
  group_key_package_export,
  group_receive_export,
  verify_transparency_export
)
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.V1 import AccountIdentity, DeviceSet, DirectoryEntry
from Tests.Support import append, database_path, install_security_config, repeated, vector
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash, consistency_proof, inclusion_proof, leaf_hash, sign_checkpoint, sign_witness
from Transparency.Wire import TransparencyEvidence, encode_checkpoint, encode_consistency_proof, encode_transparency_evidence

pub struct ConsistencyAccount do
  path :: String
  username :: String
  entry :: DirectoryEntry
  device_set :: Bytes
end

pub struct SignedTransparencyViewFixture do
  checkpoint :: Bytes
  consistency :: Bytes
  service_public_key :: Bytes
  witness_a_public_key :: Bytes
  witness_b_public_key :: Bytes
end

pub fn vectors(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    vectors(values, index + 1, append(output, vector(List.get(values, index))?)?)
  end
end

pub fn request(values :: List<Bytes>) -> Bytes!String do
  vectors(values, 0, Bytes.empty())
end

pub fn wide(value :: Int) -> U64!String do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err("test integer conversion failed")
    Ok(parsed)
  end
end

pub fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test signing key generation failed")
    Ok(value)
  end
end

pub fn signed_transparency_view(leaves :: List<Bytes>) -> SignedTransparencyViewFixture!String do
  if List.length(leaves) == 0 || List.length(leaves) > 4096 do
    Err("invalid_test_transparency_view")
  else
    let service_pair = signing_pair()?
    let witness_a_pair = signing_pair()?
    let witness_b_pair = signing_pair()?
    let checkpoint = sign_checkpoint(service_pair.private_key,
      service_pair.public_key.bytes,
      wide(1)?,
      leaves,
      repeated(0, 32)?,
      current_time()?)?
    Ok(SignedTransparencyViewFixture {
      checkpoint: encode_checkpoint(checkpoint)?,
      consistency: encode_consistency_proof(consistency_proof(List.new(), leaves)?)?,
      service_public_key: service_pair.public_key.bytes,
      witness_a_public_key: witness_a_pair.public_key.bytes,
      witness_b_public_key: witness_b_pair.public_key.bytes
    })
  end
end

pub fn decode_entry(input :: Bytes) -> DirectoryEntry!String do
  case decode_directory_entry(input) do
    Err(_) -> Err("directory entry decode failed")
    Ok(value)
  end
end

pub fn decode_account(input :: Bytes) -> AccountIdentity!String do
  case decode_account_identity(input) do
    Err(_) -> Err("account identity decode failed")
    Ok(value)
  end
end

pub fn encode_set(value :: DeviceSet) -> Bytes!String do
  case encode_device_set(value) do
    Err(_) -> Err("device set encode failed")
    Ok(encoded)
  end
end

pub fn account_fixture(label :: String, username :: String) -> ConsistencyAccount!String do
  let path = database_path(label)?
  create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8(username)])?)?
  let entry = decode_entry(directory_entry_export(Bytes.from_utf8(path))?)?
  let account = decode_account(entry.account_identity)?
  let device_set = encode_set(DeviceSet {
    version: 1,
    username: username,
    account_identity: entry.account_identity,
    sequence: account.directory_sequence,
    devices: [entry],
    revoked_device_ids: List.new()
  })?
  Ok(ConsistencyAccount {
    path: path,
    username: username,
    entry: entry,
    device_set: device_set
  })
end

pub fn evidence_bytes(entry_bytes :: Bytes,
  leaves :: List<Bytes>,
  leaf_index :: Int,
  previous_leaves :: List<Bytes>,
  checkpoint :: TransparencyCheckpoint,
  witness_a :: borrow SigningPrivateKey,
  witness_b :: borrow SigningPrivateKey) -> Bytes!String do
  let inclusion = inclusion_proof(leaves, leaf_index)?
  let consistency = consistency_proof(previous_leaves, leaves)?
  let attestation_a = sign_witness("witness-a", witness_a, checkpoint)?
  let attestation_b = sign_witness("witness-b", witness_b, checkpoint)?
  case encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: entry_bytes,
    inclusion: inclusion,
    consistency: consistency,
    checkpoint: checkpoint,
    witnesses: [attestation_a, attestation_b]
  }) do
    Err(_) -> Err("transparency evidence encode failed")
    Ok(encoded)
  end
end

pub fn verify_for(account :: ConsistencyAccount,
  username :: String,
  evidence :: Bytes,
  service_public_key :: Bytes,
  witness_a_public_key :: Bytes,
  witness_b_public_key :: Bytes) -> Bytes!String do
  let delivery_pair = case Crypto.x25519_generate() do
    Err(_) -> Err("test delivery key generation failed")
    Ok(value)
  end?
  if install_security_config(service_public_key,
    witness_a_public_key,
    witness_b_public_key,
    delivery_pair.public_key.bytes,
    8) do
    verify_transparency_export(request([
      Bytes.from_utf8(account.path),
      Bytes.from_utf8(username),
      evidence
    ])?)
  else
    Err("test security config install failed")
  end
end
