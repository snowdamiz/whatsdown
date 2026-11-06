##! Local public canary directory. Only the standalone witness processes sign attestations.
from MobileCore import initialize
from Mobile.Codec import current_time, encode_output_list, mobile_zeroes
from Mobile.TransparencyCache import cached_transparency_bytes
from Mobile.Transparency import load_transparency_view
from Storage.Keys import platform_key
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.V1 import DeviceSet
from Privacy.Edge import decode_stamped_request, verify_request_stamp
from Transparency.Config import decode_security_config, encode_security_config, pinned_witness_keys
from Transparency.Merkle import (
  TransparencyCheckpoint,
  checkpoint_hash,
  leaf_hash_for,
  merkle_root_for,
  sign_tree_checkpoint_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  verify_witnesses
)
from Transparency.LeafProof import LeafProof, compact_leaf_proof, encode_leaf_proof
from Transparency.Wire import (
  TransparencyEvidence,
  encode_transparency_evidence,
  encode_checkpoint,
  decode_checkpoint,
  decode_transparency_lookup,
  decode_transparency_tree_query,
  encode_consistency_proof,
  decode_witnesses,
  encode_witnesses,
  decode_transparency_evidence
)

fn root() -> String do
  Env.get("BOOTSTRAP_FIXTURE", "")
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn signer(seed :: String) -> SigningKeyPair!String do
  let material = case Env.get_secret_hex("OUTAGE_SEED_" <> seed) do
    Err(_) -> return Err("fixture_seed")
    Ok(value) -> value
  end
  case Crypto.signing_from_secret(material) do
    Err(_) -> Err("fixture_key")
    Ok(value)
  end
end

fn count() -> Int!String do
  case String.to_int(File.read(root() <> "/size")?) do
    None -> Err("fixture_size")
    Some(value) -> Ok(value)
  end
end

fn checkpoint(size :: Int) -> TransparencyCheckpoint!String do
  decode_checkpoint(Bytes.from_hex(File.read(root() <> "/checkpoint-#{size}.hex")?)?)
end

fn leaves(size :: Int) -> List<Bytes>!String do
  Ok(for index in 0..size do
    leaf_hash_for(2,
      if index == 0 do
        Bytes.from_hex(File.read(root() <> "/devices.hex")?)?
      else
        Bytes.from_utf8("public synthetic canary leaf #{index}")
      end)?
  end)
end

fn save(name :: String, value :: Bytes) -> Result<(), String> do
  let path = root() <> "/" <> name
  File.write(path, Bytes.to_hex(value))?
  File.sync(path)
end

@export("outage_initialize")
pub fn outage_initialize_impl(input :: Bytes) -> Bytes!String do
  let entry = case decode_directory_entry(Bytes.from_hex(File.read(root() <> "/entry.hex")?)?) do
    Err(_) -> return Err("fixture_entry")
    Ok(value) -> value
  end
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> return Err("fixture_identity")
    Ok(value) -> value
  end
  let devices = case encode_device_set(DeviceSet {
    version: 1,
    username: entry.username,
    account_identity: entry.account_identity,
    sequence: account.directory_sequence,
    devices: [entry],
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("fixture_devices")
    Ok(value) -> value
  end
  save("devices.hex", devices)?
  let log = signer("44")?
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> return Err("fixture_delivery_key")
    Ok(value) -> value
  end
  let pins = for item in ["a 11", "b 22", "c 33"] do
    let pair = signer(List.get(String.split(item, " "), 1))?
    "witness-"
      <> List.get(String.split(item, " "), 0)
      <> " "
      <> Bytes.to_hex(pair.public_key.bytes)
      <> " LocalFixture"
  end
  let frame = Bytes.from_utf8(String.join([
      "4",
      Bytes.to_hex(log.public_key.bytes),
      Bytes.to_hex(delivery.public_key.bytes),
      "1",
      "2",
      "3"
    ]
      ++ pins
      ++ ["-", "0", "-", "2", "2", "3"]
      ++ pins
      ++ ["-", "-"],
    "\n"))
  let canonical = encode_security_config(decode_security_config(frame)?)?
  File.write(root() <> "/security", Bytes.to_utf8(canonical)?)?
  File.write(root() <> "/log-public-key", Bytes.to_hex(log.public_key.bytes))?
  let network = Bytes.from_utf8(File.read(root() <> "/network")?)
  File.write(root() <> "/ohttp",
    "1\n"
      <> Bytes.to_hex(Crypto.sha256(network))
      <> "\n"
      <> Bytes.to_hex(Crypto.sha256(canonical))
      <> "\n1\noff\n0")?
  Ok(devices)
end

@export("outage_advance")
pub fn outage_advance_impl(input :: Bytes) -> Bytes!String do
  let size = if File.exists(root() <> "/size") do
    count()? + 1
  else
    1
  end
  let previous = if size == 1 do
    mobile_zeroes(32)?
  else
    checkpoint_hash(checkpoint(size - 1)?)?
  end
  let log = signer("44")?
  let value = sign_tree_checkpoint_for(2,
    log.private_key,
    log.public_key.bytes,
    wide(size)?,
    wide(size)?,
    merkle_root_for(2, leaves(size)?)?,
    previous,
    current_time()?)?
  let encoded = encode_checkpoint(value)?
  save("checkpoint-#{size}.hex", encoded)?
  File.write(root() <> "/size.pending", Int.to_string(size))?
  File.sync(root() <> "/size.pending")?
  File.rename(root() <> "/size.pending", root() <> "/size")?
  File.sync(root())?
  Ok(encoded)
end

@export("outage_consistency")
pub fn outage_consistency_impl(input :: Bytes) -> Bytes!String do
  let query = decode_transparency_tree_query(input)?
  if query.new_tree_size > count()? || query.previous_tree_size > query.new_tree_size do
    return Err("fixture_consistency_range")
  end
  encode_consistency_proof(compact_consistency_proof_for(2,
    leaves(query.previous_tree_size)?,
    leaves(query.new_tree_size)?)?)
end

@export("outage_attestation")
pub fn outage_attestation_impl(input :: Bytes) -> Bytes!String do
  let attestations = decode_witnesses(input)?
  let config = decode_security_config(Bytes.from_utf8(File.read(root() <> "/security")?))?
  let size = case String.to_int(File.read(root() <> "/verify-size")?) do
    None -> return Err("fixture_verify_size")
    Some(value) -> value
  end
  if List.length(attestations) != 1
    || !verify_witnesses(checkpoint(size)?, attestations, pinned_witness_keys(config), 1)? do
    return Err("fixture_unverified_attestation")
  end
  Ok(Bytes.from_utf8(List.get(attestations, 0).witness_id))
end

@export("outage_lookup")
pub fn outage_lookup_impl(input :: Bytes) -> Bytes!String do
  let (stamp, body) = decode_stamped_request(input, 76)?
  if !verify_request_stamp("mesh-msg/v1/work/resolve",
    body,
    stamp,
    current_time()?,
    wide(300000)?,
    1)? do
    return Err("fixture_request_stamp")
  end
  let query = decode_transparency_lookup(body)?
  if query.username != "morse-canary-1" do
    return Err("fixture_canary_only")
  end
  let size = count()?
  File.append(root() <> "/lookup-history", "#{query.previous_tree_size} #{size}\n")?
  let mode = File.read(root() <> "/lookup-mode")?
  let rows = for id in ["witness-a", "witness-b", "witness-c"] when File.exists(root()
    <> "/attest-#{size}-#{id}.hex") do
    List.get(decode_witnesses(Bytes.from_hex(File.read(root() <> "/attest-#{size}-#{id}.hex")?)?)?,
      0)
  end
  let selected = if mode == "one" do
    List.take(rows, 1)
  else if mode == "forged-witness" do
    List.take(rows, 2)
  else
    rows
  end
  let witnesses = for index in 0..List.length(selected) do
    let row = List.get(selected, index)
    if mode == "forged-witness" && index == 1 do
      %{row | signature: mobile_zeroes(64)?}
    else
      row
    end
  end
  let value = checkpoint(size)?
  let accepted = if mode == "forged" do
    %{value | signature: mobile_zeroes(64)?}
  else
    value
  end
  let response = encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: Bytes.from_hex(File.read(root() <> "/devices.hex")?)?,
    inclusion: compact_inclusion_proof_for(2, leaves(size)?, 0)?,
    consistency: compact_consistency_proof_for(2,
      leaves(query.previous_tree_size)?,
      leaves(size)?)?,
    checkpoint: accepted,
    witnesses: witnesses
  })?
  save("last-evidence.hex", response)?
  Ok(response)
end

@export("outage_audit")
pub fn outage_audit_impl(input :: Bytes) -> Bytes!String do
  let path = Bytes.to_utf8(input)?
  let key = platform_key()?
  let view = load_transparency_view(path, key)?
  let expected = decode_transparency_evidence(Bytes.from_hex(File.read(root()
    <> "/last-evidence.hex")?)?)?
  let current = encode_checkpoint(checkpoint(count()?)?)?
  let leaf = encode_leaf_proof(compact_leaf_proof(LeafProof {
      leaf_hash: leaf_hash_for(2, expected.entry_bytes)?,
      inclusion: expected.inclusion
    },
    expected.checkpoint)?)?
  if !Bytes.secure_equals(view.checkpoint, current)
    || !Bytes.secure_equals(view.consistency, encode_consistency_proof(expected.consistency)?)
    || !Bytes.secure_equals(cached_transparency_bytes(path, key, "transparency-witnesses/v2")?,
      encode_witnesses(expected.witnesses)?)
    || !Bytes.secure_equals(cached_transparency_bytes(path, key, "transparency-leaf/v1")?, leaf) do
    return Err("fixture_cache_records_not_current")
  end
  outage_cache_impl(input)
end

@export("outage_cache")
pub fn outage_cache_impl(input :: Bytes) -> Bytes!String do
  let path = Bytes.to_utf8(input)?
  let key = platform_key()?
  encode_output_list(for label in [
    "transparency-checkpoint/v1",
    "transparency-view/v1",
    "transparency-witnesses/v2",
    "transparency-leaf/v1",
    "transparency-origin/v1"
  ] do
    cached_transparency_bytes(path, key, label)?
  end)
end
