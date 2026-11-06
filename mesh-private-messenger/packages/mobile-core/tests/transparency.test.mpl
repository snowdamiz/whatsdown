from Mobile.Codec import current_time, mobile_write_u64
from Transparency.AnchorChain import AnchorPins, configured_anchor_pins
from Mobile.AnchorCheck import anchor_identity
from Mobile.AnchorSchedule import AnchorClaim, claim_anchor_check, finish_anchor_check
from Transparency.Config import SecurityConfig, decode_security_config, encode_security_config
from Mobile.Transparency import load_transparency_view
from Mobile.TransparencyCache import cached_transparency_bytes
from Transparency.LeafProof import LeafProof, decode_leaf_proof
from Transparency.Merkle import InclusionProof
from Mobile.Types import MobileTransparencyView
from Mobile.TransparencySafety import retain_fork
from Transparency.Fork import ForkProof, ForkTarget
from Storage.Keys import platform_key
from Storage.Keys import seal_local, local_context
from Storage.Records import store_updated_session
from Transparency.C2spText import checkpoint_note_text
from Transparency.Merkle import (
  WitnessAttestation,
  TransparencyCheckpoint,
  leaf_hash_for,
  sign_tree_checkpoint_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for
)
from Transparency.Merkle import merkle_root_for
from Transparency.Wire import encode_checkpoint, encode_witnesses
import File
from MobileCore import (
  create_account_export,
  directory_entry_export,
  transparency_lookup_export,
  verify_transparency_export
)
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.V1 import DeviceSet
from Tests.Support import append, database_path, install_security_config, repeated, vector
from Transparency.Merkle import (
  consistency_proof,
  checkpoint_hash,
  inclusion_proof,
  leaf_hash,
  sign_checkpoint,
  sign_witness
)
from Transparency.Wire import (
  TransparencyEvidence,
  decode_transparency_lookup,
  encode_transparency_evidence
)

fn join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index))?)
  end
end

fn wide(value :: String) -> U64!String do
  case U64.parse(value) do
    Err(_) -> Err("test integer conversion failed")
    Ok(parsed)
  end
end

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test signing key generation failed")
    Ok(value)
  end
end

fn cosign(key :: borrow SigningPrivateKey,
  checkpoint :: TransparencyCheckpoint,
  seconds :: U64) -> WitnessAttestation!String do
  let text = "cosignature/v1\ntime "
    <> U64.to_string(seconds)
    <> "\n"
    <> checkpoint_note_text(encode_checkpoint(checkpoint)?)?
  let signed = case Crypto.sign(key, Bytes.from_utf8(text)) do
    Err(_) -> return Err("test signing failed")
    Ok(value) -> value.bytes
  end
  let stamp = case Bytes.write_u64_be(seconds) do
    Err(_) -> return Err("test timestamp failed")
    Ok(value) -> value
  end
  Ok(WitnessAttestation {
    witness_id: "witness-a",
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    signature: append(stamp, signed)?
  })
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("transparency")?
  let path_bytes = Bytes.from_utf8(path)
  let username_bytes = Bytes.from_utf8("alice")
  let account_request = append(vector(path_bytes)?, vector(username_bytes)?)?
  create_account_export(account_request)?
  let entry_bytes = directory_entry_export(Bytes.from_utf8(path))?
  let output_path = Env.get("MESSENGER_M13_DIRECTORY_ENTRY_PATH", "")
  if String.length(output_path) > 0 do
    File.write_bytes(output_path, 0, entry_bytes, true)?
  else
    nil
  end
  let entry = case decode_directory_entry(entry_bytes) do
    Err(_) -> Err("directory entry decode failed")
    Ok(value)
  end?
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> Err("account identity decode failed")
    Ok(value)
  end?
  let device_set = case encode_device_set(DeviceSet {
    version: 1,
    username: entry.username,
    account_identity: entry.account_identity,
    sequence: account.directory_sequence,
    devices: [entry],
    revoked_device_ids: List.new()
  }) do
    Err(_) -> Err("device set encode failed")
    Ok(value)
  end?
  let leaves = [leaf_hash(device_set)?]
  let service_pair = signing_pair()?
  let witness_a = signing_pair()?
  let witness_b = signing_pair()?
  let delivery_pair = case Crypto.x25519_generate() do
    Err(_) -> Err("test delivery key generation failed")
    Ok(value)
  end?
  assert(install_security_config(service_pair.public_key.bytes,
    witness_a.public_key.bytes,
    witness_b.public_key.bytes,
    delivery_pair.public_key.bytes,
    8))
  let stale = sign_checkpoint(service_pair.private_key,
    service_pair.public_key.bytes,
    wide("1")?,
    leaves,
    repeated(0, 32)?,
    wide("1000")?)?
  let stale_evidence = encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: device_set,
    inclusion: inclusion_proof(leaves, 0)?,
    consistency: consistency_proof(List.new(), leaves)?,
    checkpoint: stale,
    witnesses: [
      sign_witness("witness-a", witness_a.private_key, stale)?,
      sign_witness("witness-b", witness_b.private_key, stale)?
    ]
  })?
  case verify_transparency_export(join([
      vector(path_bytes)?,
      vector(username_bytes)?,
      vector(stale_evidence)?
    ],
    0,
    Bytes.empty())?) do
    Err(error) -> assert(error == "transparency_stale")
    Ok(_) -> assert(false)
  end
  let unchanged_lookup = decode_transparency_lookup(transparency_lookup_export(append(vector(path_bytes)?,
    vector(username_bytes)?)?)?)?
  assert(unchanged_lookup.previous_tree_size == 0)
  let checkpoint = sign_checkpoint(service_pair.private_key,
    service_pair.public_key.bytes,
    wide("1")?,
    leaves,
    repeated(0, 32)?,
    current_time()?)?
  let evidence = case encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: device_set,
    inclusion: inclusion_proof(leaves, 0)?,
    consistency: consistency_proof(List.new(), leaves)?,
    checkpoint: checkpoint,
    witnesses: [
      sign_witness("witness-a", witness_a.private_key, checkpoint)?,
      sign_witness("witness-b", witness_b.private_key, checkpoint)?
    ]
  }) do
    Err(_) -> Err("transparency evidence encode failed")
    Ok(value)
  end?
  let path_vector = vector(path_bytes)?
  let username_vector = vector(username_bytes)?
  let evidence_vector = vector(evidence)?
  let request = join([path_vector, username_vector, evidence_vector], 0, Bytes.empty())?
  let wrong_reference = vector(Bytes.from_utf8("@" <> Bytes.to_hex(repeated(0, 32)?)))?
  case verify_transparency_export(join([path_vector, wrong_reference, evidence_vector],
    0,
    Bytes.empty())?) do
    Err(error) -> assert(error == "transparency_username_mismatch")
    Ok(_) -> assert(false)
  end
  let account_reference = vector(Bytes.from_utf8("@" <> Bytes.to_hex(account.account_id)))?
  assert(Bytes.secure_equals(verify_transparency_export(join([
        path_vector,
        account_reference,
        evidence_vector
      ],
      0,
      Bytes.empty())?)?,
    device_set))
  let wrapping_key = platform_key()?
  let retained_leaf = cached_transparency_bytes(path, wrapping_key, "transparency-leaf/v1")?
  let private_leaf = decode_leaf_proof(retained_leaf)?
  assert(Bytes.length(retained_leaf) == 50)
  assert(Bytes.secure_equals(private_leaf.leaf_hash, leaf_hash(device_set)?))
  assert(private_leaf.inclusion.version == 2 && private_leaf.inclusion.tree_size == 1)
  case verify_transparency_export(request) do
    Err(error) -> assert(error == "transparency_verification_failed")
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(cached_transparency_bytes(path, wrapping_key, "transparency-leaf/v1")?,
    retained_leaf))
  let lookup_request = append(path_vector, username_vector)?
  let lookup_bytes = transparency_lookup_export(lookup_request)?
  let lookup_output_path = Env.get("MESSENGER_M13_TRANSPARENCY_LOOKUP_PATH", "")
  if String.length(lookup_output_path) > 0 do
    File.write_bytes(lookup_output_path, 0, lookup_bytes, true)?
  else
    nil
  end
  let lookup = decode_transparency_lookup(lookup_bytes)?
  assert(lookup.username == "alice")
  assert(lookup.previous_tree_size == 1)
  # A native release adds witness C and moves to 2-of-3. The old cached view
  # must stop authorizing operations, while its checkpoint still prevents a
  # rollback when evidence under the new set is ingested.
  let witness_c = signing_pair()?
  let native_v2 = Bytes.from_utf8(String.join([
      "2",
      Bytes.to_hex(service_pair.public_key.bytes),
      Bytes.to_hex(delivery_pair.public_key.bytes),
      "8",
      "2",
      "3",
      "witness-a " <> Bytes.to_hex(witness_a.public_key.bytes) <> " Morse",
      "witness-b " <> Bytes.to_hex(witness_b.public_key.bytes) <> " Morse",
      "witness-c " <> Bytes.to_hex(witness_c.public_key.bytes) <> " Outside",
      "-",
      "0",
      "-"
    ],
    "\n"))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), native_v2))
  case load_transparency_view(path, wrapping_key) do
    Err(error) -> assert(error == "transparency_trust_mismatch")
    Ok(_) -> assert(false)
  end
  let refreshed = sign_checkpoint(service_pair.private_key,
    service_pair.public_key.bytes,
    wide("2")?,
    leaves,
    checkpoint_hash(checkpoint)?,
    current_time()?)?
  let one_signature = TransparencyEvidence {
    entry_bytes: device_set,
    inclusion: inclusion_proof(leaves, 0)?,
    consistency: consistency_proof(leaves, leaves)?,
    checkpoint: refreshed,
    witnesses: [sign_witness("witness-a", witness_a.private_key, refreshed)?]
  }
  case verify_transparency_export(join([
      path_vector,
      username_vector,
      vector(encode_transparency_evidence(one_signature)?)?
    ],
    0,
    Bytes.empty())?) do
    Err(error) -> assert(error == "transparency_verification_failed")
    Ok(_) -> assert(false)
  end
  let enough = %{one_signature |
    witnesses: one_signature.witnesses
      ++ [sign_witness("witness-c", witness_c.private_key, refreshed)?]
  }
  assert(Bytes.secure_equals(verify_transparency_export(join([
        path_vector,
        username_vector,
        vector(encode_transparency_evidence(enough)?)?
      ],
      0,
      Bytes.empty())?)?,
    device_set))
  load_transparency_view(path, wrapping_key)?
  # A proven fork pauses changed/new device sets, but does not stop fresh
  # checkpoint authorization for the exact devices already trusted here.
  let conflicting = sign_checkpoint(service_pair.private_key,
    service_pair.public_key.bytes,
    wide("2")?,
    [Crypto.sha256(Bytes.from_utf8("other view"))],
    checkpoint_hash(checkpoint)?,
    current_time()?)?
  retain_fork(path,
    wrapping_key,
    ForkProof {
      kind: 1,
      finder: repeated(0, 32)?,
      service_public_key: service_pair.public_key.bytes,
      first: refreshed,
      second: SignedCheckpoint(conflicting),
      attestations: List.new(),
      contradiction: None
    })?
  let later = sign_checkpoint(service_pair.private_key,
    service_pair.public_key.bytes,
    wide("3")?,
    leaves,
    checkpoint_hash(refreshed)?,
    current_time()?)?
  let unchanged = %{enough |
    checkpoint: later,
    witnesses: [
      sign_witness("witness-a", witness_a.private_key, later)?,
      sign_witness("witness-c", witness_c.private_key, later)?
    ]
  }
  verify_transparency_export(join([
      path_vector,
      username_vector,
      vector(encode_transparency_evidence(unchanged)?)?
    ],
    0,
    Bytes.empty())?)?
  let changed_set = case encode_device_set(DeviceSet {
    version: 1,
    username: entry.username,
    account_identity: entry.account_identity,
    sequence: U64.add(account.directory_sequence, wide("1")?)?,
    devices: [entry],
    revoked_device_ids: List.new()
  }) do
    Err(_) -> return Err("changed device set encode failed")
    Ok(value) -> value
  end
  let new_leaves = leaves ++ [leaf_hash(changed_set)?]
  let changed_checkpoint = sign_checkpoint(service_pair.private_key,
    service_pair.public_key.bytes,
    wide("4")?,
    new_leaves,
    checkpoint_hash(later)?,
    current_time()?)?
  let changed_evidence = TransparencyEvidence {
    entry_bytes: changed_set,
    inclusion: inclusion_proof(new_leaves, 1)?,
    consistency: consistency_proof(leaves, new_leaves)?,
    checkpoint: changed_checkpoint,
    witnesses: [
      sign_witness("witness-a", witness_a.private_key, changed_checkpoint)?,
      sign_witness("witness-c", witness_c.private_key, changed_checkpoint)?
    ]
  }
  case verify_transparency_export(join([
      path_vector,
      username_vector,
      vector(encode_transparency_evidence(changed_evidence)?)?
    ],
    0,
    Bytes.empty())?) do
    Err(error) -> assert(error == "transparency_fork_detected")
    Ok(_) -> assert(false)
  end
  assert(decode_transparency_lookup(transparency_lookup_export(lookup_request)?)?.previous_tree_size == 1)
  let c2sp_path = database_path("c2sp-transparency")?
  let rfc_leaf = leaf_hash_for(2, device_set)?
  let now = current_time()?
  let seconds = U64.divide(now, wide("1000")?)?
  let rfc_checkpoint = sign_tree_checkpoint_for(2,
    service_pair.private_key,
    service_pair.public_key.bytes,
    wide("1")?,
    wide("1")?,
    rfc_leaf,
    repeated(0, 32)?,
    now)?
  let stale_cosignature = cosign(witness_a.private_key,
    rfc_checkpoint,
    U64.subtract(seconds, wide("301")?)?)?
  let native_attestation = sign_witness("witness-c", witness_c.private_key, rfc_checkpoint)?
  let rfc_evidence = TransparencyEvidence {
    entry_bytes: device_set,
    inclusion: compact_inclusion_proof_for(2, [rfc_leaf], 0)?,
    consistency: compact_consistency_proof_for(2, List.new(), [rfc_leaf])?,
    checkpoint: rfc_checkpoint,
    witnesses: [stale_cosignature, native_attestation]
  }
  let c2sp_path_vector = vector(Bytes.from_utf8(c2sp_path))?
  let rfc_request = join([
      c2sp_path_vector,
      username_vector,
      vector(encode_transparency_evidence(rfc_evidence)?)?
    ],
    0,
    Bytes.empty())?
  case verify_transparency_export(rfc_request) do
    Err(error) -> assert(error == "unsupported_transparency_log")
    Ok(_) -> assert(false)
  end
  let native_lines = String.split(Bytes.to_utf8(native_v2)?, "\n")
  let native_v3 = Bytes.from_utf8(String.join(["3"]
      ++ List.drop(native_lines, 1)
      ++ [
        "2",
        "2",
        "2",
        "witness-a " <> Bytes.to_hex(witness_a.public_key.bytes) <> " Morse",
        "witness-b " <> Bytes.to_hex(witness_b.public_key.bytes) <> " Morse"
      ],
    "\n"))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), native_v3))
  case verify_transparency_export(join([
      c2sp_path_vector,
      username_vector,
      vector(encode_transparency_evidence(rfc_evidence)?)?
    ],
    0,
    Bytes.empty())?) do
    Err(error) -> assert(error == "transparency_stale")
    Ok(_) -> assert(false)
  end
  let fresh = %{rfc_evidence |
    witnesses: [cosign(witness_a.private_key, rfc_checkpoint, seconds)?, native_attestation]
  }
  verify_transparency_export(join([
      c2sp_path_vector,
      username_vector,
      vector(encode_transparency_evidence(fresh)?)?
    ],
    0,
    Bytes.empty())?)?
  load_transparency_view(c2sp_path, wrapping_key)?
  # Reloading a fresh checkpoint cannot extend an expired cosignature's lease.
  let label = "transparency-witnesses/v2"
  store_updated_session(c2sp_path,
    label,
    seal_local(encode_witnesses(rfc_evidence.witnesses)?, wrapping_key, local_context(label)?)?)?
  case load_transparency_view(c2sp_path, wrapping_key) do
    Err(error) -> assert(error == "transparency_stale")
    Ok(_) -> assert(false)
  end
  # The live RPC test proves authentication of slash observations. Seed its
  # sealed result here to exercise actual device-set ingestion after a slash.
  let v4 = %{decode_security_config(native_v3)? |
    version: 4,
    anchor_address: "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb",
    anchor_program: String.repeat("1", 32),
    anchor_log_name: "morse-main",
    rpc_urls: ["https://one.example", "https://two.example", "https://three.example"]
  }
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), encode_security_config(v4)?))
  let pins = case configured_anchor_pins(v4)? do
    Some(value) -> value
    None -> return Err("missing anchor pins")
  end
  let claim = case claim_anchor_check(c2sp_path,
    wrapping_key,
    anchor_identity(pins, service_pair.public_key.bytes, 2)?,
    now,
    false)? do
    Some(value) -> value
    None -> return Err("missing anchor claim")
  end
  finish_anchor_check(c2sp_path,
    wrapping_key,
    claim,
    now,
    false,
    join([
        Bytes.from_hex("41434f3107")?,
        mobile_write_u64(now)?,
        mobile_write_u64(wide("501")?)?,
        mobile_write_u64(wide("500")?)?,
        mobile_write_u64(wide("0")?)?
      ],
      0,
      Bytes.empty())?)?
  let newer = sign_tree_checkpoint_for(2,
    service_pair.private_key,
    service_pair.public_key.bytes,
    wide("2")?,
    wide("1")?,
    rfc_leaf,
    checkpoint_hash(rfc_checkpoint)?,
    current_time()?)?
  let same_devices = %{fresh |
    checkpoint: newer,
    consistency: compact_consistency_proof_for(2, [rfc_leaf], [rfc_leaf])?,
    witnesses: [
      cosign(witness_a.private_key, newer, seconds)?,
      sign_witness("witness-c", witness_c.private_key, newer)?
    ]
  }
  verify_transparency_export(join([
      c2sp_path_vector,
      username_vector,
      vector(encode_transparency_evidence(same_devices)?)?
    ],
    0,
    Bytes.empty())?)?
  load_transparency_view(c2sp_path, wrapping_key)?
  let rfc_changed_leaf = leaf_hash_for(2, changed_set)?
  let rfc_changed = sign_tree_checkpoint_for(2,
    service_pair.private_key,
    service_pair.public_key.bytes,
    wide("3")?,
    wide("2")?,
    merkle_root_for(2, [rfc_leaf, rfc_changed_leaf])?,
    checkpoint_hash(newer)?,
    current_time()?)?
  let untrusted_change = TransparencyEvidence {
    entry_bytes: changed_set,
    checkpoint: rfc_changed,
    inclusion: compact_inclusion_proof_for(2, [rfc_leaf, rfc_changed_leaf], 1)?,
    consistency: compact_consistency_proof_for(2, [rfc_leaf], [rfc_leaf, rfc_changed_leaf])?,
    witnesses: [
      cosign(witness_a.private_key, rfc_changed, seconds)?,
      sign_witness("witness-c", witness_c.private_key, rfc_changed)?
    ]
  }
  case verify_transparency_export(join([
      c2sp_path_vector,
      username_vector,
      vector(encode_transparency_evidence(untrusted_change)?)?
    ],
    0,
    Bytes.empty())?) do
    Err(error) -> assert(error == "anchor_service_slashed")
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(load_transparency_view(c2sp_path, wrapping_key)?.checkpoint,
    encode_checkpoint(newer)?))
  File.delete(c2sp_path)?
  File.delete(path)?
  Ok(true)
end

test("mobile transparency persists trusted checkpoints and rejects replay") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
