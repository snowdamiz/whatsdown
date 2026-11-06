fn repeated(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("fixture bytes")
    Ok(bytes)
  end
end

from Mobile.Codec import current_time, mobile_write_u64
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Prekeys.Bundle import normalize_prekey_bundle
from Prekeys.Pool import decode_prekey_claim
from Privacy.Edge import decode_stamped_request, verify_request_stamp
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import DeviceSet
from Storage.Blobs import ensure_schema, load_blob
from Storage.Records import store_updated_blobs
from Storage.Keys import platform_key, pending_context, seal_signing, open_signing
from Transparency.Merkle import (
  leaf_hash_for,
  merkle_root_for,
  sign_tree_checkpoint_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness
)
from Transparency.Wire import (
  TransparencyEvidence,
  encode_transparency_evidence,
  encode_checkpoint,
  decode_checkpoint,
  decode_transparency_lookup
)

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("fixture signer")
    Ok(value)
  end
end

fn save_key(path :: String,
  name :: String,
  value :: borrow SigningPrivateKey) -> Result<(), String> do
  let wrapping = platform_key()?
  store_updated_blobs(path, [name], [seal_signing(value, wrapping, pending_context(name, 6)?)?])
end

fn keys(path :: String) -> Result<(), String> do
  ensure_schema(path)?
  let signer = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> return Err("fixture delivery")
    Ok(value) -> value
  end
  save_key(path, "fixture/service", signer.private_key)?
  save_key(path, "fixture/a", a.private_key)?
  save_key(path, "fixture/b", b.private_key)?
  store_updated_blobs(path,
    ["fixture/public", "fixture/config"],
    [
      signer.public_key.bytes,
      Bytes.from_utf8("1\n"
        <> Bytes.to_hex(signer.public_key.bytes)
        <> "\n"
        <> Bytes.to_hex(a.public_key.bytes)
        <> "\n"
        <> Bytes.to_hex(b.public_key.bytes)
        <> "\n"
        <> Bytes.to_hex(delivery.public_key.bytes)
        <> "\n1")
    ])
end

fn set_wire(entry_wire :: Bytes) -> Bytes!String do
  let entry = case decode_directory_entry(entry_wire) do
    Err(_) -> return Err("fixture entry")
    Ok(value) -> value
  end
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> return Err("fixture account")
    Ok(value) -> value
  end
  let claimed = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> return Err("fixture bundle")
    Ok(value) -> value
  end
  let normalized = case normalize_prekey_bundle(claimed) do
    Err(_) -> return Err("fixture normalized bundle")
    Ok(value) -> value
  end
  let encoded = case encode_prekey_bundle(normalized) do
    Err(_) -> return Err("fixture bundle wire")
    Ok(value) -> value
  end
  case encode_device_set(DeviceSet {
    version: 1,
    username: entry.username,
    account_identity: entry.account_identity,
    sequence: account.directory_sequence,
    devices: [%{entry | prekey_bundle: encoded}],
    revoked_device_ids: []
  }) do
    Err(_) -> Err("fixture set wire")
    Ok(value)
  end
end

fn configure(path :: String, input :: Bytes) -> Bytes!String do
  let entries = unpack_credit_parts(input, 2, 36134)?
  if List.length(entries) != 2 do
    return Err("fixture needs two entries")
  end
  let sets = for entry in entries do
    set_wire(entry)?
  end
  let leaves = for value in sets do
    leaf_hash_for(1, value)?
  end
  let wrapping = platform_key()?
  let private = open_signing(load_blob(path, "fixture/service")?,
    wrapping,
    pending_context("fixture/service", 6)?)?
  let checkpoint = sign_tree_checkpoint_for(1,
    private,
    load_blob(path, "fixture/public")?,
    U64.parse("1")?,
    U64.parse("2")?,
    merkle_root_for(1, leaves)?,
    repeated(0, 32)?,
    current_time()?)?
  store_updated_blobs(path,
    ["fixture/entries", "fixture/sets", "fixture/checkpoint"],
    [input, pack_credit_parts(sets)?, encode_checkpoint(checkpoint)?])?
  Ok(Bytes.from_utf8("ready"))
end

fn verified_body(input :: Request, domain :: String, limit :: Int) -> Bytes!String do
  if Request.header(input, "authorization") != None
    || Request.header(input, "cookie") != None
    || Request.header(input, "content-type") != Some("application/octet-stream") do
    return Err("fixture private header")
  end
  let (stamp, body) = decode_stamped_request(Request.body_bytes(input), limit)?
  if !verify_request_stamp(domain, body, stamp, current_time()?, U64.parse("300000")?, 1)? do
    return Err("fixture work rejected")
  end
  Ok(body)
end

fn resolution(path :: String, request :: Request) -> Bytes!String do
  let lookup = decode_transparency_lookup(verified_body(request, "mesh-msg/v1/work/resolve", 76)?)?
  if lookup.previous_tree_size != 0 && lookup.previous_tree_size != 2 do
    return Err("fixture checkpoint size")
  end
  let entries = unpack_credit_parts(load_blob(path, "fixture/entries")?, 2, 36134)?
  let sets = unpack_credit_parts(load_blob(path, "fixture/sets")?, 2, 305260)?
  let leaves = for value in sets do
    leaf_hash_for(1, value)?
  end
  let wrapping = platform_key()?
  let checkpoint = decode_checkpoint(load_blob(path, "fixture/checkpoint")?)?
  let a = open_signing(load_blob(path, "fixture/a")?, wrapping, pending_context("fixture/a", 6)?)?
  let b = open_signing(load_blob(path, "fixture/b")?, wrapping, pending_context("fixture/b", 6)?)?
  for index in 0..2 do
    let entry = case decode_directory_entry(List.get(entries, index)) do
      Err(_) -> return Err("fixture entry")
      Ok(value) -> value
    end
    if entry.username == lookup.username do
      return encode_transparency_evidence(TransparencyEvidence {
        entry_bytes: List.get(sets, index),
        inclusion: compact_inclusion_proof_for(1, leaves, index)?,
        consistency: compact_consistency_proof_for(1,
          if lookup.previous_tree_size == 0 do
            []
          else
            leaves
          end,
          leaves)?,
        checkpoint: checkpoint,
        witnesses: [
          sign_witness("witness-a", a, checkpoint)?,
          sign_witness("witness-b", b, checkpoint)?
        ]
      })
    end
  end
  Err("fixture username not found")
end

fn claim(path :: String, request :: Request) -> Bytes!String do
  let wire = verified_body(request, "mesh-msg/v1/work/prekey-claim", 100)?
  let claim = decode_prekey_claim(wire)?
  let entries = unpack_credit_parts(load_blob(path, "fixture/entries")?, 2, 36134)?
  for entry_wire in entries do
    let entry = case decode_directory_entry(entry_wire) do
      Err(_) -> return Err("fixture entry")
      Ok(value) -> value
    end
    let account = case decode_account_identity(entry.account_identity) do
      Err(_) -> return Err("fixture account")
      Ok(value) -> value
    end
    let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
      Err(_) -> return Err("fixture bundle")
      Ok(value) -> value
    end
    let credential = case decode_device_credential(bundle.device_credential) do
      Err(_) -> return Err("fixture credential")
      Ok(value) -> value
    end
    # The canonical device set decoder authenticates these IDs
    # Compare the signed device and canonical normalized bundle hash.
    let normalized = case normalize_prekey_bundle(bundle) do
      Err(_) -> return Err("fixture normalized bundle")
      Ok(value) -> value
    end
    let base = case encode_prekey_bundle(normalized) do
      Err(_) -> return Err("fixture base")
      Ok(value) -> value
    end
    if Bytes.secure_equals(account.account_id, claim.account_id)
      && Bytes.secure_equals(credential.device_id, claim.device_id)
      && Bytes.secure_equals(Crypto.sha256(base), claim.base_bundle_hash) do
      let label = "fixture/claim/"
        <> Bytes.to_hex(claim.account_id)
        <> "/"
        <> Bytes.to_hex(claim.device_id)
      case load_blob(path, label) do
        Ok(previous) -> if !Bytes.secure_equals(previous, wire) do
          return Err("fixture claim changed")
        end
        Err(error) -> if error != "local_state_not_found" do
          return Err(error)
        end
      end
      store_updated_blobs(path, [label], [wire])?
      return Ok(entry.prekey_bundle)
    end
  end
  Err("fixture claim mismatch")
end

fn reply(value :: Bytes!String) -> Response do
  case value do
    Err(error) -> HTTP.response(409, error)
    Ok(bytes) -> HTTP.response_bytes_with_headers(200,
      bytes,
      Map.put(Map.new(), "Cache-Control", "no-store"))
  end
end

actor peer(path :: String, port :: Int) do
  HTTP.router()
    |> HTTP.on_post("/fixture/config", fn(_) -> reply(load_blob(path, "fixture/config")) end)
    |> HTTP.on_post("/fixture/entries",
      fn(input) -> reply(configure(path, Request.body_bytes(input))) end)
    |> HTTP.on_post("/v1/devices/resolve", fn(input) -> reply(resolution(path, input)) end)
    |> HTTP.on_post("/v1/prekeys/bundle", fn(input) -> reply(claim(path, input)) end)
    |> HTTP.serve(port)
end

fn proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let directory = Env.get("MORSE_FANOUT_FIXTURE", "")
  if String.length(directory) == 0 do
    return Err("fixture directory required")
  end
  let path = directory <> "/peer.db"
  let port = case String.to_int(Env.get("MORSE_FANOUT_PORT", "24331")) do
    None -> return Err("fixture port")
    Some(value) -> value
  end
  keys(path)?
  let server = spawn(peer, path, port)
  File.write(directory <> "/ready", "ready")?
  while !File.exists(directory <> "/done") do
    Timer.sleep(50)
  end
  Ok(nil)
end

test("owned dynamic signed Mesh fanout peer") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
