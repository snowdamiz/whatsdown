from MobileCore import (
  create_account_export,
  directory_entry_export,
  transparency_lookup_export,
  verify_transparency_export
)
from Mobile.Codec import current_time
from Mobile.Transparency import (
  load_transparency_view,
  transparency_checkpoint_bytes,
  transparency_checkpoint_in_cached_view,
  transparency_checkpoint_in_native_view,
  capture_native_transparency_basis,
  verify_transparency_response_native,
  transparency_checkpoint_precedes
)
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.V1 import DeviceSet
from Storage.Keys import platform_key, open_local, local_context
from Storage.Blobs import load_blob
from Storage.Records import with_record_transaction, delete_blob
from Mobile.Requests import parse_transparency_request
from Mobile.OhttpContext import capture_native_ohttp_context
from Ohttp.Keys import OhttpKeyConfig, encode_key_config
from Ohttp.BinaryHttp import decode_request, encode_response
from Ohttp.LookupPolicy import OhttpLookupOperation, admit_lookup_request, lookup_response
from Ohttp.Types import BhttpFraming, default_bhttp_limits
from Mobile.Platform import native_security_config
from Transparency.Config import encode_security_config
from Tests.Support import append, database_path, install_security_config, repeated, vector
from Transparency.Merkle import (
  sign_tree_checkpoint_for,
  merkle_root_for,
  leaf_hash_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness,
  checkpoint_hash
)
from Transparency.Migration import (
  LegacyBridge,
  legacy_bridge_leaf,
  encode_legacy_bridge,
  decode_bridge_query
)
from Transparency.Wire import (
  TransparencyEvidence,
  encode_checkpoint,
  encode_transparency_evidence,
  decode_transparency_lookup
)

fn signer() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("fixture signer failed")
    Ok(value)
  end
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn request(path :: String, evidence :: TransparencyEvidence, origin :: String) -> Bytes!String do
  append(append(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?,
      vector(encode_transparency_evidence(evidence)?)?)?,
    vector(Bytes.from_utf8(origin))?)
end

fn bridge_response(request :: Request, path :: String, calls :: String) -> Response do
  let (old, current) = case decode_bridge_query(Request.body_bytes(request)) do
    Err(_) -> return HTTP.response(400, "invalid bridge query")
    Ok(value) -> value
  end
  if old != 3 || current != 2 do
    return HTTP.response(400, "wrong bridge sizes")
  end
  let hex = case File.read(path) do
    Err(_) -> return HTTP.response(503, "fixture unavailable")
    Ok(value) -> value
  end
  let bytes = case Bytes.from_hex(hex) do
    Err(_) -> return HTTP.response(500, "bad fixture")
    Ok(value) -> value
  end
  case File.append(calls, "x") do
    Err(_) -> HTTP.response(500, "counter failed")
    Ok(_) -> HTTP.response_bytes(200, bytes)
  end
end

fn bridge_key() -> X25519KeyPair!String do
  case Crypto.x25519_from_seed(Bytes.from_hex("ef0106ca50fd40bd29f8e1cfb6079fd37b4052d3bf4ce20b616aff8dd2bd8c5f")?) do
    Err(_) -> Err("bridge fixture key")
    Ok(value)
  end
end

fn opaque_bridge(input :: Request,
  path :: String,
  calls :: String,
  port :: Int) -> Response!String do
  let key = bridge_key()?.private_key
  let opening = case Ohttp.decapsulate_request(key, 37, Request.body_bytes(input)) do
    Err(_) -> return Err("bridge fixture open")
    Ok(value) -> value
  end
  let inner = case decode_request(opening.plaintext, default_bhttp_limits()) do
    Err(_) -> return Err("bridge fixture request")
    Ok(value) -> value
  end
  let query = admit_lookup_request(inner, "http://127.0.0.1:#{port}", true)?
  assert(query.operation == OhttpLegacyBridgeLookup)
  let (old, current) = decode_bridge_query(query.body)?
  assert(old == 3 && current == 2)
  File.append(calls <> ".opaque", "x")?
  let response = lookup_response(query.operation, 200, Bytes.from_hex(File.read(path)?)?)?
  let encoded = case encode_response(response, BhttpKnownLength, default_bhttp_limits()) do
    Err(_) -> return Err("bridge fixture response")
    Ok(value) -> value
  end
  let wire = case Ohttp.encapsulate_response(opening.response_context, encoded) do
    Err(_) -> return Err("bridge fixture encryption")
    Ok(value) -> value
  end
  Ok(HTTP.response_bytes_with_headers(200,
    wire,
    Map.new()
      |> Map.put("Content-Type", "message/ohttp-res")
      |> Map.put("Cache-Control", "no-store")))
end

fn native_verify(input :: Bytes) -> Bytes!String do
  let request = parse_transparency_request(input)?
  let context = capture_native_ohttp_context(request.database_path,
    load_blob(request.database_path, "profile/v1")?)?
  verify_transparency_response_native(request,
    capture_native_transparency_basis(request.database_path, context)?)
end

actor bridge_server(path :: String, calls :: String, port :: Int) do
  HTTP.router()
    |> HTTP.on_post("/v2/transparency/legacy-bridge",
      fn(request :: Request) -> bridge_response(request, path, calls) end)
    |> HTTP.on_post("/v1/ohttp",
      fn(input) do
        case opaque_bridge(input, path, calls, port) do
          Err(error) -> HTTP.response(500, error)
          Ok(value) -> value
        end
      end)
    |> HTTP.serve(port)
end

fn proof(config_version :: Int) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("transparency-cutover")?
  create_account_export(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?)?
  let entry = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(path))?) do
    Err(_) -> return Err("fixture entry failed")
    Ok(value) -> value
  end
  let identity = case decode_account_identity(entry.account_identity) do
    Err(_) -> return Err("fixture identity failed")
    Ok(value) -> value
  end
  let devices = case encode_device_set(DeviceSet {
    version: 1,
    username: "alice",
    account_identity: entry.account_identity,
    sequence: identity.directory_sequence,
    devices: [entry],
    revoked_device_ids: List.new()
  }) do
    Err(_) -> return Err("fixture devices failed")
    Ok(value) -> value
  end
  let directory_signer = signer()?
  let a = signer()?
  let b = signer()?
  let c = signer()?
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> return Err("fixture delivery failed")
    Ok(value) -> value
  end
  assert(install_security_config(directory_signer.public_key.bytes,
    a.public_key.bytes,
    b.public_key.bytes,
    delivery.public_key.bytes,
    8))
  let old_leaves = [
    leaf_hash_for(1, devices)?,
    Crypto.sha256(Bytes.from_utf8("old-1")),
    Crypto.sha256(Bytes.from_utf8("old-2"))
  ]
  let now = current_time()?
  let old = sign_tree_checkpoint_for(1,
    directory_signer.private_key,
    directory_signer.public_key.bytes,
    wide(1)?,
    wide(3)?,
    merkle_root_for(1, old_leaves)?,
    repeated(0, 32)?,
    now)?
  let legacy_evidence = TransparencyEvidence {
    entry_bytes: devices,
    inclusion: compact_inclusion_proof_for(1, old_leaves, 0)?,
    consistency: compact_consistency_proof_for(1, List.new(), old_leaves)?,
    checkpoint: old,
    witnesses: [
      sign_witness("witness-a", a.private_key, old)?,
      sign_witness("witness-b", b.private_key, old)?
    ]
  }
  verify_transparency_export(request(path, legacy_evidence, "")?)?
  let key = platform_key()?
  let anchor_fields = if config_version == 5 do
    ["-", "-", "-", "0"]
  else if config_version == 4 do
    ["-", "-"]
  else
    []
  end
  let frame = Bytes.from_utf8(String.join([
      Int.to_string(config_version),
      Bytes.to_hex(directory_signer.public_key.bytes),
      Bytes.to_hex(delivery.public_key.bytes),
      "8",
      "2",
      "2",
      "witness-a " <> Bytes.to_hex(a.public_key.bytes) <> " Morse",
      "witness-c " <> Bytes.to_hex(c.public_key.bytes) <> " Outside",
      "-",
      "0",
      "-",
      "2",
      "2",
      "2",
      "witness-a " <> Bytes.to_hex(a.public_key.bytes) <> " Morse",
      "witness-b " <> Bytes.to_hex(b.public_key.bytes) <> " Morse"
    ]
      ++ anchor_fields,
    "\n"))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame))
  # A returning phone can keep operating against its explicit old policy while
  # the migration-capable native build is deployed before server activation.
  load_transparency_view(path, key)?
  let query = append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?
  assert(decode_transparency_lookup(transparency_lookup_export(query)?)?.previous_tree_size == 0)
  let sealed_leaves = old_leaves
    ++ [Crypto.sha256(Bytes.from_utf8("old-3")), Crypto.sha256(Bytes.from_utf8("old-4"))]
  let seal = sign_tree_checkpoint_for(1,
    directory_signer.private_key,
    directory_signer.public_key.bytes,
    wide(2)?,
    wide(5)?,
    merkle_root_for(1, sealed_leaves)?,
    checkpoint_hash(old)?,
    now)?
  let rfc_leaves = [leaf_hash_for(2, legacy_bridge_leaf(seal)?)?, leaf_hash_for(2, devices)?]
  let current = sign_tree_checkpoint_for(2,
    directory_signer.private_key,
    directory_signer.public_key.bytes,
    wide(1)?,
    wide(2)?,
    merkle_root_for(2, rfc_leaves)?,
    repeated(0, 32)?,
    now)?
  let bridge = LegacyBridge {
    checkpoint: seal,
    witnesses: [
      sign_witness("witness-a", a.private_key, seal)?,
      sign_witness("witness-b", b.private_key, seal)?
    ],
    consistency: compact_consistency_proof_for(1, old_leaves, sealed_leaves)?,
    inclusion: compact_inclusion_proof_for(2, rfc_leaves, 0)?
  }
  let evidence = TransparencyEvidence {
    entry_bytes: devices,
    inclusion: compact_inclusion_proof_for(2, rfc_leaves, 1)?,
    consistency: compact_consistency_proof_for(2, List.new(), rfc_leaves)?,
    checkpoint: current,
    witnesses: [
      sign_witness("witness-a", a.private_key, current)?,
      sign_witness("witness-c", c.private_key, current)?
    ]
  }
  let body_file = path <> ".bridge"
  let calls_file = path <> ".calls"
  File.write(body_file,
    Bytes.to_hex(encode_legacy_bridge(%{bridge | witnesses: [List.head(bridge.witnesses)]})?))?
  File.write(calls_file, "")?
  let port = 20310 + config_version
  let origin = "http://127.0.0.1:#{port}"
  let _server = spawn(bridge_server, body_file, calls_file, port)
  Timer.sleep(100)
  File.write(calls_file <> ".opaque", "")?
  let network = Bytes.from_utf8("1\n1\n"
    <> origin
    <> "\n"
    <> origin
    <> "\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream")
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), network))
  let security = encode_security_config(native_security_config()?)?
  let gateway = encode_key_config(OhttpKeyConfig {
    key_id: 37,
    public_key: bridge_key()?.public_key
  })?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/rpc-tls-roots/v1"), Bytes.from_hex("0100")?))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"),
    Bytes.from_utf8("1\n"
      <> Bytes.to_hex(Crypto.sha256(network))
      <> "\n"
      <> Bytes.to_hex(Crypto.sha256(security))
      <> "\n1\nrequired\n1\n0 18446744073709551615 "
      <> Bytes.to_base64(gateway))))
  let incoming = request(path, evidence, origin)?
  case native_verify(incoming) do
    Err(error) -> assert(error == "transparency_verification_failed")
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(transparency_checkpoint_bytes(path, key)?, encode_checkpoint(old)?))
  File.write(body_file, Bytes.to_hex(encode_legacy_bridge(bridge)?))?
  assert(Bytes.secure_equals(native_verify(incoming)?, devices))
  assert(Bytes.secure_equals(transparency_checkpoint_bytes(path, key)?,
    encode_checkpoint(current)?))
  assert(decode_transparency_lookup(transparency_lookup_export(query)?)?.previous_tree_size == 2)
  let view = load_transparency_view(path, key)?
  let bridge_label = "transparency-bridge/v2/#{Bytes.get(checkpoint_hash(old)?, 0)?}"
  with_record_transaction(path, fn(database) -> delete_blob(database, bridge_label) end)?
  assert(transparency_checkpoint_in_native_view(path, key, encode_checkpoint(old)?, view)?)
  let cached_bridge = load_blob(path, bridge_label)?
  assert(transparency_checkpoint_in_native_view(path, key, encode_checkpoint(old)?, view)?)
  assert(Bytes.secure_equals(open_local(cached_bridge, key, local_context(bridge_label)?)?,
    open_local(load_blob(path, bridge_label)?, key, local_context(bridge_label)?)?))
  assert(transparency_checkpoint_in_cached_view(path, key, encode_checkpoint(old)?, view)?)
  assert(transparency_checkpoint_precedes(encode_checkpoint(old)?,
    encode_checkpoint(current)?,
    view,
    path,
    key)?)
  assert(!transparency_checkpoint_precedes(encode_checkpoint(current)?,
    encode_checkpoint(old)?,
    view,
    path,
    key)?)
  let fork = sign_tree_checkpoint_for(1,
    directory_signer.private_key,
    directory_signer.public_key.bytes,
    wide(1)?,
    wide(3)?,
    Crypto.sha256(Bytes.from_utf8("forked legacy root")),
    repeated(0, 32)?,
    now)?
  case transparency_checkpoint_in_native_view(path, key, encode_checkpoint(fork)?, view) do
    Err(error) -> assert(error == "transparency_verification_failed")
    Ok(_) -> assert(false)
  end
  # A valid legacy response still cannot undo the completed transition.
  let downgrade = %{legacy_evidence |
    inclusion: compact_inclusion_proof_for(1, sealed_leaves, 0)?,
    consistency: compact_consistency_proof_for(1, old_leaves, sealed_leaves)?,
    checkpoint: seal,
    witnesses: bridge.witnesses
  }
  case native_verify(request(path, downgrade, origin)?) do
    Err(error) -> assert(error == "transparency_verification_failed")
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(transparency_checkpoint_bytes(path, key)?,
    encode_checkpoint(current)?))
  assert(File.read(calls_file)? == "")
  assert(File.read(calls_file <> ".opaque")? == "xxxx")
  File.delete(calls_file <> ".opaque")?
  File.delete(body_file)?
  File.delete(calls_file)?
  File.delete(path)?
  Ok(true)
end

test("a phone verifies both migration quorums, retains legacy group anchors and cannot downgrade") do
  case proof(3) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> do
      assert(value)
      println("m3-native-bridge-3:passed")
    end
  end
end

test("native v4 retains the RFC migration and downgrade protections") do
  case proof(4) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> do
      assert(value)
      println("m3-native-bridge-4:passed")
    end
  end
end

test("native v5 relay configuration preserves both migration quorums and rejects downgrade") do
  case proof(5) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> do
      assert(value)
      println("m3-native-bridge-5:passed")
    end
  end
end
