from Mobile.Transparency import (
  legacy_witness_set_id,
  store_transparency_origin,
  transparency_checkpoint_in_cached_view,
  transparency_checkpoint_in_native_view,
  transparency_checkpoint_in_view
)
from Mobile.Types import MobileTransparencyView
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_blobs
from MobileCore import create_account_export, erase_account_export
from Mobile.Platform import native_security_config
from Mobile.Codec import current_time
from Tests.Support import append, vector, install_security_config
from Transparency.Config import encode_security_config
from Ohttp.Keys import OhttpKeyConfig, encode_key_config
from Ohttp.BinaryHttp import decode_request, encode_response
from Ohttp.LookupPolicy import OhttpLookupOperation, admit_lookup_request, lookup_response
from Ohttp.Types import BhttpFraming, default_bhttp_limits
from Tests.GroupConsistencySupport import signing_pair, wide
from Tests.Support import database_path, repeated
from Transparency.Merkle import checkpoint_hash, compact_consistency_proof
from Transparency.Merkle import (
  sign_tree_checkpoint_for,
  compact_consistency_proof_for,
  merkle_root_for
)
from Transparency.Wire import (
  decode_transparency_tree_query,
  encode_checkpoint,
  encode_consistency_proof
)

fn gateway_key() -> X25519KeyPair!String do
  case Crypto.x25519_from_seed(Bytes.from_hex("ef0106ca50fd40bd29f8e1cfb6079fd37b4052d3bf4ce20b616aff8dd2bd8c5f")?) do
    Err(_) -> Err("fixture OHTTP key")
    Ok(value)
  end
end

fn proof_reply(request :: Request, proof :: Bytes, calls :: String) -> Response!String do
  let query = decode_transparency_tree_query(Request.body_bytes(request))?
  assert(query.previous_tree_size == 3 && query.new_tree_size == 7)
  File.append(calls, "d")?
  Ok(HTTP.response_bytes(200, proof))
end

fn opaque_proof(request :: Request,
  proof :: Bytes,
  calls :: String,
  port :: Int) -> Response!String do
  let key = gateway_key()?.private_key
  let opened = case Ohttp.decapsulate_request(key, 37, Request.body_bytes(request)) do
    Err(_) -> return Err("fixture OHTTP open")
    Ok(value) -> value
  end
  let inner = case decode_request(opened.plaintext, default_bhttp_limits()) do
    Err(_) -> return Err("fixture BHTTP")
    Ok(value) -> value
  end
  let query = admit_lookup_request(inner, "http://127.0.0.1:#{port}", true)?
  assert(query.operation == OhttpConsistencyLookup(1))
  let range = decode_transparency_tree_query(query.body)?
  assert(range.previous_tree_size == 3 && range.new_tree_size == 7)
  File.append(calls, "o")?
  let response = lookup_response(query.operation, 200, proof)?
  let encoded = case encode_response(response, BhttpKnownLength, default_bhttp_limits()) do
    Err(_) -> return Err("fixture encode")
    Ok(value) -> value
  end
  let wire = case Ohttp.encapsulate_response(opened.response_context, encoded) do
    Err(_) -> return Err("fixture reply")
    Ok(value) -> value
  end
  Ok(HTTP.response_bytes_with_headers(200,
    wire,
    Map.new()
      |> Map.put("Content-Type", "message/ohttp-res")
      |> Map.put("Cache-Control", "no-store")))
end

actor proof_server(port :: Int, proof :: Bytes, calls :: String) do
  HTTP.router()
    |> HTTP.on_post("/v1/transparency/consistency",
      fn(request) do
        case proof_reply(request, proof, calls) do
          Err(error) -> HTTP.response(500, error)
          Ok(value) -> value
        end
      end)
    |> HTTP.on_post("/v1/ohttp",
      fn(request) do
        case opaque_proof(request, proof, calls, port) do
          Err(error) -> HTTP.response(500, error)
          Ok(value) -> value
        end
      end)
    |> HTTP.serve(port)
end

fn native_proof(mode :: Int) -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("native-proof-#{mode}")?
  let calls = path <> ".calls"
  File.write(calls, "")?
  create_account_export(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?)?
  let key = platform_key()?
  let signer = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  let delivery = gateway_key()?
  assert(install_security_config(signer.public_key.bytes,
    a.public_key.bytes,
    b.public_key.bytes,
    delivery.public_key.bytes,
    1))
  let leaves = for index in 0..7 do
    Crypto.sha256(Bytes.from_utf8("mobile-tree/#{index}"))
  end
  let old_leaves = List.take(leaves, 3)
  let recent_leaves = List.take(leaves, 5)
  let now = current_time()?
  let anchor = sign_tree_checkpoint_for(1,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(3)?,
    merkle_root_for(1, old_leaves)?,
    repeated(0, 32)?,
    now)?
  let previous = sign_tree_checkpoint_for(1,
    signer.private_key,
    signer.public_key.bytes,
    wide(2)?,
    wide(5)?,
    merkle_root_for(1, recent_leaves)?,
    checkpoint_hash(anchor)?,
    now)?
  let current = sign_tree_checkpoint_for(1,
    signer.private_key,
    signer.public_key.bytes,
    wide(3)?,
    wide(7)?,
    merkle_root_for(1, leaves)?,
    checkpoint_hash(previous)?,
    now)?
  let view = MobileTransparencyView {
    checkpoint: encode_checkpoint(current)?,
    consistency: encode_consistency_proof(compact_consistency_proof_for(1,
      recent_leaves,
      leaves)?)?,
    service_public_key: signer.public_key.bytes,
    set_id: legacy_witness_set_id(a.public_key.bytes, b.public_key.bytes)?,
    witness_threshold: 2
  }
  let checkpoint_blob = seal_local(view.checkpoint,
    key,
    local_context("transparency-checkpoint/v1")?)?
  store_blobs(path, ["transparency-checkpoint/v1"], [checkpoint_blob])?
  let port = 20210 + mode
  let stored = "http://127.0.0.1:#{port}"
  let configured = if mode == 0 do
    stored
  else
    "http://127.0.0.1:#{20220 + mode}"
  end
  store_transparency_origin(path, key, stored)?
  let origin_blob = load_blob(path, "transparency-origin/v1")?
  let network = Bytes.from_utf8("1\n1\n"
    <> configured
    <> "\n"
    <> stored
    <> "\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream")
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), network))
  let security = encode_security_config(native_security_config()?)?
  let public = encode_key_config(OhttpKeyConfig { key_id: 37, public_key: delivery.public_key })?
  let companion = Bytes.from_utf8("1\n"
    <> Bytes.to_hex(Crypto.sha256(network))
    <> "\n"
    <> Bytes.to_hex(Crypto.sha256(security))
    <> "\n1\n"
    <> if mode == 1 do
      "off\n0"
    else
      "required\n1\n0 18446744073709551615 " <> Bytes.to_base64(public)
    end)
  assert(Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"), companion))
  let proof = encode_consistency_proof(compact_consistency_proof_for(1, old_leaves, leaves)?)?
  let core_calls = calls <> ".core"
  File.write(core_calls, "")?
  if mode == 1 || mode == 2 do
    let _core = spawn(proof_server, 20220 + mode, proof, core_calls)
    nil
  end
  let _server = spawn(proof_server, port, proof, calls)
  Timer.sleep(75)
  let label = "transparency-anchor/v2/#{Bytes.get(checkpoint_hash(anchor)?, 0)?}"
  let result = transparency_checkpoint_in_native_view(path, key, encode_checkpoint(anchor)?, view)
  if mode == 2 do
    case result do
      Err(error) -> assert(error == "transparency_origin_mismatch")
      Ok(_) -> assert(false)
    end
    assert(File.read(calls)? == "")
    assert(Result.is_err(load_blob(path, label)))
  else
    assert(result?)
    let cache = load_blob(path, label)?
    assert(transparency_checkpoint_in_native_view(path, key, encode_checkpoint(anchor)?, view)?)
    assert(Bytes.secure_equals(load_blob(path, label)?, cache))
    assert(File.read(calls)? == if mode == 1 do
        "d"
      else
        "o"
      end)
  end
  assert(Bytes.secure_equals(load_blob(path, "transparency-checkpoint/v1")?, checkpoint_blob))
  assert(Bytes.secure_equals(load_blob(path, "transparency-origin/v1")?, origin_blob))
  assert(File.read(core_calls)? == "")
  File.delete(core_calls)?
  erase_account_export(Bytes.from_utf8(path))?
  File.delete(calls)?
  File.delete(path)?
  Ok(nil)
end

test("native required consistency proof uses encrypted transport and exact cache") do
  case native_proof(0) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> println("m3-native-proof-required:passed")
  end
end

test("explicit off proof retains authenticated stored origin distinct from configured core") do
  case native_proof(1) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> println("m3-native-proof-off-origin:passed")
  end
end

test("required mismatched stored origin contacts neither origin and writes no trust cache") do
  case native_proof(2) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> println("m3-native-proof-origin-refusal:passed")
  end
end
