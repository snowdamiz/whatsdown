from Mobile.Transparency import (
  legacy_witness_set_id,
  store_transparency_origin,
  transparency_checkpoint_in_cached_view,
  transparency_checkpoint_in_view
)
from Mobile.Types import MobileTransparencyView
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
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

actor consistency_server(proof :: Bytes, calls :: String, version :: Int, port :: Int) do
  let route = if version == 2 do
    "/v2/transparency/consistency"
  else
    "/v1/transparency/consistency"
  end
  HTTP.router()
    |> HTTP.on_post(route,
      fn(request :: Request) do
        case decode_transparency_tree_query(Request.body_bytes(request)) do
          Err(_) -> HTTP.response(400, "invalid request")
          Ok(query) -> if query.previous_tree_size != 3 || query.new_tree_size != 7 do
            HTTP.response(400, "wrong proof range")
          else
            case File.append(calls, "x") do
              Err(_) -> HTTP.response(500, "counter failed")
              Ok(_) -> HTTP.response_bytes_with_headers(200,
                proof,
                Map.put(Map.new(), "Content-Type", "application/octet-stream"))
            end
          end
        end
      end)
    |> HTTP.serve(port)
end

fn proof(version :: Int, port :: Int) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("compact-transparency-#{version}")?
  let calls = path <> ".calls"
  File.write(calls, "")?
  ensure_schema(path)?
  let key = platform_key()?
  let signer = signing_pair()?
  let leaves = for index in 0..7 do
    Crypto.sha256(Bytes.from_utf8("mobile-tree/#{index}"))
  end
  let old_leaves = for index in 0..3 do
    List.get(leaves, index)
  end
  let recent_leaves = for index in 0..5 do
    List.get(leaves, index)
  end
  let anchor = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(3)?,
    merkle_root_for(version, old_leaves)?,
    repeated(0, 32)?,
    wide(1000)?)?
  let previous = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(2)?,
    wide(5)?,
    merkle_root_for(version, recent_leaves)?,
    checkpoint_hash(anchor)?,
    wide(2000)?)?
  let current = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(3)?,
    wide(7)?,
    merkle_root_for(version, leaves)?,
    checkpoint_hash(previous)?,
    wide(3000)?)?
  let view = MobileTransparencyView {
    checkpoint: encode_checkpoint(current)?,
    consistency: encode_consistency_proof(compact_consistency_proof_for(version,
      recent_leaves,
      leaves)?)?,
    service_public_key: signer.public_key.bytes,
    set_id: legacy_witness_set_id(repeated(1, 32)?, repeated(2, 32)?)?,
    witness_threshold: 2
  }
  assert(transparency_checkpoint_in_view(view.checkpoint, view)?)
  assert(transparency_checkpoint_in_view(encode_checkpoint(previous)?, view)?)
  assert(!transparency_checkpoint_in_view(encode_checkpoint(anchor)?, view)?)
  store_transparency_origin(path, key, "http://127.0.0.1:#{port}")?
  let _server = spawn(consistency_server,
    encode_consistency_proof(compact_consistency_proof_for(version, old_leaves, leaves)?)?,
    calls,
    version,
    port)
  Timer.sleep(100)
  assert(transparency_checkpoint_in_cached_view(path, key, encode_checkpoint(anchor)?, view)?)
  assert(File.read(calls)? == "x")
  # The same group anchor uses its sealed cached proof on subsequent checks.
  assert(transparency_checkpoint_in_cached_view(path, key, encode_checkpoint(anchor)?, view)?)
  assert(File.read(calls)? == "x")
  let fork_leaves = [
    List.get(leaves, 0),
    List.get(leaves, 1),
    Crypto.sha256(Bytes.from_utf8("fork"))
  ]
  let fork = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(3)?,
    merkle_root_for(version, fork_leaves)?,
    repeated(0, 32)?,
    wide(1000)?)?
  case transparency_checkpoint_in_cached_view(path, key, encode_checkpoint(fork)?, view) do
    Err(error) -> assert(error == "transparency_consistency_invalid")
    Ok(_) -> assert(false)
  end
  assert(File.read(calls)? == "xx")
  # Invalid signatures and future checkpoints must not trigger a network read.
  assert(!transparency_checkpoint_in_cached_view(path,
    key,
    encode_checkpoint(%{anchor | signature: repeated(0, 64)?})?,
    view)?)
  assert(!transparency_checkpoint_in_cached_view(path,
    key,
    view.checkpoint,
    %{view | checkpoint: encode_checkpoint(anchor)?})?)
  assert(File.read(calls)? == "xx")
  File.delete(calls)?
  File.delete(path)?
  Ok(true)
end

test("compact group anchors fetch one exact-range proof, cache it, and refuse forks") do
  case proof(1, 18995) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn log_profiles() -> Bool!String do
  let signer = signing_pair()?
  let leaf = Crypto.sha256(Bytes.from_utf8("single-leaf"))
  let old = sign_tree_checkpoint_for(1,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(1)?,
    leaf,
    repeated(0, 32)?,
    wide(1000)?)?
  let current = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(2)?,
    wide(1)?,
    leaf,
    repeated(0, 32)?,
    wide(2000)?)?
  let view = MobileTransparencyView {
    checkpoint: encode_checkpoint(current)?,
    consistency: encode_consistency_proof(compact_consistency_proof_for(2, [leaf], [leaf])?)?,
    service_public_key: signer.public_key.bytes,
    set_id: legacy_witness_set_id(repeated(1, 32)?, repeated(2, 32)?)?,
    witness_threshold: 2
  }
  assert(transparency_checkpoint_in_view(view.checkpoint, view)?)
  assert(!transparency_checkpoint_in_view(encode_checkpoint(old)?, view)?)
  let wrong_profile = %{view |
    consistency: encode_consistency_proof(compact_consistency_proof([leaf], [leaf])?)?
  }
  assert(!transparency_checkpoint_in_view(view.checkpoint, wrong_profile)?)
  assert(!transparency_checkpoint_in_view(encode_checkpoint(old)?, wrong_profile)?)
  let next_leaves = [leaf, Crypto.sha256(Bytes.from_utf8("next"))]
  let next = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(3)?,
    wide(2)?,
    merkle_root_for(2, next_leaves)?,
    checkpoint_hash(current)?,
    wide(3000)?)?
  let next_view = %{view |
    checkpoint: encode_checkpoint(next)?,
    consistency: encode_consistency_proof(compact_consistency_proof_for(2, [leaf], next_leaves)?)?
  }
  assert(transparency_checkpoint_in_view(view.checkpoint, next_view)?)
  Ok(true)
end

test("group anchor proofs are bound to the signed log version") do
  case log_profiles() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("RFC 6962 group anchors fetch and cache the versioned consistency route") do
  case proof(2, 18996) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
