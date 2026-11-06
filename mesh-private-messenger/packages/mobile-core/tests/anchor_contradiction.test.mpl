from Transparency.AnchorContradiction import AnchorLeafEvidence, discover_anchor_contradiction
from Mobile.Codec import mobile_append
from Transparency.AnchorRing import AnchorEntry
from Transparency.AnchorEvidence import retain_anchor_signatures
from Transparency.LeafProof import LeafQuery, LeafProof, encode_leaf_proof, decode_leaf_query
from Transparency.Merkle import (
  TransparencyCheckpoint,
  InclusionProof,
  compact_inclusion_proof_for,
  merkle_root_for,
  sign_tree_checkpoint_for,
  checkpoint_hash
)
from Transparency.Fork import ForkProof, ForkTarget, ForkPaths, decode_fork
from Tests.GroupConsistencySupport import signing_pair, wide
from Tests.Support import database_path, repeated

fn respond(request :: Request, mode :: String, answer :: String, calls :: String) -> Response do
  File.append(calls, "x")
  let query = case decode_leaf_query(Request.body_bytes(request)) do
    Err(_) -> return HTTP.response(400, "bad query")
    Ok(value) -> value
  end
  if query.leaf_index != 1 || query.tree_size != 7 do
    return HTTP.response(400, "wrong position")
  end
  let setting = File.read(mode).unwrap_or("down")
  if setting == "down" do
    return HTTP.response(503, "")
  end
  if setting == "missing" do
    return HTTP.response(404, "")
  end
  if setting == "bad" do
    return HTTP.response(200, "bad proof")
  end
  if setting == "big" do
    return HTTP.response(200, String.repeat("x", 1075))
  end
  let bytes = case File.read(answer) do
    Err(error) -> return HTTP.response(500, error)
    Ok(value) -> case Bytes.from_hex(value) do
      Err(error) -> return HTTP.response(500, error)
      Ok(value) -> value
    end
  end
  HTTP.response_bytes(200, bytes)
end

actor directory(mode :: String, answer :: String, calls :: String) do
  HTTP.router()
    |> HTTP.on_post("/v1/transparency/leaf",
      fn(request :: Request) do respond(request, mode, answer, calls) end)
    |> HTTP.on_post("/v2/transparency/leaf",
      fn(request :: Request) do respond(request, mode, answer, calls) end)
    |> HTTP.serve(19095)
end

fn proof() -> Bool!String do
  let signer = signing_pair()?
  let mode = database_path("anchor-leaf-mode")?
  let answer = database_path("anchor-leaf-answer")?
  let calls = database_path("anchor-leaf-calls")?
  File.write(mode, "good")?
  File.write(calls, "")?
  let _server = spawn(directory, mode, answer, calls)
  Timer.sleep(100)
  let origin = "http://127.0.0.1:19095"
  let public_leaves = for index in 0..7 do
    Crypto.sha256(Bytes.from_utf8("public/#{index}"))
  end
  let private_leaves = [
    List.get(public_leaves, 0),
    Crypto.sha256(Bytes.from_utf8("private replacement")),
    List.get(public_leaves, 2)
  ]
  for version in [1, 2] do
    let private = sign_tree_checkpoint_for(version,
      signer.private_key,
      signer.public_key.bytes,
      wide(8)?,
      wide(3)?,
      merkle_root_for(version, private_leaves)?,
      repeated(0, 32)?,
      wide(1000)?)?
    let public = sign_tree_checkpoint_for(version,
      signer.private_key,
      signer.public_key.bytes,
      wide(9)?,
      wide(7)?,
      merkle_root_for(version, public_leaves)?,
      checkpoint_hash(private)?,
      wide(2000)?)?
    let entry = AnchorEntry {
      sequence: public.sequence,
      tree_size: public.tree_size,
      tree_root: public.tree_root,
      checkpoint_hash: checkpoint_hash(public)?,
      timestamp: public.timestamp,
      slot: wide(50)?,
      cosign_bitmap: 0,
      log_version: version,
      rollback: false,
      native_bitmap: 0,
      witness_generation: 0
    }
    let leaf = LeafProof {
      leaf_hash: List.get(private_leaves, 1),
      inclusion: compact_inclusion_proof_for(version, private_leaves, 1)?
    }
    let public_leaf = LeafProof {
      leaf_hash: List.get(public_leaves, 1),
      inclusion: compact_inclusion_proof_for(version, public_leaves, 1)?
    }
    File.write(answer, Bytes.to_hex(encode_leaf_proof(public_leaf)?))?
    File.write(mode, "good")?
    let result = discover_anchor_contradiction(origin,
      private,
      entry,
      4095,
      signer.public_key.bytes,
      leaf)?
    assert(Bytes.secure_equals(result.response, encode_leaf_proof(public_leaf)?))
    let fork = decode_fork(result.fork)?
    assert(fork.kind == 2 && fork.second == AnchorReference(4095))
    retain_anchor_signatures(fork, signer.public_key, [], entry, [])?
    case fork.contradiction do
      None -> assert(false)
      Some(paths) -> assert(U64.to_string(paths.leaf_index) == "1")
    end
    for setting in ["down", "missing", "bad", "big"] do
      File.write(mode, setting)?
      let absent = discover_anchor_contradiction(origin,
        private,
        entry,
        4095,
        signer.public_key.bytes,
        leaf)?
      assert(Bytes.length(absent.fork) == 0)
      assert(absent.status == if setting == "down" || setting == "big" do
          "proof_unavailable"
        else
          "mismatch"
        end)
    end
    File.write(mode, "good")?
    for wrong in [
      %{public_leaf | leaf_hash: repeated(7, 32)?},
      LeafProof {
        leaf_hash: List.get(public_leaves, 0),
        inclusion: compact_inclusion_proof_for(version, public_leaves, 0)?
      },
      LeafProof {
        leaf_hash: List.get(public_leaves, 1),
        inclusion: compact_inclusion_proof_for(version, List.take(public_leaves, 3), 1)?
      },
      %{public_leaf |
        inclusion: %{public_leaf.inclusion |
          version: if version == 1 do
            3
          else
            2
          end
        }
      }
    ] do
      File.write(answer, Bytes.to_hex(encode_leaf_proof(wrong)?))?
      assert(Bytes.length(discover_anchor_contradiction(origin,
        private,
        entry,
        4095,
        signer.public_key.bytes,
        leaf)?.fork) == 0)
    end
    File.write(answer, Bytes.to_hex(encode_leaf_proof(public_leaf)?))?
    let same = sign_tree_checkpoint_for(version,
      signer.private_key,
      signer.public_key.bytes,
      wide(8)?,
      wide(3)?,
      merkle_root_for(version, List.take(public_leaves, 3))?,
      repeated(0, 32)?,
      wide(1000)?)?
    let same_leaf = LeafProof {
      leaf_hash: public_leaf.leaf_hash,
      inclusion: compact_inclusion_proof_for(version, List.take(public_leaves, 3), 1)?
    }
    assert(Bytes.length(discover_anchor_contradiction(origin,
      same,
      entry,
      4095,
      signer.public_key.bytes,
      same_leaf)?.fork) == 0)
    # Invalid local evidence is rejected before its index leaves the phone.
    let before = File.read(calls)?
    case discover_anchor_contradiction(origin,
      private,
      entry,
      4095,
      signer.public_key.bytes,
      %{leaf | leaf_hash: repeated(0, 32)?}) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
    case discover_anchor_contradiction(origin,
      %{private | signature: repeated(0, 64)?},
      entry,
      4095,
      signer.public_key.bytes,
      leaf) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
    assert(File.read(calls)? == before)
  end
  File.delete(mode)?
  File.delete(answer)?
  File.delete(calls)?
  Ok(true)
end

test("F2 discovery requires two authenticated paths at the exact same leaf and never fabricates evidence from refusal") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
