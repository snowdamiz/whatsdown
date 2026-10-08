##! The monitor's calls to the directory (public routes only, INTERFACES §7)
##! and to fork-evidence relays. Any failure to answer is an Err: the caller
##! treats it as "no answer yet", never as a verdict.

from Transparency.CompactWire import (
  TransparencyLeafProof,
  TransparencyLeafQuery,
  TransparencyTreeQueryV2,
  transparency_decode_consistency_v2,
  transparency_decode_cosignatures,
  transparency_decode_leaf_proof,
  transparency_encode_leaf_query,
  transparency_encode_tree_query_v2
)
from Transparency.Codec import transparency_frame_version
from Transparency.Merkle import TransparencyCheckpoint, WitnessAttestation
from Transparency.Wire import decode_checkpoint, decode_witnesses

# checkpoint is the anchored KTK when the directory includes it (the
# "checkpoint" field, hex); the §7 record carries only its hash.

pub struct AnchorRecord do
  sequence :: Int
  tree_size :: Int
  checkpoint_hash :: Bytes
  checkpoint :: Option<TransparencyCheckpoint>
  raw :: String
end

pub struct RegistryWitness do
  witness_id :: String
  public_key :: Bytes
  status :: String
end

fn get(url :: String, accept :: String) -> HttpResponse!String do
  Http.build(:get, url)
    |> Http.header("Accept", accept)
    |> Http.timeout(10000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

fn post(url :: String, body :: Bytes) -> HttpResponse!String do
  Http.build(:post, url)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(10000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

fn ok_body(response :: HttpResponse, what :: String) -> Bytes!String do
  if response.status == 200 do
    Ok(response.body_bytes)
  else
    Err("#{what} returned #{response.status}")
  end
end

# The KTC v2 path between two tree sizes of the Morse tree.

pub fn monitor_dir_consistency(base :: String,
  old_size :: Int,
  new_size :: Int) -> List<Bytes>!String do
  let query = transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
    old_size: old_size,
    new_size: new_size,
    tree: 1
  })?
  let body = ok_body(post(base <> "/v1/transparency/consistency", query)?, "consistency request")?
  let proof = transparency_decode_consistency_v2(body)?
  if proof.old_size != old_size || proof.new_size != new_size do
    Err("consistency proof covers other tree sizes")
  else
    Ok(proof.path)
  end
end

fn hex_field(root :: Json, key :: String) -> Bytes!String do
  case Bytes.from_hex(Json.as_string(Json.object_get(root, key)?)?) do
    Err(_) -> Err("invalid #{key}")
    Ok(value)
  end
end

fn anchored_checkpoint(root :: Json) -> Option<TransparencyCheckpoint> do
  case hex_field(root, "checkpoint") do
    Err(_) -> None
    Ok(bytes) -> case decode_checkpoint(bytes) do
      Err(_) -> None
      Ok(checkpoint) -> Some(checkpoint)
    end
  end
end

pub fn monitor_dir_anchor(base :: String, sequence :: Int) -> Option<AnchorRecord>!String do
  let response = get("#{base}/v1/transparency/anchor/#{sequence}", "application/json")?
  if response.status == 404 do
    Ok(None)
  else if response.status != 200 do
    Err("anchor record request returned #{response.status}")
  else
    let root = Json.parse(response.body)?
    Ok(Some(AnchorRecord {
      sequence: Json.as_int(Json.object_get(root, "sequence")?)?,
      tree_size: Json.as_int(Json.object_get(root, "tree_size")?)?,
      checkpoint_hash: hex_field(root, "checkpoint_hash")?,
      checkpoint: anchored_checkpoint(root),
      raw: response.body
    }))
  end
end

fn registry_entry(value :: Json) -> RegistryWitness!String do
  Ok(RegistryWitness {
    witness_id: Json.as_string(Json.object_get(value, "witness_id")?)?,
    public_key: hex_field(value, "public_key")?,
    status: Json.as_string(Json.object_get(value, "status")?)?
  })
end

pub fn monitor_dir_registry(base :: String) -> List<RegistryWitness>!String do
  let response = get(base <> "/v1/transparency/registry", "application/json")?
  if response.status != 200 do
    Err("registry request returned #{response.status}")
  else
    let entries = Json.object_get(Json.parse(response.body)?, "witnesses")?
    let count = Json.array_length(entries)?
    Ok(for index in 0..count do
      registry_entry(Json.array_get(entries, index)?)?
    end)
  end
end

pub fn monitor_dir_checkpoint(base :: String) -> Option<TransparencyCheckpoint>!String do
  let response = get(base <> "/v1/transparency/checkpoint", "application/octet-stream")?
  if response.status == 404 do
    Ok(None)
  else
    Ok(Some(decode_checkpoint(ok_body(response, "checkpoint request")?)?))
  end
end

fn morse_attestations(body :: Bytes) -> List<WitnessAttestation>!String do
  if transparency_frame_version(body)? == 1 do
    decode_witnesses(body)
  else
    let values = transparency_decode_cosignatures(body)?
    Ok(for value in values when value.kind == 1 do
      WitnessAttestation {
        witness_id: value.witness_id,
        checkpoint_hash: value.checkpoint_hash,
        signature: value.signature
      }
    end)
  end
end

# The Morse attestations the directory holds for its current checkpoint.

pub fn monitor_dir_attestations(base :: String) -> List<WitnessAttestation>!String do
  let response = get(base <> "/v1/transparency/witnesses", "application/x-morse-attestation-v2")?
  if response.status == 404 do
    Ok(List.new())
  else
    morse_attestations(ok_body(response, "witness list request")?)
  end
end

pub fn monitor_dir_leaf(base :: String,
  index :: Int,
  size :: Int) -> TransparencyLeafProof!String do
  let query = transparency_encode_leaf_query(TransparencyLeafQuery {
    leaf_index: index,
    tree_size: size,
    tree: 1
  })?
  let proof = transparency_decode_leaf_proof(ok_body(post(base <> "/v1/transparency/leaf", query)?,
    "leaf request")?)?
  if proof.inclusion.leaf_index != index || proof.inclusion.tree_size != size do
    Err("leaf proof covers another index or size")
  else
    Ok(proof)
  end
end

# Up to count Morse leaf hashes from start (fewer past the end of the log).

pub fn monitor_dir_leaves(base :: String, start :: Int, count :: Int) -> List<Bytes>!String do
  let body = ok_body(get("#{base}/v1/transparency/leaves?start=#{start}&count=#{count}",
      "application/octet-stream")?,
    "leaves request")?
  let total = Bytes.length(body) / 32
  if total * 32 != Bytes.length(body) || total > count do
    Err("invalid leaves response")
  else
    Ok(for index in 0..total do
      case Bytes.slice(body, index * 32, 32) do
        Err(_) -> Bytes.empty()
        Ok(value) -> value
      end
    end)
  end
end

# Files an FRK with one relay; returns the HTTP status.

pub fn monitor_relay_file(relay :: String, frk :: Bytes) -> Int!String do
  let response = post(relay <> "/v1/fork-evidence", frk)?
  Ok(response.status)
end
