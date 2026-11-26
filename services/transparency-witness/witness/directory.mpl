##! The witness's calls to the directory and to fork-evidence relays. Only
##! public routes: the checkpoint, its attestations, consistency proofs and
##! attestation submission (pull mode needs no inbound endpoint).

from Transparency.Codec import transparency_frame_version
from Transparency.CompactWire import (
  TransparencyTreeQueryV2,
  transparency_decode_consistency_v2,
  transparency_encode_tree_query_v2
)
from Transparency.Merkle import TransparencyCheckpoint, WitnessAttestation, verify_consistency
from Transparency.Tree import tlog_verify_consistency
from Transparency.Wire import (
  TransparencyTreeQuery,
  decode_checkpoint,
  decode_consistency_proof,
  decode_witnesses,
  encode_transparency_tree_query,
  encode_witnesses
)

# A consistency answer: the proof bytes the directory sent (kept as evidence)
# and whether they prove current extends previous.

pub struct ConsistencyReply do
  version :: Int
  body :: Bytes
  valid :: Bool
end

fn get(url :: String) -> HttpResponse!String do
  Http.build(:get, url)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

fn post(url :: String, body :: Bytes) -> HttpResponse!String do
  Http.build(:post, url)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

pub fn witness_fetch_checkpoint(base_url :: String) -> Option<TransparencyCheckpoint>!String do
  let response = get(base_url <> "/v1/transparency/checkpoint")?
  if response.status == 404 do
    Ok(None)
  else if response.status != 200 do
    Err("checkpoint request returned #{response.status}")
  else
    Ok(Some(decode_checkpoint(response.body_bytes)?))
  end
end

# The Morse attestations the directory holds for its current checkpoint.

pub fn witness_fetch_attestations(base_url :: String) -> List<WitnessAttestation>!String do
  let response = get(base_url <> "/v1/transparency/witnesses")?
  if response.status == 404 do
    Ok(List.new())
  else if response.status != 200 do
    Err("witness list request returned #{response.status}")
  else
    decode_witnesses(response.body_bytes)
  end
end

# 201 stored, 200 already stored (a retry after a lost answer).

pub fn witness_submit(base_url :: String,
  attestation :: WitnessAttestation) -> Result<(), String> do
  let response = post(base_url <> "/v1/transparency/witnesses", encode_witnesses([attestation])?)?
  if response.status == 200 || response.status == 201 do
    Ok(nil)
  else
    Err("witness submission returned #{response.status}")
  end
end

fn int_of(value :: U64) -> Int!String do
  U64.to_int(value)
end

fn v2_reply(body :: Bytes,
  previous :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint) -> ConsistencyReply!String do
  let proof = transparency_decode_consistency_v2(body)?
  if proof.old_size != int_of(previous.tree_size)?
    || proof.new_size != int_of(current.tree_size)? do
    Err("consistency proof covers other tree sizes")
  else
    Ok(ConsistencyReply {
      version: 2,
      body: body,
      valid: tlog_verify_consistency(1,
        proof.old_size,
        proof.new_size,
        proof.path,
        previous.tree_root,
        current.tree_root)
    })
  end
end

fn v1_reply(body :: Bytes,
  previous :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint) -> ConsistencyReply!String do
  let proof = decode_consistency_proof(body)?
  # The v1 directory proves up to its newest tree; if that moved past the
  # checkpoint being judged, ask again next round rather than call it a fork.
  if proof.old_tree_size != int_of(previous.tree_size)?
    || proof.new_tree_size != int_of(current.tree_size)? do
    Err("consistency proof covers other tree sizes")
  else
    Ok(ConsistencyReply {
      version: 1,
      body: body,
      valid: verify_consistency(previous.tree_root, current.tree_root, proof)?
    })
  end
end

fn v1_consistency(base_url :: String,
  previous :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint) -> ConsistencyReply!String do
  let size = int_of(previous.tree_size)?
  let query = case encode_transparency_tree_query(TransparencyTreeQuery {
    previous_tree_size: size
  }) do
    Err(_) -> Err("the directory offers only v1 consistency proofs, which stop at 4,096 entries")
    Ok(value)
  end?
  let response = post(base_url <> "/v1/transparency/consistency", query)?
  if response.status != 200 do
    Err("consistency request returned #{response.status}")
  else
    v1_reply(response.body_bytes, previous, current)
  end
end

# Asks for a KTC v2 proof between the two tree sizes. A directory that only
# speaks v1 refuses the v2 query (400); only then is the v1 query sent.

pub fn witness_consistency(base_url :: String,
  previous :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint) -> ConsistencyReply!String do
  let query = transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
    old_size: int_of(previous.tree_size)?,
    new_size: int_of(current.tree_size)?,
    tree: 1
  })?
  let response = post(base_url <> "/v1/transparency/consistency", query)?
  if response.status == 400 do
    v1_consistency(base_url, previous, current)
  else if response.status != 200 do
    Err("consistency request returned #{response.status}")
  else if transparency_frame_version(response.body_bytes)? == 1 do
    v1_reply(response.body_bytes, previous, current)
  else
    v2_reply(response.body_bytes, previous, current)
  end
end

# Files an FRK with one relay; returns the HTTP status.

pub fn witness_relay(relay_url :: String, frk :: Bytes) -> Int!String do
  let response = post(relay_url <> "/v1/fork-evidence", frk)?
  Ok(response.status)
end
