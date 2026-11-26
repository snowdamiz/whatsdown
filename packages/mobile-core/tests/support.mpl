from MobileCore import transparency_anchor_proof_export, transparency_anchor_requests_export
from Security.Config import SecurityConfig, SecurityWitness, security_config_encode
from Transparency.CompactWire import (
  CompactConsistency,
  CompactInclusion,
  TransparencyEvidenceV2,
  WitnessCosignature,
  transparency_decode_tree_query_v2,
  transparency_encode_consistency_v2,
  transparency_encode_evidence_v2
)
from Transparency.Merkle import TransparencyCheckpoint, WitnessAttestation
from Transparency.Tree import tlog_consistency_path, tlog_inclusion_path, tlog_list_oracle

pub fn append(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("test byte concatenation failed")
    Ok(value)
  end
end

pub fn write_u32(value :: Int) -> Bytes!String do
  let wide = case U64.parse(Int.to_string(value)) do
    Err(_) -> Err("test integer conversion failed")
    Ok(parsed)
  end?
  case Bytes.write_u32_be(wide) do
    Err(_) -> Err("test integer encoding failed")
    Ok(encoded)
  end
end

pub fn read_u32(value :: Bytes) -> Int!String do
  case Bytes.read_u32_be(value, 0) do
    Err(_) -> Err("test integer decoding failed")
    Ok(wide) -> case U64.to_int(wide) do
      Err(_) -> Err("test integer conversion failed")
      Ok(parsed)
    end
  end
end

pub fn vector(value :: Bytes) -> Bytes!String do
  append(write_u32(Bytes.length(value))?, value)
end

pub fn repeated(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("test byte allocation failed")
    Ok(output)
  end
end

pub fn database_path(label :: String) -> String!String do
  case Crypto.random_bytes(8) do
    Err(_) -> Err("test path generation failed")
    Ok(value) -> Ok("/tmp/mesh_mobile_" <> label <> "_" <> Bytes.to_hex(value) <> ".db")
  end
end

pub fn install_security_config(service_public_key :: Bytes,
  witness_a_public_key :: Bytes,
  witness_b_public_key :: Bytes,
  delivery_public_key :: Bytes,
  difficulty :: Int) -> Bool do
  Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    Bytes.from_utf8("1\n"
      <> Bytes.to_hex(service_public_key)
      <> "\n"
      <> Bytes.to_hex(witness_a_public_key)
      <> "\n"
      <> Bytes.to_hex(witness_b_public_key)
      <> "\n"
      <> Bytes.to_hex(delivery_public_key)
      <> "\n"
      <> Int.to_string(difficulty)))
end

pub fn cosignature(value :: WitnessAttestation) -> WitnessCosignature do
  WitnessCosignature {
    kind: 1,
    witness_id: value.witness_id,
    checkpoint_hash: value.checkpoint_hash,
    timestamp: 0,
    signature: value.signature
  }
end

# Version 2 evidence (compact proofs) for `entry_bytes` at `leaf_index` of the
# log `leaves`, consistent from a device that last saw `old_size` leaves.

pub fn evidence_v2(entry_bytes :: Bytes,
  leaves :: List<Bytes>,
  leaf_index :: Int,
  old_size :: Int,
  checkpoint :: TransparencyCheckpoint,
  attestations :: List<WitnessAttestation>) -> Bytes!String do
  let oracle = tlog_list_oracle(1, leaves)
  let size = List.length(leaves)
  transparency_encode_evidence_v2(TransparencyEvidenceV2 {
    entry_bytes: entry_bytes,
    inclusion: CompactInclusion {
      leaf_index: leaf_index,
      tree_size: size,
      path: tlog_inclusion_path(1, oracle, leaf_index, size)?
    },
    consistency: CompactConsistency {
      old_size: old_size,
      new_size: size,
      path: tlog_consistency_path(1, oracle, old_size, size)?
    },
    checkpoint: checkpoint,
    witnesses: List.map(attestations, fn value -> cosignature(value) end),
    c2sp_root: Bytes.empty(),
    c2sp_path: List.new()
  })
end

# The KTC v2 an honest directory answers for a KTS v2 over `leaves`.

pub fn consistency_v2(leaves :: List<Bytes>, old_size :: Int, new_size :: Int) -> Bytes!String do
  let oracle = tlog_list_oracle(1, List.take(leaves, new_size))
  transparency_encode_consistency_v2(CompactConsistency {
    old_size: old_size,
    new_size: new_size,
    path: tlog_consistency_path(1, oracle, old_size, new_size)?
  })
end

fn output_items(input :: Bytes,
  offset :: Int,
  count :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if List.length(output) >= count do
    Ok(output)
  else
    let length = read_u32(Bytes.slice(input, offset, 4)?)?
    output_items(input,
      offset + 4 + length,
      count,
      List.append(output, Bytes.slice(input, offset + 4, length)?))
  end
end

pub fn output_list_items(input :: Bytes) -> List<Bytes>!String do
  output_items(input, 8, read_u32(Bytes.slice(input, 4, 4)?)?, List.new())
end

# Answers every pending anchor proof request from the log `leaves`, as the app
# does with the directory's /v1/transparency/consistency.

pub fn supply_anchor_proofs(path :: String, leaves :: List<Bytes>) -> Int!String do
  let requests = output_list_items(transparency_anchor_requests_export(Bytes.from_utf8(path))?)?
  let answered = for request in requests do
    let query = transparency_decode_tree_query_v2(Bytes.slice(request, 0, 21)?)?
    transparency_anchor_proof_export(append(append(vector(Bytes.from_utf8(path))?,
        vector(request)?)?,
      vector(consistency_v2(leaves, query.old_size, query.new_size)?)?)?)?
  end
  Ok(List.length(answered))
end

# Pins a version 2 config: these witnesses, k their strict majority.

pub fn install_witness_config(service_public_key :: Bytes,
  delivery_public_key :: Bytes,
  witnesses :: List<SecurityWitness>) -> Bool!String do
  let frame = security_config_encode(SecurityConfig {
    version: 2,
    service_public_key: service_public_key,
    delivery_public_key: delivery_public_key,
    abuse_difficulty: 8,
    threshold: List.length(witnesses) / 2 + 1,
    witnesses: witnesses,
    judge_program_id: "",
    log_account: "",
    rpc_urls: List.new(),
    relays: List.new(),
    issuer_origin: "",
    c2sp_origin: "",
    minimum_suite: 1,
    ohttp_key_config: Bytes.empty(),
    ohttp_relay: "",
    set_id: Bytes.empty()
  })?
  Ok(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame))
end
