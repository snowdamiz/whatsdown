from Transparency.Migration import (
  LegacyBridge,
  legacy_bridge_leaf,
  encode_legacy_bridge,
  decode_legacy_bridge,
  verify_migrated_evidence
)
from Transparency.Migration import verify_legacy_bridge
from Transparency.Merkle import (
  WitnessKey,
  leaf_hash_for,
  merkle_root_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_tree_checkpoint_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence, encode_checkpoint
from Transparency.Client import verify_evidence

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test signing key failed")
    Ok(value)
  end
end

fn migration() -> Bool!String do
  let signer = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  let c = signing_pair()?
  let pins = [
    WitnessKey { witness_id: "a", public_key: a.public_key.bytes },
    WitnessKey { witness_id: "b", public_key: b.public_key.bytes },
    WitnessKey { witness_id: "c", public_key: c.public_key.bytes }
  ]
  let zero = Bytes.from_hex("0000000000000000000000000000000000000000000000000000000000000000")?
  let old_tree = [leaf_hash_for(1, Bytes.from_utf8("legacy"))?]
  let final_tree = List.append(old_tree, leaf_hash_for(1, Bytes.from_utf8("legacy-final"))?)
  let cached = sign_tree_checkpoint_for(1,
    signer.private_key,
    signer.public_key.bytes,
    wide(9000)?,
    wide(1)?,
    merkle_root_for(1, old_tree)?,
    zero,
    wide(1000)?)?
  let seal = sign_tree_checkpoint_for(1,
    signer.private_key,
    signer.public_key.bytes,
    wide(9010)?,
    wide(2)?,
    merkle_root_for(1, final_tree)?,
    zero,
    wide(2000)?)?
  let entry = Bytes.from_utf8("current-account-entry")
  let tree = [leaf_hash_for(2, legacy_bridge_leaf(seal)?)?, leaf_hash_for(2, entry)?]
  let current = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(2)?,
    merkle_root_for(2, tree)?,
    zero,
    wide(3000)?)?
  let bridge = LegacyBridge {
    checkpoint: seal,
    witnesses: [sign_witness("a", a.private_key, seal)?, sign_witness("b", b.private_key, seal)?],
    consistency: compact_consistency_proof_for(1, old_tree, final_tree)?,
    inclusion: compact_inclusion_proof_for(2, tree, 0)?
  }
  let evidence = TransparencyEvidence {
    entry_bytes: entry,
    inclusion: compact_inclusion_proof_for(2, tree, 1)?,
    consistency: compact_consistency_proof_for(2, List.new(), tree)?,
    checkpoint: current,
    witnesses: [
      sign_witness("a", a.private_key, current)?,
      sign_witness("c", c.private_key, current)?
    ]
  }
  let previous = encode_checkpoint(cached)?
  let wire = encode_legacy_bridge(bridge)?
  let decoded = decode_legacy_bridge(wire)?
  assert(Bytes.secure_equals(encode_legacy_bridge(decoded)?, wire))
  # A witness verifies the legacy side before issuing its first v2 signature;
  # requiring an already-complete v2 quorum here would deadlock migration.
  assert(verify_legacy_bridge(current, decoded, signer.public_key, pins, 2, previous)?)
  assert(!verify_legacy_bridge(%{current | signature: Bytes.concat(zero, zero)?},
    decoded,
    signer.public_key,
    pins,
    2,
    previous)?)
  # An incomplete u32-sized tree can need 33 consistency nodes, not 32.
  let widest = %{bridge |
    checkpoint: %{seal | tree_size: wide(4294967295)?},
    consistency: %{bridge.consistency |
      old_tree_size: 2147483647,
      new_tree_size: 4294967295,
      leaf_hashes: for _index in 0..33 do
        zero
      end
    },
    inclusion: %{bridge.inclusion |
      tree_size: 4294967295,
      leaf_hashes: for _index in 0..32 do
        zero
      end
    }
  }
  let widest_wire = encode_legacy_bridge(widest)?
  assert(Bytes.secure_equals(encode_legacy_bridge(decode_legacy_bridge(widest_wire)?)?,
    widest_wire))
  assert(verify_migrated_evidence(evidence,
    decoded,
    signer.public_key,
    pins,
    2,
    pins,
    2,
    previous)?)
  # Ordinary verification never crosses versions without the authenticated bridge.
  assert(!verify_evidence(evidence, signer.public_key, pins, 2, previous)?)
  assert(!verify_migrated_evidence(evidence,
    %{bridge | witnesses: [List.head(bridge.witnesses)]},
    signer.public_key,
    pins,
    2,
    pins,
    2,
    previous)?)
  assert(!verify_migrated_evidence(%{evidence | witnesses: [List.head(evidence.witnesses)]},
    bridge,
    signer.public_key,
    pins,
    2,
    pins,
    2,
    previous)?)
  assert(!verify_migrated_evidence(evidence,
    bridge,
    signer.public_key,
    pins,
    1,
    pins,
    2,
    previous)?)
  assert(!verify_migrated_evidence(evidence,
    bridge,
    signer.public_key,
    pins,
    2,
    pins,
    1,
    previous)?)
  let duplicate = [List.head(pins), %{List.head(pins) | witness_id: "duplicate"}, List.get(pins, 2)]
  assert(!verify_migrated_evidence(evidence,
    bridge,
    signer.public_key,
    duplicate,
    2,
    pins,
    2,
    previous)?)
  assert(!verify_migrated_evidence(evidence,
    %{bridge | inclusion: %{bridge.inclusion | leaf_hashes: [zero]}},
    signer.public_key,
    pins,
    2,
    pins,
    2,
    previous)?)
  assert(!verify_migrated_evidence(evidence,
    %{bridge | consistency: %{bridge.consistency | leaf_hashes: [zero]}},
    signer.public_key,
    pins,
    2,
    pins,
    2,
    previous)?)
  let forked_seal = sign_tree_checkpoint_for(1,
    signer.private_key,
    signer.public_key.bytes,
    wide(9010)?,
    wide(2)?,
    merkle_root_for(1, [zero, zero])?,
    zero,
    wide(2000)?)?
  let wrong_seal = %{bridge |
    checkpoint: forked_seal,
    witnesses: [
      sign_witness("a", a.private_key, forked_seal)?,
      sign_witness("b", b.private_key, forked_seal)?
    ]
  }
  assert(!verify_migrated_evidence(evidence,
    wrong_seal,
    signer.public_key,
    pins,
    2,
    pins,
    2,
    previous)?)
  # A cached v2 client cannot be asked to migrate or roll back again.
  assert(!verify_migrated_evidence(evidence,
    bridge,
    signer.public_key,
    pins,
    2,
    pins,
    2,
    encode_checkpoint(current)?)?)
  for length in 0..Bytes.length(wire) do
    case decode_legacy_bridge(Bytes.slice(wire, 0, length)?) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  case decode_legacy_bridge(Bytes.concat(wire, Bytes.from_utf8("x"))?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("an RFC 6962 log transition preserves the cached legacy prefix and both witness quorums") do
  case migration() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

from Transparency.Migration import encode_bridge_query, decode_bridge_query

fn bridge_query_proof() -> Bool!String do
  # A compacted new log can be much smaller than its legacy prefix. These are
  # independent tree sizes, not the ordered bounds of one consistency proof.
  for old in [0, 1, 4096, 4294967295] do
    for current in [1, 31, 4294967295] do
      let wire = encode_bridge_query(old, current)?
      assert(Bytes.length(wire) == 12)
      let (decoded_old, decoded_current) = decode_bridge_query(wire)?
      assert(decoded_old == old && decoded_current == current)
      for count in 0..12 do
        let prefix = case Bytes.slice(wire, 0, count) do
          Err(_) -> return Err("fixture slicing failed")
          Ok(value) -> value
        end
        case decode_bridge_query(prefix) do
          Err(_) -> nil
          Ok(_) -> assert(false)
        end
      end
    end
  end
  assert(encode_bridge_query(-1, 1) == Err("invalid_bridge_query"))
  assert(encode_bridge_query(1, 0) == Err("invalid_bridge_query"))
  assert(encode_bridge_query(4294967296, 1) == Err("invalid_bridge_query"))
  let extra = case Bytes.concat(encode_bridge_query(999, 1)?, Bytes.from_utf8("x")) do
    Err(_) -> return Err("fixture allocation failed")
    Ok(value) -> value
  end
  assert(decode_bridge_query(extra) == Err("invalid_bridge_query"))
  assert(decode_bridge_query(Bytes.from_hex("024b42510000000100000001")?) == Err("invalid_bridge_query"))
  Ok(true)
end

test("migration bridge queries bind independent legacy and RFC tree sizes") do
  case bridge_query_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
