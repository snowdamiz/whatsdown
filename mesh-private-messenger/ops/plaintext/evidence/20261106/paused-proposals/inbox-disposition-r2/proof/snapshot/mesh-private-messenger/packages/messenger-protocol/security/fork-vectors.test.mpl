from Transparency.Fork import (
  ForkAnchor,
  fork_at_anchor,
  ForkProof,
  ForkVerdict,
  decode_fork,
  encode_fork,
  fork_hash,
  fork_same_size,
  fork_contradiction,
  fork_rollback
)
from Transparency.Merkle import WitnessKey

fn string(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn bytes(value :: Json, key :: String) -> Bytes!String do
  case Bytes.from_hex(string(value, key)?) do
    Err(_) -> Err("invalid fixture hex")
    Ok(value)
  end
end

fn verified(proof :: ForkProof,
  key :: SigningPublicKey,
  pins :: List<WitnessKey>) -> ForkVerdict!String do
  if proof.kind == 1 do
    fork_same_size(proof, key, pins)
  else if proof.kind == 2 do
    fork_contradiction(proof, key, pins)
  else
    fork_rollback(proof, key, pins)
  end
end

fn trusted_anchor(value :: Json) -> ForkAnchor!String do
  let entries = Json.object_get(value, "cosigners")?
  let keys = for index in 0..Json.array_length(entries)? do
    let entry = Json.array_get(entries, index)?
    WitnessKey { witness_id: string(entry, "witness_id")?, public_key: bytes(entry, "public_key")? }
  end
  Ok(ForkAnchor {
    log_version: 1,
    ring_index: Json.as_int(Json.object_get(value, "ring_index")?)?,
    service_public_key: bytes(value, "service_public_key")?,
    sequence: U64.parse(string(value, "sequence")?)?,
    tree_size: U64.parse(string(value, "tree_size")?)?,
    tree_root: bytes(value, "tree_root")?,
    checkpoint_hash: bytes(value, "checkpoint_hash")?,
    cosigners: keys,
    native_cosigners: keys
  })
end

fn verify_case(proof :: ForkProof,
  key :: SigningPublicKey,
  pins :: List<WitnessKey>,
  value :: Json) -> ForkVerdict!String do
  case Json.object_get(value, "anchor") do
    Err(_) -> verified(proof, key, pins)
    Ok(anchor) -> fork_at_anchor(proof, key, pins, trusted_anchor(anchor)?)
  end
end

fn replay() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_FORK_VECTORS_PATH", ""))?)?
  assert(Json.as_int(Json.object_get(root, "version")?)? == 1)
  let key = SigningPublicKey { bytes: bytes(root, "service_public_key")? }
  let pin_values = Json.object_get(root, "pins")?
  let pins = for index in 0..Json.array_length(pin_values)? do
    let value = Json.array_get(pin_values, index)?
    WitnessKey { witness_id: string(value, "witness_id")?, public_key: bytes(value, "public_key")? }
  end
  let cases = Json.object_get(root, "cases")?
  for index in 0..Json.array_length(cases)? do
    let value = Json.array_get(cases, index)?
    let name = string(value, "name")?
    let wire = bytes(value, "wire_hex")?
    let decodable = Json.as_bool(Json.object_get(value, "decode")?)?
    let valid = Json.as_bool(Json.object_get(value, "valid")?)?
    case decode_fork(wire) do
      Err(_) -> if decodable do
        return Err("fixture decode failed: #{name}")
      end
      Ok(proof) -> do
        if !decodable do
          return Err("fixture decoded unexpectedly: #{name}")
        end
        assert(Bytes.secure_equals(encode_fork(proof)?, wire))
        assert(Bytes.secure_equals(fork_hash(proof)?, bytes(value, "proof_hash")?))
        let case_pins = case Json.object_get(value, "pins") do
          Err(_) -> pins
          Ok(entries) -> for index in 0..Json.array_length(entries)? do
            let entry = Json.array_get(entries, index)?
            WitnessKey {
              witness_id: string(entry, "witness_id")?,
              public_key: bytes(entry, "public_key")?
            }
          end
        end
        case verify_case(proof, key, case_pins, value) do
          Err(_) -> if valid do
            return Err("fixture verification failed: #{name}")
          end
          Ok(verdict) -> do
            if !valid do
              return Err("fixture verified unexpectedly: #{name}")
            end
            let expected = Json.object_get(value, "witnesses")?
            let ids = for index in 0..Json.array_length(expected)? do
              Json.as_string(Json.array_get(expected, index)?)?
            end
            let actual = for pin in verdict.witnesses do
              pin.witness_id
            end
            assert(ids == actual)
          end
        end
      end
    end
  end
  Ok(true)
end

test("FRK Mesh verifier replays the shared independent OpenSSL vectors") do
  case replay() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
