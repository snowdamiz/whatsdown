from Transparency.RelayStage import (
  RelayStagePlan,
  RelayStageSignature,
  RelayStageWitness,
  prepare_relay_stage
)
from Transparency.Relay import RelayVerification
from Transparency.Fork import ForkProof, ForkTarget, ForkVerdict, encode_fork, fork_hash
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  WitnessAttestation,
  sign_tree_checkpoint_for,
  sign_witness,
  checkpoint_hash
)
from Transparency.AnchorWrite import AnchorInstructionPair
from Transparency.AnchorBond import bond_witness_identity
from Transparency.C2spText import checkpoint_note_text
from Transparency.Wire import encode_checkpoint
from Solana.Read import Pubkey, pubkey, pubkey_equal
from Solana.Address import ProgramDerivedAddress, find_program_address

fn signing() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Ok(value)
    Err(_) -> Err("test signing")
  end
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  if List.length(parts) == 0 do
    Ok(Bytes.empty())
  else
    Bytes.concat(List.head(parts), cat(List.tail(parts))?)
  end
end

fn signature(id :: String,
  key :: borrow SigningPrivateKey,
  checkpoint :: TransparencyCheckpoint,
  c2sp :: Bool) -> WitnessAttestation!String do
  let native = sign_witness(id, key, checkpoint)?
  if !c2sp do
    return Ok(native)
  end
  let message = Bytes.from_utf8("cosignature/v1\ntime 1234\n"
    <> checkpoint_note_text(encode_checkpoint(checkpoint)?)?)
  let signed = case Crypto.sign(key, message) do
    Ok(value) -> value
    Err(_) -> return Err("test signing")
  end
  Ok(%{native | signature: cat([Bytes.from_hex("00000000000004d2")?, signed.bytes])?})
end

fn export_plan(plan :: RelayStagePlan, wire :: Bytes) -> Result<(), String> do
  let path = Env.get("MORSE_RELAY_STAGE_FIXTURES_PATH", "")
  if path == "" do
    return Ok(nil)
  end
  let chunks = String.join(for bytes in plan.append do
      Json.encode_string(Bytes.to_hex(bytes))
    end,
    ",")
  let signatures = String.join(for step in plan.signatures do
      let witness = case step.witness do
        None -> "null"
        Some(value) -> Json.encode_string(Bytes.to_hex(value.bytes))
      end
      "{\"ordinal\":#{step.ordinal},\"witness\":#{witness},\"ed25519\":\"#{Bytes.to_hex(step.pair.ed25519)}\",\"judge\":\"#{Bytes.to_hex(step.pair.judge)}\"}"
    end,
    ",")
  let witnesses = String.join(for subject in plan.witnesses do
      "{\"id\":"
        <> Json.encode_string(subject.key.witness_id)
        <> ",\"key\":\"#{Bytes.to_hex(subject.key.public_key)}\",\"address\":\"#{Bytes.to_hex(subject.address.bytes)}\"}"
    end,
    ",")
  File.append(path,
    "{\"wire\":\"#{Bytes.to_hex(wire)}\",\"stage\":\"#{Bytes.to_hex(plan.stage.bytes)}\",\"initialize\":\"#{Bytes.to_hex(plan.initialize)}\",\"append\":[#{chunks}],\"seal\":\"#{Bytes.to_hex(plan.seal)}\",\"close\":\"#{Bytes.to_hex(plan.close)}\",\"signatures\":[#{signatures}],\"witnesses\":[#{witnesses}]}\n")
end

fn proof() -> Bool!String do
  let signer = signing()?
  # Public fixture identities shared with stage_svm.rs; no deployed wallet.
  let program = Pubkey { bytes: Bytes.from_hex(String.repeat("2a", 32))? }
  let submitter = Pubkey {
    bytes: Bytes.from_hex("66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a")?
  }
  let log_id = Crypto.sha256(Bytes.from_utf8("stage-test"))
  let zero = Bytes.from_hex(String.repeat("00", 32))?
  let export_path = Env.get("MORSE_RELAY_STAGE_FIXTURES_PATH", "")
  if export_path != "" do
    File.write(export_path, "")?
  end
  for version in [1, 2] do
    for c2sp in [false, true] when version == 2 || !c2sp do
      let first = sign_tree_checkpoint_for(version,
        signer.private_key,
        signer.public_key.bytes,
        wide(1)?,
        wide(5)?,
        Crypto.sha256(Bytes.from_utf8("left")),
        zero,
        wide(1000)?)?
      let second = sign_tree_checkpoint_for(version,
        signer.private_key,
        signer.public_key.bytes,
        wide(2)?,
        wide(5)?,
        Crypto.sha256(Bytes.from_utf8("right")),
        checkpoint_hash(first)?,
        wide(2000)?)?
      let witnesses = for index in 0..16 do
        let key = signing()?
        let id = "witness-"
          <> String.repeat("x", 54)
          <> Int.to_string(index / 10)
          <> Int.to_string(index % 10)
        (WitnessKey { witness_id: id, public_key: key.public_key.bytes },
          [
            signature(id, key.private_key, first, c2sp)?,
            signature(id, key.private_key, second, c2sp)?
          ])
      end
      let keys = for (key, _) in witnesses do
        key
      end
      let attestations = List.flat_map(witnesses, fn((_, signatures)) -> signatures end)
      let proof = ForkProof {
        kind: 1,
        finder: zero,
        service_public_key: signer.public_key.bytes,
        first: first,
        second: SignedCheckpoint(second),
        attestations: attestations,
        contradiction: None
      }
      let wire = encode_fork(proof)?
      # Discovery ordering need not match the first valid attestation order.
      let verification = RelayVerification {
        proof: wire,
        proof_hash: fork_hash(proof)?,
        finder: zero,
        verdict: ForkVerdict {
          service_public_key: signer.public_key.bytes,
          witnesses: List.reverse(keys)
        },
        service_slashed: false,
        context_slot: wide(100)?,
        anchor_header: Bytes.empty(),
        anchor_entry: Bytes.empty(),
        witness_set: Bytes.empty(),
        witness_scope: "collectible-registry"
      }
      let plan = prepare_relay_stage(program, log_id, submitter, verification)?
      export_plan(plan, wire)?
      assert(Bytes.secure_equals(plan.finder, submitter.bytes))
      assert(Bytes.secure_equals(plan.full_hash, Crypto.sha256(wire)))
      assert(Bytes.secure_equals(plan.proof_hash, verification.proof_hash))
      let expected_stage = find_program_address(program,
        [Bytes.from_utf8("stage"), submitter.bytes, Crypto.sha256(wire)])?.address
      assert(pubkey_equal(plan.stage, expected_stage))
      assert(Bytes.get(plan.initialize, 0)? == 10 && Bytes.length(plan.initialize) == 35)
      assert(Bytes.read_uint_le(plan.initialize, 1, 2)? == Int.to_string(Bytes.length(wire)))
      assert(Bytes.secure_equals(Bytes.slice(plan.initialize, 3, 32)?, plan.full_hash))
      assert(Bytes.to_hex(plan.seal) == "0c" && Bytes.to_hex(plan.close) == "0e")
      let recovered = cat(for index in 0..List.length(plan.append) do
        let chunk = List.get(plan.append, index)
        assert(Bytes.get(chunk, 0)? == 11 && Bytes.length(chunk) <= 903)
        assert(Bytes.read_uint_le(chunk, 1, 2)? == Int.to_string(index * 900))
        Bytes.slice(chunk, 3, Bytes.length(chunk) - 3)?
      end)?
      assert(Bytes.secure_equals(recovered, wire))
      assert(List.length(plan.signatures) == 34 && List.length(plan.witnesses) == 16)
      for index in 0..34 do
        let step = List.get(plan.signatures, index)
        assert(step.ordinal == index
          && Bytes.to_hex(step.pair.judge) == "0d"
              <> Bytes.to_hex(Bytes.write_uint_le(Int.to_string(index), 1)?)
              <> "0000")
        let data = step.pair.ed25519
        assert(Bytes.to_hex(Bytes.slice(data, 0, 11)?) == "01003000ffff1000ffff70")
        let message = Bytes.slice(data, 112, Bytes.length(data) - 112)?
        let public_key = Bytes.slice(data, 16, 32)?
        let signed = Signature { bytes: Bytes.slice(data, 48, 64)? }
        assert(case Crypto.verify(SigningPublicKey { bytes: public_key }, message, signed) do
          Ok(value) -> value
          Err(_) -> false
        end)
        case step.witness do
          None -> assert(index < 2)
          Some(address) -> do
            assert(index >= 2)
            let key = List.get(keys, (index - 2) / 2)
            let expected = find_program_address(program,
              [
                Bytes.from_utf8("witness"),
                log_id,
                bond_witness_identity(key.witness_id, key.public_key)?
              ])?.address
            assert(pubkey_equal(address, expected))
            assert(Bytes.secure_equals(public_key, key.public_key))
          end
        end
      end
      for index in 0..16 do
        assert(List.get(plan.witnesses, index).key == List.get(keys, index))
      end
      let named = %{proof | finder: List.head(keys).public_key}
      let named_verification = %{verification | proof: encode_fork(named)?, finder: named.finder}
      let named_plan = prepare_relay_stage(program, log_id, submitter, named_verification)?
      assert(Bytes.secure_equals(named_plan.finder, named.finder))
      assert(!pubkey_equal(plan.stage, named_plan.stage)
        && Bytes.secure_equals(plan.proof_hash, named_plan.proof_hash))
      for invalid in [
        %{verification | proof_hash: zero},
        %{verification | finder: named.finder},
        %{verification | verdict: %{verification.verdict | witnesses: keys ++ [List.head(keys)]}}
      ] do
        case prepare_relay_stage(program, log_id, submitter, invalid) do
          Ok(_) -> assert(false)
          Err(_) -> nil
        end
      end
      # An invalid duplicate stays in the uploaded proof but earns no verified bit.
      let bad = %{List.head(attestations) | signature: Bytes.from_hex(String.repeat("00", 64))?}
      let smaller = %{proof |
        attestations: [bad, List.get(attestations, 0), List.get(attestations, 1)]
      }
      let fewer = %{verification |
        proof: encode_fork(smaller)?,
        proof_hash: fork_hash(smaller)?,
        verdict: %{verification.verdict | witnesses: [List.head(keys)]}
      }
      let safe = prepare_relay_stage(program, log_id, submitter, fewer)?
      assert(List.length(safe.signatures) == 4 && List.get(safe.signatures, 2).ordinal == 3)
      assert(List.length(safe.witnesses) == 1)
      let anchored = %{proof | second: AnchorReference(0)}
      let anchor_verification = %{verification |
        proof: encode_fork(anchored)?,
        proof_hash: fork_hash(anchored)?
      }
      let anchor_plan = prepare_relay_stage(program, log_id, submitter, anchor_verification)?
      assert(List.length(anchor_plan.signatures) == 17 && List.length(anchor_plan.witnesses) == 16)
      export_plan(anchor_plan, anchor_verification.proof)?
      if c2sp do
        let rollback = %{proof | kind: 3}
        let unchecked = %{verification |
          proof: encode_fork(rollback)?,
          proof_hash: fork_hash(rollback)?
        }
        case prepare_relay_stage(program, log_id, submitter, unchecked) do
          Ok(_) -> assert(false)
          Err(_) -> nil
        end
        let service_only = prepare_relay_stage(program,
          log_id,
          submitter,
          %{unchecked | verdict: %{verification.verdict | witnesses: []}})?
        assert(List.length(service_only.signatures) == 2
          && List.length(service_only.witnesses) == 0)
      end
    end
  end
  Ok(true)
end

test("Mesh prepares bounded resumable relay stages with exact signature ordinals and immutable finder attribution") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
