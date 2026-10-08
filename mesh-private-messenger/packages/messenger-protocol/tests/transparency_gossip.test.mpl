from Binary.Reader import reader
from Protocol.ExtensionWire import protocol_encode_extensions, protocol_take_extensions
from Protocol.V1 import ProtocolExtension
from Protocol.WirePrimitives import ProtocolReadExtensions
from Transparency.CompactWire import WitnessCosignature
from Transparency.Gossip import (
  GossipAnswer,
  GossipHint,
  GossipVerdict,
  gossip_compare,
  gossip_decode_answer,
  gossip_decode_hint,
  gossip_decode_request,
  gossip_encode_answer,
  gossip_encode_hint,
  gossip_encode_request,
  gossip_hint_action,
  gossip_hint_extension,
  gossip_hint_from_extensions
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  checkpoint_hash,
  leaf_hash,
  sign_checkpoint,
  sign_witness
)
from Transparency.Tree import tlog_consistency_path, tlog_list_oracle

fn is_err<T>(result :: Result<T, String>) -> Bool do
  case result do
    Ok(_) -> false
    Err(_) -> true
  end
end

fn repeated(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("bytes failed")
    Ok(output)
  end
end

fn joined(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("concat failed")
    Ok(value)
  end
end

fn hint_codec() -> Bool!String do
  let root = repeated(7, 32)?
  let hint = GossipHint { tree_size: 5_000_000_000, root: root }
  let value = gossip_encode_hint(hint)?
  assert(Bytes.length(value) == 40)
  let decoded = gossip_decode_hint(value)?
  assert(decoded.tree_size == 5_000_000_000 && Bytes.secure_equals(decoded.root, root))
  assert(is_err(gossip_decode_hint(joined(value, repeated(0, 1)?)?)))
  assert(is_err(gossip_encode_hint(GossipHint { tree_size: 1, root: repeated(7, 31)? })))
  let overflow = joined(repeated(255, 8)?, root)?
  assert(is_err(gossip_decode_hint(overflow)))
  let extension = gossip_hint_extension(hint)?
  assert(extension.id == 2 && !extension.mandatory)
  let contact = ProtocolExtension { id: 1, mandatory: false, value: repeated(9, 32)? }
  let encoded = case protocol_encode_extensions([contact, extension]) do
    Err(_) -> Err("extension encoding failed")
    Ok(bytes)
  end?
  let state = case reader(encoded, 4096) do
    Err(_) -> Err("reader failed")
    Ok(value)
  end?
  let read = case protocol_take_extensions(state) do
    Err(_) -> Err("extension decoding failed")
    Ok(value)
  end?
  assert(List.length(read.value) == 2)
  case gossip_hint_from_extensions(read.value) do
    Some(found) -> assert(found.tree_size == 5_000_000_000)
    None -> assert(false)
  end
  assert(gossip_hint_from_extensions([contact]) == None)
  let malformed = ProtocolExtension { id: 2, mandatory: false, value: repeated(1, 39)? }
  assert(gossip_hint_from_extensions([contact, malformed]) == None)
  Ok(true)
end

test("extension 2 carries 40 bytes, stays optional and is ignored when malformed") do
  case hint_codec() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

struct Views do
  log :: SigningKeyPair
  honest :: List<Bytes>
  small :: TransparencyCheckpoint
  large :: TransparencyCheckpoint
  resigned :: TransparencyCheckpoint
  forked :: TransparencyCheckpoint
  forked_large :: TransparencyCheckpoint
  rolled_back :: TransparencyCheckpoint
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn views() -> Views!String do
  let log = case Crypto.signing_from_seed(repeated(90, 32)?) do
    Err(_) -> Err("signing key failed")
    Ok(pair)
  end?
  let honest = for index in 0..12 do
    leaf_hash(Bytes.from_utf8("entry-#{index}"))?
  end
  let forked = List.take(honest, 4)
    ++ [leaf_hash(Bytes.from_utf8("forked"))?]
    ++ List.drop(honest, 5)
  let zero = repeated(0, 32)?
  let small = sign_checkpoint(log.private_key,
    log.public_key.bytes,
    wide(3)?,
    List.take(honest, 7),
    zero,
    wide(1000)?)?
  let large = sign_checkpoint(log.private_key,
    log.public_key.bytes,
    wide(4)?,
    honest,
    checkpoint_hash(small)?,
    wide(2000)?)?
  Ok(Views {
    honest: honest,
    small: small,
    large: large,
    resigned: sign_checkpoint(log.private_key,
      log.public_key.bytes,
      wide(4)?,
      List.take(honest, 7),
      checkpoint_hash(small)?,
      wide(3000)?)?,
    forked: sign_checkpoint(log.private_key,
      log.public_key.bytes,
      wide(3)?,
      List.take(forked, 7),
      zero,
      wide(1000)?)?,
    forked_large: sign_checkpoint(log.private_key,
      log.public_key.bytes,
      wide(4)?,
      forked,
      zero,
      wide(2000)?)?,
    rolled_back: sign_checkpoint(log.private_key,
      log.public_key.bytes,
      wide(5)?,
      List.take(honest, 5),
      zero,
      wide(4000)?)?,
    log: log
  })
end

fn control_frames() -> Bool!String do
  let v = views()?
  let hint = GossipHint { tree_size: 12, root: v.large.tree_root }
  let request = gossip_encode_request(hint)?
  assert(Bytes.length(request) == 44)
  assert(gossip_decode_request(request)?.tree_size == 12)
  assert(is_err(gossip_decode_request(joined(request, repeated(0, 1)?)?)))
  let attestation = case Crypto.signing_from_seed(repeated(91, 32)?) do
    Err(_) -> Err("signing key failed")
    Ok(pair) -> sign_witness("witness-a", pair.private_key, v.large)
  end?
  let answer = GossipAnswer {
    checkpoint: v.large,
    witnesses: [
      WitnessCosignature {
        kind: 1,
        witness_id: "witness-a",
        checkpoint_hash: attestation.checkpoint_hash,
        timestamp: 0,
        signature: attestation.signature
      }
    ],
    ask_back: true
  }
  let encoded = gossip_encode_answer(answer)?
  let decoded = gossip_decode_answer(encoded)?
  assert(decoded.ask_back && List.length(decoded.witnesses) == 1)
  assert(Bytes.secure_equals(checkpoint_hash(decoded.checkpoint)?, checkpoint_hash(v.large)?))
  let last = Bytes.length(encoded) - 1
  let without_flag = case Bytes.slice(encoded, 0, last) do
    Err(_) -> Err("slice failed")
    Ok(value)
  end?
  assert(is_err(gossip_decode_answer(joined(without_flag, repeated(2, 1)?)?)))
  assert(!gossip_decode_answer(joined(without_flag, repeated(0, 1)?)?)?.ask_back)
  assert(is_err(gossip_decode_answer(joined(encoded, repeated(0, 1)?)?)))
  Ok(true)
end

test("GCQ asks about a hint and GCA answers with a signed checkpoint and its attestations") do
  case control_frames() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn hint_actions() -> Bool!String do
  let root = repeated(4, 32)?
  assert(gossip_hint_action(7, root, GossipHint { tree_size: 7, root: root }) == "skip")
  assert(gossip_hint_action(7, root, GossipHint { tree_size: 7, root: repeated(5, 32)? }) == "ask")
  assert(gossip_hint_action(7,
    root,
    GossipHint { tree_size: 9, root: repeated(5, 32)? }) == "check")
  assert(gossip_hint_action(7,
    root,
    GossipHint { tree_size: 3, root: repeated(5, 32)? }) == "check")
  Ok(true)
end

test("a hint for the view already held is skipped; a same-size mismatch asks the sender") do
  case hint_actions() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn outcome_of(result :: GossipVerdict!String) -> String do
  case result do
    Ok(value) -> value.outcome <> "/" <> Int.to_string(value.fork_kind)
    Err(error) -> error
  end
end

fn comparisons() -> Bool!String do
  let v = views()?
  let key = v.log.public_key
  let path = tlog_consistency_path(1, tlog_list_oracle(1, v.honest), 7, 12)?
  assert(outcome_of(gossip_compare(v.small, v.small, key, [])) == "consistent/0")
  assert(outcome_of(gossip_compare(v.small, v.resigned, key, [])) == "consistent/0")
  assert(outcome_of(gossip_compare(v.small, v.large, key, path)) == "consistent/0")
  assert(outcome_of(gossip_compare(v.large, v.small, key, path)) == "consistent/0")
  assert(outcome_of(gossip_compare(v.small, v.large, key, [])) == "check/0")
  assert(outcome_of(gossip_compare(v.small, v.forked, key, [])) == "fork/1")
  assert(outcome_of(gossip_compare(v.large, v.rolled_back, key, [])) == "fork/3")
  assert(outcome_of(gossip_compare(v.small, v.forked_large, key, path)) == "check/0")
  let forged = %{v.forked | signature: repeated(1, 64)?}
  assert(outcome_of(gossip_compare(v.small, forged, key, [])) == "gossip_checkpoint_rejected")
  let stranger = case Crypto.signing_from_seed(repeated(92, 32)?) do
    Err(_) -> Err("signing key failed")
    Ok(pair) -> Ok(pair.public_key)
  end?
  assert(outcome_of(gossip_compare(v.small,
    v.large,
    stranger,
    path)) == "gossip_checkpoint_rejected")
  Ok(true)
end

test("two signed checkpoints compare as consistent, a provable fork, or needing a proof") do
  case comparisons() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
