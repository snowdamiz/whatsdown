##! Fork proofs (FRK v1, INTERFACES §5) from what the monitor holds: a side is
##! a checkpoint as the ring anchors it, as the directory serves it, or both.
##! A proof always names the anchored side by ring reference and carries the
##! other side's signed KTK inline. Nothing is returned unless
##! Transparency.Fork accepts the encoded proof.

from Monitor.Chain import (
  ChainLog,
  ChainWitness,
  RingEntry,
  monitor_fork_log,
  monitor_fork_ring_entry
)
from Monitor.Rpc import (
  RpcInstruction,
  RpcSignature,
  monitor_rpc_instructions,
  monitor_rpc_signatures
)
from Transparency.Fork import ForkEvidence, fork_decode, fork_encode, fork_proof_hash, fork_verify
from Transparency.Merkle import TransparencyCheckpoint, WitnessAttestation, checkpoint_hash
from Transparency.Wire import decode_checkpoint

pub struct Side do
  sequence :: Int
  tree_size :: Int
  root :: Bytes
  hash :: Bytes
  entry :: Option<RingEntry>
  checkpoint :: Option<TransparencyCheckpoint>
  attestations :: List<WitnessAttestation>
end

# The same leaf index read in two trees: side_hash names the side each
# leaf and audit path belong to.

pub struct LeafView do
  side_hash :: Bytes
  leaf :: Bytes
  path :: List<Bytes>
end

pub struct Contradiction do
  index :: Int
  views :: List<LeafView>
end

pub struct BuiltProof do
  kind :: Int
  frk :: Bytes
  proof_hash :: Bytes
  implicated :: List<String>
end

pub fn monitor_side_of_entry(entry :: RingEntry) -> Side do
  Side {
    sequence: entry.sequence,
    tree_size: entry.tree_size,
    root: entry.root,
    hash: entry.hash,
    entry: Some(entry),
    checkpoint: None,
    attestations: List.new()
  }
end

fn int_of(value :: U64) -> Int!String do
  case U64.to_int(value) do
    Err(_) -> Err("checkpoint integer out of range")
    Ok(parsed)
  end
end

pub fn monitor_side_of_checkpoint(checkpoint :: TransparencyCheckpoint,
  attestations :: List<WitnessAttestation>) -> Side!String do
  Ok(Side {
    sequence: int_of(checkpoint.sequence)?,
    tree_size: int_of(checkpoint.tree_size)?,
    root: checkpoint.tree_root,
    hash: checkpoint_hash(checkpoint)?,
    entry: None,
    checkpoint: Some(checkpoint),
    attestations: attestations
  })
end

# 1 same size, 3 rollback, 0 when only a consistency proof can tell.

pub fn monitor_fork_kind(a :: Side, b :: Side) -> Int do
  if Bytes.secure_equals(a.hash, b.hash) do
    0
  else if a.tree_size == b.tree_size && !Bytes.secure_equals(a.root, b.root) do
    1
  else if a.sequence == b.sequence
    || (a.sequence < b.sequence && a.tree_size > b.tree_size)
    || (a.sequence > b.sequence && a.tree_size < b.tree_size) do
    3
  else
    0
  end
end

fn statement(witness_id :: String, hash :: Bytes) -> Bytes do
  case Bytes.concat(Bytes.from_utf8("mesh-msg/v1/transparency-witness" <> witness_id), hash) do
    Err(_) -> Bytes.empty()
    Ok(value) -> value
  end
end

fn verifies(key :: Bytes, value :: WitnessAttestation) -> Bool do
  Bytes.length(value.signature) == 64
    && case Crypto.verify(SigningPublicKey { bytes: key },
      statement(value.witness_id, value.checkpoint_hash),
      Signature { bytes: value.signature }) do
      Ok(valid) -> valid
      Err(_) -> false
    end
end

# One verified attestation on hash per listed witness, in list order. The
# judge refuses a proof holding an attestation by a listed witness that does
# not verify, so nothing unverified is carried.

pub fn monitor_valid_attestations(log :: ChainLog,
  hash :: Bytes,
  values :: List<WitnessAttestation>) -> List<WitnessAttestation> do
  List.flat_map(log.witnesses,
    fn witness -> case List.find(values,
      fn value -> value.witness_id == witness.witness_id
        && Bytes.secure_equals(value.checkpoint_hash, hash)
        && verifies(witness.public_key, value) end) do
      None -> List.new()
      Some(value) -> [value]
    end end)
end

fn view_for(contradiction :: Contradiction, hash :: Bytes) -> LeafView!String do
  case List.find(contradiction.views, fn view -> Bytes.secure_equals(view.side_hash, hash) end) do
    None -> Err("contradiction does not cover this checkpoint")
    Some(view) -> Ok(view)
  end
end

fn with_contradiction(base :: ForkEvidence,
  contradiction :: Option<Contradiction>,
  inline :: Side,
  anchored :: Side) -> ForkEvidence!String do
  case contradiction do
    None -> Ok(base)
    Some(value) -> do
      let first = view_for(value, inline.hash)?
      let second = view_for(value, anchored.hash)?
      Ok(%{base |
        leaf_index: value.index,
        first_path: first.path,
        first_leaf: first.leaf,
        second_path: second.path,
        second_leaf: second.leaf
      })
    end
  end
end

fn required<T>(value :: Option<T>, reason :: String) -> T!String do
  case value do
    None -> Err(reason)
    Some(inner) -> Ok(inner)
  end
end

# inline carries a signed checkpoint; anchored is a ring entry.

pub fn monitor_build_frk(kind :: Int,
  inline :: Side,
  anchored :: Side,
  contradiction :: Option<Contradiction>,
  log :: ChainLog,
  finder :: Bytes) -> BuiltProof!String do
  let checkpoint = required(inline.checkpoint, "no signed checkpoint for the inline side")?
  let entry = required(anchored.entry, "the second side is not anchored")?
  let base = ForkEvidence {
    kind: kind,
    finder: finder,
    service_public_key: log.service_key,
    first: checkpoint,
    second: None,
    ring_index: entry.index,
    attestations: monitor_valid_attestations(log, inline.hash, inline.attestations),
    leaf_index: 0,
    first_path: List.new(),
    first_leaf: Bytes.empty(),
    second_path: List.new(),
    second_leaf: Bytes.empty()
  }
  let frk = fork_encode(with_contradiction(base, contradiction, inline, anchored)?)?
  let implicated = fork_verify(fork_decode(frk)?,
    monitor_fork_log(log),
    Some(monitor_fork_ring_entry(entry)?))?
  Ok(BuiltProof { kind: kind, frk: frk, proof_hash: fork_proof_hash(frk)?, implicated: implicated })
end

# --- Reading a ring entry's checkpoint and cosignatures back from the chain.
# post_anchor carries the KTK in its data (u8 6, u8 ed_ix, KTK188); cosign
# transactions carry each witness statement in their Ed25519 instruction.

fn ed25519_program() -> String do
  "Ed25519SigVerify111111111111111111111111111"
end

fn posted_checkpoint(data :: Bytes, hash :: Bytes) -> TransparencyCheckpoint!String do
  let bytes = case Bytes.slice(data, 2, 188) do
    Err(_) -> Err("not a post_anchor instruction")
    Ok(value)
  end?
  let checkpoint = decode_checkpoint(bytes)?
  if u16_at(data, 0) % 256 == 6 && Bytes.secure_equals(checkpoint_hash(checkpoint)?, hash) do
    Ok(checkpoint)
  else
    Err("another instruction or checkpoint")
  end
end

fn ktk_of(data :: Bytes, hash :: Bytes) -> Option<TransparencyCheckpoint> do
  case posted_checkpoint(data, hash) do
    Err(_) -> None
    Ok(checkpoint) -> Some(checkpoint)
  end
end

fn u16_at(data :: Bytes, offset :: Int) -> Int do
  case Bytes.read_u16_le(data, offset) do
    Err(_) -> -1
    Ok(value) -> value
  end
end

fn statement_id(message :: Bytes, hash :: Bytes) -> Option<String> do
  let length = Bytes.length(message)
  case (Bytes.slice(message, 0, 32),
    Bytes.slice(message, 32, length - 64),
    Bytes.slice(message, length - 32, 32)) do
    (Ok(prefix), Ok(id), Ok(digest)) -> if Bytes.secure_equals(prefix,
      Bytes.from_utf8("mesh-msg/v1/transparency-witness"))
      && Bytes.secure_equals(digest, hash) do
      case Bytes.to_utf8(id) do
        Err(_) -> None
        Ok(text) -> Some(text)
      end
    else
      None
    end
    _ -> None
  end
end

fn ed25519_entry(data :: Bytes, index :: Int, hash :: Bytes) -> List<WitnessAttestation> do
  let base = 2 + 14 * index
  let own = u16_at(data, base + 2) == 65535
    && u16_at(data, base + 6) == 65535
    && u16_at(data, base + 12) == 65535
  let size = u16_at(data, base + 10)
  if !own || size <= 64 do
    List.new()
  else
    case (Bytes.slice(data, u16_at(data, base + 8), size),
      Bytes.slice(data, u16_at(data, base), 64)) do
      (Ok(message), Ok(signature)) -> case statement_id(message, hash) do
        None -> List.new()
        Some(id) -> [
          WitnessAttestation { witness_id: id, checkpoint_hash: hash, signature: signature }
        ]
      end
      _ -> List.new()
    end
  end
end

fn ed25519_attestations(data :: Bytes, hash :: Bytes) -> List<WitnessAttestation> do
  case Bytes.get(data, 0) do
    Err(_) -> List.new()
    Ok(count) -> List.flat_map(Range.to_list(0..count),
      fn index -> ed25519_entry(data, index, hash) end)
  end
end

struct Found do
  checkpoint :: Option<TransparencyCheckpoint>
  attestations :: List<WitnessAttestation>
end

fn scan(url :: String,
  judge :: String,
  signatures :: List<RpcSignature>,
  hash :: Bytes,
  found :: Found) -> Found!String do
  case signatures do
    [] -> Ok(found)
    signature :: rest -> do
      let instructions = monitor_rpc_instructions(url, signature.signature)?
      let checkpoints = List.flat_map(instructions,
        fn ix -> if ix.program == judge do
          case ktk_of(ix.data, hash) do
            None -> List.new()
            Some(checkpoint) -> [checkpoint]
          end
        else
          List.new()
        end end)
      let attestations = List.flat_map(instructions,
        fn ix -> if ix.program == ed25519_program() do
          ed25519_attestations(ix.data, hash)
        else
          List.new()
        end end)
      let checkpoint = case checkpoints do
        [] -> found.checkpoint
        first :: _ -> Some(first)
      end
      scan(url,
        judge,
        rest,
        hash,
        Found { checkpoint: checkpoint, attestations: found.attestations ++ attestations })
    end
  end
end

# The ring's transactions from slot first to last (post_anchor, then cosigns
# within the 1,500-slot window). ponytail: at most 50 pages of 1,000 back
# from the newest; older anchors fall back to what the directory served.

fn window(url :: String,
  ring :: String,
  first :: Int,
  last :: Int,
  before :: String,
  pages :: Int,
  output :: List<RpcSignature>) -> List<RpcSignature>!String do
  let page = monitor_rpc_signatures(url, ring, before)?
  let kept = output ++ List.filter(page, fn value -> value.slot >= first && value.slot <= last end)
  if List.length(page) < 1000 || pages >= 50 || List.last(page).slot < first do
    Ok(kept)
  else
    window(url, ring, first, last, List.last(page).signature, pages + 1, kept)
  end
end

fn chain_side_from(urls :: List<String>,
  judge :: String,
  log :: ChainLog,
  entry :: RingEntry) -> Option<Side> do
  case urls do
    [] -> None
    url :: rest -> case window(url, log.ring, entry.slot, entry.slot + 1500, "", 0, List.new()) do
      Err(_) -> chain_side_from(rest, judge, log, entry)
      Ok(signatures) -> case scan(url,
        judge,
        signatures,
        entry.hash,
        Found { checkpoint: None, attestations: List.new() }) do
        Err(_) -> chain_side_from(rest, judge, log, entry)
        Ok(found) -> case found.checkpoint do
          None -> chain_side_from(rest, judge, log, entry)
          Some(checkpoint) -> do
            let side = monitor_side_of_entry(entry)
            Some(%{side |
              checkpoint: Some(checkpoint),
              attestations: monitor_valid_attestations(log, entry.hash, found.attestations)
            })
          end
        end
      end
    end
  end
end

# An anchored side with its KTK and the witness statements that cosigned it,
# read from the first provider that has them. Both are checked against the
# agreed ring entry (checkpoint hash) and the Log's keys, so one provider is
# enough here.

pub fn monitor_chain_side(urls :: List<String>,
  judge :: String,
  log :: ChainLog,
  entry :: RingEntry) -> Option<Side> do
  chain_side_from(urls, judge, log, entry)
end
