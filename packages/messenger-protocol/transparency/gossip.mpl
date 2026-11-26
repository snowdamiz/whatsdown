##! Checkpoint gossip: the inner-envelope extension 2 hint (the newest tree
##! size and root the sender verified), the GCQ/GCA control frames that trade
##! signed checkpoints, and the pure decisions a phone makes with them.

from Protocol.V1 import ProtocolExtension
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)
from Transparency.CompactWire import (
  WitnessCosignature,
  transparency_decode_cosignatures,
  transparency_encode_cosignatures
)
from Transparency.Fork import fork_kind_between
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash, verify_checkpoint
from Transparency.Tree import tlog_size_limit, tlog_verify_consistency
from Transparency.Wire import decode_checkpoint, encode_checkpoint

pub struct GossipHint do
  tree_size :: Int
  root :: Bytes
end

pub struct GossipAnswer do
  checkpoint :: TransparencyCheckpoint
  witnesses :: List<WitnessCosignature>
  ask_back :: Bool
end

# outcome: "consistent", "fork" (fork_kind 1 or 3, provable as FRK now) or
# "check" (orders agree but sizes differ and no consistency proof verified).

pub struct GossipVerdict do
  outcome :: String
  fork_kind :: Int
end

fn valid_hint(hint :: GossipHint) -> Bool do
  hint.tree_size >= 0 && hint.tree_size < tlog_size_limit() && Bytes.length(hint.root) == 32
end

pub fn gossip_encode_hint(hint :: GossipHint) -> Bytes!String do
  if !valid_hint(hint) do
    Err("invalid gossip hint")
  else
    tcodec_join([tcodec_u64(hint.tree_size)?, hint.root])
  end
end

pub fn gossip_decode_hint(value :: Bytes) -> GossipHint!String do
  if Bytes.length(value) != 40 do
    Err("invalid gossip hint")
  else
    let size = case Bytes.read_u64_be(value, 0) do
      Err(_) -> Err("invalid gossip hint")
      Ok(wide) -> U64.to_int(wide)
    end?
    let root = case Bytes.slice(value, 8, 32) do
      Err(_) -> Err("invalid gossip hint")
      Ok(bytes)
    end?
    let hint = GossipHint { tree_size: size, root: root }
    if valid_hint(hint) do
      Ok(hint)
    else
      Err("invalid gossip hint")
    end
  end
end

# Extension 2 is optional: never mandatory, and ignored when malformed.

pub fn gossip_hint_extension(hint :: GossipHint) -> ProtocolExtension!String do
  Ok(ProtocolExtension { id: 2, mandatory: false, value: gossip_encode_hint(hint)? })
end

pub fn gossip_hint_from_extensions(values :: List<ProtocolExtension>) -> Option<GossipHint> do
  case List.find(values, fn value -> value.id == 2 end) do
    None
    Some(extension) -> case gossip_decode_hint(extension.value) do
      Ok(hint) -> Some(hint)
      Err(_) -> None
    end
  end
end

pub fn gossip_encode_request(hint :: GossipHint) -> Bytes!String do
  tcodec_join([tcodec_u8(1)?, Bytes.from_utf8("GCQ"), gossip_encode_hint(hint)?])
end

pub fn gossip_decode_request(input :: Bytes) -> GossipHint!String do
  let value = tcodec_take_fixed(tcodec_start(input, 44, 1, "GCQ")?, 40)?
  tcodec_done(value.state)?
  gossip_decode_hint(value.value)
end

pub fn gossip_encode_answer(answer :: GossipAnswer) -> Bytes!String do
  let ask_back = if answer.ask_back do
    1
  else
    0
  end
  tcodec_join([
    tcodec_u8(1)?,
    Bytes.from_utf8("GCA"),
    tcodec_vector(encode_checkpoint(answer.checkpoint)?)?,
    tcodec_vector(transparency_encode_cosignatures(answer.witnesses)?)?,
    tcodec_u8(ask_back)?
  ])
end

pub fn gossip_decode_answer(input :: Bytes) -> GossipAnswer!String do
  let checkpoint = tcodec_take_vector(tcodec_start(input, 2847, 1, "GCA")?, 188)?
  let witnesses = tcodec_take_vector(checkpoint.state, 2646)?
  let ask_back = tcodec_take_u8(witnesses.state)?
  tcodec_done(ask_back.state)?
  if ask_back.value > 1 do
    Err("invalid gossip answer")
  else
    Ok(GossipAnswer {
      checkpoint: decode_checkpoint(checkpoint.value)?,
      witnesses: transparency_decode_cosignatures(witnesses.value)?,
      ask_back: ask_back.value == 1
    })
  end
end

# What a received hint asks of the receiver, given its own verified view:
# "skip" the view it already has, "check" consistency between the two sizes,
# or "ask" the sender for its signed checkpoint (same size, different root:
# no consistency proof can exist).

pub fn gossip_hint_action(own_size :: Int, own_root :: Bytes, hint :: GossipHint) -> String do
  if hint.tree_size == own_size && Bytes.secure_equals(hint.root, own_root) do
    "skip"
  else if hint.tree_size == own_size do
    "ask"
  else
    "check"
  end
end

fn signed_by(value :: TransparencyCheckpoint, log_key :: SigningPublicKey) -> Bool do
  case verify_checkpoint(value, log_key) do
    Ok(valid) -> valid
    Err(_) -> false
  end
end

fn verdict(outcome :: String, kind :: Int) -> GossipVerdict do
  GossipVerdict { outcome: outcome, fork_kind: kind }
end

fn ordered_consistent(own :: TransparencyCheckpoint,
  other :: TransparencyCheckpoint,
  consistency_path :: List<Bytes>) -> Bool!String do
  let own_size = U64.to_int(own.tree_size)?
  let other_size = U64.to_int(other.tree_size)?
  if own_size == other_size do
    Ok(Bytes.secure_equals(own.tree_root, other.tree_root))
  else if own_size < other_size do
    Ok(tlog_verify_consistency(1,
      own_size,
      other_size,
      consistency_path,
      own.tree_root,
      other.tree_root))
  else
    Ok(tlog_verify_consistency(1,
      other_size,
      own_size,
      consistency_path,
      other.tree_root,
      own.tree_root))
  end
end

# Compares the phone's own checkpoint with one a contact sent. A checkpoint
# that fails the log's signature is refused (drop it, do not ask again today).
# consistency_path proves the smaller tree a prefix of the larger; pass [] when
# none was fetched.

pub fn gossip_compare(own :: TransparencyCheckpoint,
  other :: TransparencyCheckpoint,
  log_key :: SigningPublicKey,
  consistency_path :: List<Bytes>) -> GossipVerdict!String do
  if !signed_by(other, log_key) || !signed_by(own, log_key) do
    Err("gossip_checkpoint_rejected")
  else if Bytes.secure_equals(checkpoint_hash(own)?, checkpoint_hash(other)?) do
    Ok(verdict("consistent", 0))
  else
    let kind = fork_kind_between(own, other)?
    if kind != 0 do
      Ok(verdict("fork", kind))
    else if ordered_consistent(own, other, consistency_path)? do
      Ok(verdict("consistent", 0))
    else
      Ok(verdict("check", 0))
    end
  end
end
