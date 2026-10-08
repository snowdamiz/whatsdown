##! Checking two checkpoints against each other: the ring's consecutive
##! anchors, an anchor against the directory's record of it, and the
##! directory's current checkpoint against the newest anchor. Two signed
##! checkpoints that contradict each other become an FRK; a directory that
##! does not answer is only ever "pending".

from Monitor.Chain import ChainLog, RingEntry
from Monitor.Flags import MonitorConfig
from Monitor.Directory import monitor_dir_consistency, monitor_dir_leaf
from Monitor.Evidence import (
  BuiltProof,
  Contradiction,
  LeafView,
  Side,
  monitor_build_frk,
  monitor_chain_side,
  monitor_fork_kind
)
from Monitor.Mirror import (
  monitor_mirror_first_difference,
  monitor_mirror_leaf,
  monitor_mirror_oracle,
  monitor_mirror_verified
)
from Monitor.Report import Context, monitor_finding, monitor_report, monitor_side_json
from Monitor.Store import Finding, monitor_observed_get
from Transparency.CompactWire import CompactInclusion, TransparencyLeafProof
from Transparency.Merkle import TransparencyCheckpoint, WitnessAttestation
from Transparency.Tree import (
  tlog_inclusion_path,
  tlog_root,
  tlog_verify_consistency,
  tlog_verify_inclusion
)
from Transparency.Wire import decode_checkpoint, decode_witnesses, encode_checkpoint

pub type PairResult do
  PairConsistent
  PairPending(reason :: String)
  PairFork(key :: String)
  PairUnproven(key :: String)
end

fn checkpoint_bytes(side :: Side) -> Option<Bytes> do
  case side.checkpoint do
    None
    Some(checkpoint) -> case encode_checkpoint(checkpoint) do
      Err(_) -> None
      Ok(bytes) -> Some(bytes)
    end
  end
end

fn sides_json(label :: String, a :: Side, b :: Side, extra :: String) -> String do
  "{\"check\":#{Json.encode_string(label)},\"a\":#{monitor_side_json(a,
    checkpoint_bytes(a))},\"b\":#{monitor_side_json(b, checkpoint_bytes(b))}#{extra}}"
end

fn describe(side :: Side) -> String do
  let place = case side.entry do
    None -> "served by the directory"
    Some(entry) -> "anchored at ring index #{entry.index}"
  end
  "checkpoint #{side.sequence} (tree size #{side.tree_size}, #{place})"
end

pub fn monitor_unproven(ctx :: Context,
  label :: String,
  a :: Side,
  b :: Side,
  detail :: String,
  extra :: String) -> PairResult!String do
  let key = "unproven:#{label}:#{Bytes.to_hex(a.hash)}:#{Bytes.to_hex(b.hash)}"
  monitor_report(ctx,
    monitor_finding(ctx,
      key,
      "P0",
      "inconsistency_unproven",
      "#{describe(a)} and #{describe(b)}: #{detail}",
      sides_json(label, a, b, extra)))?
  Ok(PairUnproven(key))
end

fn record_fork(ctx :: Context,
  label :: String,
  proof :: BuiltProof,
  a :: Side,
  b :: Side) -> PairResult!String do
  let hash = Bytes.to_hex(proof.proof_hash)
  let implicated = if List.length(proof.implicated) == 0 do
    "none"
  else
    String.join(proof.implicated, ", ")
  end
  let finding = Finding {
    key: "frk:#{hash}",
    found_at: ctx.now_ms,
    severity: "P0",
    kind: "fork_kind_#{proof.kind}",
    detail: "#{describe(a)} and #{describe(b)} cannot both be true; witnesses that signed both: #{implicated}",
    evidence: sides_json(label, a, b, ",\"frk\":#{Json.encode_string(Bytes.to_hex(proof.frk))}"),
    frk: proof.frk,
    proof_hash: hash
  }
  monitor_report(ctx, finding)?
  Ok(PairFork(finding.key))
end

fn observed_side(ctx :: Context, side :: Side) -> Side!String do
  case monitor_observed_get(ctx.db, side.hash)? do
    None -> Ok(side)
    Some((checkpoint, attestations)) -> Ok(%{side |
      checkpoint: Some(decode_checkpoint(checkpoint)?),
      attestations: side.attestations ++ decode_witnesses(attestations)?
    })
  end
end

# Adds the signed checkpoint behind an anchored side: what the directory
# served when the monitor saw it, and the chain's own post_anchor data and
# cosign statements.

fn resolved(ctx :: Context, side :: Side) -> Side!String do
  let seen = observed_side(ctx, side)?
  case side.entry do
    None -> Ok(seen)
    Some(entry) -> case monitor_chain_side(ctx.config.rpc_urls, ctx.config.judge, ctx.log, entry) do
      None -> Ok(seen)
      Some(chain) -> Ok(%{seen |
        checkpoint: case seen.checkpoint do
          None -> chain.checkpoint
          Some(value)
        end,
        attestations: seen.attestations ++ chain.attestations
      })
    end
  end
end

fn signed(side :: Side) -> Bool do
  case side.checkpoint do
    None -> false
    Some(_) -> true
  end
end

fn anchored(side :: Side) -> Bool do
  case side.entry do
    None -> false
    Some(_) -> true
  end
end

fn build(ctx :: Context,
  kind :: Int,
  inline :: Side,
  ring :: Side,
  contradiction :: Option<Contradiction>,
  label :: String,
  a :: Side,
  b :: Side) -> PairResult!String do
  case monitor_build_frk(kind, inline, ring, contradiction, ctx.log, ctx.config.finder) do
    Ok(proof) -> record_fork(ctx, label, proof, a, b)
    Err(reason) -> monitor_unproven(ctx,
      label,
      a,
      b,
      "a fork proof could not be completed (#{reason})",
      "")
  end
end

fn prove(ctx :: Context,
  kind :: Int,
  a :: Side,
  b :: Side,
  contradiction :: Option<Contradiction>,
  label :: String) -> PairResult!String do
  if signed(a) && anchored(b) do
    build(ctx, kind, a, b, contradiction, label, a, b)
  else if signed(b) && anchored(a) do
    build(ctx, kind, b, a, contradiction, label, a, b)
  else
    let first = resolved(ctx, a)?
    if signed(first) && anchored(b) do
      build(ctx, kind, first, b, contradiction, label, a, b)
    else
      let second = resolved(ctx, b)?
      if signed(second) && anchored(a) do
        build(ctx, kind, second, a, contradiction, label, a, b)
      else
        monitor_unproven(ctx,
          label,
          a,
          b,
          "no signed checkpoint for either side could be found on the chain or from the directory",
          "")
      end
    end
  end
end

# A leaf the monitor's copy (mine's tree) and the directory's current tree
# (theirs) read differently, each proven against its own root.

fn leaf_contradiction(ctx :: Context,
  mine :: Side,
  theirs :: Side,
  index :: Int) -> Option<Contradiction>!String do
  let proof = monitor_dir_leaf(ctx.config.directory, index, theirs.tree_size)?
  let oracle = monitor_mirror_oracle(ctx.db, mine.tree_size)
  let leaf = monitor_mirror_leaf(ctx.db, index)?
  if Bytes.secure_equals(leaf, proof.leaf_hash)
    || !tlog_verify_inclusion(1,
      proof.leaf_hash,
      index,
      theirs.tree_size,
      proof.inclusion.path,
      theirs.root) do
    Ok(None)
  else
    Ok(Some(Contradiction {
      index: index,
      views: [
        LeafView {
          side_hash: mine.hash,
          leaf: leaf,
          path: tlog_inclusion_path(1, oracle, index, mine.tree_size)?
        },
        LeafView { side_hash: theirs.hash, leaf: proof.leaf_hash, path: proof.inclusion.path }
      ]
    }))
  end
end

fn from_copy(ctx :: Context, mine :: Side, theirs :: Side) -> Option<Contradiction>!String do
  let limit = if mine.tree_size < theirs.tree_size do
    mine.tree_size
  else
    theirs.tree_size
  end
  if limit == 0 || mine.tree_size > monitor_mirror_verified(ctx.db)? do
    Ok(None)
  else if !Bytes.secure_equals(tlog_root(1,
      monitor_mirror_oracle(ctx.db, mine.tree_size),
      mine.tree_size)?,
    mine.root) do
    Ok(None)
  else
    case monitor_mirror_first_difference(ctx.db, ctx.config.directory, limit, 0)? do
      None -> Ok(None)
      Some(index) -> leaf_contradiction(ctx, mine, theirs, index)
    end
  end
end

fn find_contradiction(ctx :: Context, lo :: Side, hi :: Side) -> Option<Contradiction>!String do
  case from_copy(ctx, lo, hi)? do
    Some(value) -> Ok(Some(value))
    None -> from_copy(ctx, hi, lo)
  end
end

fn path_json(path :: List<Bytes>) -> String do
  "["
    <> String.join(List.map(path, fn value -> Json.encode_string(Bytes.to_hex(value)) end), ",")
    <> "]"
end

fn contradiction(ctx :: Context,
  lo :: Side,
  hi :: Side,
  path :: List<Bytes>,
  label :: String) -> PairResult!String do
  case find_contradiction(ctx, lo, hi) do
    Err(reason) -> Ok(PairPending("leaf search: #{reason}"))
    Ok(Some(value)) -> prove(ctx, 2, lo, hi, Some(value), label)
    Ok(None) -> monitor_unproven(ctx,
      label,
      lo,
      hi,
      "the directory's consistency proof between them does not verify, and no leaf contradiction could be built from the monitor's copy of the log",
      ",\"consistency_path\":#{path_json(path)}")
  end
end

# older/newer is the order the two were published in (ring order, or the
# anchor before the directory's current checkpoint).

pub fn monitor_check_pair(ctx :: Context,
  older :: Side,
  newer :: Side,
  label :: String) -> PairResult!String do
  let kind = monitor_fork_kind(older, newer)
  if Bytes.secure_equals(older.hash, newer.hash) do
    Ok(PairConsistent)
  else if kind != 0 do
    prove(ctx, kind, older, newer, None, label)
  else if older.tree_size == newer.tree_size do
    Ok(PairConsistent)
  else
    let (lo, hi) = if older.tree_size < newer.tree_size do
      (older, newer)
    else
      (newer, older)
    end
    case monitor_dir_consistency(ctx.config.directory, lo.tree_size, hi.tree_size) do
      Err(reason) -> Ok(PairPending("consistency #{lo.tree_size}->#{hi.tree_size}: #{reason}"))
      Ok(path) -> if tlog_verify_consistency(1,
        lo.tree_size,
        hi.tree_size,
        path,
        lo.root,
        hi.root) do
        Ok(PairConsistent)
      else
        contradiction(ctx, lo, hi, path, label)
      end
    end
  end
end
