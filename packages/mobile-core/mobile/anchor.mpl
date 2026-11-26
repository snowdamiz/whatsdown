from Mobile.Types import MobileSecurityConfig, MobileTransparencyView
from Security.Config import SecurityConfig
from Binary.Reader import BinaryReader
from Mobile.AnchorEvidence import (
  anchor_evidence_mismatch,
  anchor_filing,
  anchor_fork_kind,
  anchor_landing
)
from Mobile.AnchorSteps import (
  AnchorContext,
  AnchorStop,
  anchor_asks,
  anchor_call,
  anchor_context,
  anchor_fail,
  anchor_kind_directory,
  anchor_lift,
  anchor_local,
  anchor_parse_input,
  anchor_rpc,
  anchor_soft,
  anchor_step,
  anchor_waiting
)
from Mobile.BondCounter import bond_counter_read
from Mobile.Chain import (
  ChainAccount,
  ChainLog,
  ChainRingEntry,
  ChainRingHeader,
  ChainWitness,
  chain_account,
  chain_account_request,
  chain_block_time,
  chain_block_time_request,
  chain_decode_entry,
  chain_decode_header,
  chain_entry_offset,
  chain_log_from_projection,
  chain_log_projection,
  chain_project_account,
  chain_project_block_time,
  chain_ring_capacity
)
from Mobile.Transparency import canonical_transparency_checkpoint, load_transparency_view
from Mobile.TrustAlarm import (
  TrustAlarm,
  TrustSummary,
  trust_alarm_clear_mismatch,
  trust_alarm_raise,
  trust_alarm_service_slashed,
  trust_summary_none
)
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.Records import store_updated_blobs
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_start,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)
from Transparency.CompactWire import (
  CompactConsistency,
  TransparencyTreeQueryV2,
  transparency_decode_consistency_v2,
  transparency_encode_tree_query_v2
)
from Transparency.Merkle import TransparencyCheckpoint
from Transparency.Tree import tlog_empty_root, tlog_verify_consistency

##! Mobile.Anchor: the phone's check against the public record (plan §6.7).
##!
##! Run daily, and after a contact's keys change (at most hourly), through
##! `mesh_messenger_anchor_check` (the request/answer steps are in
##! Mobile.AnchorSteps). With no anchor pinned the check is OFF. Otherwise the
##! phone reads the pinned Log account and its anchor ring from two random
##! pinned RPC providers (a third on disagreement; still no agreement is
##! `rpc_disagree`, never a pass), and:
##!
##! - refuses the service key when the judge has slashed it (a
##!   `service_slashed` trust alarm: new lookups fail closed);
##! - notes the public record as STALE when the newest anchor is more than
##!   two hours old (a quiet notice; nothing is blocked);
##! - takes the newest anchored checkpoint (evidence entries skipped) and
##!   compares it with the checkpoint this device verified: equal sizes need
##!   equal roots, one sequence needs one checkpoint, and different sizes need
##!   the directory's consistency proof between the two (KTS v2 with both sizes
##!   explicit), verified against the anchored root. A refused or invalid
##!   proof is a MISMATCH: an `anchor_mismatch` trust alarm fails new sessions
##!   and key changes closed, keeps the evidence, and files FRK proofs with
##!   every pinned relay (Mobile.AnchorEvidence).
##!
##! It also reads the bond counter (Mobile.BondCounter). Everything is kept on
##! the device; nothing is reported to Morse, and no read goes through Morse's
##! servers except the directory's own consistency and leaf proofs.
##!
##! Local record "anchor-check/v1": u8 1 || "ACR" || u8 outcome ||
##! u64 checked_at_ms || u64 anchor_time_ms || u64 anchor_slot ||
##! u64 public_tree_size || vector32(bond counter body).
##! Outcomes: 0 never checked, 1 ok, 2 stale, 3 rpc_disagree,
##! 4 rpc_unavailable, 5 mismatch, 6 service_slashed, 7 off,
##! 8 directory_unavailable, 9 chain_invalid (the chain does not hold the
##! pinned log as this build expects).

pub struct AnchorRecord do
  outcome :: Int
  checked_at :: Int
  anchor_ms :: Int
  anchor_slot :: Int
  public_size :: Int
  bonds :: Bytes
end

fn label() -> String do
  "anchor-check/v1"
end

fn stale_after_ms() -> Int do
  7_200_000
end

# Evidence entries skipped before the newest normal one, at most.

fn entry_walk() -> Int do
  8
end

fn outcome_code(outcome :: String) -> Option<Int> do
  if outcome == "rpc_disagree" do
    Some(3)
  else if outcome == "rpc_unavailable" do
    Some(4)
  else if outcome == "chain_invalid" do
    Some(9)
  else
    None
  end
end

fn record(ctx :: AnchorContext, outcome :: Int) -> AnchorRecord do
  AnchorRecord {
    outcome: outcome,
    checked_at: ctx.now,
    anchor_ms: 0,
    anchor_slot: 0,
    public_size: 0,
    bonds: Bytes.empty()
  }
end

fn encode_record(value :: AnchorRecord) -> Bytes!String do
  tcodec_join([
    tcodec_u8(1)?,
    Bytes.from_utf8("ACR"),
    tcodec_u8(value.outcome)?,
    tcodec_u64(value.checked_at)?,
    tcodec_u64(value.anchor_ms)?,
    tcodec_u64(value.anchor_slot)?,
    tcodec_u64(value.public_size)?,
    tcodec_vector(value.bonds)?
  ])
end

fn decode_record(input :: Bytes) -> AnchorRecord!String do
  let state = tcodec_start(input, 1048576, 1, "ACR")?
  let outcome = tcodec_take_u8(state)?
  let checked = tcodec_take_u64(outcome.state)?
  let anchor = tcodec_take_u64(checked.state)?
  let slot = tcodec_take_u64(anchor.state)?
  let size = tcodec_take_u64(slot.state)?
  let bonds = tcodec_take_vector(size.state, 1048576)?
  tcodec_done(bonds.state)?
  Ok(AnchorRecord {
    outcome: outcome.value,
    checked_at: checked.value,
    anchor_ms: anchor.value,
    anchor_slot: slot.value,
    public_size: size.value,
    bonds: bonds.value
  })
end

pub fn anchor_record_load(database_path :: String) -> Option<AnchorRecord>!String do
  case load_blob(database_path, label()) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(None)
    else
      Err(error)
    end
    Ok(blob) -> Ok(Some(decode_record(open_local(blob,
      platform_key()?,
      local_context(label())?)?)?))
  end
end

fn store_record(database_path :: String, value :: AnchorRecord) -> ()!String do
  let blob = seal_local(encode_record(value)?, platform_key()?, local_context(label())?)?
  store_updated_blobs(database_path, [label()], [blob])
end

fn agreed_account(projection :: Bytes, owner :: String) -> Result<ChainAccount, AnchorStop> do
  case anchor_lift(chain_account(projection), "chain_invalid")? do
    None -> Err(anchor_fail("chain_invalid"))
    Some(account) -> if account.owner != owner do
      Err(anchor_fail("chain_invalid"))
    else
      Ok(account)
    end
  end
end

fn log_projection(body :: Bytes) -> Bytes!String do
  let projection = chain_project_account(body, 2584)?
  case chain_account(projection)? do
    None -> Ok(projection)
    Some(account) -> chain_log_projection(account)
  end
end

fn read_log(ctx :: AnchorContext) -> Result<ChainLog, AnchorStop> do
  let config = ctx.config.config
  let projection = anchor_rpc(ctx,
    "log",
    chain_account_request(config.log_account, 0, 2584),
    fn body -> log_projection(body) end)?
  let account = agreed_account(projection, config.judge_program_id)?
  let log = anchor_lift(chain_log_from_projection(account), "chain_invalid")?
  if !Bytes.secure_equals(log.service_key, ctx.config.transparency_service_public_key) do
    Err(anchor_fail("chain_invalid"))
  else
    Ok(log)
  end
end

fn read_header(ctx :: AnchorContext, log :: ChainLog) -> Result<ChainRingHeader, AnchorStop> do
  let projection = anchor_rpc(ctx,
    "ring",
    chain_account_request(log.ring, 0, 64),
    fn body -> chain_project_account(body, 64) end)?
  let account = agreed_account(projection, ctx.config.config.judge_program_id)?
  let header = anchor_lift(chain_decode_header(account.data), "chain_invalid")?
  if !Bytes.secure_equals(header.log_id, log.log_id) do
    Err(anchor_fail("chain_invalid"))
  else
    Ok(header)
  end
end

# The newest anchored checkpoint, walking back past evidence entries (the
# contradicting checkpoints post_anchor keeps; monitors file those).

fn newest_entry(ctx :: AnchorContext,
  log :: ChainLog,
  header :: ChainRingHeader,
  step :: Int) -> Result<Option<ChainRingEntry>, AnchorStop> do
  if step >= entry_walk() || step >= header.count do
    return Ok(None)
  end
  let capacity = chain_ring_capacity()
  let index = (header.head - 1 - step + 2 * capacity) % capacity
  let projection = anchor_rpc(ctx,
    "entry:#{index}",
    chain_account_request(log.ring, chain_entry_offset(index), 104),
    fn body -> chain_project_account(body, 104) end)?
  let account = agreed_account(projection, ctx.config.config.judge_program_id)?
  let entry = anchor_lift(chain_decode_entry(index, account.data), "chain_invalid")?
  if entry.evidence != 0 do
    newest_entry(ctx, log, header, step + 1)
  else
    Ok(Some(entry))
  end
end

fn size_of(value :: TransparencyCheckpoint) -> Int do
  case U64.to_int(value.tree_size) do
    Ok(size) -> size
    Err(_) -> -1
  end
end

fn directory_down(status :: Int) -> Bool do
  status == 0 || status == 408 || status == 429 || status >= 500
end

fn consistent(status :: Int,
  answer :: Bytes,
  old_size :: Int,
  new_size :: Int,
  old_root :: Bytes,
  new_root :: Bytes) -> Bool do
  if status != 200 do
    false
  else
    case transparency_decode_consistency_v2(answer) do
      Err(_) -> false
      Ok(proof) -> proof.old_size == old_size
        && proof.new_size == new_size
        && tlog_verify_consistency(1, old_size, new_size, proof.path, old_root, new_root)
    end
  end
end

fn verified_view(database_path :: String) -> Option<TransparencyCheckpoint>!String do
  case load_transparency_view(database_path, platform_key()?) do
    Err(error) -> if error == "group_transparency_unverified" do
      Ok(None)
    else
      Err(error)
    end
    Ok(view) -> Ok(Some(canonical_transparency_checkpoint(view.checkpoint)?))
  end
end

# 0 nothing to compare, 1 consistent, 5 mismatch, 8 directory unavailable.

fn compare(ctx :: AnchorContext,
  log :: ChainLog,
  entry :: ChainRingEntry) -> Result<Int, AnchorStop> do
  let local = case anchor_local(verified_view(ctx.database_path))? do
    None -> return Ok(0)
    Some(value) -> value
  end
  let kind = anchor_local(anchor_fork_kind(local, entry))?
  let local_size = size_of(local)
  if kind != 0 do
    anchor_evidence_mismatch(ctx, log, entry, local, kind)?
    return Ok(5)
  end
  if local_size == entry.tree_size do
    return Ok(1)
  end
  let (old_size, old_root, new_size, new_root) = if local_size < entry.tree_size do
    (local_size, local.tree_root, entry.tree_size, entry.root)
  else
    (entry.tree_size, entry.root, local_size, local.tree_root)
  end
  let valid = if old_size == 0 do
    Bytes.secure_equals(old_root, anchor_lift(tlog_empty_root(1), "chain_invalid")?)
  else
    let query = anchor_lift(transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
        old_size: old_size,
        new_size: new_size,
        tree: 1
      }),
      "chain_invalid")?
    let answer = anchor_call(ctx,
      anchor_kind_directory(),
      "consistency",
      "/v1/transparency/consistency",
      query)?
    if directory_down(answer.status) do
      return Ok(8)
    end
    consistent(answer.status, answer.answer, old_size, new_size, old_root, new_root)
  end
  if valid do
    Ok(1)
  else
    anchor_evidence_mismatch(ctx, log, entry, local, 0)?
    Ok(5)
  end
end

fn slashed_alarm(ctx :: AnchorContext) -> TrustAlarm!String do
  Ok(TrustAlarm {
    kind: trust_alarm_service_slashed(),
    active: true,
    raised_at: ctx.now,
    service_key: ctx.config.transparency_service_public_key,
    first: trust_summary_none()?,
    second: trust_summary_none()?,
    frks: List.new()
  })
end

fn run(ctx :: AnchorContext) -> Result<AnchorRecord, AnchorStop> do
  if ctx.config.config.log_account == "" do
    return Ok(record(ctx, 7))
  end
  let log = read_log(ctx)?
  if log.service_slashed do
    anchor_local(trust_alarm_raise(ctx.database_path, anchor_local(slashed_alarm(ctx))?))?
  end
  let header = read_header(ctx, log)?
  let time_read = if header.count == 0 do
    Ok(None)
  else
    anchor_soft(anchor_rpc(ctx,
      "time",
      chain_block_time_request(header.last_slot),
      fn body -> chain_project_block_time(body) end))
  end
  let entry_read = if log.service_slashed || header.count == 0 do
    Ok(None)
  else
    newest_entry(ctx, log, header, 0)
  end
  let bonds_read = bond_counter_read(ctx, log)
  anchor_waiting(anchor_asks(time_read) ++ anchor_asks(entry_read) ++ anchor_asks(bonds_read))?
  let seconds = case time_read? do
    None -> 0
    Some(projection) -> case chain_block_time(projection) do
      Ok(value) -> value
      Err(_) -> 0
    end
  end
  let bonds = case bonds_read do
    Ok(body) -> body
    Err(_) -> Bytes.empty()
  end
  let anchor_ms = seconds * 1000
  let stale = header.count == 0 || (anchor_ms > 0 && ctx.now - anchor_ms > stale_after_ms())
  let base = %{record(ctx, 1) |
    anchor_ms: anchor_ms,
    anchor_slot: header.last_slot,
    public_size: header.last_size,
    bonds: bonds
  }
  let quiet = if stale do
    2
  else
    1
  end
  if log.service_slashed do
    return Ok(%{base | outcome: 6})
  end
  case entry_read? do
    None -> Ok(%{base | outcome: quiet})
    Some(entry) -> do
      let compared = compare(ctx, log, entry)?
      if compared == 1 do
        anchor_local(trust_alarm_clear_mismatch(ctx.database_path))?
      end
      Ok(%{base |
        outcome: if compared == 5 do
          5
        else if compared == 8 do
          8
        else
          quiet
        end
      })
    end
  end
end

# One step of a run (Mobile.AnchorSteps): the requests still needed, or done
# once the check, the filing of any trust alarm's proofs and the reading of
# where filed proofs landed have all settled.

pub fn anchor_check(input :: Bytes) -> Bytes!String do
  let (database_path, exchanges) = anchor_parse_input(input)?
  if String.length(database_path) > 4096 do
    return Err("invalid_database_path")
  end
  ensure_schema(database_path)?
  let ctx = anchor_context(database_path, exchanges)?
  let checked = run(ctx)
  let filing = anchor_filing(ctx)
  let landing = if ctx.config.config.log_account == "" do
    Ok(nil)
  else
    anchor_landing(ctx)
  end
  let asks = anchor_asks(checked) ++ anchor_asks(filing) ++ anchor_asks(landing)
  if List.length(asks) > 0 do
    return anchor_step(false, asks)
  end
  let result = case checked do
    Ok(value)
    Err(stop) -> case outcome_code(stop.outcome) do
      Some(code) -> Ok(record(ctx, code))
      None -> Err(stop.outcome)
    end
  end?
  store_record(database_path, result)?
  anchor_step(true, List.new())
end
