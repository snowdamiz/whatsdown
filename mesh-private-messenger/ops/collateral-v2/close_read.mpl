##! Owner-only staged-upload cleanup, independent of mutable proof eligibility.
from Read import (
  CollateralOperatorPins,
  validate_collateral_operator_pins,
  validate_collateral_operator_sources
)
from Plan import CollateralOperationPlan
from Accounts import (
  operator_required,
  operator_owned,
  operator_absent,
  operator_code,
  operator_number,
  operator_snapshot_digest
)
from Transparency.AnchorLog import decode_anchor_log
from Transparency.TokenCollateralWrite import token_collateral_addresses, collateral_public_key
from Transparency.TokenProofWrite import (
  token_proof_owner_stage_address,
  token_proof_owner_close_instruction
)
from Solana.Read import (
  Pubkey,
  OptionalAccountSlicesAtSlot,
  pubkey,
  clock_sysvar,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_send
)

pub struct CollateralStageCloseIntent do
  fee_payer :: Pubkey
  submitter :: Pubkey
  full_hash :: Bytes
end

pub struct CollateralStageCloseState do
  slot :: U64
  timestamp :: U64
  digest :: Bytes
  selection :: Bytes
  present :: Bool
end

pub fn collateral_stage_close_keys(pins :: CollateralOperatorPins,
  intent :: CollateralStageCloseIntent) -> List<Pubkey>!String do
  validate_collateral_operator_pins(pins)?
  if !collateral_public_key(intent.fee_payer) do
    return Err("collateral_close_fee_payer")
  end
  let a = token_collateral_addresses(pins.context)?
  Ok([
    a.judge_config,
    a.log,
    pubkey("SysvarC1ock11111111111111111111111111111111")?,
    pins.context.judge,
    a.judge_data,
    token_proof_owner_stage_address(pins.context.judge, intent.submitter, intent.full_hash)?,
    intent.submitter
  ])
end

fn close_selection(pins :: CollateralOperatorPins,
  intent :: CollateralStageCloseIntent) -> Bytes!String do
  let keys = collateral_stage_close_keys(pins, intent)?
  let body = List.reduce(keys,
    Ok(Bytes.concat(intent.full_hash,
      Bytes.concat(intent.fee_payer.bytes,
        Bytes.write_uint_le(Int.to_string(pins.log_version), 1)?)?)?),
    fn(raw, key) do Bytes.concat(raw?, key.bytes) end)?
  Ok(Crypto.sha256(Bytes.concat(Bytes.concat(body, pins.governance.bytes)?,
    Bytes.concat(pins.service_key, Bytes.write_uint_le(U64.to_string(pins.judge_slot), 8)?)?)?))
end

fn close_fresh(timestamp :: U64, now :: U64) -> Bool!String do
  if U64.compare(timestamp, now) > 0
    || U64.compare(U64.subtract(now, timestamp)?, U64.parse("300")?) > 0 do
    return Err("collateral_close_stale")
  end
  Ok(true)
end

pub fn decode_collateral_stage_close(pins :: CollateralOperatorPins,
  intent :: CollateralStageCloseIntent,
  minimum :: U64,
  reference_time :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> CollateralStageCloseState!String do
  let keys = collateral_stage_close_keys(pins, intent)?
  if List.length(snapshot.accounts) != 7 || U64.compare(snapshot.slot, minimum) < 0 do
    return Err("collateral_close_snapshot")
  end
  let judge = pins.context.judge
  let cfg = operator_owned(snapshot, 0, judge, 40)?
  if Bytes.to_hex(Bytes.slice(cfg, 0, 4)?) != "4d434601"
    || Bytes.slice(cfg, 4, 32)? != pins.governance.bytes
    || Bytes.to_hex(Bytes.slice(cfg, 36, 4)?) != "00000000" do
    return Err("collateral_close_governance")
  end
  let a = token_collateral_addresses(pins.context)?
  let log = decode_anchor_log(operator_owned(snapshot, 1, judge, 352)?)?
  if log.log_id != a.log_id
    || log.name != pins.context.log_name
    || log.version != pins.log_version
    || log.service_public_key != pins.service_key
    || log.ring_address != a.ring.bytes do
    return Err("collateral_close_log")
  end
  if operator_code(snapshot, judge, 3, 4)? != pins.judge_slot do
    return Err("collateral_close_code_changed")
  end
  let clock = clock_sysvar(operator_required(snapshot,
    2,
    pubkey("Sysvar1111111111111111111111111111111111111")?,
    U64.parse("40")?,
    40,
    false)?.info)?
  if clock.slot != snapshot.slot || clock.unix_timestamp <= 0 do
    return Err("collateral_close_clock")
  end
  let now = U64.parse(Int.to_string(clock.unix_timestamp))?
  close_fresh(now, reference_time)?
  let present = !operator_absent(List.get(snapshot.accounts, 5))
  if present do
    let value = case List.get(snapshot.accounts, 5) do
      None -> return Err("collateral_close_stage")
      Some(v) -> v
    end
    let data = value.info.data
    if value.info.owner != judge
      || value.info.executable
      || value.info.lamports == U64.parse("0")?
      || Bytes.length(data) < 1153
      || Bytes.length(data) > 9161 do
      return Err("collateral_close_stage")
    end
    let total = U64.to_int(U64.parse(Bytes.read_uint_le(data, 8, 2)?)?)?
    let received = U64.to_int(U64.parse(Bytes.read_uint_le(data, 10, 2)?)?)?
    if Bytes.to_hex(Bytes.slice(data, 0, 4)?) != "4d535401"
      || Bytes.get(data, 4)? > 1
      || Bytes.to_hex(Bytes.slice(data, 5, 3)?) != "000000"
      || Bytes.to_hex(Bytes.slice(data, 12, 4)?) != "00000000"
      || Bytes.to_hex(Bytes.slice(data, 1144, 8)?) != String.repeat("00", 8)
      || total < 1
      || total > 8009
      || received > total
      || (Bytes.get(data, 4)? == 1 && received != total)
      || Bytes.length(data) != 1152 + total
      || value.space != U64.parse(Int.to_string(1152 + total))?
      || Bytes.slice(data, 16, 32)? != intent.submitter.bytes
      || Bytes.slice(data, 48, 32)? != a.log_id
      || Bytes.slice(data, 80, 32)? != intent.full_hash do
      return Err("collateral_close_stage_binding")
    end
    let refund = case List.get(snapshot.accounts, 6) do
      None -> U64.parse("0")?
      Some(account) -> account.info.lamports
    end
    U64.add(refund, value.info.lamports)?
    nil
  end
  Ok(CollateralStageCloseState {
    slot: snapshot.slot,
    timestamp: now,
    digest: operator_snapshot_digest(keys, snapshot)?,
    selection: close_selection(pins, intent)?,
    present: present
  })
end

pub fn collateral_stage_close_quorum(a :: CollateralStageCloseState!String,
  b :: CollateralStageCloseState!String,
  c :: CollateralStageCloseState!String) -> CollateralStageCloseState!String do
  for pair in [(a, b), (a, c), (b, c)] do
    case pair do
      (Ok(x), Ok(y)) -> if x.digest == y.digest && x.selection == y.selection do
        return Ok(x)
      end
      _ -> nil
    end
  end
  Err("collateral_close_quorum_unavailable_or_disagreed")
end

pub fn read_collateral_stage_close_origin(client :: Int,
  url :: String,
  pins :: CollateralOperatorPins,
  intent :: CollateralStageCloseIntent,
  minimum :: U64,
  reference_time :: U64) -> CollateralStageCloseState!String do
  let request = get_multiple_accounts_slice_request(1,
    collateral_stage_close_keys(pins, intent)?,
    "finalized",
    0,
    9216,
    Some(minimum))?
  decode_collateral_stage_close(pins,
    intent,
    minimum,
    reference_time,
    optional_accounts_slice_from_response(rpc_send(client, url, request, 5000, 131072)?)?)
end

pub fn read_collateral_stage_close(client :: Int,
  sources :: List<String>,
  pins :: CollateralOperatorPins,
  intent :: CollateralStageCloseIntent,
  minimum :: U64) -> CollateralStageCloseState!String do
  validate_collateral_operator_sources(sources)?
  let now = U64.parse(Int.to_string(DateTime.to_unix_secs(DateTime.utc_now())))?
  let value = collateral_stage_close_quorum(read_collateral_stage_close_origin(client,
      List.get(sources, 0),
      pins,
      intent,
      minimum,
      now),
    read_collateral_stage_close_origin(client, List.get(sources, 1), pins, intent, minimum, now),
    read_collateral_stage_close_origin(client, List.get(sources, 2), pins, intent, minimum, now))?
  close_fresh(value.timestamp,
    U64.parse(Int.to_string(DateTime.to_unix_secs(DateTime.utc_now())))?)?
  Ok(value)
end

pub fn plan_collateral_stage_close(pins :: CollateralOperatorPins,
  intent :: CollateralStageCloseIntent,
  state :: CollateralStageCloseState) -> CollateralOperationPlan!String do
  if state.selection != close_selection(pins, intent)? do
    return Err("collateral_close_selection")
  end
  Ok(CollateralOperationPlan {
    state: if state.present do
      "ready"
    else
      "complete"
    end,
    reason: if state.present do
      "owner_stage_close"
    else
      "stage_absent"
    end,
    slot: state.slot,
    digest: state.digest,
    fee_payer: intent.fee_payer,
    rent_payers: [],
    instruction_signers: if state.present do
      [intent.submitter]
    else
      []
    end,
    governance_required: false,
    wait_until: None,
    instructions: if state.present do
      [token_proof_owner_close_instruction(pins.context.judge, intent.submitter, intent.full_hash)?]
    else
      []
    end
  })
end
