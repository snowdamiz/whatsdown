##! One bounded unsigned next step. Chain execution remains the final authority.
from Read import CollateralOperatorPins, CollateralOperatorState, collateral_selection_digest
from Transparency.TokenCollateralWrite import (
  TokenCollateralSubject,
  TokenCollateralContext,
  token_collateral_addresses,
  token_collateral_subject,
  token_binding_propose_instruction,
  token_binding_activate_permissionless_instruction,
  token_collateral_migrate_instruction,
  token_collateral_deposit_instruction,
  token_collateral_activate_pending_instruction,
  token_collateral_assess_instruction,
  token_collateral_request_unbond_instruction,
  token_collateral_withdraw_instruction,
  token_collateral_propose_minimums_instruction,
  token_collateral_activate_minimums_instruction,
  collateral_public_key
)
from Transparency.TokenChain import token_payout_address
from Solana.Read import Pubkey
from Solana.Tx import Instruction, create_associated_token_idempotent_instruction

pub struct CollateralOperation do
  tag :: Int
  fee_payer :: Pubkey
  operator :: Pubkey
  subject :: TokenCollateralSubject
  asset :: Int
  amount :: U64
  witness_minimum :: U64
  directory_minimum :: U64
end

pub struct CollateralOperationPlan do
  state :: String
  reason :: String
  slot :: U64
  digest :: Bytes
  fee_payer :: Pubkey
  rent_payers :: List<Pubkey>
  instruction_signers :: List<Pubkey>
  governance_required :: Bool
  wait_until :: Option<U64>
  instructions :: List<Instruction>
end

fn result(request :: CollateralOperation,
  snapshot :: CollateralOperatorState,
  state :: String,
  reason :: String,
  until :: Option<U64>,
  instructions :: List<Instruction>,
  governance :: Bool) -> CollateralOperationPlan do
  let all = List.reduce(instructions,
    [],
    fn(keys, ix) do keys
      ++ (for meta in ix.accounts do
        if meta.signer do
          [meta.pubkey]
        else
          []
        end
      end
        |> List.flatten()) end)
  let unique = List.reduce(all,
    [],
    fn(keys, key) do
      if List.contains(keys, key) do
        keys
      else
        keys ++ [key]
      end
    end)
  CollateralOperationPlan {
    state: state,
    reason: reason,
    slot: snapshot.slot,
    digest: snapshot.digest,
    fee_payer: request.fee_payer,
    instruction_signers: unique,
    rent_payers: if state != "ready" do
      []
    else if request.tag == 31 || request.tag == 38 do
      [request.fee_payer]
    else if request.tag == 34 || request.tag == 35 do
      [request.operator]
    else
      []
    end,
    governance_required: governance,
    wait_until: until,
    instructions: instructions
  }
end

fn waiting(r :: CollateralOperation,
  s :: CollateralOperatorState,
  reason :: String,
  until :: Option<U64>) -> CollateralOperationPlan do
  result(r, s, "waiting", reason, until, [], false)
end

fn complete(r :: CollateralOperation,
  s :: CollateralOperatorState,
  reason :: String) -> CollateralOperationPlan do
  result(r, s, "complete", reason, None, [], false)
end

fn ready(r :: CollateralOperation,
  s :: CollateralOperatorState,
  ix :: List<Instruction>,
  governance :: Bool) -> CollateralOperationPlan do
  result(r, s, "ready", "", None, ix, governance)
end

fn value(usd :: U64, morse :: U64, price :: U64) -> U128!String do
  U128.add(U128.multiply(U128.parse(U64.to_string(usd))?, U128.parse("1000000")?)?,
    U128.multiply(U128.parse(U64.to_string(morse))?, U128.parse(U64.to_string(price))?)?)
end

fn target(amount :: U64) -> U128!String do
  U128.multiply(U128.parse(U64.to_string(amount))?, U128.parse("1000000")?)
end

# The state must come from read_collateral_operator with matching request subject
# and operator. For offline replay use the pure strict decoder with an explicit
# fixture clock; it does not turn a caller's JSON claim into chain authority.
pub fn plan_collateral_operation(pins :: CollateralOperatorPins,
  r :: CollateralOperation,
  s :: CollateralOperatorState) -> CollateralOperationPlan!String do
  if !collateral_public_key(r.fee_payer)
    || !collateral_public_key(r.operator)
    || r.asset < 0
    || r.asset > 1
    || r.tag < 31
    || (r.tag > 40 && r.tag != 45) do
    return Err("collateral_operation_request")
  end
  if s.selection != collateral_selection_digest(pins, r.subject, r.operator)? do
    return Err("collateral_operation_snapshot_selection")
  end
  let c = pins.context
  let zero = U64.parse("0")?
  let b = s.binding
  if r.tag == 31 do
    case b do
      Some(binding) ->
        if binding.activated_at != zero do
          if !s.oracle_current || !s.binding_current do
            return Err("collateral_active_binding_changed")
          end
          return Ok(complete(r, s, "binding_active"))
        end
        if s.oracle_current && s.binding_current do
          return Ok(complete(r, s, "binding_already_proposed"))
        end
      None -> nil
    end
    if !s.oracle_current do
      return Err("collateral_oracle_source_changed")
    end
    if s.oracle_twap == None do
      return Ok(waiting(r, s, "oracle_full_window_required", None))
    end
    return Ok(ready(r,
      s,
      [token_binding_propose_instruction(c, pins.governance, r.fee_payer)?],
      true))
  end
  let binding = case b do
    None -> return Err("collateral_binding_not_proposed")
    Some(v) -> v
  end
  if r.tag == 32 do
    if !s.oracle_current || !s.binding_current do
      return Err("collateral_binding_proposal_refresh_required")
    end
    if binding.activated_at != zero do
      return Ok(complete(r, s, "binding_active"))
    end
    if U64.compare(s.timestamp, binding.ready_at) < 0 do
      return Ok(waiting(r, s, "binding_fourteen_day_wait", Some(binding.ready_at)))
    end
    if s.twap == None do
      return Ok(waiting(r, s, "oracle_full_window_required", None))
    end
    if s.pool.active_epoch != None
      || s.pool.next_epoch != U64.divide(s.timestamp, U64.parse("604800")?)? do
      return Ok(waiting(r, s, "legacy_reward_epochs_must_be_drained", None))
    end
    return Ok(ready(r,
      s,
      [token_binding_activate_permissionless_instruction(c, pins.governance, r.fee_payer)?],
      false))
  end
  if binding.activated_at == zero || s.legacy_economics do
    return Err("collateral_binding_inactive")
  end
  if U64.compare(s.timestamp, s.economics.ready_at) < 0 do
    return Ok(waiting(r, s, "economics_policy_wait", Some(s.economics.ready_at)))
  end
  if r.tag == 39 do
    if r.witness_minimum == zero || U64.compare(r.directory_minimum, r.witness_minimum) < 0 do
      return Err("collateral_minimums")
    end
    if s.economics.pending_ready != zero
      && s.economics.pending_witness_usd == r.witness_minimum
      && s.economics.pending_directory_usd == r.directory_minimum do
      return Ok(complete(r, s, "minimums_already_proposed"))
    end
    return Ok(ready(r,
      s,
      [
        token_collateral_propose_minimums_instruction(c,
          pins.governance,
          r.witness_minimum,
          r.directory_minimum)?
      ],
      true))
  end
  if r.tag == 40 do
    if s.economics.pending_ready == zero do
      return Ok(complete(r, s, "no_pending_minimums"))
    end
    if U64.compare(s.timestamp, s.economics.pending_ready) < 0 do
      return Ok(waiting(r, s, "minimums_fourteen_day_wait", Some(s.economics.pending_ready)))
    end
    return Ok(ready(r, s, [token_collateral_activate_minimums_instruction(c)?], false))
  end
  if r.tag == 33 do
    case s.bond do
      None -> return Err("collateral_bond_missing")
      Some(_) -> nil
    end
    if !s.legacy_bond do
      return Ok(complete(r, s, "bond_already_migrated"))
    end
    return Ok(ready(r, s, [token_collateral_migrate_instruction(c, r.subject)?], false))
  end
  if List.contains([34, 35, 36, 45], r.tag) && !s.binding_release_current do
    return Err("collateral_binding_code_changed")
  end
  if s.legacy_bond do
    return Err("collateral_explicit_migration_required")
  end
  let witness = case r.subject do
    CollateralDirectory -> false
    CollateralWitness(_) -> true
  end
  if (r.tag == 34 && !witness) || (r.tag == 35 && witness) do
    return Err("collateral_subject_tag")
  end
  if r.tag == 34 || r.tag == 35 do
    if r.amount == zero || s.subject_owner != r.operator.bytes do
      return Err("collateral_deposit_owner_or_amount")
    end
    let source = if r.asset == 0 do
      s.source_usdc
    else
      s.source_morse
    end
    if U64.compare(source, r.amount) < 0 do
      return Err("collateral_source_underfunded")
    end
    let new_bond = case s.bond do
      None -> true
      Some(v) ->
        if v.status == 1 do
          if v.asset != r.asset do
            return Err("collateral_topup_asset")
          end
          let pending = case s.pending do
            None -> zero
            Some(p) -> p.amount
          end
          let total = U64.add(U64.add(v.principal, pending)?, r.amount)?
          if r.asset == 1 && U64.compare(total, U64.parse("1000000000000000")?) > 0 do
            return Err("collateral_token_supply_bound")
          end
          false
        else if v.status == 4 do
          true
        else
          return Err("collateral_deposit_status")
        end
    end
    if new_bond do
      if s.pool.active_epoch != None do
        return Ok(waiting(r, s, "reward_epoch_collecting", None))
      end
      let price = if r.asset == 1
        || s.economics.witness_morse != zero
        || s.economics.directory_morse != zero do
        if !s.oracle_current || !s.binding_current do
          return Err("collateral_oracle_source_changed")
        end
        case s.twap do
          None -> return Ok(waiting(r, s, "oracle_full_window_required", None))
          Some(v) -> v
        end
      else
        zero
      end
      let required = if witness do
        s.economics.witness_target_usd
      else
        s.economics.directory_target_usd
      end
      if U128.compare(if r.asset == 0 do
          value(r.amount, zero, price)?
        else
          value(zero, r.amount, price)?
        end,
        target(required)?) < 0 do
        return Err("collateral_below_entry_minimum")
      end
      let wu = if witness && r.asset == 0 do
        U64.add(s.economics.witness_usdc, r.amount)?
      else
        s.economics.witness_usdc
      end
      let wm = if witness && r.asset == 1 do
        U64.add(s.economics.witness_morse, r.amount)?
      else
        s.economics.witness_morse
      end
      let du = if !witness && r.asset == 0 do
        r.amount
      else
        s.economics.directory_usdc
      end
      let dm = if !witness && r.asset == 1 do
        r.amount
      else
        s.economics.directory_morse
      end
      if U64.compare(U64.add(wm, dm)?, U64.parse("1000000000000000")?) > 0 do
        return Err("collateral_token_supply_bound")
      end
      if (witness && s.economics.directory_status != 1)
        || U128.compare(value(du, dm, price)?, value(wu, wm, price)?) < 0 do
        return Err("collateral_directory_coverage")
      end
    end
    return Ok(ready(r,
      s,
      [
        token_collateral_deposit_instruction(c,
          pins.governance,
          r.operator,
          r.subject,
          r.asset,
          r.amount)?
      ],
      !witness))
  end
  let bond = case s.bond do
    None -> return Err("collateral_bond_missing")
    Some(v) -> v
  end
  if r.asset != bond.asset do
    return Err("collateral_requested_asset_mismatch")
  end
  if r.tag == 37 || r.tag == 38 do
    if r.operator.bytes != bond.owner do
      return Err("collateral_owner_required")
    end
    if r.tag == 37 do
      if bond.status == 2 do
        return Ok(complete(r, s, "unbond_already_requested"))
      end
      if bond.status != 1 do
        return Err("collateral_unbond_status")
      end
      return Ok(ready(r,
        s,
        [token_collateral_request_unbond_instruction(c, r.operator, r.subject)?],
        false))
    end
    if bond.status == 4 do
      return Ok(complete(r, s, "collateral_withdrawn"))
    end
    if bond.status != 2 do
      return Err("collateral_withdraw_status")
    end
    let until = U64.add(bond.unbond_at, U64.parse("2592000")?)?
    if U64.compare(s.timestamp, until) < 0 do
      return Ok(waiting(r, s, "owner_thirty_day_exit_wait", Some(until)))
    end
    if !witness
      && (s.economics.witness_usdc != zero
        || s.economics.witness_morse != zero
        || s.log.service_slashed) do
      return Err("collateral_directory_exit_blocked")
    end
    let a = token_collateral_subject(c, r.subject, r.asset)?
    let destination = token_payout_address(r.operator, a.mint)?
    # Idempotent setup is safe even if the destination already exists.
    return Ok(ready(r,
      s,
      [
        create_associated_token_idempotent_instruction(r.fee_payer,
          destination,
          r.operator,
          a.mint)?,
        token_collateral_withdraw_instruction(c, r.operator, r.subject, r.asset)?
      ],
      false))
  end
  if bond.status != 1 do
    return Err("collateral_assessment_status")
  end
  let pending = case s.pending do
    None -> return Err("collateral_pending_record_required")
    Some(v) -> v
  end
  if r.tag == 36 && s.pool.active_epoch != None do
    return Ok(waiting(r, s, "reward_epoch_collecting", None))
  end
  let price = if bond.asset == 1
    || (r.tag == 36
      && pending.amount != zero
      && (s.economics.witness_morse != zero || s.economics.directory_morse != zero)) do
    if !s.oracle_current || !s.binding_current do
      return Err("collateral_oracle_source_changed")
    end
    case s.twap do
      None -> return Ok(waiting(r, s, "oracle_full_window_required", None))
      Some(v) -> v
    end
  else
    zero
  end
  if r.tag == 36 do
    let resulting = U64.add(bond.principal, pending.amount)?
    if bond.asset == 1 && U64.compare(resulting, U64.parse("1000000000000000")?) > 0 do
      return Err("collateral_token_supply_bound")
    end
    let wu = if witness && bond.asset == 0 do
      U64.add(s.economics.witness_usdc, pending.amount)?
    else
      s.economics.witness_usdc
    end
    let wm = if witness && bond.asset == 1 do
      U64.add(s.economics.witness_morse, pending.amount)?
    else
      s.economics.witness_morse
    end
    let du = if !witness && bond.asset == 0 do
      U64.add(s.economics.directory_usdc, pending.amount)?
    else
      s.economics.directory_usdc
    end
    let dm = if !witness && bond.asset == 1 do
      U64.add(s.economics.directory_morse, pending.amount)?
    else
      s.economics.directory_morse
    end
    if U128.compare(value(du, dm, price)?, value(wu, wm, price)?) < 0 do
      return Err("collateral_directory_coverage")
    end
    return Ok(ready(r,
      s,
      [token_collateral_activate_pending_instruction(c, r.subject, r.asset)?],
      false))
  end
  Ok(ready(r, s, [token_collateral_assess_instruction(c, r.subject, r.asset)?], false))
end
