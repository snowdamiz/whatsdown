from Transparency.RpcTransport import webpki_rpc_transport
from Input import RelayConfig, LookupRequest
from ProofRead import CollateralProofIntent, CollateralProofState
from Transparency.RelayLookupRead import RelayLookupState, read_relay_lookup
from Transparency.RelayLookup import RelayLookupPlan, prepare_relay_lookup
from Transparency.TokenProofWrite import (
  TokenPreparedProof,
  TokenPreparedProofRow,
  token_proof_prepare_instruction,
  token_proof_settle_instruction
)
from Transparency.TokenCollateralWrite import token_collateral_addresses
from Transparency.AnchorBond import bond_witness_identity
from Solana.Tx import Instruction, AccountMeta, instruction_report_json
from Solana.Read import Pubkey, pubkey_string

# Derive future tag44 metas from authenticated selected lifetimes, so one ALT
# can survive initialize -> prepare -> settle without changing its identity.
fn settlement_shape(config :: RelayConfig,
  state :: CollateralProofState) -> TokenPreparedProof!String do
  case state.receipt do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let zero = U64.parse("0")?
  let a = token_collateral_addresses(config.operator.pins.context)?
  Ok(TokenPreparedProof {
    kind: 1,
    anchored: state.anchor_generation != None,
    settled: false,
    log_id: a.log_id,
    proof_hash: state.plan.proof_hash,
    finder: state.plan.finder,
    submitter: config.submitter.bytes,
    usdc_mint: config.operator.pins.context.usdc_mint.bytes,
    morse_mint: a.morse_mint.bytes,
    first_hash: state.second_hash,
    second_hash: state.second_hash,
    prepared_at: state.base.timestamp,
    usdc_slashed: zero,
    usdc_finder: zero,
    directory_usdc: zero,
    morse_slashed: zero,
    morse_finder: zero,
    directory_morse: zero,
    verified_signature_mask: zero,
    stage: state.plan.stage.bytes,
    deadline_ms: state.deadline_ms,
    directory_bonded_at: state.directory.bonded_at,
    directory_asset: state.directory.asset,
    settled_at: zero,
    rows: for index in 0..List.length(state.plan.witnesses) do
      let target = List.get(state.plan.witnesses, index)
      let bond = List.get(state.subjects, index)
      TokenPreparedProofRow {
        identity: bond_witness_identity(target.key.witness_id, target.key.public_key)?,
        witness: target.address.bytes,
        public_key: target.key.public_key,
        asset: bond.asset,
        bonded_at: bond.bonded_at,
        principal: zero,
        slashed: zero,
        finder: zero
      }
    end
  })
end

pub fn plan_lookup(config :: RelayConfig,
  intent :: CollateralProofIntent,
  state :: CollateralProofState,
  requested :: Option<LookupRequest>) -> RelayLookupPlan!String do
  let c = config.operator.pins.context
  let settle = token_proof_settle_instruction(c, settlement_shape(config, state)?)?
  let accounts = case state.receipt do
    Some(_) -> settle.accounts
    None ->
      let prepare = token_proof_prepare_instruction(c,
        intent.fee_payer,
        intent.submitter,
        intent.wire,
        state.plan,
        state.second_hash,
        state.anchor_generation)?
      prepare.accounts ++ settle.accounts
  end
  let combined = Instruction { program_id: c.judge, accounts: accounts, data: Bytes.empty() }
  let candidate = prepare_relay_lookup(config.submitter, combined, state.base.slot)?
  case requested do
    None -> Ok(candidate)
    Some(value) ->
      let observed = read_relay_lookup(webpki_rpc_transport(config.operator.sources)?,
        config.submitter,
        value.creation_slot,
        value.addresses,
        state.base.slot)?
      choose_lookup(config, candidate, value, observed)
  end
end

# A changed candidate is not permission to abandon the owned table. The durable
# journal retires its old recipe before adopting this replacement.
pub fn choose_lookup(config :: RelayConfig,
  candidate :: RelayLookupPlan,
  requested :: LookupRequest,
  observed :: RelayLookupState) -> RelayLookupPlan!String do
  let previous = retained_lookup(config, requested)?
  if observed.address != previous.table
    || observed.authority != config.submitter
    || observed.creation_slot != requested.creation_slot do
    return Err("relay_lookup_observation_binding")
  end
  for key in candidate.addresses do
    if !List.contains(requested.addresses, key) do
      return Ok(candidate)
    end
  end
  let expired_missing = observed.status == "missing"
    && U64.compare(observed.context_slot, requested.creation_slot) > 0
    && U64.compare(U64.subtract(observed.context_slot, requested.creation_slot)?,
      U64.parse("512")?) > 0
  if expired_missing do
    Ok(candidate)
  else
    Ok(previous)
  end
end

fn key(value :: Pubkey) -> String do
  Json.encode_string(pubkey_string(value))
end

pub fn lookup_report(value :: RelayLookupPlan) -> String do
  let extensions = String.join(for ix in value.extend do
      instruction_report_json(ix)
    end,
    ",")
  let addresses = String.join(for address in value.addresses do
      key(address)
    end,
    ",")
  let rents = for index in 0..List.length(value.extend) do
    let count = if (index + 1) * 20 < List.length(value.addresses) do
      (index + 1) * 20
    else
      List.length(value.addresses)
    end
    """{"step":"extend-table/#{index}","address":#{key(value.table)},"space":#{56 + count * 32}}"""
  end
  """{"address":#{key(value.table)},"creation_slot":"#{U64.to_string(value.recent_slot)}","recent_slot":"#{U64.to_string(value.recent_slot)}","addresses":[#{addresses}],"create":#{instruction_report_json(value.create)},"extend":[#{extensions}],"deactivate":#{instruction_report_json(value.deactivate)},"close":#{instruction_report_json(value.close)},"rent_allocations":[{"step":"create-table","address":#{key(value.table)},"space":56}#{if List.length(rents) == 0 do
    ""
  else
    "," <> String.join(rents, ",")
  end}]}"""
end

# Reconstruct a journaled table's lifecycle without current proof eligibility.
# Exact identity/order is validated by the existing lookup reader before writes.
pub fn retained_lookup(config :: RelayConfig,
  requested :: LookupRequest) -> RelayLookupPlan!String do
  let c = config.operator.pins.context
  let metas = for key in requested.addresses do
    if key == config.submitter do
      return Err("relay_lookup_signer")
    end
    from_meta(key)
  end
  let plan = prepare_relay_lookup(config.submitter,
    Instruction { program_id: c.judge, accounts: metas, data: Bytes.empty() },
    requested.creation_slot)?
  if plan.addresses != requested.addresses do
    return Err("relay_lookup_duplicate")
  end
  Ok(plan)
end

fn from_meta(key :: Pubkey) -> AccountMeta do
  AccountMeta { pubkey: key, signer: false, writable: false }
end
