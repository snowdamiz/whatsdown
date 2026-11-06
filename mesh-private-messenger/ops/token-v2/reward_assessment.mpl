##! Continuous bounded permissionless maintenance for the current settlement.
from RewardRead import TokenRewardReadPins, TokenRewardReadState
from RewardIdentities import read_token_reward_identities_quorum
from Read import CollateralOperatorPins, CollateralOperatorState
from AssessmentRead import read_collateral_assessment_group
from Plan import CollateralOperation, plan_collateral_operation, collateral_grace_update_needed
from Transparency.TokenCollateralWrite import (
  TokenCollateralContext,
  TokenCollateralSubject,
  token_collateral_assess_instruction
)
from Transparency.Merkle import WitnessKey
from Solana.Read import Pubkey
from Solana.Tx import Instruction, instruction_report_json

pub struct RewardAssessment do
  slot :: U64
  instructions :: List<Instruction>
  evidence :: String
end

fn collateral_pins(p :: TokenRewardReadPins) -> CollateralOperatorPins do
  CollateralOperatorPins {
    context: TokenCollateralContext {
      judge: p.context.judge,
      token: p.context.token,
      rewards: p.context.program,
      log_name: p.context.log_name,
      usdc_mint: p.context.usdc_mint
    },
    governance: p.governance,
    token_governance: p.token_governance,
    service_key: p.service_key,
    log_version: p.log_version,
    network_started: p.network_started,
    judge_slot: p.judge_slot,
    token_slot: p.token_slot,
    rewards_slot: p.rewards_slot,
    source_program: p.source_program,
    source: p.source,
    feed: p.feed,
    source_revision: p.source_revision
  }
end

fn lifetime(s :: CollateralOperatorState) -> String!String do
  let b = case s.bond do
    None -> return Err("rewards_assessment_bond_missing")
    Some(v) -> v
  end
  let p = case s.pending do
    None -> return Err("rewards_assessment_pending_missing")
    Some(v) -> v
  end
  Ok(Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(String.join([
      Bytes.to_hex(b.log_id),
      Bytes.to_hex(b.witness_address),
      Bytes.to_hex(b.owner),
      Bytes.to_hex(b.mint),
      Bytes.to_hex(b.vault),
      U64.to_string(b.bonded_at),
      U64.to_string(b.principal),
      U64.to_string(p.target_usd),
      Int.to_string(b.status),
      Int.to_string(b.asset)
    ],
    "\n")))))
end

fn evidence(subject :: TokenCollateralSubject,
  state :: CollateralOperatorState,
  next_cursor :: Int) -> String!String do
  let b = case state.bond do
    None -> return Err("rewards_assessment_bond_missing")
    Some(v) -> v
  end
  let identity = case subject do
    CollateralDirectory -> "null"
    CollateralWitness(key) -> """{"witness_id":#{Json.encode_string(key.witness_id)},"public_key":"#{Bytes.to_hex(key.public_key)}"}"""
  end
  Ok(""",\"assessment\":{\"subject\":#{identity},\"lifetime\":\"#{lifetime(state)?}\",\"next_cursor\":\"#{Int.to_string(next_cursor)}\",\"before\":\"#{U64.to_string(b.underwater_since)}\",\"at\":\"#{U64.to_string(state.timestamp)}\"}""")
end

fn scan_assessments(client :: Int,
  urls :: List<String>,
  test_mode :: Bool,
  pins :: TokenRewardReadPins,
  payer :: Pubkey,
  state :: TokenRewardReadState,
  subjects :: List<TokenCollateralSubject>,
  start :: Int,
  cursor :: Int,
  minimum :: U64) -> RewardAssessment!String do
  if start >= List.length(subjects) do
    return Ok(RewardAssessment { slot: minimum, instructions: [], evidence: "" })
  end
  let p = collateral_pins(pins)
  let stop = if start + 14 < List.length(subjects) do
    start + 14
  else
    List.length(subjects)
  end
  let selected = for at in start..stop do
    List.get(subjects, at)
  end
  let states = read_collateral_assessment_group(client,
    urls,
    p,
    selected,
    payer,
    minimum,
    test_mode)?
  for at in 0..List.length(states) do
    let s = List.get(states, at)
    if s.economics.revision != state.economics.revision
      || s.pool.next_epoch != state.pool.next_epoch
      || s.pool.active_epoch != state.pool.active_epoch do
      return Err("rewards_assessment_snapshot_changed")
    end
    if !s.oracle_current || !s.binding_current || !s.binding_release_current do
      return Err("rewards_assessment_pins_changed")
    end
    if collateral_grace_update_needed(s)? do
      let b = case s.bond do
        None -> return Err("rewards_assessment_bond_missing")
        Some(v) -> v
      end
      let subject = List.get(selected, at)
      let plan = plan_collateral_operation(p,
        CollateralOperation {
          tag: 45,
          fee_payer: payer,
          operator: payer,
          subject: subject,
          asset: b.asset,
          amount: U64.parse("0")?,
          witness_minimum: U64.parse("0")?,
          directory_minimum: U64.parse("0")?
        },
        s)?
      if plan.state != "ready" do
        return Err("rewards_assessment_not_ready")
      end
      return Ok(RewardAssessment {
        slot: s.slot,
        instructions: plan.instructions,
        evidence: evidence(subject, s, (cursor + start + at + 1) % List.length(subjects))?
      })
    end
  end
  scan_assessments(client,
    urls,
    test_mode,
    pins,
    payer,
    state,
    subjects,
    stop,
    cursor,
    List.head(states).slot)
end

# Every invocation scans directory plus all (at most 64) attendance witnesses,
# including rows already appended. At most five groups of fourteen subjects,
# each <=100 accounts, plus one immutable identity batch. No offchain eligibility
# verdict is signed; the canonical Judge instruction checks its current bank.
pub fn plan_reward_assessment(client :: Int,
  urls :: List<String>,
  test_mode :: Bool,
  pins :: TokenRewardReadPins,
  payer :: Pubkey,
  cursor :: Int,
  state :: TokenRewardReadState) -> RewardAssessment!String do
  let keys = case state.attendance do
    None -> []
    Some(week) -> for row in week.rows do
      Pubkey { bytes: row.witness }
    end
  end
  let identities = if List.length(keys) == 0 do
    []
  else
    read_token_reward_identities_quorum(client, urls, test_mode, pins.context, state, keys)?
  end
  let subjects = [CollateralDirectory]
    ++ (for row in identities do
      CollateralWitness(row.key)
    end)
  if cursor < 0 || cursor > 64 do
    return Err("rewards_assessment_cursor")
  end
  let offset = cursor % List.length(subjects)
  let ordered = for at in 0..List.length(subjects) do
    List.get(subjects, (offset + at) % List.length(subjects))
  end
  scan_assessments(client,
    urls,
    test_mode,
    pins,
    payer,
    state,
    ordered,
    0,
    offset,
    state.context_slot)
end

# Mutable assessment evidence is bound to the selected subject's bond lifetime,
# principal and recorded target. An unrelated eligibility revision is no proof.
pub fn read_reward_assessment_effect(client :: Int,
  urls :: List<String>,
  test_mode :: Bool,
  pins :: TokenRewardReadPins,
  payer :: Pubkey,
  previous :: Json,
  minimum :: U64) -> (Bool, U64)!String do
  let proof = Json.object_get(previous, "assessment")?
  let raw = Json.object_get(proof, "subject")?
  let subject = if Json.encode(raw) == "null" do
    CollateralDirectory
  else
    CollateralWitness(WitnessKey {
      witness_id: Json.as_string(Json.object_get(raw, "witness_id")?)?,
      public_key: Bytes.from_hex(Json.as_string(Json.object_get(raw, "public_key")?)?)?
    })
  end
  let states = read_collateral_assessment_group(client,
    urls,
    collateral_pins(pins),
    [subject],
    payer,
    minimum,
    test_mode)?
  let s = List.head(states)
  if !s.oracle_current || !s.binding_current || !s.binding_release_current do
    return Err("rewards_assessment_effect_pins_changed")
  end
  let expected = Json.as_string(Json.object_get(proof, "lifetime")?)?
  let b = case s.bond do
    None -> return Ok((false, s.slot))
    Some(v) -> v
  end
  if expected != lifetime(s)? do
    return Ok((false, s.slot))
  end
  let instructions = Json.object_get(previous, "instructions")?
  let encoded = Json.array_get(instructions, Json.array_length(instructions)? - 1)?
  let canonical = Json.parse(instruction_report_json(token_collateral_assess_instruction(collateral_pins(pins).context,
    subject,
    b.asset)?))?
  for field in ["programId", "accountKeys", "signerKeys", "writableKeys", "dataBase64"] do
    if Json.encode(Json.object_get(encoded, field)?) != Json.encode(Json.object_get(canonical,
        field)?) do
      return Err("rewards_assessment_effect_instruction")
    end
  end
  let before = U64.parse(Json.as_string(Json.object_get(proof, "before")?)?)?
  let at = U64.parse(Json.as_string(Json.object_get(proof, "at")?)?)?
  Ok((if before == U64.parse("0")? do
      b.underwater_since != before && U64.compare(b.underwater_since, at) >= 0
    else
      b.underwater_since == U64.parse("0")?
    end,
    s.slot))
end
