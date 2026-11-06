from RewardRead import decode_token_reward_snapshot, TokenRewardReadState
from RewardFixture import token_reward_fixture
from RewardKeeper import plan_token_reward_step, plan_token_reward_claim
from Transparency.RewardsWrite import RewardAppendWitness
from Transparency.TokenWrite import (
  token_reward_begin_instruction,
  token_reward_append_instruction,
  token_reward_cancel_instruction,
  token_reward_finalize_instruction,
  token_reward_claim_instruction,
  token_reward_claim_usdc_instruction
)
from Transparency.Merkle import WitnessKey
from Solana.Read import Pubkey, pubkey

fn state(name :: String) -> TokenRewardReadState!String do
  let baseline = token_reward_fixture("token-rewards-finalized")?
  let fixture = token_reward_fixture("token-rewards-" <> name)?
  decode_token_reward_snapshot(baseline.pins,
    fixture.epoch,
    fixture.snapshot.slot,
    fixture.snapshot)
end

fn text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn actual_plan() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_CUSTODY_FIXTURES_PATH", ""))?)?
  let vectors = Json.object_get(root, "write_vectors")?
  let all = Json.object_get(vectors, "cohort")?
  let cohort = for index in 0..Json.array_length(all)? do
    let item = Json.array_get(all, index)?
    RewardAppendWitness {
      witness: pubkey(text(item, "witness")?)?,
      key: WitnessKey {
        witness_id: text(item, "id")?,
        public_key: Bytes.from_hex(text(item, "key_hex")?)?
      }
    }
  end
  let fixture = token_reward_fixture("token-rewards-finalized")?
  let context = fixture.pins.context
  let payer = pubkey(text(vectors, "payer")?)?
  let epoch = fixture.epoch
  let open = plan_token_reward_step(context, payer, epoch, state("open")?, [])?
  assert(open.status == "begin"
    && open.instructions == [token_reward_begin_instruction(context, epoch)?])
  let partial = state("collecting")?
  let batch = List.take(List.drop(cohort, 1), 3)
  let append = plan_token_reward_step(context, payer, epoch, partial, batch)?
  assert(append.status == "append"
    && append.instructions == [token_reward_append_instruction(context, epoch, batch)?])
  assert(Result.is_err(plan_token_reward_step(context, payer, epoch, partial, List.drop(batch, 1))))
  assert(Result.is_err(plan_token_reward_step(context, payer, epoch, partial, List.reverse(batch))))
  assert(Result.is_err(plan_token_reward_step(context,
    payer,
    epoch,
    partial,
    List.take(cohort, 3))))
  for name in ["invalidated", "source-changed", "expired"] do
    let cancel = plan_token_reward_step(context, payer, epoch, state(name)?, [])?
    assert(cancel.status == "cancel"
      && cancel.instructions == [token_reward_cancel_instruction(context, epoch)?])
  end
  let unfunded = plan_token_reward_step(context, payer, epoch, state("floor-unfunded")?, [])?
  assert(unfunded.status == "waiting:token_reserve_cap" && List.length(unfunded.instructions) == 0)
  let stale_floor = plan_token_reward_step(context,
    payer,
    epoch,
    state("stale-floor-unfunded")?,
    [])?
  assert(stale_floor.status == "waiting:token_reserve_unavailable"
    && List.length(stale_floor.instructions) == 0)
  let ready = state("ready")?
  let finalize = plan_token_reward_step(context, payer, epoch, %{ready | twap: None}, [])?
  assert(finalize.status == "finalize"
    && finalize.instructions == [token_reward_finalize_instruction(context, payer, epoch)?])
  let ended = plan_token_reward_step(context, payer, epoch, state("claimed")?, [])?
  assert(ended.status == "complete" && List.length(ended.instructions) == 0)
  let paused = plan_token_reward_step(context, payer, epoch, %{partial | code_current: false}, [])?
  assert(paused.status == "waiting:code-pins" && List.length(paused.instructions) == 0)
  let source = plan_token_reward_step(context,
    payer,
    epoch,
    %{state("open")? | source_current: false},
    [])?
  assert(source.status == "waiting:source-pins" && List.length(source.instructions) == 0)
  assert(Result.is_err(plan_token_reward_step(%{context | program: payer},
    payer,
    epoch,
    partial,
    batch)))
  let earned = %{state("finalized")? | source_current: false, revision_matches: false, twap: None}
  let morse_claim = plan_token_reward_claim(context, payer, epoch, earned, 63, 1)?
  assert(morse_claim.status == "claim-morse" && List.length(morse_claim.instructions) == 2)
  let earned_record = case earned.record do
    None -> return Err("missing_record")
    Some(value) -> value
  end
  assert(List.get(morse_claim.instructions, 1) == token_reward_claim_instruction(context,
      earned_record,
      63)?)
  let dollar_claim = plan_token_reward_claim(context, payer, epoch, earned, 63, 0)?
  assert(dollar_claim.status == "claim-usdc"
    && List.length(dollar_claim.instructions) == 2
    && List.get(dollar_claim.instructions, 1) == token_reward_claim_usdc_instruction(context,
        earned_record,
        63)?)
  assert(Result.is_err(plan_token_reward_claim(context, payer, epoch, earned, 64, 1)))
  assert(Result.is_err(plan_token_reward_claim(context, payer, epoch, earned, 63, 2)))
  assert(Result.is_err(plan_token_reward_claim(context, payer, epoch, state("claimed")?, 63, 1)))
  IO.eprintln("MORSE_TOKEN_REWARD_KEEPER begin_orderedAppend_cancel_cap_topup_finalize_complete")
  Ok(true)
end

test("bounded v2 keeper plans only the next authenticated stage without omitting zero-weight rows") do
  let result = actual_plan()
  case result do
    Err(error) -> IO.eprintln("MORSE_TOKEN_KEEPER_PLAN_ERROR " <> error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
