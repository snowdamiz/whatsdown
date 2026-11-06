from BurnCarryFixture import token_burn_carry_fixture
from Transparency.TokenBurnCarryRead import (
  decode_token_burn_carry_snapshot,
  plan_token_burn_carry_close
)
from Transparency.TokenBurnCarryWrite import token_burn_close_instruction
from Solana.Read import AccountSlice, OptionalAccountSlicesAtSlot

fn replace(snapshot :: OptionalAccountSlicesAtSlot,
  at :: Int,
  value :: Option<AccountSlice>) -> OptionalAccountSlicesAtSlot do
  %{snapshot |
    accounts: for index in 0..List.length(snapshot.accounts) do
      if index == at do
        value
      else
        List.get(snapshot.accounts, index)
      end
    end
  }
end

fn selected(snapshot :: OptionalAccountSlicesAtSlot, at :: Int) -> AccountSlice!String do
  case List.get(snapshot.accounts, at) do
    None -> Err("missing_fixture_account")
    Some(value) -> Ok(value)
  end
end

fn actual_read() -> Bool!String do
  for name in [
    "legacy-partial",
    "legacy-closed",
    "mixed-funded",
    "mixed-executed",
    "mixed-closed",
    "all-missed-closed",
    "carry-only-funded"
  ] do
    let f = token_burn_carry_fixture(name)?
    let state = decode_token_burn_carry_snapshot(f.pins, f.epoch, f.snapshot.slot, f.snapshot)?
    assert(state.context_slot == f.snapshot.slot && state.code_current)
    let closed = String.ends_with(name, "closed")
    let frame = case state.frame do
      None -> return Err("missing_fixture_frame")
      Some(value) -> value
    end
    assert(frame.closed == closed)
    let plan = plan_token_burn_carry_close(f.pins, f.pins.governance, state)?
    if closed do
      assert(plan.status == "complete" && List.length(plan.instructions) == 0)
    else if name == "legacy-partial" do
      assert(plan.status == "close"
        && plan.instructions == [
            token_burn_close_instruction(f.pins.program, f.pins.governance, state.profile, f.epoch)?
          ])
    else
      assert(plan.status == "waiting:week" && List.length(plan.instructions) == 0)
    end
    let paused = plan_token_burn_carry_close(f.pins,
      f.pins.governance,
      %{state | code_current: false})?
    assert(paused.status == "paused:code" && List.length(paused.instructions) == 0)
    if closed do
      assert(state.remaining == U64.parse("0")? && state.receipt != None)
      assert(state.week_surplus == (if name == "legacy-closed" do
          U64.parse("17")?
        else if name == "mixed-closed" do
          U64.parse("23")?
        else
          U64.parse("0")?
        end))
    else
      assert(state.remaining == U64.subtract(frame.week.budget, frame.week.spent)?)
    end
    assert(state.carry_surplus == U64.parse("19")?)
    assert(Result.is_err(decode_token_burn_carry_snapshot(f.pins,
      f.epoch,
      U64.add(f.snapshot.slot, U64.parse("1")?)?,
      f.snapshot)))
    for index in [0, 1, 2, 3, 4, 5, 6, 10, 11] do
      assert(Result.is_err(decode_token_burn_carry_snapshot(f.pins,
        f.epoch,
        f.snapshot.slot,
        replace(f.snapshot, index, None))))
      let account = selected(f.snapshot, index)?
      let wrong = %{account | info: %{account.info | owner: f.pins.treasury}}
      assert(Result.is_err(decode_token_burn_carry_snapshot(f.pins,
        f.epoch,
        f.snapshot.slot,
        replace(f.snapshot, index, Some(wrong)))))
    end
    if closed do
      assert(Result.is_err(decode_token_burn_carry_snapshot(f.pins,
        f.epoch,
        f.snapshot.slot,
        replace(f.snapshot, 9, None))))
    end
    let code = selected(f.snapshot, 11)?
    let upgraded = %{code |
      info: %{code.info |
        data: Bytes.concat(Bytes.concat(Bytes.slice(code.info.data, 0, 4)?,
            Bytes.write_uint_le("1", 8)?)?,
          Bytes.slice(code.info.data, 12, Bytes.length(code.info.data) - 12)?)?
      }
    }
    assert(!decode_token_burn_carry_snapshot(f.pins,
      f.epoch,
      f.snapshot.slot,
      replace(f.snapshot, 11, Some(upgraded)))?.code_current)
    assert(Result.is_err(decode_token_burn_carry_snapshot(%{f.pins | treasury: f.pins.governance},
      f.epoch,
      f.snapshot.slot,
      f.snapshot)))
  end
  IO.eprintln("MORSE_TOKEN_BURN_CARRY_READER custody_only_actual_12_roles_exact_liabilities_and_donation_surplus")
  Ok(true)
end

test("finalized carry custody authentication survives unavailable markets without inventing surplus") do
  if Env.get("MORSE_TOKEN_CARRY_FIXTURES_PATH", "") == "" do
    assert(true)
  else
    let result = actual_read()
    case result do
      Err(error) -> IO.eprintln(error)
      Ok(_) -> nil
    end
    assert(result == Ok(true))
  end
end
