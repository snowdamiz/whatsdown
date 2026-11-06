from Transparency.Rewards import (
  RewardMember,
  RewardAllocation,
  RewardPlan,
  attendance_weight,
  first_year_floor,
  plan_rewards
)
from Transparency.Attendance import AttendanceEpoch, AttendanceRow

fn number(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn key(value :: String) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, 32))
end

fn epoch(posts :: U64, a :: U64, b :: U64, week :: Int) -> AttendanceEpoch!String do
  Ok(AttendanceEpoch {
    log_id: key("09")?,
    epoch: number(week)?,
    posts: posts,
    max_post_slot: number(100)?,
    sealed: true,
    rows: [
      AttendanceRow { witness: key("01")?, signed: a },
      AttendanceRow { witness: key("02")?, signed: b }
    ]
  })
end

fn members() -> List<RewardMember>!String do
  Ok([
    RewardMember {
      witness: key("01")?,
      payout: key("11")?,
      active: true,
      excluded: false,
      bonded_at: number(0)?
    },
    RewardMember {
      witness: key("02")?,
      payout: key("12")?,
      active: true,
      excluded: false,
      bonded_at: number(0)?
    }
  ])
end

fn sum(values :: List<U64>, total :: U64) -> U64!String do
  if List.length(values) == 0 do
    Ok(total)
  else
    sum(List.tail(values), U64.add(total, List.head(values))?)
  end
end

fn proof() -> Bool!String do
  let zero = number(0)?
  assert(U128.to_string(attendance_weight(number(80)?, number(100)?)?) == "0")
  assert(U128.to_string(attendance_weight(number(90)?, number(100)?)?) == "200")
  assert(U128.to_string(attendance_weight(number(95)?, number(100)?)?) == "300")
  assert(U128.to_string(attendance_weight(number(100)?, number(100)?)?) == "300")
  case attendance_weight(number(101)?, number(100)?) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  # Calendar anniversaries from the original start, including leap day and a
  # clipped final week, must add up to exactly twelve monthly base floors.
  let start = DateTime.to_unix_secs(DateTime.from_iso8601("2024-01-31T12:34:56Z")?)
  let end_at = DateTime.to_unix_secs(DateTime.add_months(DateTime.from_unix_secs(start)?, 12)?)
  let weeks = for week in 0..53 do
    let part_start = start + week * 604800
    let to = if part_start + 604800 > end_at do
      end_at
    else
      part_start + 604800
    end
    first_year_floor(start, part_start, to)?
  end
  assert(U64.to_string(sum(weeks, zero)?) == "3600000000")
  assert(first_year_floor(start, end_at, end_at + 604800)? == zero)
  assert(first_year_floor(start, start - 604800, start)? == zero)
  let rows = epoch(number(100)?, number(95)?, number(90)?, 5000)?
  let people = members()?
  let plan = plan_rewards(rows, people, 0, number(100)?, number(999)?)?
  assert(U64.to_string(List.get(plan.rows, 0).amount) == "60")
  assert(U64.to_string(List.get(plan.rows, 1).amount) == "40")
  assert(plan.subsidy_used == zero && plan.carry == zero)
  let first = epoch(number(100)?, number(95)?, number(90)?, 0)?
  let floor = plan_rewards(first, people, 0, number(100000000)?, number(20000000)?)?
  assert(U64.to_string(floor.subsidy_used) == "12903225")
  assert(U64.to_string(List.get(floor.rows, 0).amount) == "67741935")
  assert(U64.to_string(List.get(floor.rows, 1).amount) == "45161290")
  assert(floor.carry == zero)
  case plan_rewards(first, people, 0, number(100000000)?, number(10000000)?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "rewards_floor_underfunded")
  end
  let excluded = [%{List.get(people, 0) | excluded: true}, %{List.get(people, 1) | active: false}]
  let unpaid = plan_rewards(first, excluded, 0, number(99)?, number(999)?)?
  assert(unpaid.carry == number(99)? && unpaid.subsidy_used == zero && unpaid.allocated == zero)
  let empty = %{first | posts: zero, max_post_slot: zero, rows: []}
  let quiet = plan_rewards(empty, [], 0, number(99)?, number(999)?)?
  assert(quiet.carry == number(99)? && quiet.subsidy_used == zero && List.length(quiet.rows) == 0)
  let below = epoch(number(100)?, number(80)?, number(79)?, 0)?
  let absent = plan_rewards(below, people, 0, number(99)?, number(999)?)?
  assert(absent.carry == number(99)? && absent.subsidy_used == zero && absent.allocated == zero)
  let recent = [%{List.get(people, 0) | bonded_at: number(1)?}, List.get(people, 1)]
  let partial = plan_rewards(first, recent, 0, number(100000000)?, zero)?
  assert(List.get(partial.rows, 0).amount == zero
    && List.get(partial.rows, 1).amount == number(100000000)?)
  let maximum = U64.parse("18446744073709551615")?
  let huge = plan_rewards(epoch(maximum, maximum, maximum, 5000)?, people, 0, maximum, zero)?
  assert(U64.to_string(List.get(huge.rows, 0).amount) == "9223372036854775807")
  assert(huge.carry == number(1)?)
  for malformed in [
    %{rows | sealed: false},
    %{rows | rows: [List.get(rows.rows, 1), List.get(rows.rows, 0)]}
  ] do
    case plan_rewards(malformed, people, 0, number(100)?, zero) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  case plan_rewards(rows, [List.get(people, 0)], 0, number(100)?, zero) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  Ok(true)
end

test("rewards use exact weights, scaled calendar floors, explicit subsidies and retained rounding remainder") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
