from RewardsPolicy import TokenFloorInput, plan_token_floor

fn unit(value :: String) -> U64!String do
  U64.parse(value)
end

fn input(weight :: String, floor :: String) -> TokenFloorInput!String do
  Ok(TokenFloorInput { weight: U128.parse(weight)?, floor: unit(floor)? })
end

fn floor_conservation() -> Bool!String do
  let cohort = [input("1", "100")?, input("3", "200")?, input("0", "0")?]
  let plan = plan_token_floor(unit("151")?, unit("0")?, cohort, unit("2000000")?, unit("75")?)?
  assert(plan.required == unit("300")? && plan.floor_shortfall == unit("149")?)
  assert(plan.usd_allocated == unit("151")?
    && plan.morse_allocated == unit("75")?
    && plan.carry == unit("0")?)
  assert(List.get(plan.rows, 0).usd == unit("50")? && List.get(plan.rows, 0).morse == unit("25")?)
  assert(List.get(plan.rows, 1).usd == unit("101")? && List.get(plan.rows, 1).morse == unit("50")?)
  assert(List.get(plan.rows, 2).usd == unit("0")? && List.get(plan.rows, 2).morse == unit("0")?)
  assert(Result.is_err(plan_token_floor(unit("151")?,
    unit("0")?,
    cohort,
    unit("2000000")?,
    unit("74")?)))
  assert(Result.is_err(plan_token_floor(unit("151")?, unit("0")?, cohort, unit("0")?, unit("75")?)))
  let cap = unit("500000000000")?
  assert(plan_token_floor(unit("0")?,
    unit("0")?,
    [input("1", "500000")?],
    unit("1")?,
    cap)?.morse_allocated == cap)
  assert(Result.is_err(plan_token_floor(unit("0")?,
    unit("0")?,
    [input("1", "500001")?],
    unit("1")?,
    unit("1000000000000000")?)))
  let topped = plan_token_floor(unit("0")?, unit("1")?, [input("1", "500001")?], unit("1")?, cap)?
  assert(topped.subsidy_used == unit("1")? && topped.morse_allocated == cap)
  let funded = plan_token_floor(unit("1000")?,
    unit("999")?,
    [input("1", "40")?, input("2", "60")?],
    unit("0")?,
    unit("0")?)?
  assert(funded.subsidy_used == unit("0")?
    && funded.morse_allocated == unit("0")?
    && funded.carry == unit("0")?)
  assert(List.get(funded.rows, 0).usd == unit("340")?
    && List.get(funded.rows, 1).usd == unit("660")?)
  let dust = plan_token_floor(unit("10")?,
    unit("0")?,
    [input("1", "0")?, input("1", "0")?, input("1", "0")?],
    unit("0")?,
    unit("0")?)?
  assert(dust.usd_allocated == unit("9")?
    && dust.carry == unit("1")?
    && dust.morse_allocated == unit("0")?)
  let maximum = unit("18446744073709551615")?
  let nobody = plan_token_floor(maximum, maximum, [input("0", "0")?], unit("0")?, unit("0")?)?
  assert(nobody.carry == maximum
    && nobody.subsidy_used == unit("0")?
    && nobody.morse_allocated == unit("0")?)
  let wide = plan_token_floor(maximum,
    unit("0")?,
    [input("340282366920938463463374607431768211455", "1")?],
    unit("0")?,
    unit("0")?)?
  assert(wide.usd_allocated == maximum && wide.carry == unit("0")?)
  assert(Result.is_err(plan_token_floor(unit("10")?,
    unit("0")?,
    [input("0", "1")?],
    unit("1")?,
    cap)))
  assert(Result.is_err(plan_token_floor(unit("10")?,
    unit("0")?,
    [input("1", "18446744073709551615")?, input("1", "1")?],
    unit("1")?,
    cap)))
  Ok(true)
end

test("USDC floors consume exact available money before capped MORSE shortfall with conserved dust") do
  assert(floor_conservation() == Ok(true))
end
