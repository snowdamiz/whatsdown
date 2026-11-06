from Policy import split_pre_token_credit_revenue

fn proof() -> Bool!String do
  let initial = split_pre_token_credit_revenue(0, U64.parse("25000001")?, 0)?
  assert(initial.asset == 0 && initial.witness == U64.parse("5000000")?)
  assert(initial.operations == U64.parse("20000001")? && initial.fifths_carry == 1)
  let next = split_pre_token_credit_revenue(0, U64.parse("4")?, initial.fifths_carry)?
  assert(next.witness == U64.parse("1")?
    && next.operations == U64.parse("3")?
    && next.fifths_carry == 0)
  let large = split_pre_token_credit_revenue(1, U64.parse("9007199254740993")?, 0)?
  assert(large.asset == 1 && large.witness == U64.parse("1801439850948198")?)
  assert(large.operations == U64.parse("7205759403792795")? && large.fifths_carry == 3)
  let max = split_pre_token_credit_revenue(0, U64.parse("18446744073709551615")?, 4)?
  assert(max.witness == U64.parse("3689348814741910323")?)
  assert(max.operations == U64.parse("14757395258967641292")? && max.fifths_carry == 4)
  let crossing = split_pre_token_credit_revenue(1, U64.parse("1")?, 4)?
  assert(crossing.witness == U64.parse("1")?
    && crossing.operations == U64.parse("0")?
    && crossing.fifths_carry == 0)
  let empty = split_pre_token_credit_revenue(1, U64.parse("0")?, 4)?
  assert(empty.witness == U64.parse("0")?
    && empty.operations == U64.parse("0")?
    && empty.fifths_carry == 4)
  assert(Result.is_err(split_pre_token_credit_revenue(2, U64.parse("1")?, 0)))
  assert(Result.is_err(split_pre_token_credit_revenue(0, U64.parse("1")?, -1)))
  assert(Result.is_err(split_pre_token_credit_revenue(0, U64.parse("1")?, 5)))
  let chunks = ["1", "2", "4", "9", "10"]
  let first = split_pre_token_credit_revenue(0, U64.parse(List.get(chunks, 0))?, 0)?
  let second = split_pre_token_credit_revenue(0,
    U64.parse(List.get(chunks, 1))?,
    first.fifths_carry)?
  let third = split_pre_token_credit_revenue(0,
    U64.parse(List.get(chunks, 2))?,
    second.fifths_carry)?
  let fourth = split_pre_token_credit_revenue(0,
    U64.parse(List.get(chunks, 3))?,
    third.fifths_carry)?
  let fifth = split_pre_token_credit_revenue(0,
    U64.parse(List.get(chunks, 4))?,
    fourth.fifths_carry)?
  let combined = split_pre_token_credit_revenue(0, U64.parse("26")?, 0)?
  assert(U64.add(U64.add(U64.add(U64.add(first.witness, second.witness)?, third.witness)?,
      fourth.witness)?,
    fifth.witness)? == combined.witness)
  assert(fifth.fifths_carry == combined.fifths_carry)
  Ok(true)
end

test("pre-token 20 percent allocation conserves integer units and carries fifths per asset") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
