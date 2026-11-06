from Transparency.Rewards import first_year_floor

# These are the same Python exact-integer/calendar CSVs consumed by the
# dependency-free Rust arithmetic crate. Run with run-rewards-vectors.sh from
# any directory, or set MORSE_REWARD_MATH_FIXTURES_PATH explicitly.
fn discover_fixture(roots :: List<String>, name :: String) -> String!String do
  if List.length(roots) == 0 do
    Err("reward math fixtures not found; set MORSE_REWARD_MATH_FIXTURES_PATH")
  else
    case File.read(List.head(roots) <> "/tests/fixtures/" <> name) do
      Ok(contents)
      Err(_) -> discover_fixture(List.tail(roots), name)
    end
  end
end

fn fixture(name :: String) -> List<String>!String do
  let root = Env.get("MORSE_REWARD_MATH_FIXTURES_PATH", "")
  let contents = if root != "" do
    File.read(root <> "/" <> name)?
  else
    # Product, protocol package, repository root, CI's mesh-lang sibling,
    # and this development checkout's mesh-lang sibling, respectively.
    discover_fixture([
        "programs/morse-rewards-math",
        "../../programs/morse-rewards-math",
        "mesh-private-messenger/programs/morse-rewards-math",
        "../mesh-private-messenger/programs/morse-rewards-math",
        "../whatsdown/mesh-private-messenger/programs/morse-rewards-math"
      ],
      name)?
  end
  Ok(String.split(String.trim(contents), "\n"))
end

fn timestamp(value :: String) -> Int!String do
  U64.to_int(U64.parse(value)?)
end

fn calendar_vectors() -> Bool!String do
  let lines = fixture("calendar_floor.csv")?
  assert(List.length(lines) == 694)
  assert(List.head(lines) == "case,network_started,interval_start,interval_end,result")
  for index in 1..List.length(lines) do
    let columns = String.split(List.get(lines, index), ",")
    assert(List.length(columns) == 5)
    let label = List.get(columns, 0)
    let actual = U64.to_string(first_year_floor(timestamp(List.get(columns, 1))?,
      timestamp(List.get(columns, 2))?,
      timestamp(List.get(columns, 3))?)?)
    let expected = List.get(columns, 4)
    if actual != expected do
      return Err("calendar vector #{label}: expected #{expected}, got #{actual}")
    end
  end
  # The final full anniversary year supported by chrono/DateTime, including
  # its last second, must agree with the Rust calendar implementation.
  assert(U64.to_string(first_year_floor(8210235340799,
    8210235340799,
    8210266876799)?) == "3600000000")
  case first_year_floor(8210235340800, 0, 1) do
    Ok(_) -> return Err("calendar accepted an unrepresentable twelfth anniversary")
    Err(error) -> assert(error == "calendar month arithmetic out of range")
  end
  case first_year_floor(8210266876800, 0, 1) do
    Ok(_) -> return Err("calendar accepted an unrepresentable launch date")
    Err(error) -> assert(error == "unix timestamp out of range")
  end
  println("matched 693 Rust/Python calendar vectors and 3 chrono limits")
  Ok(true)
end

fn arithmetic128(a :: String,
  b :: String,
  divisor :: String,
  expected :: String,
  index :: Int) -> Bool!String do
  case U128.multiply_divide(U128.parse(a)?, U128.parse(b)?, U128.parse(divisor)?) do
    Ok(value) -> do
      let actual = U128.to_string(value)
      if actual != expected do
        return Err("u128 vector #{index}: expected #{expected}, got #{actual}")
      end
    end
    Err(error) -> do
      let expected_error = if expected == "division_by_zero" do
        "u128 multiply_divide division by zero"
      else if expected == "overflow" do
        "u128 multiply_divide quotient overflow"
      else
        "unexpected error"
      end
      if error != expected_error do
        return Err("u128 vector #{index}: expected #{expected}, got #{error}")
      end
    end
  end
  Ok(true)
end

# A row is applicable to U64 only when all three inputs fit. Parse decimal
# strings directly into the opaque integer types, never through signed Int.
fn arithmetic64(a :: String,
  b :: String,
  divisor :: String,
  expected :: String,
  index :: Int) -> Bool!String do
  let left = case U64.parse(a) do
    Err(_) -> return Ok(false)
    Ok(value) -> value
  end
  let right = case U64.parse(b) do
    Err(_) -> return Ok(false)
    Ok(value) -> value
  end
  let denominator = case U64.parse(divisor) do
    Err(_) -> return Ok(false)
    Ok(value) -> value
  end
  let expected_error = if expected == "division_by_zero" do
    "u64 multiply_divide division by zero"
  else
    "u64 multiply_divide quotient overflow"
  end
  case U64.multiply_divide(left, right, denominator) do
    Ok(value) -> do
      let actual = U64.to_string(value)
      if actual != expected do
        return Err("u64 vector #{index}: expected #{expected}, got #{actual}")
      end
    end
    Err(error) -> do
      case U64.parse(expected) do
        Ok(_) -> return Err("u64 vector #{index}: unexpected #{error}")
        Err(_) -> if error != expected_error do
          return Err("u64 vector #{index}: expected #{expected_error}, got #{error}")
        end
      end
    end
  end
  Ok(true)
end

fn arithmetic_vectors() -> Bool!String do
  let lines = fixture("multiply_divide.csv")?
  assert(List.length(lines) == 577)
  assert(List.head(lines) == "a,b,divisor,result")
  let applicable64 = for index in 1..List.length(lines) do
    let columns = String.split(List.get(lines, index), ",")
    assert(List.length(columns) == 4)
    let a = List.get(columns, 0)
    let b = List.get(columns, 1)
    let divisor = List.get(columns, 2)
    let expected = List.get(columns, 3)
    arithmetic128(a, b, divisor, expected, index)?
    arithmetic128(b, a, divisor, expected, index)?
    arithmetic64(a, b, divisor, expected, index)?
  end
  assert(List.length(List.filter(applicable64, fn(value) -> value end)) == 48)
  println("matched 576 Rust/Python u128 vectors in both orders and 48 applicable u64 vectors")
  Ok(true)
end

test("Mesh calendar floors match the independent Rust/Python corpus") do
  case calendar_vectors() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("Mesh exact multiply/divide matches the independent Rust/Python corpus") do
  case arithmetic_vectors() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
