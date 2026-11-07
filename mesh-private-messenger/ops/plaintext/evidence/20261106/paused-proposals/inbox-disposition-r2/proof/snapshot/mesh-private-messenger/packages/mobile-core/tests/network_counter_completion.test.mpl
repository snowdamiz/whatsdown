from Mobile.NetworkCounter import finish_network_counter

# Public synthetic framing only: this is not a chain/RPC authentication fixture.
fn frame(status :: String, checked :: String, bank :: String) -> Bytes do
  Bytes.from_utf8("NCR1{\"schema_version\":1,\"status\":\""
    <> status
    <> "\",\"reason\":\"fixture\",\"config_id\":\""
    <> String.repeat("ab", 32)
    <> "\",\"checked_at\":\""
    <> checked
    <> "\",\"slash_mask\":1,\"slash_history\":[{\"index\":0,\"context_slot\":\"123\"}],\"observation\":{\"bank_time\":\""
    <> bank
    <> "\",\"service_slashed\":true,\"rows\":[{\"private_fixture_marker\":\"preserved\"}]}}")
end

fn field(wire :: Bytes, name :: String) -> String!String do
  let value = Json.parse(Bytes.to_utf8(Bytes.slice(wire, 4, Bytes.length(wire) - 4)?)?)?
  Json.as_string(Json.object_get(value, name)?)
end

fn body(wire :: Bytes, name :: String) -> String!String do
  let value = Json.parse(Bytes.to_utf8(Bytes.slice(wire, 4, Bytes.length(wire) - 4)?)?)?
  Ok(Json.encode(Json.object_get(value, name)?))
end

fn scenario_0() -> Bool!String do
  let original = frame("available", "200000", "100")
  assert(finish_network_counter(original,
    U64.parse("200000")?,
    U64.parse("220999")?) == Ok(original))
  let old = finish_network_counter(original, U64.parse("200000")?, U64.parse("221000")?)?
  assert(field(old, "status")? == "historical")
  assert(field(old, "reason")? == "counter-stale-completion")
  assert(body(old, "observation")? == body(original, "observation")?)
  assert(body(old, "slash_history")? == body(original, "slash_history")?)
  assert(body(old, "slash_mask")? == body(original, "slash_mask")?)
  Ok(true)
end

test("completion expires at the exact inclusive120-second boundary and retains observation/slash evidence") do
  case scenario_0() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn scenario_1() -> Bool!String do
  let cached = frame("available", "202000", "100")
  let old = finish_network_counter(cached, U64.parse("205000")?, U64.parse("203000")?)?
  assert(field(old, "status")? == "historical")
  assert(field(old, "reason")? == "clock-rollback")
  assert(body(old, "observation")? == body(cached, "observation")?)
  let zero = finish_network_counter(cached, U64.parse("205000")?, U64.parse("0")?)?
  assert(field(zero, "status")? == "historical")
  Ok(true)
end

test("completion rollback compares actual start even when cached checked_at is older") do
  case scenario_1() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn scenario_2() -> Bool!String do
  let zero = U64.parse("0")?
  for status in ["historical", "unavailable", "unconfigured"] do
    let previous = frame(status, "202000", "100")
    assert(finish_network_counter(previous, U64.parse("205000")?, zero) == Ok(previous))
  end
  assert(field(finish_network_counter(frame("available", "200000", "100"),
      U64.parse("200000")?,
      U64.parse("18446744073709551615")?)?,
    "status")? == "historical")
  assert(Result.is_err(finish_network_counter(Bytes.from_utf8("NCR1{"), zero, zero)))
  assert(Result.is_err(finish_network_counter(frame("available", "x", "100"), zero, zero)))
  assert(Result.is_err(finish_network_counter(frame("available", "0", "18446744073709551616"),
    zero,
    zero)))
  Ok(true)
end

test("completion never promotes historical/failure outcomes and handles malformed/full-width times") do
  case scenario_2() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
