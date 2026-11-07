from Protocol.Capabilities import supports_ach3

fn capability_vectors() -> Bool!String do
  let clear = ["0", "1", "4", "5", "4294967293", "18446744073709551613"]
  let set = ["2", "3", "6", "7", "4294967295", "18446744073709551615"]
  for value in clear do
    assert(!supports_ach3(U64.parse(value)?))
  end
  for value in set do
    assert(supports_ach3(U64.parse(value)?))
  end
  Ok(true)
end

test("ACH3 support tests only mask2 and preserves full unsigned precision") do
  case capability_vectors() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
