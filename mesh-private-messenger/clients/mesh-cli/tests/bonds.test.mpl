from Client.Bonds import parse_bonds_command

test("bond reads require an explicit unambiguous log and never default to main or canary") do
  assert(parse_bonds_command(["morse", "bonds", "--log", "morse-main"]) == Ok("morse-main"))
  assert(parse_bonds_command(["morse", "bonds", "--log", "morse-canary"]) == Ok("morse-canary"))
  for args in [
    ["morse", "bonds"],
    ["morse", "bonds", "--log", "Morse-main"],
    ["morse", "bonds", "--log", "morse-main", "--log", "morse-canary"],
    ["morse", "monitor", "--log", "morse-main"],
    ["morse", "bonds", "--log", String.repeat("a", 33)]
  ] do
    case parse_bonds_command(args) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
end
