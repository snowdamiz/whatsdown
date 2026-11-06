from Command import parse_command

test("cutover commands require an explicit bounded action") do
  assert(parse_command([
    "cutover"
  ]) == Err("usage: transparency-cutover status|prepare|accept|resume [1..100]"))
  assert(parse_command(["cutover", "status"]) == Ok(("status", 100)))
  assert(parse_command(["cutover", "prepare"]) == Ok(("prepare", 100)))
  assert(parse_command(["cutover", "accept"]) == Ok(("accept", 100)))
  assert(parse_command(["cutover", "resume"]) == Ok(("resume", 100)))
  assert(parse_command(["cutover", "resume", "1"]) == Ok(("resume", 1)))
  assert(parse_command(["cutover", "resume", "100"]) == Ok(("resume", 100)))
  for args in [
    ["cutover", "rollback"],
    ["cutover", "status", "1"],
    ["cutover", "resume", "0"],
    ["cutover", "resume", "101"],
    ["cutover", "resume", "01"],
    ["cutover", "resume", "1", "2"]
  ] do
    case parse_command(args) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
end
