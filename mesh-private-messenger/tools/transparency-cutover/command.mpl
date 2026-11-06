fn usage() -> String do
  "usage: transparency-cutover status|prepare|accept|resume [1..100]"
end

pub fn parse_command(args :: List<String>) -> (String, Int)!String do
  if List.length(args) < 2 || List.length(args) > 3 do
    return Err(usage())
  end
  let action = List.get(args, 1)
  if action != "status" && action != "prepare" && action != "accept" && action != "resume" do
    return Err(usage())
  end
  if List.length(args) == 2 do
    return Ok((action, 100))
  end
  let limit = case String.to_int(List.get(args, 2)) do
    None -> return Err(usage())
    Some(value) -> value
  end
  if action != "resume" || limit < 1 || limit > 100 || Int.to_string(limit) != List.get(args, 2) do
    Err(usage())
  else
    Ok((action, limit))
  end
end
