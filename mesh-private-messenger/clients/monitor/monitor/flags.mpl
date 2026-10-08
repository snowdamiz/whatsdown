##! morse-monitor's flags (clients/monitor/README.md lists them). Anything the
##! flags leave out that a supported security config pins (the anchor pair,
##! RPC URLs, relays) is taken from the first config that sets it.

from Security.Config import SecurityConfig, security_config_parse

pub struct MonitorConfig do
  log_name :: String
  directory :: String
  judge :: String
  log_account :: String
  rpc_urls :: List<String>
  sets :: List<SecurityConfig>
  relays :: List<String>
  state_path :: String
  listen :: Int
  interval_ms :: Int
  finder :: Bytes
  once :: Bool
end

struct Flag do
  name :: String
  value :: String
end

fn flags(args :: List<String>, output :: List<Flag>) -> List<Flag>!String do
  case args do
    [] -> Ok(output)
    "--once" :: rest -> flags(rest, List.append(output, Flag { name: "once", value: "1" }))
    name :: rest -> if !String.starts_with(name, "--") do
      Err("unexpected argument #{name}")
    else
      case rest do
        [] -> Err("#{name} needs a value")
        value :: tail -> flags(tail,
          List.append(output,
            Flag { name: String.slice(name, 2, String.length(name)), value: value }))
      end
    end
  end
end

fn all(values :: List<Flag>, name :: String) -> List<String> do
  for flag in values when flag.name == name do
    flag.value
  end
end

fn one(values :: List<Flag>, name :: String, fallback :: String) -> String do
  let given = all(values, name)
  if List.length(given) == 0 do
    fallback
  else
    List.last(given)
  end
end

fn trimmed_url(value :: String) -> String do
  if String.ends_with(value, "/") do
    String.slice(value, 0, String.length(value) - 1)
  else
    value
  end
end

fn url(value :: String, what :: String) -> String!String do
  if (String.starts_with(value, "https://") || String.starts_with(value, "http://"))
    && !String.contains(value, "?")
    && !String.contains(value, "#")
    && !String.contains(value, "@")
    && !String.contains(value, " ") do
    Ok(trimmed_url(value))
  else
    Err("#{what} must be an http(s) URL without userinfo, query or fragment: #{value}")
  end
end

fn address(value :: String, what :: String) -> String!String do
  case Bytes.from_base58(value) do
    Ok(bytes) -> if Bytes.length(bytes) == 32 && Bytes.to_base58(bytes) == value do
      Ok(value)
    else
      Err("#{what} must be a base58 Solana address")
    end
    Err(_) -> Err("#{what} must be a base58 Solana address")
  end
end

fn number(value :: String, what :: String, low :: Int, high :: Int) -> Int!String do
  case String.to_int(value) do
    None -> Err("#{what} must be a number")
    Some(parsed) -> if parsed < low || parsed > high do
      Err("#{what} must be between #{low} and #{high}")
    else
      Ok(parsed)
    end
  end
end

# A config file holds one frame; one trailing newline is allowed.

fn read_set(path :: String) -> SecurityConfig!String do
  let text = case File.read(path) do
    Err(error) -> Err("cannot read config #{path}: #{error}")
    Ok(value)
  end?
  let frame = if String.ends_with(text, "\n") do
    String.slice(text, 0, String.length(text) - 1)
  else
    text
  end
  case security_config_parse(Bytes.from_utf8(frame)) do
    Err(_) -> Err("config #{path} is not a valid security config frame")
    Ok(value)
  end
end

fn pinned_anchor(sets :: List<SecurityConfig>) -> Option<SecurityConfig> do
  List.find(sets, fn set -> set.judge_program_id != "" end)
end

fn from_sets(sets :: List<SecurityConfig>,
  pick :: Fun(SecurityConfig) -> List<String>) -> List<String> do
  case List.find(sets, fn set -> List.length(pick(set)) > 0 end) do
    None -> List.new()
    Some(set) -> pick(set)
  end
end

fn unique(values :: List<String>) -> Bool do
  List.all(values,
    fn value -> List.length(List.filter(values, fn other -> other == value end)) == 1 end)
end

fn finder(value :: String) -> Bytes!String do
  if value == "" do
    case Bytes.repeat(0, 32) do
      Err(_) -> Err("finder failed")
      Ok(zero)
    end
  else
    case Bytes.from_base58(address(value, "--finder")?) do
      Err(_) -> Err("--finder must be a base58 Solana address")
      Ok(bytes)
    end
  end
end

fn anchor_value(values :: List<Flag>,
  name :: String,
  pinned :: Option<SecurityConfig>,
  pick :: Fun(SecurityConfig) -> String) -> String!String do
  let given = one(values, name, "")
  if given != "" do
    address(given, "--#{name}")
  else
    case pinned do
      None -> Err("--#{name} is required (no supported config pins an anchor)")
      Some(set) -> Ok(pick(set))
    end
  end
end

fn log_name(value :: String) -> String!String do
  if value == "morse-main" || value == "morse-canary" do
    Ok(value)
  else
    Err("--log must be morse-main or morse-canary")
  end
end

pub fn monitor_config_parse(args :: List<String>) -> MonitorConfig!String do
  let values = flags(args, List.new())?
  let sets = for path in all(values, "config") do
    read_set(path)?
  end
  let pinned = pinned_anchor(sets)
  let given_rpc = for value in all(values, "rpc") do
    url(value, "--rpc")?
  end
  let rpc_urls = if List.length(given_rpc) > 0 do
    given_rpc
  else
    from_sets(sets, fn set -> set.rpc_urls end)
  end
  let given_relays = for value in all(values, "relay") do
    url(value, "--relay")?
  end
  let config = MonitorConfig {
    log_name: log_name(one(values, "log", ""))?,
    directory: url(one(values, "directory", ""), "--directory")?,
    judge: anchor_value(values, "judge", pinned, fn set -> set.judge_program_id end)?,
    log_account: anchor_value(values, "log-account", pinned, fn set -> set.log_account end)?,
    rpc_urls: rpc_urls,
    sets: sets,
    relays: if List.length(given_relays) > 0 do
      given_relays
    else
      from_sets(sets, fn set -> set.relays end)
    end,
    state_path: one(values, "state", ""),
    listen: number(one(values, "listen", "0"), "--listen", 0, 65535)?,
    interval_ms: 1000 * number(one(values, "interval", "30"), "--interval", 1, 3600)?,
    finder: finder(one(values, "finder", ""))?,
    once: List.length(all(values, "once")) > 0
  }
  if List.length(sets) == 0 do
    Err("at least one --config (a supported security config) is required")
  else if List.length(config.rpc_urls) < 2 || !unique(config.rpc_urls) do
    Err("at least two different --rpc URLs are required")
  else if config.state_path == "" do
    Err("--state is required")
  else if List.any(sets,
    fn set -> set.judge_program_id != ""
      && (set.judge_program_id != config.judge || set.log_account != config.log_account) end) do
    Err("a supported config pins another judge program or Log account")
  else
    Ok(config)
  end
end
