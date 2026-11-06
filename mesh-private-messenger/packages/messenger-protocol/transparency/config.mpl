##! Release-pinned security configuration. A directory response never supplies
##! this frame: native resources and explicit CLI configuration own it.
from Transparency.Merkle import WitnessKey

pub struct WitnessPin do
  witness_id :: String
  public_key :: Bytes
  operator_label :: String
end

pub struct SecurityConfig do
  # Feature profile stays 1..5 even inside a v6 policy envelope. It controls
  # existing log, anchor and relay permissions independently of the suite floor.
  version :: Int
  wire_version :: Int
  minimum_session_suite :: Int
  service_public_key :: Bytes
  delivery_public_key :: Bytes
  abuse_difficulty :: Int
  threshold :: Int
  witnesses :: List<WitnessPin>
  set_id :: Bytes
  anchor_address :: String
  anchor_program :: String
  anchor_log_name :: String
  rpc_urls :: List<String>
  issuer_origin :: String
  # v3 prefers the RFC log and carries trusted historical pins. The legacy
  # policy also allows operation before cutover; a cached v2 view is sticky.
  log_version :: Int
  legacy_threshold :: Int
  legacy_witnesses :: List<WitnessPin>
  # v5 adds release-pinned relay origins and the expected slash-receipt mint.
  # Older frames always decode to an empty list and a disabled mint.
  relay_urls :: List<String>
  slash_mint :: String
end

pub struct LogWitnessPolicy do
  keys :: List<WitnessKey>
  threshold :: Int
  set_id :: Bytes
end

# Before cutover, a v3 release can still authenticate legacy evidence with its
# explicit historical policy. Clients enforce the one-way transition once they
# have persisted a v2 checkpoint. Older native formats never authorize v2.
pub fn witness_policy_for_log(config :: SecurityConfig,
  version :: Int) -> LogWitnessPolicy!String do
  if version == config.log_version do
    Ok(LogWitnessPolicy {
      keys: pinned_witness_keys(config),
      threshold: config.threshold,
      set_id: config.set_id
    })
  else if (config.version == 3 || config.version == 4 || config.version == 5) && version == 1 do
    Ok(LogWitnessPolicy {
      keys: pinned_legacy_witness_keys(config),
      threshold: config.legacy_threshold,
      set_id: witness_set_id(config.legacy_witnesses, config.legacy_threshold)?
    })
  else
    Err("unsupported_transparency_log")
  end
end

fn invalid() -> String do
  "invalid_messenger_configuration"
end

fn key(input :: String) -> Bytes!String do
  let decoded = case Bytes.from_hex(input) do
    Err(_) -> Err(invalid())
    Ok(value)
  end?
  if String.length(input) != 64 || Bytes.length(decoded) != 32 || Bytes.to_hex(decoded) != input do
    Err(invalid())
  else
    Ok(decoded)
  end
end

fn number(input :: String, minimum :: Int, maximum :: Int) -> Int!String do
  let value = case String.to_int(input) do
    None -> Err(invalid())
    Some(value) -> Ok(value)
  end?
  if value < minimum || value > maximum || Int.to_string(value) != input do
    Err(invalid())
  else
    Ok(value)
  end
end

fn ascii_between(input :: String, minimum :: Int, maximum :: Int) -> Bool do
  let bytes = Bytes.from_utf8(input)
  List.all(for index in 0..Bytes.length(bytes) do
      case Bytes.get(bytes, index) do
        Err(_) -> false
        Ok(value) -> value >= minimum && value <= maximum
      end
    end,
    fn(valid) -> valid end)
end

pub fn valid_witness_id(input :: String) -> Bool do
  let bytes = Bytes.from_utf8(input)
  Bytes.length(bytes) >= 1
    && Bytes.length(bytes) <= 64
    && List.all(for index in 0..Bytes.length(bytes) do
        case Bytes.get(bytes, index) do
          Err(_) -> false
          Ok(value) -> (value >= 97 && value <= 122) || (value >= 48 && value <= 57) || value == 45
        end
      end,
      fn(valid) -> valid end)
end

fn witness_line(pin :: WitnessPin) -> String do
  pin.witness_id <> " " <> Bytes.to_hex(pin.public_key) <> " " <> pin.operator_label
end

fn parse_pin(line :: String) -> WitnessPin!String do
  let fields = String.split(line, " ")
  if List.length(fields) < 3 do
    return Err(invalid())
  end
  let pin = WitnessPin {
    witness_id: List.get(fields, 0),
    public_key: key(List.get(fields, 1))?,
    operator_label: String.join(List.drop(fields, 2), " ")
  }
  if !valid_witness_id(pin.witness_id)
    || String.length(pin.operator_label) < 1
    || String.length(pin.operator_label) > 48
    || String.trim(pin.operator_label) != pin.operator_label
    || !ascii_between(pin.operator_label, 32, 126)
    || witness_line(pin) != line do
    Err(invalid())
  else
    Ok(pin)
  end
end

fn validate_pins(pins :: List<WitnessPin>, threshold :: Int) -> Result<(), String> do
  let count = List.length(pins)
  if count < 1 || count > 16 || threshold != count / 2 + 1 do
    return Err(invalid())
  end
  for index in 0..count do
    let pin = parse_pin(witness_line(List.get(pins, index)))?
    if index > 0 && List.get(pins, index - 1).witness_id >= pin.witness_id do
      return Err(invalid())
    end
    for earlier in 0..index do
      if Bytes.secure_equals(List.get(pins, earlier).public_key, pin.public_key) do
        return Err(invalid())
      end
    end
  end
  Ok(nil)
end

pub fn witness_set_id(pins :: List<WitnessPin>, threshold :: Int) -> Bytes!String do
  validate_pins(pins, threshold)?
  let lines = [Int.to_string(threshold), Int.to_string(List.length(pins))]
    ++ for pin in pins do
      witness_line(pin)
    end
  Ok(Crypto.sha256(Bytes.from_utf8("morse-witness-set-v1" <> String.join(lines, "\n"))))
end

pub fn pinned_witness_keys(config :: SecurityConfig) -> List<WitnessKey> do
  for pin in config.witnesses do
    WitnessKey { witness_id: pin.witness_id, public_key: pin.public_key }
  end
end

pub fn pinned_legacy_witness_keys(config :: SecurityConfig) -> List<WitnessKey> do
  for pin in config.legacy_witnesses do
    WitnessKey { witness_id: pin.witness_id, public_key: pin.public_key }
  end
end

fn valid_https_url(value :: String, origin_only :: Bool) -> Bool do
  if String.length(value) > 2048
    || !String.starts_with(value, "https://")
    || !ascii_between(value, 33, 126)
    || String.contains(value, "\\")
    || String.contains(value, "#")
    || String.contains(value, "@") do
    return false
  end
  let origin = case Http.url_origin(value) do
    Err(_) -> return false
    Ok(origin) -> origin
  end
  if origin_only do
    value == origin
  else
    value == origin
      || String.starts_with(value, origin <> "/")
      || String.starts_with(value, origin <> "?")
  end
end

fn validate_endpoints(value :: SecurityConfig) -> Result<(), String> do
  let count = List.length(value.rpc_urls)
  if count != 0 && (count < 3 || count > 8) do
    return Err(invalid())
  end
  if value.anchor_address != "-" do
    let address = case Bytes.from_base58(value.anchor_address) do
      Err(_) -> Err(invalid())
      Ok(bytes)
    end?
    if Bytes.length(address) != 32
      || Bytes.to_base58(address) != value.anchor_address
      || count == 0 do
      return Err(invalid())
    end
  end
  for index in 0..count do
    let url = List.get(value.rpc_urls, index)
    if !valid_https_url(url, false) do
      return Err(invalid())
    end
    for earlier in 0..index do
      if Http.url_origin(List.get(value.rpc_urls, earlier))? == Http.url_origin(url)? do
        return Err(invalid())
      end
    end
  end
  if value.issuer_origin != "-" && !valid_https_url(value.issuer_origin, true) do
    Err(invalid())
  else
    Ok(nil)
  end
end

fn validate_anchor_identity(value :: SecurityConfig) -> Result<(), String> do
  if (value.version != 4 && value.version != 5) || value.anchor_address == "-" do
    if value.anchor_program != "-" || value.anchor_log_name != "-" do
      return Err(invalid())
    end
  else
    let program = case Bytes.from_base58(value.anchor_program) do
      Err(_) -> return Err(invalid())
      Ok(bytes) -> bytes
    end
    if Bytes.length(program) != 32
      || Bytes.to_base58(program) != value.anchor_program
      || value.anchor_log_name == "-"
      || !valid_witness_id(value.anchor_log_name)
      || String.length(value.anchor_log_name) > 32 do
      return Err(invalid())
    end
  end
  Ok(nil)
end

fn validate_relays(value :: SecurityConfig) -> Result<(), String> do
  let count = List.length(value.relay_urls)
  if value.version != 5 do
    if count != 0 || value.slash_mint != "-" do
      return Err(invalid())
    end
    return Ok(nil)
  end
  if count > 8 || (count > 0 && value.slash_mint == "-") do
    return Err(invalid())
  end
  if value.slash_mint != "-" do
    let mint = case Bytes.from_base58(value.slash_mint) do
      Err(_) -> return Err(invalid())
      Ok(bytes) -> bytes
    end
    if value.anchor_address == "-"
      || Bytes.length(mint) != 32
      || Bytes.to_base58(mint) != value.slash_mint
      || value.slash_mint == String.repeat("1", 32) do
      return Err(invalid())
    end
  end
  for index in 0..count do
    let origin = List.get(value.relay_urls, index)
    if !valid_https_url(origin, true)
      || List.any(List.take(value.relay_urls, index), fn(other) do other == origin end) do
      return Err(invalid())
    end
  end
  Ok(nil)
end

fn encode_feature_config(value :: SecurityConfig) -> Bytes!String do
  key(Bytes.to_hex(value.service_public_key))?
  key(Bytes.to_hex(value.delivery_public_key))?
  number(Int.to_string(value.abuse_difficulty), 1, 24)?
  let digest = witness_set_id(value.witnesses, value.threshold)?
  if !Bytes.secure_equals(value.set_id, digest) do
    return Err(invalid())
  end
  validate_endpoints(value)?
  validate_anchor_identity(value)?
  validate_relays(value)?
  if value.version == 3 || value.version == 4 || value.version == 5 do
    if value.log_version != 2 do
      return Err(invalid())
    end
    validate_pins(value.legacy_witnesses, value.legacy_threshold)?
  else if value.log_version != 1
    || value.legacy_threshold != 0
    || List.length(value.legacy_witnesses) != 0 do
    return Err(invalid())
  end
  let lines = if value.version == 1 do
    if value.threshold != 2
      || List.length(value.witnesses) != 2
      || List.get(value.witnesses, 0).witness_id != "witness-a"
      || List.get(value.witnesses, 1).witness_id != "witness-b"
      || List.get(value.witnesses, 0).operator_label != "Morse"
      || List.get(value.witnesses, 1).operator_label != "Morse"
      || value.anchor_address != "-"
      || value.issuer_origin != "-"
      || List.length(value.rpc_urls) != 0 do
      return Err(invalid())
    end
    [
      "1",
      Bytes.to_hex(value.service_public_key),
      Bytes.to_hex(List.get(value.witnesses, 0).public_key),
      Bytes.to_hex(List.get(value.witnesses, 1).public_key),
      Bytes.to_hex(value.delivery_public_key),
      Int.to_string(value.abuse_difficulty)
    ]
  else if value.version == 2 || value.version == 3 || value.version == 4 || value.version == 5 do
    [
      Int.to_string(value.version),
      Bytes.to_hex(value.service_public_key),
      Bytes.to_hex(value.delivery_public_key),
      Int.to_string(value.abuse_difficulty),
      Int.to_string(value.threshold),
      Int.to_string(List.length(value.witnesses))
    ]
      ++ (for pin in value.witnesses do
        witness_line(pin)
      end)
      ++ [value.anchor_address, Int.to_string(List.length(value.rpc_urls))]
      ++ value.rpc_urls
      ++ [value.issuer_origin]
  else
    return Err(invalid())
  end
  let migration = if value.version == 3 || value.version == 4 || value.version == 5 do
    ["2", Int.to_string(value.legacy_threshold), Int.to_string(List.length(value.legacy_witnesses))]
      ++ for pin in value.legacy_witnesses do
        witness_line(pin)
      end
  else
    List.new()
  end
  let anchor = if value.version == 4 || value.version == 5 do
    [value.anchor_program, value.anchor_log_name]
  else
    List.new()
  end
  let relays = if value.version == 5 do
    [value.slash_mint, Int.to_string(List.length(value.relay_urls))] ++ value.relay_urls
  else
    List.new()
  end
  let frame = Bytes.from_utf8(String.join(lines ++ migration ++ anchor ++ relays, "\n"))
  let maximum = if value.version == 3 || value.version == 4 || value.version == 5 do
    8192
  else
    4096
  end
  if Bytes.length(frame) > maximum do
    Err(invalid())
  else
    Ok(frame)
  end
end

# Physical v6 adds only a new-session minimum to an exact older feature frame.
# Bare old frames remain byte-for-byte stable and always mean floor one.
pub fn encode_security_config(value :: SecurityConfig) -> Bytes!String do
  if value.wire_version == 6 do
    number(Int.to_string(value.minimum_session_suite), 1, 2)?
    let embedded = encode_feature_config(%{value |
      wire_version: value.version,
      minimum_session_suite: 1
    })?
    let text = case Bytes.to_utf8(embedded) do
      Err(_) -> Err(invalid())
      Ok(value)
    end?
    let frame = Bytes.from_utf8("6\n#{value.minimum_session_suite}\n" <> text)
    if Bytes.length(frame) > 8192 do
      Err(invalid())
    else
      Ok(frame)
    end
  else if value.wire_version != value.version || value.minimum_session_suite != 1 do
    Err(invalid())
  else
    encode_feature_config(value)
  end
end

fn decode_v1(fields :: List<String>) -> SecurityConfig!String do
  if List.length(fields) != 6 do
    return Err(invalid())
  end
  let pins = [
    WitnessPin {
      witness_id: "witness-a",
      public_key: key(List.get(fields, 2))?,
      operator_label: "Morse"
    },
    WitnessPin {
      witness_id: "witness-b",
      public_key: key(List.get(fields, 3))?,
      operator_label: "Morse"
    }
  ]
  Ok(SecurityConfig {
    version: 1,
    wire_version: 1,
    minimum_session_suite: 1,
    service_public_key: key(List.get(fields, 1))?,
    delivery_public_key: key(List.get(fields, 4))?,
    abuse_difficulty: number(List.get(fields, 5), 1, 24)?,
    threshold: 2,
    witnesses: pins,
    set_id: witness_set_id(pins, 2)?,
    anchor_address: "-",
    anchor_program: "-",
    anchor_log_name: "-",
    rpc_urls: List.new(),
    issuer_origin: "-",
    log_version: 1,
    legacy_threshold: 0,
    legacy_witnesses: List.new(),
    relay_urls: List.new(),
    slash_mint: "-"
  })
end

fn decode_v2(fields :: List<String>) -> SecurityConfig!String do
  if List.length(fields) < 10 do
    return Err(invalid())
  end
  let count = number(List.get(fields, 5), 1, 16)?
  let threshold = number(List.get(fields, 4), 1, 16)?
  if List.length(fields) < 9 + count do
    return Err(invalid())
  end
  let pins = for index in 0..count do
    parse_pin(List.get(fields, 6 + index))?
  end
  let rpc_count = number(List.get(fields, 7 + count), 0, 8)?
  if List.length(fields) != 9 + count + rpc_count do
    return Err(invalid())
  end
  Ok(SecurityConfig {
    version: 2,
    wire_version: 2,
    minimum_session_suite: 1,
    service_public_key: key(List.get(fields, 1))?,
    delivery_public_key: key(List.get(fields, 2))?,
    abuse_difficulty: number(List.get(fields, 3), 1, 24)?,
    threshold: threshold,
    witnesses: pins,
    set_id: witness_set_id(pins, threshold)?,
    anchor_address: List.get(fields, 6 + count),
    anchor_program: "-",
    anchor_log_name: "-",
    rpc_urls: for index in 0..rpc_count do
      List.get(fields, 8 + count + index)
    end,
    issuer_origin: List.get(fields, 8 + count + rpc_count),
    log_version: 1,
    legacy_threshold: 0,
    legacy_witnesses: List.new(),
    relay_urls: List.new(),
    slash_mint: "-"
  })
end

fn decode_v3(fields :: List<String>) -> SecurityConfig!String do
  if List.length(fields) < 13 do
    return Err(invalid())
  end
  let count = number(List.get(fields, 5), 1, 16)?
  if List.length(fields) < 12 + count do
    return Err(invalid())
  end
  let rpc_count = number(List.get(fields, 7 + count), 0, 8)?
  let base_length = 9 + count + rpc_count
  if List.length(fields) < base_length + 3 do
    return Err(invalid())
  end
  let base = decode_v2(List.take(fields, base_length))?
  let version = number(List.get(fields, base_length), 2, 2)?
  let threshold = number(List.get(fields, base_length + 1), 1, 16)?
  let legacy_count = number(List.get(fields, base_length + 2), 1, 16)?
  if List.length(fields) != base_length + 3 + legacy_count do
    return Err(invalid())
  end
  let pins = for index in 0..legacy_count do
    parse_pin(List.get(fields, base_length + 3 + index))?
  end
  Ok(%{base |
    version: 3,
    wire_version: 3,
    log_version: version,
    legacy_threshold: threshold,
    legacy_witnesses: pins
  })
end

fn decode_v4(fields :: List<String>) -> SecurityConfig!String do
  let count = List.length(fields)
  if count < 15 do
    return Err(invalid())
  end
  let base = decode_v3(List.take(fields, count - 2))?
  Ok(%{base |
    version: 4,
    wire_version: 4,
    anchor_program: List.get(fields, count - 2),
    anchor_log_name: List.get(fields, count - 1)
  })
end

fn decode_v5(fields :: List<String>) -> SecurityConfig!String do
  # Locate the extension through bounded counts, never by searching for a URL
  # or sentinel that could also occur in an older field.
  if List.length(fields) < 17 do
    return Err(invalid())
  end
  let count = number(List.get(fields, 5), 1, 16)?
  if List.length(fields) <= 7 + count do
    return Err(invalid())
  end
  let rpc_count = number(List.get(fields, 7 + count), 0, 8)?
  let base_length = 9 + count + rpc_count
  if List.length(fields) <= base_length + 2 do
    return Err(invalid())
  end
  let legacy_count = number(List.get(fields, base_length + 2), 1, 16)?
  let v4_length = base_length + 3 + legacy_count + 2
  if List.length(fields) < v4_length + 2 do
    return Err(invalid())
  end
  let relay_count = number(List.get(fields, v4_length + 1), 0, 8)?
  if List.length(fields) != v4_length + 2 + relay_count do
    return Err(invalid())
  end
  let base = decode_v4(List.take(fields, v4_length))?
  Ok(%{base |
    version: 5,
    wire_version: 5,
    slash_mint: List.get(fields, v4_length),
    relay_urls: List.drop(fields, v4_length + 2)
  })
end

fn decode_feature_config(fields :: List<String>) -> SecurityConfig!String do
  case List.head(fields) do
    "1" -> decode_v1(fields)
    "2" -> decode_v2(fields)
    "3" -> decode_v3(fields)
    "4" -> decode_v4(fields)
    "5" -> decode_v5(fields)
    _ -> Err(invalid())
  end
end

pub fn decode_security_config(input :: Bytes) -> SecurityConfig!String do
  if Bytes.length(input) == 0 || Bytes.length(input) > 8192 do
    return Err(invalid())
  end
  let text = case Bytes.to_utf8(input) do
    Err(_) -> Err(invalid())
    Ok(value)
  end?
  let fields = String.split(text, "\n")
  let value = if List.head(fields) == "6" do
    if List.length(fields) < 3 do
      return Err(invalid())
    end
    let minimum = number(List.get(fields, 1), 1, 2)?
    # A separate feature decoder never accepts nested policy envelopes.
    let base = decode_feature_config(List.drop(fields, 2))?
    Ok(%{base | wire_version: 6, minimum_session_suite: minimum})
  else
    decode_feature_config(fields)
  end?
  if Bytes.secure_equals(encode_security_config(value)?, input) do
    Ok(value)
  else
    Err(invalid())
  end
end
