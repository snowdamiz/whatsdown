##! The security config each build pins: transparency service key, delivery
##! key, proof-of-work difficulty, the witness set and its strict-majority
##! threshold, the chain anchor, relays, the credit issuer, the C2SP origin and
##! the minimum session suite, and optionally the Oblivious HTTP gateway key
##! with its relay. Version 1 frames map onto the same struct.

from Privacy.OhttpWire import ohttp_key_config_decode, ohttp_key_config_encode
from Transparency.Codec import tcodec_decimal
from Transparency.Merkle import WitnessKey

pub struct SecurityWitness do
  witness_id :: String
  public_key :: Bytes
  label :: String
end

# "" marks a field the frame switched off with "-".

pub struct SecurityConfig do
  version :: Int
  service_public_key :: Bytes
  delivery_public_key :: Bytes
  abuse_difficulty :: Int
  threshold :: Int
  witnesses :: List<SecurityWitness>
  judge_program_id :: String
  log_account :: String
  rpc_urls :: List<String>
  relays :: List<String>
  issuer_origin :: String
  c2sp_origin :: String
  minimum_suite :: Int
  # RFC 9458 key configuration of the OHTTP gateway, and the relay's origin
  # (protocol/ohttp-v1.md); empty when the frame pins none.
  ohttp_key_config :: Bytes
  ohttp_relay :: String
  set_id :: Bytes
end

fn refused<T>() -> T!String do
  Err("invalid_messenger_configuration")
end

pub fn security_config_majority(count :: Int) -> Int do
  count / 2 + 1
end

pub fn security_config_morse_run(config :: SecurityConfig) -> Int do
  List.length(List.filter(config.witnesses, fn witness -> witness.label == "Morse" end))
end

# Bootstrap: Morse runs a threshold of the set. Open: Morse runs at most one.

pub fn security_config_profile(config :: SecurityConfig) -> String do
  let morse = security_config_morse_run(config)
  if morse >= config.threshold do
    "bootstrap"
  else if morse > 1 do
    "transitional"
  else
    "open"
  end
end

pub fn security_config_witness_keys(config :: SecurityConfig) -> List<WitnessKey> do
  List.map(config.witnesses,
    fn witness -> WitnessKey { witness_id: witness.witness_id, public_key: witness.public_key } end)
end

fn line_at(lines :: List<String>, index :: Int) -> String!String do
  if index < 0 || index >= List.length(lines) do
    refused()
  else
    Ok(List.get(lines, index))
  end
end

fn number(text :: String, low :: Int, high :: Int) -> Int!String do
  case tcodec_decimal(text) do
    Ok(value) -> if value >= low && value <= high do
      Ok(value)
    else
      refused()
    end
    Err(_) -> refused()
  end
end

fn hex_key(text :: String) -> Bytes!String do
  case Bytes.from_hex(text) do
    Ok(value) -> if Bytes.length(value) == 32 && Bytes.to_hex(value) == text do
      Ok(value)
    else
      refused()
    end
    Err(_) -> refused()
  end
end

# The delivery key must be a contributory X25519 point, as the v1 parser required.

fn delivery_key(text :: String) -> Bytes!String do
  let value = hex_key(text)?
  let probe = case Crypto.x25519_generate() do
    Err(_) -> Err("messenger_configuration_validation_failed")
    Ok(pair)
  end?
  let shared = case Crypto.x25519_shared(probe.private_key, X25519PublicKey { bytes: value }) do
    Err(_) -> refused()
    Ok(secret)
  end?
  Secret.destroy(shared)
  Ok(value)
end

fn bytes_of(text :: String) -> List<Int> do
  Bytes.to_list(Bytes.from_utf8(text))
end

fn valid_witness_id(id :: String) -> Bool do
  let bytes = bytes_of(id)
  List.length(bytes) >= 1
    && List.length(bytes) <= 64
    && List.all(bytes,
      fn byte -> (byte >= 97 && byte <= 122) || (byte >= 48 && byte <= 57) || byte == 45 end)
end

fn valid_label(label :: String) -> Bool do
  let bytes = bytes_of(label)
  List.length(bytes) >= 1
    && List.length(bytes) <= 48
    && List.all(bytes, fn byte -> byte >= 32 && byte <= 126 end)
    && List.get(bytes, 0) != 32
    && List.last(bytes) != 32
end

fn witness_line(text :: String) -> SecurityWitness!String do
  let fields = String.split(text, " ")
  if List.length(fields) < 3 do
    refused()
  else
    let id = List.get(fields, 0)
    let label = String.join(List.drop(fields, 2), " ")
    if !valid_witness_id(id) || !valid_label(label) do
      refused()
    else
      Ok(SecurityWitness {
        witness_id: id,
        public_key: hex_key(List.get(fields, 1))?,
        label: label
      })
    end
  end
end

fn sorted_and_unique(witnesses :: List<SecurityWitness>) -> Bool do
  let ordered = for index in 1..List.length(witnesses) do
    List.get(witnesses, index - 1).witness_id < List.get(witnesses, index).witness_id
  end
  List.all(ordered, fn value -> value end)
    && List.all(witnesses,
      fn witness -> List.length(List.filter(witnesses,
        fn other -> Bytes.secure_equals(other.public_key, witness.public_key) end)) == 1 end)
end

fn printable_token(text :: String, maximum :: Int) -> Bool do
  let bytes = bytes_of(text)
  List.length(bytes) >= 1
    && List.length(bytes) <= maximum
    && List.all(bytes, fn byte -> byte > 32 && byte < 127 end)
end

# https only; no userinfo, query or fragment. An origin also has no path.
# The 4,096-byte frame bounds the length.

fn https_url(text :: String, origin_only :: Bool) -> Bool do
  let rest = String.slice(text, 8, String.length(text))
  let host = List.get(String.split(rest, "/"), 0)
  String.starts_with(text, "https://")
    && printable_token(text, 4096)
    && String.length(host) > 0
    && !String.contains(text, "@")
    && !String.contains(text, "?")
    && !String.contains(text, "#")
    && (!origin_only || host == rest)
end

fn base58_key(text :: String) -> Bool do
  case Bytes.from_base58(text) do
    Ok(value) -> Bytes.length(value) == 32 && Bytes.to_base58(value) == text
    Err(_) -> false
  end
end

fn optional_origin(text :: String) -> String!String do
  if text == "-" do
    Ok("")
  else if https_url(text, true) do
    Ok(text)
  else
    refused()
  end
end

fn c2sp_origin(text :: String) -> String!String do
  if text == "-" do
    Ok("")
  else if printable_token(text, 255) && !String.contains(text, "+") do
    Ok(text)
  else
    refused()
  end
end

fn anchor_fields(text :: String) -> (String, String)!String do
  let fields = String.split(text, " ")
  if text == "-" do
    Ok(("", ""))
  else if List.length(fields) == 2
    && base58_key(List.get(fields, 0))
    && base58_key(List.get(fields, 1)) do
    Ok((List.get(fields, 0), List.get(fields, 1)))
  else
    refused()
  end
end

fn set_lines(threshold :: Int, witnesses :: List<SecurityWitness>) -> List<String> do
  [Int.to_string(threshold), Int.to_string(List.length(witnesses))]
    ++ List.map(witnesses,
      fn witness -> witness.witness_id
        <> " "
        <> Bytes.to_hex(witness.public_key)
        <> " "
        <> witness.label end)
end

fn set_id(threshold :: Int, witnesses :: List<SecurityWitness>) -> Bytes do
  Crypto.sha256(Bytes.from_utf8("morse-witness-set-v1"
    <> String.join(set_lines(threshold, witnesses), "\n")))
end

fn anchor_line(config :: SecurityConfig) -> String do
  if config.judge_program_id == "" do
    "-"
  else
    config.judge_program_id <> " " <> config.log_account
  end
end

fn dash(text :: String) -> String do
  if text == "" do
    "-"
  else
    text
  end
end

fn ohttp_line(config :: SecurityConfig) -> List<String> do
  if Bytes.length(config.ohttp_key_config) == 0 do
    List.new()
  else
    [Bytes.to_hex(config.ohttp_key_config) <> " " <> config.ohttp_relay]
  end
end

fn octets(host :: String) -> List<Int> do
  let parts = String.split(host, ".")
  let values = List.map(parts,
    fn part -> case tcodec_decimal(part) do
      Ok(value) -> if value <= 255 do
        value
      else
        -1
      end
      Err(_) -> -1
    end end)
  if List.length(values) == 4 && List.all(values, fn value -> value >= 0 end) do
    values
  else
    List.new()
  end
end

# A development relay: http on localhost, [::1] or a private IPv4 address,
# with an optional port, as development builds reach local services.

fn development_host(host :: String) -> Bool do
  let values = octets(host)
  let first = if List.length(values) == 4 do
    List.get(values, 0)
  else
    -1
  end
  let second = if List.length(values) == 4 do
    List.get(values, 1)
  else
    -1
  end
  host == "localhost"
    || host == "[::1]"
    || first == 127
    || first == 10
    || (first == 192 && second == 168)
    || (first == 172 && second >= 16 && second <= 31)
end

fn development_origin(text :: String) -> Bool do
  let rest = String.slice(text, 7, String.length(text))
  let host = if String.starts_with(rest, "[::1]") do
    "[::1]"
  else
    List.get(String.split(rest, ":"), 0)
  end
  let port = String.slice(rest, String.length(host), String.length(rest))
  let port_valid = port == ""
    || (String.starts_with(port, ":")
      && case tcodec_decimal(String.slice(port, 1, String.length(port))) do
        Ok(value) -> value >= 1 && value <= 65535
        Err(_) -> false
      end)
  String.starts_with(text, "http://")
    && printable_token(text, 255)
    && development_host(host)
    && port_valid
end

fn ohttp_fields(text :: String) -> (Bytes, String)!String do
  let fields = String.split(text, " ")
  if List.length(fields) != 2 do
    refused()
  else
    let hex = List.get(fields, 0)
    let relay = List.get(fields, 1)
    let config = case Bytes.from_hex(hex) do
      Ok(value) -> if Bytes.to_hex(value) == hex do
        Ok(value)
      else
        refused()
      end
      Err(_) -> refused()
    end?
    let canonical = case ohttp_key_config_decode(config) do
      Ok(decoded) -> ohttp_key_config_encode(decoded)
      Err(_) -> refused()
    end?
    if !Bytes.secure_equals(canonical, config) do
      refused()
    else if https_url(relay, true) || development_origin(relay) do
      Ok((config, relay))
    else
      refused()
    end
  end
end

fn canonical_lines(config :: SecurityConfig) -> List<String> do
  [
    "2",
    Bytes.to_hex(config.service_public_key),
    Bytes.to_hex(config.delivery_public_key),
    Int.to_string(config.abuse_difficulty)
  ]
    ++ set_lines(config.threshold, config.witnesses)
    ++ [anchor_line(config), Int.to_string(List.length(config.rpc_urls))]
    ++ config.rpc_urls
    ++ [Int.to_string(List.length(config.relays))]
    ++ config.relays
    ++ [dash(config.issuer_origin), dash(config.c2sp_origin), Int.to_string(config.minimum_suite)]
    ++ ohttp_line(config)
end

fn urls(lines :: List<String>,
  start :: Int,
  count :: Int,
  origin_only :: Bool) -> List<String>!String do
  let values = for index in start..start + count do
    line_at(lines, index)?
  end
  let distinct = List.all(values,
    fn value -> List.length(List.filter(values, fn other -> other == value end)) == 1 end)
  if distinct && List.all(values, fn value -> https_url(value, origin_only) end) do
    Ok(values)
  else
    refused()
  end
end

fn witnesses_at(lines :: List<String>, count :: Int) -> List<SecurityWitness>!String do
  let values = for index in 6..6 + count do
    witness_line(line_at(lines, index)?)?
  end
  if sorted_and_unique(values) do
    Ok(values)
  else
    refused()
  end
end

# Lines after the witness set: anchor, r and the RPC URLs, s and the relays,
# issuer, C2SP origin and minimum suite.

fn parse_tail(lines :: List<String>, base :: SecurityConfig) -> SecurityConfig!String do
  let at = 6 + List.length(base.witnesses)
  let (program, account) = anchor_fields(line_at(lines, at)?)?
  let rpc_count = number(line_at(lines, at + 1)?, 0, 8)?
  let rpc_valid = if program == "" do
    rpc_count == 0
  else
    rpc_count >= 3
  end
  let relay_at = at + 2 + rpc_count
  let relay_count = number(line_at(lines, relay_at)?, 0, 8)?
  let issuer_at = relay_at + 1 + relay_count
  let ohttp = if List.length(lines) == issuer_at + 4 do
    ohttp_fields(line_at(lines, issuer_at + 3)?)?
  else
    (Bytes.empty(), "")
  end
  let (ohttp_key_config, ohttp_relay) = ohttp
  if !rpc_valid || (List.length(lines) != issuer_at + 3 && List.length(lines) != issuer_at + 4) do
    refused()
  else
    Ok(%{base |
      ohttp_key_config: ohttp_key_config,
      ohttp_relay: ohttp_relay,
      judge_program_id: program,
      log_account: account,
      rpc_urls: urls(lines, at + 2, rpc_count, false)?,
      relays: urls(lines, relay_at + 1, relay_count, true)?,
      issuer_origin: optional_origin(line_at(lines, issuer_at)?)?,
      c2sp_origin: c2sp_origin(line_at(lines, issuer_at + 1)?)?,
      minimum_suite: number(line_at(lines, issuer_at + 2)?, 1, 2)?
    })
  end
end

fn parse_v2(text :: String) -> SecurityConfig!String do
  let lines = String.split(text, "\n")
  let count = number(line_at(lines, 5)?, 1, 16)?
  let threshold = number(line_at(lines, 4)?, 1, 16)?
  let witnesses = witnesses_at(lines, count)?
  let base = SecurityConfig {
    version: 2,
    service_public_key: hex_key(line_at(lines, 1)?)?,
    delivery_public_key: delivery_key(line_at(lines, 2)?)?,
    abuse_difficulty: number(line_at(lines, 3)?, 1, 24)?,
    threshold: threshold,
    witnesses: witnesses,
    judge_program_id: "",
    log_account: "",
    rpc_urls: List.new(),
    relays: List.new(),
    issuer_origin: "",
    c2sp_origin: "",
    minimum_suite: 1,
    ohttp_key_config: Bytes.empty(),
    ohttp_relay: "",
    set_id: set_id(threshold, witnesses)
  }
  let config = parse_tail(lines, base)?
  if threshold != security_config_majority(count)
    || String.join(canonical_lines(config), "\n") != text do
    refused()
  else
    Ok(config)
  end
end

# v1: "1", service key, witness A key, witness B key, delivery key, difficulty.

fn parse_v1(text :: String) -> SecurityConfig!String do
  let lines = String.split(text, "\n")
  if List.length(lines) != 6 do
    refused()
  else
    let witnesses = [
      SecurityWitness {
        witness_id: "witness-a",
        public_key: hex_key(List.get(lines, 2))?,
        label: "Morse"
      },
      SecurityWitness {
        witness_id: "witness-b",
        public_key: hex_key(List.get(lines, 3))?,
        label: "Morse"
      }
    ]
    let difficulty = number(List.get(lines, 5), 1, 24)?
    let delivery = delivery_key(List.get(lines, 4))?
    if Bytes.secure_equals(List.get(witnesses, 0).public_key, List.get(witnesses, 1).public_key) do
      refused()
    else
      Ok(SecurityConfig {
        version: 1,
        service_public_key: hex_key(List.get(lines, 1))?,
        delivery_public_key: delivery,
        abuse_difficulty: difficulty,
        threshold: 2,
        witnesses: witnesses,
        judge_program_id: "",
        log_account: "",
        rpc_urls: List.new(),
        relays: List.new(),
        issuer_origin: "",
        c2sp_origin: "",
        minimum_suite: 1,
        ohttp_key_config: Bytes.empty(),
        ohttp_relay: "",
        set_id: set_id(2, witnesses)
      })
    end
  end
end

pub fn security_config_parse(frame :: Bytes) -> SecurityConfig!String do
  let text = case Bytes.to_utf8(frame) do
    Err(_) -> refused()
    Ok(value)
  end?
  if Bytes.length(frame) > 4096 do
    refused()
  else if String.starts_with(text, "1\n")
    && Bytes.length(frame) >= 263
    && Bytes.length(frame) <= 264 do
    parse_v1(text)
  else if String.starts_with(text, "2\n") do
    parse_v2(text)
  else
    refused()
  end
end

# Always writes the canonical version 2 frame, and refuses to write one its
# own parser would refuse.

pub fn security_config_encode(config :: SecurityConfig) -> Bytes!String do
  let frame = Bytes.from_utf8(String.join(canonical_lines(config), "\n"))
  security_config_parse(frame)?
  Ok(frame)
end
