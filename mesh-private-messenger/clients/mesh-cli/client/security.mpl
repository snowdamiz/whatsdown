##! Explicit local trust for the CLI. HTTP responses never supply this policy.
from Transparency.Client import checkpoint_fresh_at, verify_evidence
from Transparency.Config import decode_security_config, pinned_witness_keys
from Transparency.Merkle import WitnessKey, verify_witnesses_at
from Transparency.Wire import TransparencyEvidence

pub struct CliSecurityPolicy do
  log_version :: Int
  service_public_key :: Bytes
  witnesses :: List<WitnessKey>
  threshold :: Int
  abuse_difficulty :: Int
end

fn setting(environment :: Map<String, String>, name :: String, fallback :: String) -> String do
  if Map.has_key(environment, name) do
    Map.get(environment, name)
  else
    fallback
  end
end

fn pinned_key(environment :: Map<String, String>, name :: String) -> Bytes!String do
  let text = setting(environment, name, "")
  let value = Bytes.from_hex(text)?
  if Bytes.length(value) != 32 || Bytes.to_hex(value) != text do
    Err("#{name} must be a canonical 32-byte public key")
  else
    Ok(value)
  end
end

pub fn security_policy(environment :: Map<String, String>) -> CliSecurityPolicy!String do
  if Map.has_key(environment, "MESSENGER_SECURITY_CONFIG") do
    let frame = Map.get(environment, "MESSENGER_SECURITY_CONFIG")
    let config = decode_security_config(Bytes.from_utf8(frame))?
    Ok(CliSecurityPolicy {
      log_version: config.log_version,
      service_public_key: config.service_public_key,
      witnesses: pinned_witness_keys(config),
      threshold: config.threshold,
      abuse_difficulty: config.abuse_difficulty
    })
  else
    let a = pinned_key(environment, "MESSENGER_WITNESS_A_PUBLIC_KEY_HEX")?
    let b = pinned_key(environment, "MESSENGER_WITNESS_B_PUBLIC_KEY_HEX")?
    let difficulty = work_difficulty(environment)?
    if Bytes.secure_equals(a, b) do
      Err("invalid CLI security configuration")
    else
      Ok(CliSecurityPolicy {
        log_version: 1,
        service_public_key: pinned_key(environment, "MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX")?,
        witnesses: [
          WitnessKey { witness_id: "witness-a", public_key: a },
          WitnessKey { witness_id: "witness-b", public_key: b }
        ],
        threshold: 2,
        abuse_difficulty: difficulty
      })
    end
  end
end

fn configured_environment() -> Map<String, String>!String do
  let names = [
    "MESSENGER_SECURITY_CONFIG",
    "MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX",
    "MESSENGER_WITNESS_A_PUBLIC_KEY_HEX",
    "MESSENGER_WITNESS_B_PUBLIC_KEY_HEX",
    "MESSENGER_ABUSE_DIFFICULTY"
  ]
  # Environment values cannot contain NUL, including an explicitly empty value.
  let absent = Bytes.to_utf8(Bytes.from_hex("00")?)?
  let environment = List.reduce(names,
    Map.new(),
    fn(values, name) do
      let value = Env.get(name, absent)
      if value == absent do
        values
      else
        Map.put(values, name, value)
      end
    end)
  Ok(environment)
end

pub fn resolution_path(policy :: CliSecurityPolicy) -> String do
  if policy.log_version == 2 do
    "/v2/devices/resolve"
  else
    "/v1/devices/resolve"
  end
end

pub fn verify_cli_evidence(evidence :: TransparencyEvidence,
  policy :: CliSecurityPolicy,
  now :: U64) -> Bool!String do
  if evidence.checkpoint.version != policy.log_version
    || !checkpoint_fresh_at(evidence.checkpoint.timestamp, now)
    || !verify_witnesses_at(evidence.checkpoint,
      evidence.witnesses,
      policy.witnesses,
      policy.threshold,
      now)? do
    Ok(false)
  else
    verify_evidence(evidence,
      SigningPublicKey { bytes: policy.service_public_key },
      policy.witnesses,
      policy.threshold,
      Bytes.empty())
  end
end

pub fn work_difficulty(environment :: Map<String, String>) -> Int!String do
  if Map.has_key(environment, "MESSENGER_SECURITY_CONFIG") do
    Ok(decode_security_config(Bytes.from_utf8(Map.get(environment,
      "MESSENGER_SECURITY_CONFIG")))?.abuse_difficulty)
  else
    let text = setting(environment, "MESSENGER_ABUSE_DIFFICULTY", "16")
    let value = case String.to_int(text) do
      None -> Err("invalid abuse difficulty")
      Some(value) -> Ok(value)
    end?
    if value < 1 || value > 24 || Int.to_string(value) != text do
      Err("invalid abuse difficulty")
    else
      Ok(value)
    end
  end
end

pub fn configured_policy() -> CliSecurityPolicy!String do
  security_policy(configured_environment()?)
end

pub fn configured_difficulty() -> Int!String do
  work_difficulty(configured_environment()?)
end

# Session-only fixture roles historically ran without lookup pins. A supplied
# frame is authoritative and must decode; no frame keeps manual floor one.
pub fn session_minimum(environment :: Map<String, String>) -> Int!String do
  if Map.has_key(environment, "MESSENGER_SECURITY_CONFIG") do
    Ok(decode_security_config(Bytes.from_utf8(Map.get(environment,
      "MESSENGER_SECURITY_CONFIG")))?.minimum_session_suite)
  else
    Ok(1)
  end
end

pub fn configured_session_minimum() -> Int!String do
  session_minimum(configured_environment()?)
end
