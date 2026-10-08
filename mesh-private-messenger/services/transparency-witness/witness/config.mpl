##! The witness's configuration, read from the environment. Every variable is
##! listed in services/transparency-witness/README.md.

pub struct WitnessSetup do
  witness_id :: String
  base_url :: String
  state_path :: String
  log_key :: Bytes
  witness_key :: Bytes
  evidence_dir :: String
  relay_urls :: List<String>
  # Pull mode refuses to start from a missing state unless bootstrap says how
  # ("new-identity", or a checkpoint's hex to transfer). The Cloudflare
  # witnesses (once mode) have their Worker check that before each run.
  require_bootstrap :: Bool
  bootstrap :: String
  # A copy of the last signed checkpoint on this host's own disk, off the
  # shared state volume ("" for none): a state restored from an older
  # snapshot is caught even when the directory has moved on.
  guard_path :: String
end

fn identifier_byte(byte :: Int) -> Bool do
  (byte >= 97 && byte <= 122) || (byte >= 48 && byte <= 57) || byte == 45
end

pub fn witness_valid_id(value :: String) -> Bool do
  let bytes = Bytes.from_utf8(value)
  Bytes.length(bytes) >= 1
    && Bytes.length(bytes) <= 64
    && List.all(Bytes.to_list(bytes), identifier_byte)
end

fn web_url(value :: String) -> Bool do
  (String.starts_with(value, "https://") || String.starts_with(value, "http://"))
    && !String.contains(value, "?")
    && !String.contains(value, "#")
    && !String.contains(value, "@")
end

fn without_trailing_slash(value :: String) -> String do
  if String.ends_with(value, "/") do
    String.slice(value, 0, String.length(value) - 1)
  else
    value
  end
end

# MESSENGER_WITNESS_RELAY_URLS: comma-separated relay origins (may be empty).

pub fn witness_relay_list(text :: String) -> List<String>!String do
  let values = List.filter(List.map(String.split(text, ","), fn value -> String.trim(value) end),
    fn value -> String.length(value) > 0 end)
  if List.length(values) > 8 || !List.all(values, web_url) do
    Err("invalid MESSENGER_WITNESS_RELAY_URLS")
  else
    Ok(List.map(values, without_trailing_slash))
  end
end

pub fn witness_mode(text :: String) -> String!String do
  if text == "once" || text == "pull" || text == "restore" do
    Ok(text)
  else
    Err("MESSENGER_WITNESS_MODE must be once, pull or restore")
  end
end

pub fn witness_poll_ms(text :: String) -> Int!String do
  case String.to_int(text) do
    None -> Err("invalid MESSENGER_WITNESS_POLL_MS")
    Some(value) -> if value < 50 || value > 60000 do
      Err("MESSENGER_WITNESS_POLL_MS must be between 50 and 60000")
    else
      Ok(value)
    end
  end
end

fn public_key(name :: String) -> Bytes!String do
  case Bytes.from_hex(Env.get(name, "")) do
    Err(_) -> Err("invalid witness configuration")
    Ok(value) -> if Bytes.length(value) == 32 do
      Ok(value)
    else
      Err("invalid witness configuration")
    end
  end
end

fn base_url() -> String!String do
  let value = without_trailing_slash(Env.get("MESSENGER_BASE_URL", ""))
  if !web_url(value) do
    Err("missing MESSENGER_BASE_URL")
  else
    Ok(value)
  end
end

pub fn witness_setup_from_env(require_bootstrap :: Bool) -> WitnessSetup!String do
  let witness_id = Env.get("MESSENGER_WITNESS_ID", "")
  let state_path = Env.get("MESSENGER_WITNESS_CHECKPOINT_PATH", "")
  if !witness_valid_id(witness_id) || String.length(state_path) == 0 do
    Err("invalid witness configuration")
  else
    Ok(WitnessSetup {
      witness_id: witness_id,
      base_url: base_url()?,
      state_path: state_path,
      log_key: public_key("MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX")?,
      witness_key: public_key("MESSENGER_WITNESS_PUBLIC_KEY_HEX")?,
      evidence_dir: without_trailing_slash(Env.get("MESSENGER_WITNESS_EVIDENCE_DIR", "")),
      relay_urls: witness_relay_list(Env.get("MESSENGER_WITNESS_RELAY_URLS", ""))?,
      require_bootstrap: require_bootstrap,
      bootstrap: Env.get("MESSENGER_WITNESS_INITIAL_CHECKPOINT_HEX", ""),
      guard_path: Env.get("MESSENGER_WITNESS_GUARD_PATH", "")
    })
  end
end

# The signing key, which must match the pinned public key.

pub fn witness_signer(setup :: WitnessSetup) -> SigningKeyPair!String do
  let material = case Env.get_secret_hex("MESSENGER_WITNESS_SIGNING_SEED_HEX") do
    Err(_) -> Err("invalid witness signing seed")
    Ok(value)
  end?
  let signer = case Crypto.signing_from_secret(material) do
    Err(_) -> Err("invalid witness signing seed")
    Ok(value)
  end?
  if !Bytes.secure_equals(signer.public_key.bytes, setup.witness_key) do
    Err("witness signing key does not match pinned public key")
  else
    Ok(signer)
  end
end
