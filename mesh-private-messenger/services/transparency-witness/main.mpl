from Witness.State import read_local_checkpoint, save_local_checkpoint, save_local_evidence
from Witness.History import verify_history_header, verify_history_proof
from Witness.Policy import WitnessPolicy, configured_policy
from Transparency.Migration import encode_bridge_query, decode_legacy_bridge, verify_legacy_bridge
from Transparency.Merkle import (
  TransparencyCheckpoint,
  checkpoint_conflict,
  sign_witness,
  verify_checkpoint,
  verify_consistency
)
from Transparency.Wire import (
  TransparencyTreeQuery,
  decode_checkpoint,
  decode_consistency_proof,
  encode_checkpoint,
  encode_transparency_tree_query,
  encode_witnesses
)

fn configured_public_key(name :: String) -> Bytes!String do
  case Bytes.from_hex(Env.get(name, "")) do
    Err(_) -> Err("invalid witness configuration")
    Ok(value) -> if Bytes.length(value) == 32 do
      Ok(value)
    else
      Err("invalid witness configuration")
    end
  end
end

fn configured_signer() -> SigningKeyPair!String do
  let material = case Env.get_secret_hex("MESSENGER_WITNESS_SIGNING_SEED_HEX") do
    Err(_) -> Err("invalid witness signing seed")
    Ok(value)
  end?
  case Crypto.signing_from_secret(material) do
    Err(_) -> Err("invalid witness signing seed")
    Ok(signer)
  end
end

fn base_url() -> String!String do
  let value = Env.get("MESSENGER_BASE_URL", "")
  if String.length(value) == 0 do
    Err("missing MESSENGER_BASE_URL")
  else
    Ok(value)
  end
end

fn get(path :: String) -> HttpResponse!String do
  Http.build(:get, base_url()? <> path)
    |> Http.max_redirects(0)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

fn post(path :: String, body :: Bytes) -> HttpResponse!String do
  let maximum = if path == "/v2/transparency/legacy-bridge" do
    4942
  else
    600000
  end
  let content_type = if path == "/v1/transparency/witnesses"
    || path == "/v2/transparency/witnesses" do
    "application/x-morse-attestation"
  else
    "application/octet-stream"
  end
  Http.build(:post, base_url()? <> path)
    |> Http.header("Content-Type", content_type)
    |> Http.body_bytes(body)
    |> Http.max_redirects(0)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(maximum)
    |> Http.send()
end

fn fetch_checkpoint_for(version :: Int) -> Option<TransparencyCheckpoint>!String do
  let response = get("/v#{version}/transparency/checkpoint")?
  if response.status == 404 do
    Ok(None)
  else if response.status != 200 do
    Err("checkpoint request returned #{response.status}")
  else
    let checkpoint = decode_checkpoint(response.body_bytes)?
    if checkpoint.version != version do
      Err("checkpoint log version mismatch")
    else
      Ok(Some(checkpoint))
    end
  end
end

fn fetch_checkpoint(previous :: Option<TransparencyCheckpoint>,
  policy :: WitnessPolicy) -> Option<TransparencyCheckpoint>!String do
  let previous_version = case previous do
    None -> 0
    Some(value) -> value.version
  end
  if previous_version > policy.log_version do
    return Err("unsupported_transparency_log")
  end
  case fetch_checkpoint_for(policy.log_version)? do
    Some(value) -> Ok(Some(value))
    None -> if policy.log_version == 2 && previous_version != 2 do
      fetch_checkpoint_for(1)
    else
      Ok(None)
    end
  end
end

fn cached_checkpoint(path :: String) -> Option<TransparencyCheckpoint>!String do
  if String.starts_with(path, "http://") || String.starts_with(path, "https://") do
    let request = Http.build(:get, path)
      |> Http.header("Accept-Encoding", "identity")
      |> Http.max_redirects(0)
      |> Http.timeout(10000)
      |> Http.max_response_bytes(4096)
    let response = Http.send(request)?
    if response.status == 404 do
      Ok(None)
    else if response.status == 200 do
      Ok(Some(decode_checkpoint(response.body_bytes)?))
    else
      Err("witness checkpoint read failed")
    end
  else
    read_local_checkpoint(path)
  end
end

fn verify_history(previous :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint,
  trusted_log_key :: SigningPublicKey) -> Result<(), String> do
  let previous_size = U64.to_int(previous.tree_size)?
  let current_size = U64.to_int(current.tree_size)?
  if current_size < previous_size || U64.compare(current.sequence, previous.sequence) < 0 do
    Err("transparency log rolled back")
  else if U64.compare(current.sequence, previous.sequence) == 0 do
    if checkpoint_conflict(previous, current, trusted_log_key)? do
      Err("transparency checkpoint conflict")
    else if Bytes.secure_equals(previous.tree_root, current.tree_root) do
      Ok(nil)
    else
      Err("transparency checkpoint changed")
    end
  else
    let response = post("/v#{current.version}/transparency/consistency",
      encode_transparency_tree_query(TransparencyTreeQuery {
        new_tree_size: current_size,
        previous_tree_size: previous_size
      })?)?
    if response.status != 200 do
      Err("consistency request returned #{response.status}")
    else if verify_history_proof(previous,
      current,
      decode_consistency_proof(response.body_bytes)?)? do
      Ok(nil)
    else
      Err("transparency consistency verification failed")
    end
  end
end

fn save_checkpoint(path :: String,
  previous :: Option<TransparencyCheckpoint>,
  value :: TransparencyCheckpoint) -> Result<(), String> do
  if String.starts_with(path, "http://") || String.starts_with(path, "https://") do
    let expected = case previous do
      None -> "none"
      Some(prior) -> Bytes.to_hex(Crypto.sha256(encode_checkpoint(prior)?))
    end
    let request = Http.build(:put, path)
      |> Http.header("Accept-Encoding", "identity")
      |> Http.header("If-Match", expected)
      |> Http.body_bytes(encode_checkpoint(value)?)
      |> Http.max_redirects(0)
      |> Http.timeout(10000)
      |> Http.max_response_bytes(1024)
    let response = Http.send(request)?
    if response.status == 204 do
      Ok(nil)
    else
      Err("witness checkpoint write failed")
    end
  else
    save_local_checkpoint(path, previous, value)
  end
end

fn previous_checkpoint(path :: String,
  trusted :: SigningPublicKey) -> Option<TransparencyCheckpoint>!String do
  let stored = cached_checkpoint(path)?
  if String.starts_with(path, "http://") || String.starts_with(path, "https://") do
    return Ok(stored)
  end
  case stored do
    Some(_) -> Ok(stored)
    None -> do
      let initial = Env.get("WITNESS_INITIAL_CHECKPOINT_HEX", "")
      if initial == "new-identity" do
        Ok(None)
      else
        let bytes = case Bytes.from_hex(initial) do
          Err(_) -> return Err("witness requires explicit checkpoint transfer")
          Ok(value) -> value
        end
        if Bytes.length(bytes) != 188 || Bytes.to_hex(bytes) != initial do
          return Err("witness requires explicit checkpoint transfer")
        end
        let checkpoint = decode_checkpoint(bytes)?
        if !verify_checkpoint(checkpoint, trusted)? do
          return Err("initial checkpoint signature failed")
        end
        save_local_checkpoint(path, None, checkpoint)?
        Ok(Some(checkpoint))
      end
    end
  end
end

fn checked_history(previous :: Option<TransparencyCheckpoint>,
  current :: TransparencyCheckpoint,
  trusted :: SigningPublicKey,
  now :: U64,
  policy :: WitnessPolicy) -> Result<(), String> do
  case previous do
    Some(prior) -> if prior.version == 1 && current.version == 2 && policy.log_version == 2 do
      # The first RFC checkpoint starts its own sequence and tree. Authenticate
      # its freshness, then the sealed old prefix and inclusion of that seal.
      verify_history_header(None, current, trusted, now)?
      let response = post("/v2/transparency/legacy-bridge",
        encode_bridge_query(U64.to_int(prior.tree_size)?, U64.to_int(current.tree_size)?)?)?
      if response.status != 200 do
        return Err("legacy bridge request returned #{response.status}")
      end
      let bridge = decode_legacy_bridge(response.body_bytes)?
      if !verify_legacy_bridge(current,
        bridge,
        trusted,
        policy.legacy_keys,
        policy.legacy_threshold,
        encode_checkpoint(prior)?)? do
        return Err("legacy bridge verification failed")
      end
      return Ok(nil)
    end
    None -> nil
  end
  verify_history_header(previous, current, trusted, now)?
  case previous do
    None -> Ok(nil)
    Some(prior) -> verify_history(prior, current, trusted)
  end
end

fn capture_rejection(path :: String,
  previous :: Option<TransparencyCheckpoint>,
  current :: TransparencyCheckpoint,
  error :: String) -> Result<(), String> do
  let prior = case previous do
    None -> "null"
    Some(value) -> Json.encode_string(Bytes.to_hex(encode_checkpoint(value)?))
  end
  let evidence = "{\"version\":1,\"previous\":"
    <> prior
    <> ",\"current\":"
    <> Json.encode_string(Bytes.to_hex(encode_checkpoint(current)?))
    <> ",\"error\":"
    <> Json.encode_string(error)
    <> "}"
  let slot = if error == "transparency checkpoint clock skew"
    || error == "transparency checkpoint timestamp did not advance" do
    "timing"
  else
    "history"
  end
  if String.starts_with(path, "http://") || String.starts_with(path, "https://") do
    let separator = if String.ends_with(path, "/") do
      ""
    else
      "/"
    end
    let response = Http.build(:put, path <> separator <> "evidence/" <> slot)
      |> Http.header("Content-Type", "application/json")
      |> Http.body_bytes(Bytes.from_utf8(evidence))
      |> Http.max_redirects(0)
      |> Http.timeout(10000)
      |> Http.max_response_bytes(1024)
      |> Http.send()?
    if response.status != 204 do
      Err("witness evidence write failed")
    else
      Ok(nil)
    end
  else
    save_local_evidence(path <> ".evidence-" <> slot <> ".json", evidence)
  end
end

fn witness_once() -> Result<(), String> do
  let witness_id = Env.get("MESSENGER_WITNESS_ID", "")
  let checkpoint_path = Env.get("MESSENGER_WITNESS_CHECKPOINT_PATH", "")
  if String.length(witness_id) == 0
    || String.length(witness_id) > 64
    || String.length(checkpoint_path) == 0 do
    return Err("invalid witness configuration")
  end
  let trusted_log_key = SigningPublicKey {
    bytes: configured_public_key("MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX")?
  }
  let signer = configured_signer()?
  if !Bytes.secure_equals(signer.public_key.bytes,
    configured_public_key("MESSENGER_WITNESS_PUBLIC_KEY_HEX")?) do
    return Err("witness signing key does not match pinned public key")
  end
  let previous = previous_checkpoint(checkpoint_path, trusted_log_key)?
  let policy = configured_policy(trusted_log_key)?
  case fetch_checkpoint(previous, policy)? do
    None -> case previous do
      None -> Ok(nil)
      Some(_) -> Err("checkpoint missing after initialization")
    end
    Some(checkpoint) -> if !verify_checkpoint(checkpoint, trusted_log_key)? do
      Err("transparency checkpoint signature failed")
    else
      let now = U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?
      case checked_history(previous, checkpoint, trusted_log_key, now, policy) do
        Ok(_) -> nil
        Err(error) -> do
          capture_rejection(checkpoint_path, previous, checkpoint, error)?
          return Err(error)
        end
      end
      # Commit continuity before releasing a signature; a failed publication can retry.
      save_checkpoint(checkpoint_path, previous, checkpoint)?
      let response = post("/v#{checkpoint.version}/transparency/witnesses",
        encode_witnesses([sign_witness(witness_id, signer.private_key, checkpoint)?])?)?
      if response.status != 201 do
        Err("witness submission returned #{response.status}")
      else
        Ok(nil)
      end
    end
  end
end

fn wait_for_poll(remaining :: Int) do
  if remaining > 0 && !Process.shutdown_requested() do
    Timer.sleep(250)
    wait_for_poll(remaining - 250)
  end
end

fn main() do
  let mode = Env.get("MESSENGER_WITNESS_MODE", "once")
  if mode != "once" && mode != "pull" do
    io_eprintln("MESSENGER_WITNESS_MODE must be once or pull")
    Process.exit(1)
  end
  if mode == "pull" do
    Process.install_shutdown_signals()
    while !Process.shutdown_requested() do
      case witness_once() do
        Err(error) -> io_eprintln("witness failed: #{error}")
        Ok(_) -> println("witness check completed")
      end
      wait_for_poll(15000)
    end
  else
    case witness_once() do
      Err(error) -> do
        io_eprintln("witness failed: #{error}")
        Process.exit(1)
      end
      Ok(_) -> println("witness check completed")
    end
  end
end
