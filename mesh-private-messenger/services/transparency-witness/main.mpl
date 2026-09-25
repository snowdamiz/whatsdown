from Transparency.Merkle import TransparencyCheckpoint, checkpoint_conflict, sign_witness, verify_checkpoint, verify_consistency
from Transparency.Wire import TransparencyTreeQuery, decode_checkpoint, decode_consistency_proof, encode_checkpoint, encode_transparency_tree_query, encode_witnesses

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
    |> Http.timeout(5000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

fn post(path :: String, body :: Bytes) -> HttpResponse!String do
  Http.build(:post, base_url()? <> path)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

fn fetch_checkpoint() -> Option<TransparencyCheckpoint>!String do
  let response = get("/v1/transparency/checkpoint")?
  if response.status == 404 do
    Ok(None)
  else if response.status != 200 do
    Err("checkpoint request returned #{response.status}")
  else
    Ok(Some(decode_checkpoint(response.body_bytes)?))
  end
end

fn cached_checkpoint(path :: String) -> Option<TransparencyCheckpoint>!String do
  if String.starts_with(path, "http://") || String.starts_with(path, "https://") do
    let request = Http.build(:get, path)
      |> Http.header("Accept-Encoding", "identity")
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
  else if !File.exists(path) do
    Ok(None)
  else
    case File.read(path) do
      Err(_) -> Err("witness checkpoint read failed")
      Ok(encoded) -> case Bytes.from_base64(encoded) do
        Err(_) -> Err("invalid cached witness checkpoint")
        Ok(bytes) -> Ok(Some(decode_checkpoint(bytes)?))
      end
    end
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
    let response = post("/v1/transparency/consistency",
      encode_transparency_tree_query(TransparencyTreeQuery { previous_tree_size: previous_size })?)?
    if response.status != 200 do
      Err("consistency request returned #{response.status}")
    else if verify_consistency(previous.tree_root,
      current.tree_root,
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
      |> Http.timeout(10000)
      |> Http.max_response_bytes(1024)
    let response = Http.send(request)?
    if response.status == 204 do
      Ok(nil)
    else
      Err("witness checkpoint write failed")
    end
  else
    save_local_checkpoint(path, value)
  end
end

fn save_local_checkpoint(path :: String, value :: TransparencyCheckpoint) -> Result<(), String> do
  case File.write(path, Bytes.to_base64(encode_checkpoint(value)?)) do
    Err(_) -> Err("witness checkpoint write failed")
    Ok(_) -> Ok(nil)
  end
end

fn witness_once() -> Result<(), String> do
  let witness_id = Env.get("MESSENGER_WITNESS_ID", "")
  let checkpoint_path = Env.get("MESSENGER_WITNESS_CHECKPOINT_PATH", "")
  if String.length(witness_id) == 0 || String.length(witness_id) > 64 || String.length(checkpoint_path) == 0 do
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
  let previous = cached_checkpoint(checkpoint_path)?
  case fetch_checkpoint()? do
    None -> case previous do
      None -> Ok(nil)
      Some(_) -> Err("checkpoint missing after initialization")
    end
    Some(checkpoint) -> if !verify_checkpoint(checkpoint, trusted_log_key)? do
      Err("transparency checkpoint signature failed")
    else
      case previous do
        None -> Ok(nil)
        Some(prior) -> if verify_checkpoint(prior, trusted_log_key)? do
          verify_history(prior, checkpoint, trusted_log_key)
        else
          Err("cached witness checkpoint signature failed")
        end
      end?
      # Commit continuity before releasing a signature; a failed publication can retry.
      save_checkpoint(checkpoint_path, previous, checkpoint)?
      let response = post("/v1/transparency/witnesses",
        encode_witnesses([sign_witness(witness_id, signer.private_key, checkpoint)?])?)?
      if response.status != 201 do
        Err("witness submission returned #{response.status}")
      else
        Ok(nil)
      end
    end
  end
end

fn main() do
  case witness_once() do
    Err(error) -> do
      io_eprintln("witness failed: #{error}")
      Process.exit(1)
    end
    Ok(_) -> println("witness check completed")
  end
end
