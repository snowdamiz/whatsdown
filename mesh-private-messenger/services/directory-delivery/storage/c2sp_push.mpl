from Storage.Transparency import (
  polled_checkpoint_for,
  configured_note_for,
  consistency_between_for,
  store_c2sp_response
)
from Storage.WitnessRegistry import RegisteredWitness, registered_profile
from Transparency.C2sp import note_key_id
from Transparency.Merkle import TransparencyCheckpoint, ConsistencyProof

fn push_body(pool :: PoolHandle,
  checkpoint :: TransparencyCheckpoint,
  note :: Bytes,
  old_size :: Int) -> Bytes!String do
  let proof = consistency_between_for(pool, 2, old_size, U64.to_int(checkpoint.tree_size)?)?
  let hashes = String.join(for hash in proof.leaf_hashes do
      Bytes.to_base64(hash) <> "\n"
    end,
    "")
  Bytes.concat(Bytes.from_utf8("old #{old_size}\n" <> hashes <> "\n"), note)
end

fn retry_size(body :: Bytes, maximum :: Int) -> Int!String do
  if Bytes.length(body) < 2 || Bytes.length(body) > 11 do
    return Err("invalid C2SP witness size")
  end
  let value = Bytes.to_utf8(body)?
  let number = case String.to_int(String.trim(value)) do
    None -> return Err("invalid C2SP witness size")
    Some(value) -> value
  end
  if number < 0 || number > maximum || value != "#{number}\n" do
    Err("invalid C2SP witness size")
  else
    Ok(number)
  end
end

fn post_note(endpoint :: String, body :: Bytes) -> HttpResponse!String do
  Http.build(:post, endpoint)
    |> Http.header("Content-Type", "text/plain; charset=utf-8")
    |> Http.body_bytes(body)
    |> Http.max_redirects(0)
    |> Http.timeout(8000)
    |> Http.max_response_bytes(196608)
    |> Http.send()
end

fn registered(pool :: PoolHandle, id :: String) -> RegisteredWitness!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let value = case registered_profile(conn, id)? do
        None -> return Err("untrusted witness")
        Some(value) -> value
      end
      if value.software != "c2sp" || value.push_url == "" do
        return Err("witness is not configured for C2SP push")
      end
      note_key_id(value.note_name, 4, value.key.public_key)?
      Ok(value)
    end)
end

fn push_to(pool :: PoolHandle, id :: String, endpoint :: String) -> Result<(), String> do
  if Env.get("MORSE_C2SP_PUSH", "off") != "on" do
    return Err("C2SP push disabled")
  end
  let checkpoint = case polled_checkpoint_for(pool, 2)? do
    None -> return Err("transparency_v2_not_active")
    Some(value) -> value
  end
  let note = configured_note_for(checkpoint)?
  let first = post_note(endpoint, push_body(pool, checkpoint, note, 0)?)?
  let response = if first.status == 409 do
    let old_size = retry_size(first.body_bytes, U64.to_int(checkpoint.tree_size)?)?
    # One retry only. A witness that advanced again will be retried by the job
    # with a new checkpoint, never by an unbounded request-controlled loop.
    post_note(endpoint, push_body(pool, checkpoint, note, old_size)?)?
  else
    first
  end
  if response.status != 200 do
    return Err("C2SP witness returned #{response.status}")
  end
  store_c2sp_response(pool, id, checkpoint, response.body_bytes)
end

pub fn push_registered_c2sp(pool :: PoolHandle, id :: String) -> Result<(), String> do
  let value = registered(pool, id)?
  let origin = Http.url_origin(value.push_url)?
  if !String.starts_with(origin, "https://")
    || !String.starts_with(value.push_url, origin <> "/")
    || String.contains(value.push_url, "?")
    || String.contains(value.push_url, "#") do
    return Err("invalid C2SP witness URL")
  end
  push_to(pool, id, value.push_url)
end

# Standard push witnesses cannot refresh an idle log themselves. Once RFC is
# active, the durable scheduler polls it and refreshes cosignatures every 15 s.
# The normal checkpoint policy decides whether a new checkpoint is needed.
pub fn witness_job_deadline(pool :: PoolHandle) -> Int!String do
  case polled_checkpoint_for(pool, 2)? do
    None -> Ok(0)
    Some(_) -> Ok(DateTime.to_unix_ms(DateTime.utc_now()) + 15000)
  end
end
