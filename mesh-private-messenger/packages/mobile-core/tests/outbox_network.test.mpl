from Mobile.OutboxNetwork import drain_outbox
from Mobile.Outbox import prepare_outbox_writes, load_outbox_ids, load_outbox_entry
from Mobile.PostageQueue import load_postage_queue, postage_queue_cache
from Mobile.Profile import load_profile
from Mobile.Codec import current_time, canonical_outer, mobile_join, mobile_vector
from MobileCore import create_account_export, erase_account_export
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Protocol.V1 import OuterEnvelope
from Protocol.EnvelopeWire import encode_outer_envelope
from Privacy.Edge import decode_privacy_submission, open_delivery, verify_submission
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_outbound, compare_and_swap_blobs, store_blobs
from Storage.Blobs import load_blob
from Transport.Packet import ClientProfile, decode_client_profile
from Tests.Support import database_path, repeated, install_security_config

fn configured(port :: Int) -> Bool do
  Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("2\n1\nhttp://127.0.0.1:20799\nhttp://127.0.0.1:"
      <> Int.to_string(port)
      <> "\nhttp://127.0.0.1:20899\nws://127.0.0.1:20999/v1/mailbox/stream\n8"))
end

fn outer(id :: Int, mailbox :: Int, expired :: Bool, full :: Bool) -> Bytes!String do
  let expiration = if expired do
    U64.subtract(current_time()?, U64.parse("1000")?)?
  else
    U64.add(current_time()?, U64.parse("2592000000")?)?
  end
  case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(id, 16)?,
    mailbox_token: repeated(mailbox, 32)?,
    suite: 1,
    expiration: expiration,
    padding_bucket: if full do
      65536
    else
      256
    end,
    ciphertext: repeated(42,
      if full do
        65536
      else
        32
      end)?
  }) do
    Err(_) -> Err("fixture outer")
    Ok(value)
  end
end

fn queue(path :: String, values :: List<Bytes>) -> Result<(), String> do
  let key = platform_key()?
  let profile = decode_client_profile(load_profile(path)?)?
  let (labels, blobs, index) = prepare_outbox_writes(key,
    load_outbox_ids(path, key)?,
    values,
    path,
    Bytes.empty(),
    0,
    0,
    profile)?
  let sessions = case load_blob(path, "sessions/v1") do
    Ok(value) -> value
    Err("local_state_not_found") -> Bytes.from_utf8("opaque fixture session index")
    Err(error) -> return Err(error)
  end
  store_outbound(path, [], [], sessions, [], [], labels, blobs, index)
end

fn received(path :: String) -> List<String> do
  case File.read(path <> ".received") do
    Err(_) -> []
    Ok(value) -> List.filter(String.split(value, "\n"), fn(row) -> row != "" end)
  end
end

fn reply(input :: Request, path :: String, seed :: Bytes, mode :: Int) -> Response!String do
  if Request.header(input, "authorization") != None || Request.header(input, "cookie") != None do
    return Ok(HTTP.response(500, "private header"))
  end
  let bytes = Request.body_bytes(input)
  let valid = case verify_submission(bytes, current_time()?, U64.parse("300000")?, 8) do
    Ok(value) -> value
    Err(_) -> false
  end
  if !valid do
    return Ok(HTTP.response(400, "invalid work"))
  end
  let submission = case decode_privacy_submission(bytes) do
    Err(_) -> return Ok(HTTP.response(400, "invalid submission"))
    Ok(value) -> value
  end
  let wire = case open_delivery(submission.sealed, seed) do
    Err(_) -> return Ok(HTTP.response(400, "invalid sealed delivery"))
    Ok(value) -> value
  end
  let envelope = case canonical_outer(wire) do
    Err(_) -> return Ok(HTTP.response(400, "invalid outer"))
    Ok(value) -> value
  end
  let key = case platform_key() do
    Err(_) -> return Ok(HTTP.response(500, "fixture storage"))
    Ok(value) -> value
  end
  let saved = case load_outbox_entry(path, key, envelope.envelope_id) do
    Err(_) -> return Ok(HTTP.response(409, "not durable"))
    Ok(value) -> value
  end
  if !Bytes.secure_equals(saved, wire) do
    return Ok(HTTP.response(409, "replaced outer"))
  end
  let prior = received(path)
  let id = Bytes.to_hex(envelope.envelope_id)
  case File.write(path <> ".received", String.join(prior ++ [id], "\n")) do
    Err(_) -> return Ok(HTTP.response(500, "fixture counter"))
    Ok(_) -> nil
  end
  if (mode == 1 || mode == 13)
    && Bytes.get(envelope.mailbox_token, 0)? == 1
    && !File.exists(path <> ".allow") do
    return Ok(HTTP.response(402, ""))
  end
  if mode == 2 && Bytes.get(envelope.mailbox_token, 0)? == 1 do
    return Ok(HTTP.response(429, ""))
  end
  if mode == 3 && !List.contains(prior, id) do
    return Ok(HTTP.response(503, ""))
  end
  if mode == 4 do
    return Ok(HTTP.response(400, ""))
  end
  if mode == 5 && List.length(prior) == 0 do
    return Ok(HTTP.response(410, ""))
  end
  if mode == 6 do
    return Ok(HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/evil")))
  end
  if mode == 7 do
    return Ok(HTTP.response(202, String.repeat("x", 1025)))
  end
  if mode == 8 || mode == 9 || mode == 14 do
    case erase_account_export(Bytes.from_utf8(path)) do
      Err(_) -> return Ok(HTTP.response(500, "fixture erase"))
      Ok(_) -> nil
    end
    if mode == 9 do
      case create_account_export(mobile_join([
          mobile_vector(Bytes.from_utf8(path))?,
          mobile_vector(Bytes.from_utf8("replacement"))?
        ],
        0,
        Bytes.empty())?) do
        Err(_) -> return Ok(HTTP.response(500, "fixture replace"))
        Ok(_) -> nil
      end
    end
  end
  if mode == 14 do
    return Ok(HTTP.response(402, ""))
  end
  if mode == 10 do
    configured(20799)
  end
  if mode == 11 do
    let before = case load_postage_queue(path, key) do
      Err(_) -> return Ok(HTTP.response(500, "fixture queue"))
      Ok(value) -> value
    end
    let cache = case postage_queue_cache(before,
      repeated(41, 32)?,
      load_outbox_ids(path, key)?,
      key) do
      Err(_) -> return Ok(HTTP.response(500, "fixture ownership"))
      Ok(value) -> value
    end
    case compare_and_swap_blobs(path, [cache.label], [cache.value], cache.previous) do
      Err(_) -> return Ok(HTTP.response(500, "fixture ownership commit"))
      Ok(_) -> nil
    end
  end
  if mode == 12 && List.length(prior) == 0 do
    case queue(path, [outer(99, 9, false, false)?]) do
      Err(_) -> return Ok(HTTP.response(500, "fixture append"))
      Ok(_) -> nil
    end
  end
  Ok(HTTP.response(202, ""))
end

actor peer(port :: Int, path :: String, seed :: Bytes, mode :: Int) do
  HTTP.router()
    |> HTTP.on_post("/v1/envelopes/batch",
      fn(input) do
        case reply(input, path, seed, mode) do
          Ok(value) -> value
          Err(error) -> do
            println("fixture handler: #{error}")
            HTTP.response(500, "fixture error")
          end
        end
      end)
    |> HTTP.on_post("/evil",
      fn(_) do
        File.write(path <> ".evil", "followed")
        HTTP.response(202, "")
      end)
    |> HTTP.serve(port)
end

fn run_case(port :: Int, mode :: Int) -> Result<(), String> do
  let path = database_path("outbox_native")?
  create_account_export(mobile_join([
      mobile_vector(Bytes.from_utf8(path))?,
      mobile_vector(Bytes.from_utf8("alice"))?
    ],
    0,
    Bytes.empty())?)?
  let values = if mode == 0 do
    for index in 1..13 do
      outer(index, 1, false, index == 1)?
    end
  else if mode == 4 do
    [outer(1, 1, true, false)?, outer(2, 2, false, false)?]
  else if mode == 12 || mode == 13 do
    [outer(1, 1, false, false)?]
  else
    [outer(1, 1, false, false)?, outer(2, 1, false, false)?, outer(3, 2, false, false)?]
  end
  queue(path, values)?
  if mode == 13 do
    let old = for index in 0..256 do
      Bytes.concat(repeated(index, 31)?, Bytes.from_hex("fe")?)?
    end
    let key = platform_key()?
    let label = "outbox-postage-pauses/v1"
    store_blobs(path, [label], [seal_local(pack_credit_parts(old)?, key, local_context(label)?)?])?
  end
  let seed = repeated(15, 32)?
  let pair = case Crypto.x25519_from_seed(seed) do
    Ok(value) -> value
    Err(_) -> return Err("fixture delivery key")
  end
  let signing = signing_pair()?
  let witness_a = signing_pair()?
  let witness_b = signing_pair()?
  assert(install_security_config(signing.public_key.bytes,
    witness_a.public_key.bytes,
    witness_b.public_key.bytes,
    pair.public_key.bytes,
    8))
  assert(configured(port))
  let _server = spawn(peer, port, path, seed, mode)
  Timer.sleep(100)
  if mode == 8 || mode == 9 || mode == 10 || mode == 14 do
    assert(Result.is_err(drain_outbox(path, false)))
    if mode == 8 || mode == 9 || mode == 14 do
      assert(Result.is_err(load_blob(path, "outbox/v1")))
      assert(Result.is_err(load_blob(path, "outbox-postage-pauses/v1")))
    else
      assert(List.length(load_outbox_ids(path, platform_key()?)?) == 3)
    end
  else
    let first = drain_outbox(path, false)?
    if mode == 0 do
      assert(first.accepted == 12 && first.remaining == 0 && first.status == 0)
      assert(List.length(received(path)) == 12)
    else if mode == 1 do
      assert(first.accepted == 1 && first.remaining == 2 && List.length(first.postage) == 2)
      assert(List.length(received(path)) == 2)
      let reopened = drain_outbox(path, false)?
      assert(reopened.accepted == 0
        && reopened.remaining == 2
        && List.length(reopened.postage) == 2)
      assert(List.length(received(path)) == 2)
      File.write(path <> ".allow", "explicit retry")?
      let retried = drain_outbox(path, true)?
      assert(retried.accepted == 2 && retried.remaining == 0)
      assert(List.length(received(path)) == 4)
    else if mode == 2 do
      assert(first.accepted == 1 && first.remaining == 2 && first.status == 1)
      assert(List.length(received(path)) == 2)
      assert(List.head(received(path)) == Bytes.to_hex(canonical_outer(List.head(values))?.envelope_id))
    else if mode == 3 do
      assert(first.accepted == 0 && first.remaining == 3 && first.status == 2)
      let second = drain_outbox(path, false)?
      assert(second.accepted == 1 && second.remaining == 2 && second.status == 2)
      let third = drain_outbox(path, false)?
      assert(third.accepted == 1 && third.remaining == 1 && third.status == 2)
      let fourth = drain_outbox(path, false)?
      assert(fourth.accepted == 1 && fourth.remaining == 0 && fourth.status == 0)
    else if mode == 4 do
      assert(List.length(first.failures) == 1 && List.head(first.failures).status == 400)
      assert(first.remaining == 1 && first.status == 2)
    else if mode == 5 do
      assert(List.length(first.failures) == 1 && List.head(first.failures).status == 410)
      assert(first.accepted == 2 && first.remaining == 0)
    else if mode == 6 || mode == 7 do
      assert(first.remaining == 3 && first.accepted == 0 && first.status == 2)
      assert(!File.exists(path <> ".evil"))
    else if mode == 11 do
      assert(first.accepted == 0 && first.remaining == 0)
      assert(List.length(load_outbox_ids(path, platform_key()?)?) == 3)
    else if mode == 13 do
      assert(first.accepted == 0 && first.remaining == 1 && List.length(first.postage) == 1)
      assert(List.length(received(path)) == 1)
      let repeated = drain_outbox(path, false)?
      assert(List.length(repeated.postage) == 1 && List.length(received(path)) == 1)
    else if mode == 12 do
      assert(first.accepted == 1 && first.remaining == 1)
      let following = drain_outbox(path, false)?
      assert(following.accepted == 1 && following.remaining == 0)
    end
  end
  Timer.sleep(30)
  erase_account_export(Bytes.from_utf8(path))?
  File.delete(path)?
  for suffix in [".received", ".allow", ".evil"] do
    if File.exists(path <> suffix) do
      File.delete(path <> suffix)?
    end
  end
  Ok(nil)
end

fn proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  for mode in 0..15 do
    println("outbox case #{mode}")
    run_case(20700 + mode, mode)?
  end
  Ok(nil)
end

test("native outbox keeps durable pause, ordering, exact retries and guarded acknowledgements") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Ok(value)
    Err(_) -> Err("fixture signing key")
  end
end
