from Api.Binary import BinaryResult, submit_request
from Api.Gateway import ohttp_gateway_answer_with_key
from Api.Router import build_router
from Privacy.Bhttp import BhttpResponse, bhttp_decode_response
from Privacy.Edge import encode_stamped_request, mint_request_stamp
from Privacy.Ohttp import OhttpContext, ohttp_decapsulate_response, ohttp_encapsulate_request
from Privacy.OhttpWire import OhttpKeyConfig, ohttp_request_message
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.MailboxWire import decode_delivery_batch
from Protocol.V1 import OuterEnvelope
from Runtime.OhttpStrikes import ohttp_strikes_start
from Runtime.Registry import start_registry
from Tests.MailboxSupport import mailbox_test_now, register_test_mailbox, signed_ack, signed_fetch
from Transparency.CompactWire import transparency_encode_lookup_v2
from Transparency.Wire import TransparencyLookup

fn repeated(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("repeat failed")
    Ok(bytes)
  end
end

fn now_ms() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn reset(pool :: PoolHandle) -> Result<(), String> do
  Pool.execute(pool,
    "TRUNCATE messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
    [])?
  Ok(nil)
end

fn gateway_pair() -> X25519KeyPair!String do
  case Crypto.x25519_from_seed(Bytes.from_hex("3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a")?) do
    Err(_) -> Err("gateway key failed")
    Ok(pair)
  end
end

# A phone's request through the gateway, as the relay would forward it:
# (the relayed bytes, the gateway's outer answer, the inner response).

fn exchange(pair :: borrow X25519KeyPair,
  method :: String,
  path :: String,
  body :: Bytes) -> (Bytes, BinaryResult, BhttpResponse)!String do
  let config = OhttpKeyConfig { key_id: 1, public_key: pair.public_key.bytes }
  let (relayed, context) = ohttp_encapsulate_request(config,
    ohttp_request_message(method, path, body)?)?
  let outer = ohttp_gateway_answer_with_key(1, pair.private_key, relayed, now_ms())
  if outer.status != 200 do
    Err("gateway answered #{outer.status}")
  else
    let inner = bhttp_decode_response(ohttp_decapsulate_response(context, outer.body)?)?
    Ok((relayed, outer, inner))
  end
end

fn inner_status(pair :: borrow X25519KeyPair,
  method :: String,
  path :: String,
  body :: Bytes) -> Int!String do
  let (_, _, inner) = exchange(pair, method, path, body)?
  Ok(inner.status)
end

fn deliveries(response :: BhttpResponse) -> Int!String do
  case decode_delivery_batch(response.content) do
    Err(_) -> Err("invalid delivery batch")
    Ok(values) -> Ok(List.length(values))
  end
end

fn stamped_lookup(username :: String) -> Bytes!String do
  let lookup = transparency_encode_lookup_v2(TransparencyLookup {
    username: username,
    previous_tree_size: 0
  })?
  let expires_at = U64.add(mailbox_test_now()?, U64.parse("240000")?)?
  encode_stamped_request(mint_request_stamp("mesh-msg/v1/work/resolve",
      lookup,
      expires_at,
      Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16))?,
    lookup)
end

fn mailbox_proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
    "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000)?
  reset(pool)?
  start_registry(pool)
  ohttp_strikes_start()
  let pair = gateway_pair()?
  let token = repeated(3, 32)?
  let owner = register_test_mailbox(pool, "device-b", token)?
  let envelope_id = repeated(4, 16)?
  let envelope = case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: envelope_id,
    mailbox_token: token,
    suite: 4,
    expiration: U64.add(mailbox_test_now()?, U64.parse("86400000")?)?,
    padding_bucket: 256,
    ciphertext: Bytes.from_utf8("opaque ciphertext")
  }) do
    Err(_) -> Err("envelope encoding failed")
    Ok(value)
  end?
  assert(submit_request(pool, envelope).status == 202)
  # The signed fetch goes through the gateway: the relay forwards only
  # ciphertext, and the phone gets the batch back.
  let fetch = signed_fetch(owner, token)?
  let config = OhttpKeyConfig { key_id: 1, public_key: pair.public_key.bytes }
  let (relayed, context) = ohttp_encapsulate_request(config,
    ohttp_request_message("POST", "/v1/mailbox/fetch", fetch)?)?
  assert(!String.contains(Bytes.to_hex(relayed), Bytes.to_hex(fetch)))
  assert(!String.contains(Bytes.to_hex(relayed), Bytes.to_hex(Bytes.from_utf8("/v1/mailbox"))))
  let outer = ohttp_gateway_answer_with_key(1, pair.private_key, relayed, now_ms())
  assert(outer.status == 200)
  assert(!String.contains(Bytes.to_hex(outer.body),
    Bytes.to_hex(Bytes.from_utf8("opaque ciphertext"))))
  let fetched = bhttp_decode_response(ohttp_decapsulate_response(context, outer.body)?)?
  assert(fetched.status == 200 && deliveries(fetched)? == 1)
  # The same encapsulated request again is refused: a relay can't replay a
  # phone's fetch to watch its mailbox.
  let replayed = ohttp_gateway_answer_with_key(1, pair.private_key, relayed, now_ms())
  assert(replayed.status == 200)
  let refused = bhttp_decode_response(ohttp_decapsulate_response(context, replayed.body)?)?
  assert(refused.status == 409 && Bytes.length(refused.content) == 0)
  # Acknowledged through the gateway, the mailbox is empty.
  assert(inner_status(pair,
    "POST",
    "/v1/mailbox/ack",
    signed_ack(owner, token, [envelope_id])?)? == 200)
  let (_, _, after_ack) = exchange(pair, "POST", "/v1/mailbox/fetch", signed_fetch(owner, token)?)?
  assert(deliveries(after_ack)? == 0)
  # Only the served routes: not registration, not an internal route, no
  # query on a route that takes none.
  assert(inner_status(pair, "PUT", "/v1/devices/register", Bytes.from_utf8("x"))? == 404)
  assert(inner_status(pair, "POST", "/internal/v1/envelopes/sealed", Bytes.from_utf8("x"))? == 404)
  assert(inner_status(pair, "POST", "/v1/mailbox/fetch?x=1", fetch)? == 404)
  # A lookup keeps its proof of work: a fresh stamp is answered (this name
  # doesn't exist), the same stamp in a new encapsulation is spent.
  let lookup = stamped_lookup("nobody")?
  assert(inner_status(pair, "POST", "/v1/devices/resolve", lookup)? == 404)
  assert(inner_status(pair, "POST", "/v1/devices/resolve", lookup)? == 429)
  assert(inner_status(pair, "POST", "/v1/devices/resolve", Bytes.from_utf8("unstamped"))? == 400)
  Pool.close(pool)
  Ok(true)
end

test("the gateway answers a relayed fetch, ack and lookup, and refuses replays") do
  case mailbox_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn refusal_proof() -> Bool!String do
  let pair = gateway_pair()?
  let config = OhttpKeyConfig { key_id: 1, public_key: pair.public_key.bytes }
  let (relayed, _) = ohttp_encapsulate_request(config,
    ohttp_request_message("POST", "/v1/mailbox/fetch", Bytes.from_utf8("x"))?)?
  # Another key id, another key, or a short frame: answered bare, so the
  # relay learns only that the request couldn't be opened.
  let other = OhttpKeyConfig { key_id: 2, public_key: pair.public_key.bytes }
  let (wrong_id, _) = ohttp_encapsulate_request(other, Bytes.from_utf8("x"))?
  assert(ohttp_gateway_answer_with_key(1, pair.private_key, wrong_id, now_ms()).status == 422)
  let stranger = case Crypto.x25519_generate() do
    Err(_) -> Err("key failed")
    Ok(value)
  end?
  assert(ohttp_gateway_answer_with_key(1, stranger.private_key, relayed, now_ms()).status == 422)
  assert(ohttp_gateway_answer_with_key(1,
    pair.private_key,
    Bytes.from_utf8("short"),
    now_ms()).status == 400)
  Ok(true)
end

test("requests for another key or cut short are refused before anything is read") do
  ohttp_strikes_start()
  case refusal_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

actor gateway_router() do
  build_router()
    |> HTTP.serve(18993)
end

test("the gateway route needs the edge's bearer, and publishes no key it doesn't hold") do
  let _server = spawn(gateway_router)
  Timer.sleep(100)
  case Http.build(:post, "http://127.0.0.1:18993/internal/v1/ohttp")
    |> Http.body_bytes(Bytes.from_utf8("encapsulated"))
    |> Http.send() do
    Err(_) -> assert(false)
    Ok(response) -> assert(response.status == 401 || response.status == 503)
  end
  # These tests run without MESSENGER_OHTTP_GATEWAY_KEY_ID: no key, none listed.
  case Http.build(:get, "http://127.0.0.1:18993/v1/ohttp/keys")
    |> Http.send() do
    Err(_) -> assert(false)
    Ok(response) -> assert(response.status == 404)
  end
  Process.request_shutdown()
end
