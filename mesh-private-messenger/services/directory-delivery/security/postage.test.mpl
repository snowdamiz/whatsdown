from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  generate_account,
  generate_device,
  issue_device_credential
)
from Prekeys.Bundle import build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey
from Protocol.IdentityWire import encode_account_identity
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import AccountIdentity, DirectoryEntry, ProtocolExtension
from Credits.PostagePolicy import (
  postage_policy_from_device_set,
  sign_postage_policy,
  encode_postage_policy
)
from Storage.CreditPostagePolicy import publish_postage_policy
from Storage.Delivery import enqueue_envelope, DeliveryInsert
from Storage.ContactAddress import publish_contact_address, ContactAddressWrite
from Protocol.V1 import OuterEnvelope
from Storage.Devices import register_device, resolve_devices, DeviceWrite

fn bytes(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("test bytes failed")
    Ok(value)
  end
end

fn now() -> U64!String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn entry(owner :: borrow AccountKeys,
  identity :: AccountIdentity,
  device :: borrow DeviceKeys,
  sequence :: String,
  token :: Int) -> DirectoryEntry!String do
  let created = now()?
  let expires = U64.add(created, U64.parse("86400000")?)?
  let credential = case issue_device_credential(owner,
    device,
    U64.parse("1")?,
    created,
    expires,
    U64.parse(sequence)?) do
    Err(_) -> return Err("test credential failed")
    Ok(value) -> value
  end
  let signed = case generate_signed_prekey(device, credential, U64.parse("1")?, expires) do
    Err(_) -> return Err("test prekey failed")
    Ok(value) -> value
  end
  let once = case generate_one_time_prekey(U64.parse("1")?) do
    Err(_) -> return Err("test prekey failed")
    Ok(value) -> value
  end
  let bundle = case build_prekey_bundle(credential, signed, once) do
    Err(_) -> return Err("test bundle failed")
    Ok(value) -> value
  end
  let account_bytes = case encode_account_identity(identity) do
    Err(_) -> return Err("test identity failed")
    Ok(value) -> value
  end
  let bundle_bytes = case encode_prekey_bundle(bundle) do
    Err(_) -> return Err("test bundle failed")
    Ok(value) -> value
  end
  Ok(DirectoryEntry {
    version: 1,
    username: "postage-owner",
    account_identity: account_bytes,
    prekey_bundle: bundle_bytes,
    mailbox_token: bytes(token, 32)?
  })
end

fn current(pool :: PoolHandle) -> DeviceSet!String do
  case resolve_devices(pool, "postage-owner")? do
    None -> Err("missing test devices")
    Some(value) -> Ok(value)
  end
end

fn current_price(pool :: PoolHandle) -> Int!String do
  case postage_policy_from_device_set(current(pool)?)? do
    None -> Ok(0)
    Some(value) -> Ok(value.credits)
  end
end

from Credits.ActionWire import CreditActionSubmission, decode_credit_action_receipt
from Credits.Cancellation import decode_credit_cancellation, verify_credit_cancellation
from Credits.Postage import (
  credit_postage_request_for_devices,
  encode_credit_postage_request,
  credit_postage_action,
  verify_credit_postage_receipt,
  decode_credit_postage_result
)
from Credits.PostageBox import (
  SealedPostageBatch,
  seal_postage_credit_box,
  encode_sealed_postage_batch
)
from Credits.PostageReply import open_postage_reply
from Credits.Issuer import CreditIssuerKey, encode_issuer_key
from Credits.Policy import issuer_epoch
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Credits.Wire import CreditToken, CreditFrame
from Storage.CreditIssuers import announce_credit_issuer, admit_credit_issuer
from Transparency.Merkle import (
  leaf_hash_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence
from Protocol.EnvelopeWire import encode_outer_envelope
from Privacy.Edge import (
  seal_delivery,
  encode_sealed_delivery,
  mint_request_stamp,
  encode_stamped_request
)

struct Reply do
  status :: Int
  body :: Bytes
end

struct Plan do
  wire :: Bytes
  submission :: CreditActionSubmission
  deliveries :: List<Bytes>
end

fn signer(name :: String) -> SigningKeyPair!String do
  let seed = case Env.get_secret_hex(name) do
    Err(_) -> return Err("test signer missing")
    Ok(value) -> value
  end
  case Crypto.signing_from_secret(seed) do
    Err(_) -> Err("test signer failed")
    Ok(value)
  end
end

fn post(base :: String, route :: String, body :: Bytes) -> Reply!String do
  let edge = Env.get("CREDIT_POSTAGE_EDGE_A", "")
  let through_edge = base == Env.get("CREDIT_POSTAGE_CORE_A", "") && edge != ""
  let is_postage = route == "/internal/credits/postage"
    || route == "/internal/credits/postage/reconcile"
  let target = if through_edge do
    edge
  else
    base
  end
  let target_route = if through_edge && is_postage do
    if route == "/internal/credits/postage" do
      "/v1/credits/postage"
    else
      "/v1/credits/postage/reconcile"
    end
  else
    route
  end
  let payload = if through_edge && is_postage do
    let label = if route == "/internal/credits/postage" do
      "mesh-msg/v1/work/postage"
    else
      "mesh-msg/v1/work/postage/reconcile"
    end
    encode_stamped_request(mint_request_stamp(label,
        body,
        U64.add(now()?, U64.parse("240000")?)?,
        4)?,
      body)?
  else
    body
  end
  let response = Http.build(:post, target <> target_route)
    |> Http.header("Authorization", "Bearer " <> Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", ""))
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Accept-Encoding", "identity")
    |> Http.body_bytes(payload)
    |> Http.timeout(15000)
    |> Http.max_response_bytes(564)
    |> Http.send()
  let value = response?
  Ok(Reply { status: value.status, body: value.body_bytes })
end

fn scalar(pool :: PoolHandle, sql :: String) -> String!String do
  Ok(Map.get(List.head(Pool.query(pool, sql, [])?), "value"))
end

fn mint(secret :: borrow BlindRsaSecretKey,
  key :: CreditIssuerKey,
  core :: Bytes) -> CreditToken!String do
  let pending = blind_credit(key, core, U64.divide(now()?, U64.parse("1000")?)?)?
  let signed = sign_credit_request(secret, key, pending.request)?
  finalize_credit(key, pending, signed)
end

fn plan(devices :: DeviceSet,
  core :: X25519PublicKey,
  reply :: X25519PublicKey,
  nonce :: Int,
  tokens :: List<CreditToken>,
  expires :: U64) -> Plan!String do
  let deliveries = for index in 0..List.length(devices.devices) do
    let entry = List.get(devices.devices, index)
    let outer = OuterEnvelope {
      version: 1,
      envelope_id: bytes(nonce + index * 10, 16)?,
      mailbox_token: entry.mailbox_token,
      suite: 1,
      expiration: U64.add(now()?, U64.parse("86400000")?)?,
      padding_bucket: 512,
      ciphertext: bytes(71, 512)?
    }
    let encoded = case encode_outer_envelope(outer) do
      Err(_) -> return Err("test outer failed")
      Ok(value) -> value
    end
    encode_sealed_delivery(seal_delivery(encoded, core)?)?
  end
  let request = credit_postage_request_for_devices(devices,
    deliveries,
    bytes(nonce, 32)?,
    reply,
    expires)?
  let body = encode_credit_postage_request(request)?
  let submission = CreditActionSubmission {
    action: credit_postage_action(request)?,
    request_body: body,
    frame: CreditFrame { binding: Crypto.sha256(body), tokens: tokens }
  }
  let box = seal_postage_credit_box(core, deliveries, submission)?
  Ok(Plan {
    wire: encode_sealed_postage_batch(SealedPostageBatch {
      deliveries: deliveries,
      credit_box: box
    })?,
    submission: submission,
    deliveries: deliveries
  })
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL", "")
  if !String.contains(url, "/postage_core_test?") do
    return Err("postage proof requires its isolated local HTTP/PostgreSQL harness")
  end
  let pool = Pool.open(url, 1, 4, 5000)?
  let a = Env.get("CREDIT_POSTAGE_CORE_A", "")
  let b = Env.get("CREDIT_POSTAGE_CORE_B", "")
  let off = Env.get("CREDIT_POSTAGE_CORE_OFF", "")
  let core_signer = signer("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX")?
  let witness_a = signer("CREDIT_FIXTURE_WITNESS_A_SEED")?
  let witness_b = signer("CREDIT_FIXTURE_WITNESS_B_SEED")?
  let rsa = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(rsa) do
    Err(_) -> return Err("test RSA public failed")
    Ok(value) -> value
  end
  let issuer = CreditIssuerKey {
    epoch: issuer_epoch(U64.divide(now()?, U64.parse("1000")?)?)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: core_signer.public_key.bytes
  }
  let leaf = encode_issuer_key(issuer)?
  let announced = announce_credit_issuer(pool, leaf)?
  let tree = [leaf_hash_for(2, leaf)?]
  assert(admit_credit_issuer(pool,
    TransparencyEvidence {
      entry_bytes: leaf,
      inclusion: compact_inclusion_proof_for(2, tree, 0)?,
      consistency: compact_consistency_proof_for(2, [], tree)?,
      checkpoint: announced.checkpoint,
      witnesses: [
        sign_witness("witness-a", witness_a.private_key, announced.checkpoint)?,
        sign_witness("witness-b", witness_b.private_key, announced.checkpoint)?
      ]
    })?)
  let (owner, identity) = case generate_account(now()?, U64.parse("1")?) do
    Err(_) -> return Err("test account failed")
    Ok(value) -> value
  end
  let first = case generate_device() do
    Err(_) -> return Err("test device failed")
    Ok(value) -> value
  end
  let second = case generate_device() do
    Err(_) -> return Err("test device failed")
    Ok(value) -> value
  end
  assert(register_device(pool, entry(owner, identity, first, "1", 31)?)? == DeviceAccepted)
  assert(register_device(pool, entry(owner, identity, second, "2", 32)?)? == DeviceAccepted)
  for index in 3..9 do
    let linked = case generate_device() do
      Err(_) -> return Err("test device failed")
      Ok(value) -> value
    end
    assert(register_device(pool,
      entry(owner, identity, linked, Int.to_string(index), 30 + index)?)? == DeviceAccepted)
  end
  let policy = sign_postage_policy(owner,
    first.device_id,
    U64.parse("1")?,
    U64.parse("8")?,
    1,
    now()?)?
  let policy_wire = encode_postage_policy(policy)?
  assert(post(off, "/v1/credits/postage-policy", policy_wire)?.status == 503)
  assert(post(a, "/v1/credits/postage-policy", policy_wire)?.status == 201)
  assert(post(b, "/v1/credits/postage-policy", policy_wire)?.status == 200)
  let devices = current(pool)?
  let core = case Crypto.x25519_from_seed(Bytes.from_hex(String.repeat("77", 32))?) do
    Err(_) -> return Err("test delivery key failed")
    Ok(value) -> value
  end
  let reply = case Crypto.x25519_generate() do
    Err(_) -> return Err("test reply key failed")
    Ok(value) -> value
  end
  let expires = U64.add(U64.divide(now()?, U64.parse("1000")?)?, U64.parse("600")?)?
  let shared = mint(rsa, issuer, core_signer.public_key.bytes)?
  let plans = [
    plan(devices, core.public_key, reply.public_key, 1, [shared], expires)?,
    plan(devices, core.public_key, reply.public_key, 2, [shared], expires)?
  ]
  assert(post(off, "/internal/credits/postage", List.head(plans).wire)?.status == 503)
  assert(post(a, "/internal/credits/postage", Bytes.empty())?.status == 400)
  assert(post(a, "/internal/credits/postage/reconcile", List.head(plans).wire)?.status == 425)
  Pool.execute(pool,
    "CREATE FUNCTION postage_race_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.2); RETURN NEW; END $$",
    [])?
  Pool.execute(pool,
    "CREATE TRIGGER postage_race_pause BEFORE INSERT ON credit_spent FOR EACH ROW EXECUTE FUNCTION postage_race_pause()",
    [])?
  let racing = Job.map([0, 1],
    fn(index) -> post(if index == 0 do
        a
      else
        b
      end,
      "/internal/credits/postage",
      List.get(plans, index).wire) end)
  let responses = for value in racing do
    value??
  end
  Pool.execute(pool, "DROP TRIGGER postage_race_pause ON credit_spent", [])?
  assert(List.length(List.filter(responses, fn(value) -> value.status == 201 end)) == 1)
  assert(List.length(List.filter(responses, fn(value) -> value.status == 409 end)) == 1)
  let winning_index = if List.head(responses).status == 201 do
    0
  else
    1
  end
  let winning = List.get(plans, winning_index)
  let raw_receipt = open_postage_reply(reply.private_key,
    winning.deliveries,
    List.get(responses, winning_index).body)?
  let receipt = decode_credit_action_receipt(raw_receipt)?
  assert(verify_credit_postage_receipt(receipt,
    core_signer.public_key,
    winning.submission,
    devices,
    winning.deliveries)?)
  assert(decode_credit_postage_result(receipt.result)?.enqueued_count == 8)
  assert(scalar(pool,
    "SELECT concat((SELECT count(*) FROM credit_spent), ':', (SELECT count(*) FROM credit_holds), ':', (SELECT count(*) FROM messenger_envelopes), ':', (SELECT count(*) FROM credit_action_effects)) AS value")? == "1:1:8:1")
  let repeated = post(b, "/internal/credits/postage", winning.wire)?
  assert(repeated.status == 200)
  assert(Bytes.secure_equals(open_postage_reply(reply.private_key,
      winning.deliveries,
      repeated.body)?,
    raw_receipt))
  let recovered = post(off, "/internal/credits/postage/reconcile", winning.wire)?
  assert(recovered.status == 200
    && Bytes.secure_equals(open_postage_reply(reply.private_key,
        winning.deliveries,
        recovered.body)?,
      raw_receipt))
  let next_policy = sign_postage_policy(owner,
    first.device_id,
    U64.parse("2")?,
    devices.sequence,
    5,
    now()?)?
  assert(post(a, "/v1/credits/postage-policy", encode_postage_policy(next_policy)?)?.status == 201)
  assert(post(b, "/internal/credits/postage", winning.wire)?.status == 200)
  let priced_devices = current(pool)?
  let fresh = for _index in 0..5 do
    mint(rsa, issuer, core_signer.public_key.bytes)?
  end
  let mixed = plan(priced_devices,
    core.public_key,
    reply.public_key,
    3,
    [shared] ++ List.take(fresh, 4),
    expires)?
  assert(post(a, "/internal/credits/postage", mixed.wire)?.status == 409)
  assert(scalar(pool,
    "SELECT concat((SELECT count(*) FROM credit_spent), ':', (SELECT count(*) FROM credit_holds), ':', (SELECT count(*) FROM messenger_envelopes)) AS value")? == "1:1:8")
  let paid = plan(priced_devices, core.public_key, reply.public_key, 4, fresh, expires)?
  # Force the final fanout insertion to fail after the first device and all five
  # token inserts. The entire transaction, including the first enqueue, rolls back.
  let blocked = Crypto.sha256(List.get(priced_devices.devices, 7).mailbox_token)
  Pool.execute(pool,
    "CREATE FUNCTION postage_enqueue_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.mailbox_token_hash = decode('"
      <> Bytes.to_hex(blocked)
      <> "', 'hex') THEN RAISE EXCEPTION 'forced final postage enqueue failure'; END IF; RETURN NEW; END $$",
    [])?
  Pool.execute(pool,
    "CREATE TRIGGER postage_enqueue_failure BEFORE INSERT ON messenger_envelopes FOR EACH ROW EXECUTE FUNCTION postage_enqueue_failure()",
    [])?
  assert(post(a, "/internal/credits/postage", paid.wire)?.status == 503)
  assert(scalar(pool,
    "SELECT concat((SELECT count(*) FROM credit_spent), ':', (SELECT count(*) FROM credit_holds), ':', (SELECT count(*) FROM messenger_envelopes)) AS value")? == "1:1:8")
  Pool.execute(pool, "DROP TRIGGER postage_enqueue_failure ON messenger_envelopes", [])?
  let exact = Job.map([a, b], fn(base) -> post(base, "/internal/credits/postage", paid.wire) end)
  let exact_responses = for value in exact do
    value??
  end
  assert(List.length(List.filter(exact_responses, fn(value) -> value.status == 201 end)) == 1)
  assert(List.length(List.filter(exact_responses, fn(value) -> value.status == 200 end)) == 1)
  let first_receipt = open_postage_reply(reply.private_key,
    paid.deliveries,
    List.head(exact_responses).body)?
  assert(Bytes.secure_equals(first_receipt,
    open_postage_reply(reply.private_key, paid.deliveries, List.get(exact_responses, 1).body)?))
  assert(verify_credit_postage_receipt(decode_credit_action_receipt(first_receipt)?,
    core_signer.public_key,
    paid.submission,
    priced_devices,
    paid.deliveries)?)
  assert(scalar(pool,
    "SELECT concat((SELECT count(*) FROM credit_spent), ':', (SELECT count(*) FROM credit_holds), ':', (SELECT count(*) FROM messenger_envelopes), ':', (SELECT count(*) FROM credit_action_effects)) AS value")? == "6:2:16:2")
  let cancelled_plan = plan(priced_devices,
    core.public_key,
    reply.public_key,
    5,
    [mint(rsa, issuer, core_signer.public_key.bytes)?],
    U64.subtract(U64.divide(now()?, U64.parse("1000")?)?, U64.parse("1")?)?)?
  let cancelled = post(off, "/internal/credits/postage/reconcile", cancelled_plan.wire)?
  assert(cancelled.status == 200)
  assert(verify_credit_cancellation(decode_credit_cancellation(open_postage_reply(reply.private_key,
      cancelled_plan.deliveries,
      cancelled.body)?)?,
    core_signer.public_key,
    cancelled_plan.submission)?)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_cancellations")? == "0")
  println("CREDITS_POSTAGE_ATOMIC")
  Ok(true)
end

test("one recipient postage charge atomically enqueues all devices and recovers encrypted exact effects") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
