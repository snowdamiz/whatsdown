from MobileCore import (
  create_account_export,
  group_create_export,
  group_add_export,
  group_send_export,
  group_history_export,
  group_key_package_export,
  mailbox_fetch_export,
  process_delivery_batch_export,
  presentation_save_export,
  register_request_export,
  prepare_fanout_prekeys_export,
  privacy_submission_export,
  send_fanout_export,
  resolve_request_export,
  verify_transparency_export
)
from Privacy.Edge import RequestStamp, decode_stamped_request
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.V1 import OuterEnvelope
from Transparency.Wire import TransparencyTreeQuery, decode_transparency_lookup, decode_witnesses, encode_transparency_tree_query

fn append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("live proof encoding failed")
    Ok( value) -> Ok(value)
  end
end

fn write_u32(value :: Int) -> Bytes ! String do
  let wide = case U64.parse(Int.to_string(value)) do
    Err( _) -> Err("live proof encoding failed")
    Ok( parsed) -> Ok(parsed)
  end ?
  case Bytes.write_u32_be(wide) do
    Err( _) -> Err("live proof encoding failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes ! String do
  append(write_u32(Bytes.length(value)) ?, value)
end

fn encode_vectors(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_vectors(values, index + 1, append(output, vector(List.get(values, index)) ?) ?)
  end
end

fn request(values :: List < Bytes >) -> Bytes ! String do
  encode_vectors(values, 0, Bytes.empty())
end

fn read_u32_at(input :: Bytes, offset :: Int) -> Int ! String do
  case Bytes.read_u32_be(input, offset) do
    Err( _) -> Err("live proof output decode failed")
    Ok( value) -> case U64.to_int(value) do
      Err( _) -> Err("live proof output decode failed")
      Ok( parsed) -> Ok(parsed)
    end
  end
end

fn output_parts(input :: Bytes, count :: Int, index :: Int, offset :: Int, items :: List < Bytes >) -> List < Bytes > ! String do
  if index >= count do
    if offset == Bytes.length(input) do
      Ok(items)
    else
      Err("live proof output decode failed")
    end
  else
    let length = read_u32_at(input, offset) ?
    let item = case Bytes.slice(input, offset + 4, length) do
      Err( _) -> Err("live proof output decode failed")
      Ok( value) -> Ok(value)
    end ?
    output_parts(input, count, index + 1, offset + 4 + length, List.append(items, item))
  end
end

fn output_list(input :: Bytes) -> List < Bytes > ! String do
  if Bytes.length(input) < 8 || read_u32_at(input, 0) ? != 4 do
    Err("live proof output decode failed")
  else
    let count = read_u32_at(input, 4) ?
    if count < 0 || count > 64 do
      Err("live proof output decode failed")
    else
      output_parts(input, count, 0, 8, List.new())
    end
  end
end

fn outer(input :: Bytes) -> OuterEnvelope ! String do
  case decode_outer_envelope(input) do
    Err( _) -> Err("live proof outer decode failed")
    Ok( value) -> Ok(value)
  end
end

fn configured_bytes(name :: String) -> Bytes ! String do
  case Bytes.from_hex(Env.get(name, "")) do
    Err( _) -> Err("invalid live proof configuration")
    Ok( value) -> if Bytes.length(value) == 32 do
      Ok(value)
    else
      Err("invalid live proof configuration")
    end
  end
end

fn install_security_config(service_public_key :: Bytes,
witness_a_public_key :: Bytes,
witness_b_public_key :: Bytes,
delivery_public_key :: Bytes) -> Bool do
  Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
  Bytes.from_utf8("1\n" <> Bytes.to_hex(service_public_key) <> "\n" <> Bytes.to_hex(witness_a_public_key) <> "\n" <> Bytes.to_hex(witness_b_public_key) <> "\n" <> Bytes.to_hex(delivery_public_key) <> "\n8"))
end

fn delivery_key_pair() -> X25519KeyPair ! String do
  let seed = case Env.get_secret_hex("MESSENGER_DELIVERY_SEALING_SEED_HEX") do
    Err( _) -> Err("invalid live proof delivery key")
    Ok( value) -> Ok(value)
  end ?
  case Crypto.x25519_from_secret(seed) do
    Err( _) -> Err("invalid live proof delivery key")
    Ok( pair) -> Ok(pair)
  end
end

fn post(base_url :: String, path :: String, body :: Bytes) -> HttpResponse ! String do
  Http.build(:post, base_url <> path)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

fn put(base_url :: String, path :: String, body :: Bytes) -> HttpResponse ! String do
  Http.build(:put, base_url <> path)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

fn get(base_url :: String, path :: String) -> HttpResponse ! String do
  Http.build(:get, base_url <> path)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

fn wait_for_witnesses(base_url :: String, attempts :: Int) -> Result <(), String > do
  if attempts >= 400 do
    Err("live witness attestations timed out")
  else
    case get(base_url, "/v1/transparency/witnesses") do
      Err( _) -> do
        Timer.sleep(50)
        wait_for_witnesses(base_url, attempts + 1)
      end
      Ok( response) -> if response.status != 200 do
        Timer.sleep(50)
        wait_for_witnesses(base_url, attempts + 1)
      else
        let witnesses = decode_witnesses(response.body_bytes) ?
        if List.length(witnesses) == 2 do
          Ok(nil)
        else
          Timer.sleep(50)
          wait_for_witnesses(base_url, attempts + 1)
        end
      end
    end
  end
end

fn verified_set(base_url :: String,
database_path :: String,
username :: String,
expected_previous_size :: Int) -> Bytes ! String do
  let lookup = resolve_request_export(request([Bytes.from_utf8(database_path), Bytes.from_utf8(username)]) ?) ?
  # The lookup leaves the core wrapped in proof of work; the request inside is
  # what names the previous tree size.
  let ( _stamp, inner_lookup) = decode_stamped_request(lookup, 76) ?
  assert(decode_transparency_lookup(inner_lookup) ?.previous_tree_size == expected_previous_size)
  let response = post(base_url, "/v1/devices/resolve", lookup) ?
  if response.status != 200 do
    Err("live transparency resolution returned #{response.status}")
  else
    verify_transparency_export(request([Bytes.from_utf8(database_path), Bytes.from_utf8(username), response.body_bytes]) ?)
  end
end

fn submit_and_receive_group(core_url :: String,
edge_url :: String,
bob_path :: String,
envelopes :: Bytes) -> Bool ! String do
  let values = output_list(envelopes) ?
  assert(List.length(values) == 1)
  assert(post(edge_url, "/v1/envelopes/batch", privacy_submission_export(List.head(values)) ?) ?.status == 202)
  let batch = post(core_url, "/v1/mailbox/fetch", mailbox_fetch_export(Bytes.from_utf8(bob_path)) ?) ?
  assert(batch.status == 200)
  assert(Bytes.length(process_delivery_batch_export(request([Bytes.from_utf8(bob_path), batch.body_bytes]) ?) ?) > 0)
  # Leave rows queued so the harness can inspect delivery's decrypted storage boundary.
  Ok(true)
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let delivery = delivery_key_pair() ?
  assert(install_security_config(configured_bytes("MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX") ?,
  configured_bytes("MESSENGER_WITNESS_A_PUBLIC_KEY_HEX") ?,
  configured_bytes("MESSENGER_WITNESS_B_PUBLIC_KEY_HEX") ?,
  delivery.public_key.bytes))
  let core_url = Env.get("MESSENGER_M13_CORE_URL", "")
  let edge_url = Env.get("MESSENGER_M13_EDGE_URL", "")
  let alice_path = Env.get("MESSENGER_M13_ALICE_DB_PATH", "")
  let bob_path = Env.get("MESSENGER_M13_BOB_DB_PATH", "")
  let proof_plaintext = Env.get("MESSENGER_M13_PROOF_PLAINTEXT", "")
  if String.length(core_url) == 0 || String.length(edge_url) == 0 || String.length(alice_path) == 0 || String.length(bob_path) == 0 || String.length(proof_plaintext) == 0 do
    Err("missing live proof configuration")
  else
    let _alice = create_account_export(request([Bytes.from_utf8(alice_path), Bytes.from_utf8("alice")]) ?) ?
    let _bob = create_account_export(request([Bytes.from_utf8(bob_path), Bytes.from_utf8("bob")]) ?) ?
    assert(put(core_url,
    "/v1/devices/register",
    register_request_export(Bytes.from_utf8(alice_path)) ?) ?.status == 201)
    assert(put(core_url,
    "/v1/devices/register",
    register_request_export(Bytes.from_utf8(bob_path)) ?) ?.status == 201)
    assert(post(core_url,
    "/v1/transparency/consistency",
    encode_transparency_tree_query(TransparencyTreeQuery { previous_tree_size : 0 }) ?) ?.status == 200)
    wait_for_witnesses(core_url, 0) ?
    let alice_set = verified_set(core_url, alice_path, "alice", 0) ?
    let bob_set = verified_set(core_url, alice_path, "bob", 2) ?
    assert(Bytes.length(prepare_fanout_prekeys_export(request([Bytes.from_utf8(alice_path), bob_set, alice_set, Bytes.from_utf8(core_url)]) ?) ?) == 0)
    let message = Bytes.from_utf8(proof_plaintext)
    let sent = output_list(send_fanout_export(request([Bytes.from_utf8(alice_path), bob_set, alice_set, message]) ?) ?) ?
    assert(List.length(sent) == 1)
    let envelope = List.head(sent)
    # Delivery sees only the recipient-sealed transport, never the protocol suite.
    assert(outer(envelope) ?.suite == 4)
    let submission = privacy_submission_export(envelope) ?
    assert(post(edge_url, "/v1/envelopes/batch", submission) ?.status == 202)
    let _ = verified_set(core_url, bob_path, "bob", 0) ?
    let _ = verified_set(core_url, bob_path, "alice", 2) ?
    let group_id = group_create_export(Bytes.from_utf8(alice_path)) ?
    let key_package = group_key_package_export(Bytes.from_utf8(bob_path)) ?
    assert(submit_and_receive_group(core_url,
    edge_url,
    bob_path,
    group_add_export(request([Bytes.from_utf8(alice_path), group_id, bob_set, key_package]) ?) ?) ?)
    let group_name = Bytes.from_utf8("private-group-name-9d128aa39099")
    presentation_save_export(request([Bytes.from_utf8(alice_path), Bytes.from_utf8("group/" <> Bytes.to_hex(group_id)), request([group_name, Bytes.empty()]) ?]) ?) ?
    assert(submit_and_receive_group(core_url,
    edge_url,
    bob_path,
    group_send_export(request([Bytes.from_utf8(alice_path), group_id, Bytes.from_utf8("private-group-body-373bc740b242")]) ?) ?) ?)
    assert(List.length(output_list(group_history_export(request([Bytes.from_utf8(bob_path), group_id]) ?) ?) ?) == 1)
    println("PRIVACY_GROUP_ID=" <> Bytes.to_hex(group_id))
    Ok(true)
  end
end

test("live mobile path verifies transparency and sends one sealed hybrid fanout") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
