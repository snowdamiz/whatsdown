# TEST ONLY: appended after the actual Main functions, replacing only main().
# Session setup follows tests/header_ratchet.test.mpl and uses the real CLI wrappers.
from Protocol.V1 import ProtocolError
from Protocol.MailboxWire import decode_mailbox_ack, mailbox_ack_signing_bytes

fn proof_check(value :: Bool) do
  if !declassify(value,
    "TEST ONLY fixed expected Boolean comparison for offline CLI qualification; no raw result, error, envelope, or body is released") do
    Process.exit(71)
  end
end

fn proof_bytes(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("fixture allocation failed")
    Ok(value)
  end
end

fn proof_bob() -> DeviceKeys!String do
  let signing = case Crypto.signing_from_seed(Bytes.from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")?) do
    Err(_) -> return Err("fixture signing failed")
    Ok(value) -> value
  end
  let identity = case Crypto.x25519_from_seed(Bytes.from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")?) do
    Err(_) -> return Err("fixture identity failed")
    Ok(value) -> value
  end
  let signing_public = signing.public_key
  let signing_private = signing.private_key
  let identity_public = identity.public_key
  let identity_private = identity.private_key
  Ok(DeviceKeys {
    device_id: proof_bytes(22, 16)?,
    signing_private_key: signing_private,
    signing_public_key: signing_public,
    identity_private_key: identity_private,
    identity_public_key: identity_public
  })
end

fn proof_payload(mode :: Int, text :: String) -> Bytes!String do
  if mode == 1 do
    Ok(Bytes.from_utf8("invalid inner envelope"))
  else
    let value = inner(proof_bytes(11, 32)?, proof_bytes(12, 16)?,
      proof_bytes(22, 16)?, proof_bytes(13, 16)?, proof_bytes(14, 16)?, text)?
    if mode == 2 do
      inner_wire(%{value | body: Bytes.from_hex("fffe")?})
    else
      inner_wire(value)
    end
  end
end

fn proof_delivery(packet :: Bytes, bob :: borrow DeviceKeys,
  token :: Bytes, id :: Int, sequence :: Int) -> DeliveredEnvelope!String do
  let sealed = seal_recipient_packet(packet, bob.identity_public_key)?
  let outer = outer_wire(OuterEnvelope {
    version: 1,
    envelope_id: proof_bytes(id, 16)?,
    mailbox_token: token,
    suite: 4,
    expiration: wide("1900000000000")?,
    padding_bucket: Bytes.length(sealed),
    ciphertext: sealed
  })?
  Ok(DeliveredEnvelope { sequence: wide(Int.to_string(sequence))?, envelope: outer })
end

fn proof_encrypt(state :: consume RatchetState, payload :: Bytes,
  aad :: Bytes) -> Result<(RatchetState, RatchetMessage), String> do
  case encrypt_sealed(state, payload, aad) do
    Err(_) -> Err("fixture encryption failed")
    Ok(value)
  end
end

fn proof_case(mode :: Int) -> Int!String do
  let created = wide("1700000000000")?
  let now = wide("1800000000000")?
  let expires = wide("1900000000000")?
  let (alice_keys, alice_account) = account(created)?
  let alice = device()?
  let alice_credential = credential(alice_keys, alice, created, expires)?
  let (bob_keys, bob_account) = account(created)?
  let bob = proof_bob()?
  let bob_credential = credential(bob_keys, bob, created, expires)?
  let signed = signed_prekey(bob, bob_credential, expires)?
  let one_time = one_time_prekey()?
  let pq = post_quantum_prekey()?
  let published = bundle(bob_credential, signed, one_time)?
  let token = proof_bytes(70 + mode, 32)?
  let (alice_state, initial) = case initiate_cli(1, alice, alice_credential,
    bob_account, published, policy(now)?, 1, proof_payload(mode, "initial")?) do
    Err(_) -> return Err("fixture initiate failed")
    Ok(value) -> value
  end
  let offset = 10 * mode
  let first = proof_delivery(encode_packet(InitialPacket(account_wire(alice_account)?,
    initial_wire(initial)?))?, bob, token, offset + 1, 1)?
  let first_outer = case decode_outer_envelope(first.envelope) do
    Err(_) -> return Err("fixture initial outer failed")
    Ok(value) -> value
  end
  let (sender, initial_bytes) = case opened_packet(first_outer, bob) do
    Ok(InitialPacket(account_bytes, message)) -> case decode_account_identity(account_bytes) do
      Ok(value) -> (value, message)
      Err(_) -> return Err("fixture sender failed")
    end
    _ -> return Err("fixture initial packet failed")
  end
  let (bob_state, initial_plaintext) = case receive_initial_cli(1, bob, bob_account,
    published, signed, one_time, pq, sender, policy(now)?, policy(now)?, 1, initial_bytes) do
    Err(_) -> return Err("fixture receive failed")
    Ok(value) -> value
  end
  display(initial_plaintext)
  let aad = session_aad(bob_state.session_id)?
  let (alice_state, one) = proof_encrypt(alice_state, proof_payload(0, "first")?, aad)?
  let (alice_state, two) = proof_encrypt(alice_state, proof_payload(0, "second")?, aad)?
  let (alice_state, three) = proof_encrypt(alice_state, proof_payload(0, "third")?, aad)?
  let (alice_state, bad_inner) = proof_encrypt(alice_state, proof_payload(1, "")?, aad)?
  let (_alice_state, bad_utf8) = proof_encrypt(alice_state, proof_payload(2, "")?, aad)?
  # Send order differs from display order. The second packet is delivered twice
  # under distinct outer IDs; both must be ACKed while only one is displayed.
  let ordered = [first,
    proof_delivery(encode_packet(RatchetPacket(ratchet_wire(three)?))?, bob, token, offset + 4, 2)?,
    proof_delivery(encode_packet(RatchetPacket(ratchet_wire(one)?))?, bob, token, offset + 2, 3)?,
    proof_delivery(encode_packet(RatchetPacket(ratchet_wire(two)?))?, bob, token, offset + 3, 4)?]
  let deliveries = if mode == 0 do
    # Retain the complete existing prove-m8.sh display order and acked=5 case.
    List.append(ordered,
      proof_delivery(encode_packet(RatchetPacket(ratchet_wire(two)?))?, bob, token, offset + 5, 5)?)
  else
    let with_bad_inner = List.append(ordered,
      proof_delivery(encode_packet(RatchetPacket(ratchet_wire(bad_inner)?))?, bob, token, offset + 5, 5)?)
    let with_bad_utf8 = List.append(with_bad_inner,
      proof_delivery(encode_packet(RatchetPacket(ratchet_wire(bad_utf8)?))?, bob, token, offset + 6, 6)?)
    List.append(with_bad_utf8,
      proof_delivery(encode_packet(RatchetPacket(ratchet_wire(two)?))?, bob, token, offset + 7, 7)?)
  end
  let _bob_state = process_deliveries(bob_state, bob, deliveries, 1, aad)
  let ids = envelope_ids(deliveries, 0, List.new())
  acknowledge(bob, token, ids)?
  println("device-b:acked=#{List.length(ids)}")
  Ok(0)
end

fn proof_identities() -> Bool!String do
  let valid = proof_payload(0, "identity ✓")?
  let inner_ok = case decode_inner_envelope(valid) do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value.body, Bytes.from_utf8("identity ✓"))
      && Bytes.secure_equals(value.sender_account_id, proof_bytes(11, 32)?)
      && value.message_type == 1
  end
  let unsupported = case decode_inner_envelope(Bytes.from_hex("02")?) do
    Err(error) -> error == ProtocolError.UnsupportedVersion
    Ok(_) -> false
  end
  let malformed = case decode_inner_envelope(Bytes.from_hex("01424144")?) do
    Err(error) -> error == ProtocolError.MalformedEncoding
    Ok(_) -> false
  end
  let invalid_utf8 = proof_payload(2, "")?
  let utf8_error_equal = case decode_inner_envelope(invalid_utf8) do
    Err(_) -> false
    Ok(value) -> case Bytes.to_utf8(value.body) do
      Ok(_) -> false
      Err(actual) -> case Bytes.to_utf8(Bytes.from_hex("fffe")?) do
        Ok(_) -> false
        Err(expected) -> actual == expected
      end
    end
  end
  Ok(inner_ok && unsupported && malformed && utf8_error_equal)
end

fn proof_verify_ack(encoded :: String) -> Bool!String do
  let wire = Bytes.from_hex(encoded)?
  let ack = case decode_mailbox_ack(wire) do
    Err(_) -> return Err("fixture ack decoding failed")
    Ok(value) -> value
  end
  let signed = case mailbox_ack_signing_bytes(ack) do
    Err(_) -> return Err("fixture ack content failed")
    Ok(value) -> value
  end
  case Crypto.verify(SigningPublicKey { bytes: Bytes.from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")? },
    signed, Signature { bytes: ack.signature }) do
    Err(_) -> Err("fixture signature check failed")
    Ok(value)
  end
end

fn main() do
  let ack = Env.get("PROOF_VERIFY_ACK", "")
  if ack != "" do
    proof_check(case proof_verify_ack(ack) do
      Err(_) -> false
      Ok(value) -> value
    end)
    println("ack-signature:valid")
  else
    proof_check(case proof_identities() do Err(_) -> false Ok(value) -> value end)
    println("case:initial-valid")
    proof_check(case proof_case(0) do Err(_) -> false Ok(_) -> true end)
    println("case:initial-invalid-inner")
    proof_check(case proof_case(1) do Err(_) -> false Ok(_) -> true end)
    println("case:initial-invalid-utf8")
    proof_check(case proof_case(2) do Err(_) -> false Ok(_) -> true end)
  end
end
