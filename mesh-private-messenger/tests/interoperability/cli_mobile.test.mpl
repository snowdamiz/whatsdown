from Mobile.Codec import current_time
from Transparency.Merkle import sign_checkpoint, consistency_proof, inclusion_proof, sign_witness
from Transparency.Wire import TransparencyEvidence, encode_transparency_evidence
from Protocol.DirectoryWire import encode_device_set
from Protocol.V1 import DeviceSet
from Transparency.Merkle import leaf_hash
from Transport.Packet import decode_client_profile
from Protocol.Capabilities import supports_header_encryption, supports_attachment_buckets
import File
from Interop.Client import interop_state_suite, open_mobile_reply, opened_body, start_mobile_session
from MobileCore import (
  create_account_export,
  verify_transparency_export,
  outbox_ack_export,
  receive_initial_export,
  send_message_export,
  update_conversation_export
)

fn append(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("interop request too large")
    Ok(value)
  end
end

fn write_u32(value :: Int) -> Bytes!String do
  let wide = case U64.parse(Int.to_string(value)) do
    Err(_) -> Err("invalid interop request length")
    Ok(parsed)
  end?
  case Bytes.write_u32_be(wide) do
    Err(_) -> Err("invalid interop request length")
    Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes!String do
  append(write_u32(Bytes.length(value))?, value)
end

fn encode_vectors(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_vectors(values, index + 1, append(output, vector(List.get(values, index))?)?)
  end
end

fn request(values :: List<Bytes>) -> Bytes!String do
  encode_vectors(values, 0, Bytes.empty())
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid interop request byte")
    Ok(encoded)
  end
end

fn database_path() -> String!String do
  let configured = Env.get("MESSENGER_M10_INTEROP_PATH", "")
  if String.length(configured) > 0 do
    Ok(configured)
  else
    case Crypto.random_bytes(8) do
      Err(_) -> Err("interop path generation failed")
      Ok(value) -> Ok("/tmp/mesh_cli_mobile_interop_" <> Bytes.to_hex(value) <> ".db")
    end
  end
end

fn set_for(profile_wire :: Bytes) -> Bytes!String do
  let profile = decode_client_profile(profile_wire)?
  case encode_device_set(DeviceSet {
    version: 1,
    username: profile.username,
    account_identity: profile.entry.account_identity,
    sequence: profile.account.directory_sequence,
    devices: [profile.entry],
    revoked_device_ids: []
  }) do
    Err(_) -> Err("interop device set")
    Ok(value)
  end
end

fn signing() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("interop signer")
    Ok(value)
  end
end

fn install_interop_evidence(path :: String,
  local_wire :: Bytes,
  cli_wire :: Bytes,
  local_set :: Bytes,
  cli_set :: Bytes) -> Unit!String do
  let signer = signing()?
  let first = signing()?
  let second = signing()?
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> Err("interop delivery")
    Ok(value)
  end?
  if !Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    Bytes.from_utf8("1\n"
      <> Bytes.to_hex(signer.public_key.bytes)
      <> "\n"
      <> Bytes.to_hex(first.public_key.bytes)
      <> "\n"
      <> Bytes.to_hex(second.public_key.bytes)
      <> "\n"
      <> Bytes.to_hex(delivery.public_key.bytes)
      <> "\n8")) do
    return Err("interop pins")
  end
  if !Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("2\n1\nhttps://core.example\nhttps://edge.example\nhttps://objects.example\nwss://core.example/v1/mailbox/stream\n1")) do
    return Err("interop network pins")
  end
  let zero = case Bytes.repeat(0, 32) do
    Err(_) -> Err("interop zeros")
    Ok(value)
  end?
  let leaves = [leaf_hash(local_set)?, leaf_hash(cli_set)?]
  let checkpoint = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    U64.parse("1")?,
    leaves,
    zero,
    current_time()?)?
  let attestations = [
    sign_witness("witness-a", first.private_key, checkpoint)?,
    sign_witness("witness-b", second.private_key, checkpoint)?
  ]
  for index in 0..2 do
    let devices = if index == 0 do
      local_set
    else
      cli_set
    end
    let profile = decode_client_profile(if index == 0 do
      local_wire
    else
      cli_wire
    end)?
    let evidence = encode_transparency_evidence(TransparencyEvidence {
      entry_bytes: devices,
      inclusion: inclusion_proof(leaves, index)?,
      consistency: consistency_proof(if index == 0 do
          []
        else
          leaves
        end,
        leaves)?,
      checkpoint: checkpoint,
      witnesses: attestations
    })?
    case verify_transparency_export(request([
      Bytes.from_utf8(path),
      Bytes.from_utf8(profile.username),
      evidence,
      Bytes.from_utf8("https://core.example")
    ])?) do
      Err(error) -> return Err("interop transparency #{index}: #{error}")
      Ok(_) -> nil
    end
  end
  Ok(nil)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path()?
  let mobile_profile = create_account_export(request([
    Bytes.from_utf8(path),
    Bytes.from_utf8("mobile")
  ])?)?
  let greeting = Bytes.from_utf8("m10-cli-greeting-opaque")
  let reply = Bytes.from_utf8("m10-mobile-reply-opaque")
  let (cli_state, cli_device, cli_session, cli_profile, initial_outer) = start_mobile_session(mobile_profile,
    greeting)?
  assert(interop_state_suite(cli_state) == 2)
  assert(cli_state.version == 2)
  let cli = decode_client_profile(cli_profile)?
  assert(supports_header_encryption(cli.credential.capabilities))
  assert(!supports_attachment_buckets(cli.credential.capabilities))
  let local_set = set_for(mobile_profile)?
  let cli_set = set_for(cli_profile)?
  install_interop_evidence(path, mobile_profile, cli_profile, local_set, cli_set)?
  assert(cli_session.suite == 2)
  assert(!String.contains(Bytes.to_hex(initial_outer), Bytes.to_hex(greeting)))
  assert(Bytes.secure_equals(receive_initial_export(request([
      Bytes.from_utf8(path),
      initial_outer
    ])?)?,
    greeting))
  assert(Bytes.secure_equals(update_conversation_export(request([
      Bytes.from_utf8(path),
      cli_profile,
      byte(1)?,
      write_u32(0)?
    ])?)?,
    Bytes.from_utf8("ok")))
  let reply_outer = send_message_export(request([Bytes.from_utf8(path), cli_profile, reply])?)?
  assert(!String.contains(Bytes.to_hex(reply_outer), Bytes.to_hex(reply)))
  # Neither direction shows delivery the session both sides share.
  assert(!String.contains(Bytes.to_hex(initial_outer), Bytes.to_hex(cli_session.session_id)))
  assert(!String.contains(Bytes.to_hex(reply_outer), Bytes.to_hex(cli_session.session_id)))
  assert(Bytes.secure_equals(opened_body(open_mobile_reply(cli_state,
      cli_device,
      cli_session,
      reply_outer))?,
    reply))
  outbox_ack_export(request([Bytes.from_utf8(path), reply_outer])?)?
  if String.length(Env.get("MESSENGER_M10_INTEROP_PATH", "")) == 0 do
    File.delete(path)?
  else
    nil
  end
  Ok(true)
end

test("Mesh CLI and mobile share an authenticated HE hybrid session with opaque RAT4 and exact client wire") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
