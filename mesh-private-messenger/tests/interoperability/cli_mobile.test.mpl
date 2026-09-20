import File
from Interop.Client import interop_state_suite, open_mobile_reply, opened_body, start_mobile_session
from MobileCore import (
  create_account_export,
  outbox_ack_export,
  receive_initial_export,
  send_message_export,
  update_conversation_export
)

fn append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("interop request too large")
    Ok( value) -> Ok(value)
  end
end

fn write_u32(value :: Int) -> Bytes ! String do
  let wide = case U64.parse(Int.to_string(value)) do
    Err( _) -> Err("invalid interop request length")
    Ok( parsed) -> Ok(parsed)
  end ?
  case Bytes.write_u32_be(wide) do
    Err( _) -> Err("invalid interop request length")
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

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("invalid interop request byte")
    Ok( encoded) -> Ok(encoded)
  end
end

fn database_path() -> String ! String do
  let configured = Env.get("MESSENGER_M10_INTEROP_PATH", "")
  if String.length(configured) > 0 do
    Ok(configured)
  else
    case Crypto.random_bytes(8) do
      Err( _) -> Err("interop path generation failed")
      Ok( value) -> Ok("/tmp/mesh_cli_mobile_interop_" <> Bytes.to_hex(value) <> ".db")
    end
  end
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path() ?
  let mobile_profile = create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8("mobile")]) ?) ?
  let greeting = Bytes.from_utf8("m10-cli-greeting-opaque")
  let reply = Bytes.from_utf8("m10-mobile-reply-opaque")
  let ( cli_state, cli_device, cli_session, cli_profile, initial_outer) = start_mobile_session(mobile_profile,
  greeting) ?
  assert(interop_state_suite(cli_state) == 2)
  assert(cli_session.suite == 2)
  assert(!String.contains(Bytes.to_hex(initial_outer), Bytes.to_hex(greeting)))
  assert(Bytes.secure_equals(receive_initial_export(request([Bytes.from_utf8(path), initial_outer]) ?) ?,
  greeting))
  assert(Bytes.secure_equals(update_conversation_export(request([Bytes.from_utf8(path), cli_profile, byte(1) ?, write_u32(0) ?]) ?) ?,
  Bytes.from_utf8("ok")))
  let reply_outer = send_message_export(request([Bytes.from_utf8(path), cli_profile, reply]) ?) ?
  assert(!String.contains(Bytes.to_hex(reply_outer), Bytes.to_hex(reply)))
  # Neither direction shows delivery the session both sides share.
  assert(!String.contains(Bytes.to_hex(initial_outer), Bytes.to_hex(cli_session.session_id)))
  assert(!String.contains(Bytes.to_hex(reply_outer), Bytes.to_hex(cli_session.session_id)))
  assert(Bytes.secure_equals(opened_body(open_mobile_reply(cli_state,
  cli_device,
  cli_session,
  reply_outer)) ?,
  reply))
  let _ = outbox_ack_export(request([Bytes.from_utf8(path), reply_outer]) ?) ?
  if String.length(Env.get("MESSENGER_M10_INTEROP_PATH", "")) == 0 do
    File.delete(path) ?
  else
    nil
  end
  Ok(true)
end

test("Mesh CLI and mobile share a hybrid session and exact client wire") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
