from Mobile.AccountNetwork import (
  native_account_delete,
  native_account_discard,
  native_account_capabilities
)
from Mobile.DeviceNetwork import native_devices_renew, native_device_revoke
from Mobile.Account import account_deletion, forget_on_proof_at_profile
from Mobile.Codec import mobile_join, mobile_vector
from Mobile.Profile import load_profile
from MobileCore import create_account_export, erase_account_export
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import with_record_transaction, delete_blob, store_updated_blobs
from Tests.Support import database_path, repeated
from Transport.Packet import ClientProfile, decode_client_profile, encode_client_profile
from Protocol.DirectoryWire import decode_account_deletion, decode_device_departure
from Identity.Device import verify_account_deletion, verify_device_departure

fn request(path :: String, profile :: Bytes) -> Bytes!String do
  mobile_join([mobile_vector(Bytes.from_utf8(path))?, mobile_vector(profile)?], 0, Bytes.empty())
end

fn create(path :: String) -> Bytes!String do
  create_account_export(mobile_join([
      mobile_vector(Bytes.from_utf8(path))?,
      mobile_vector(Bytes.from_utf8("alice"))?
    ],
    0,
    Bytes.empty())?)
end

fn configured(port :: Int) -> Bool do
  Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("1\n1\nhttp://127.0.0.1:"
      <> Int.to_string(port)
      <> "\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream"))
end

fn signed_by_owner(wire :: Bytes, profile :: ClientProfile, primary :: Bool) -> Bool do
  if primary do
    case decode_account_deletion(wire) do
      Err(_) -> false
      Ok(statement) -> case verify_account_deletion(profile.account, statement) do
        Ok(value) -> value
        Err(_) -> false
      end
    end
  else
    case decode_device_departure(wire) do
      Err(_) -> false
      Ok(statement) -> Bytes.secure_equals(statement.account_id, profile.account_id)
        && Bytes.secure_equals(statement.device_id, profile.device_id)
        && case verify_device_departure(profile.credential.signing_public_key, statement) do
          Ok(value) -> value
          Err(_) -> false
        end
    end
  end
end

fn response(input :: Request,
  path :: String,
  profile :: ClientProfile,
  primary :: Bool,
  mode :: Int,
  port :: Int) -> Response do
  if Request.header(input, "cookie") != None
    || Request.header(input, "authorization") != None
    || !signed_by_owner(Request.body_bytes(input), profile, primary) do
    return HTTP.response(400, "invalid native request")
  end
  File.write(path <> ".called",
    if primary do
      "delete"
    else
      "leave"
    end)
  if mode == 2 do
    return HTTP.response(403, "")
  end
  if mode == 3 do
    return HTTP.response(404, "")
  end
  if mode == 4 do
    return HTTP.response(200, "")
  end
  if mode == 5 && !File.exists(path <> ".unknown") do
    File.write(path <> ".unknown", "remote outcome unknown")
    return HTTP.response(503, "")
  end
  if mode == 6 do
    return HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted"))
  end
  if mode == 7 do
    return HTTP.response(500, String.repeat("x", 1025))
  end
  if mode == 8 || mode == 9 do
    case erase_account_export(Bytes.from_utf8(path)) do
      Err(_) -> return HTTP.response(500, "fixture erase failed")
      Ok(_) -> nil
    end
    if mode == 8 do
      let replacement = case create(path) do
        Err(_) -> return HTTP.response(500, "fixture replacement failed")
        Ok(value) -> value
      end
      File.write(path <> ".replacement", Bytes.to_hex(replacement))
    end
  end
  if mode == 10 do
    configured(port + 100)
  end
  HTTP.response(204, "")
end

actor account_peer(port :: Int,
  path :: String,
  profile :: ClientProfile,
  primary :: Bool,
  mode :: Int) do
  HTTP.router()
    |> HTTP.on_post(if primary do
        "/v1/accounts/delete"
      else
        "/v1/devices/leave"
      end,
      fn(input) -> response(input, path, profile, primary, mode, port) end)
    |> HTTP.on_post("/untrusted",
      fn(_) do
        File.write(path <> ".redirected", "unsafe redirect")
        HTTP.response(500, "redirect followed")
      end)
    |> HTTP.serve(port)
end

fn run_case(port :: Int, mode :: Int) -> Result<(), String> do
  let path = database_path("account_native_network")?
  let public_profile = create(path)?
  let profile = decode_client_profile(public_profile)?
  let primary = mode != 1
  if !primary do
    with_record_transaction(path,
      fn(database) -> delete_blob(database, "account-signing-key/v1") end)?
  end
  let action = request(path, public_profile)?
  assert(Bytes.to_hex(native_account_capabilities(action)?) == if primary do
      "0141435001"
    else
      "0141435000"
    end)
  let _server = spawn(account_peer, port, path, profile, primary, mode)
  Timer.sleep(100)
  assert(configured(port))
  let result = native_account_delete(action)
  if mode == 0 || mode == 1 do
    assert(Bytes.to_hex(result?) == if primary do
        "0141444e01"
      else
        "0141444e03"
      end)
    assert(Result.is_err(load_profile(path)))
  else if mode == 5 do
    assert(Result.is_err(result))
    assert(Bytes.secure_equals(load_profile(path)?, public_profile))
    assert(Bytes.to_hex(native_account_delete(action)?) == "0141444e01")
    assert(Result.is_err(load_profile(path)))
  else if mode == 8 do
    assert(case result do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(Bytes.to_hex(load_profile(path)?) == File.read(path <> ".replacement")?)
  else if mode == 9 do
    assert(case result do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(Result.is_err(load_profile(path)))
  else
    assert(Result.is_err(result))
    assert(Bytes.secure_equals(load_profile(path)?, public_profile))
  end
  assert(File.read(path <> ".called")? == if primary do
      "delete"
    else
      "leave"
    end)
  assert(!File.exists(path <> ".redirected"))
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

fn proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  for mode in 0..11 do
    run_case(22310 + mode, mode)?
  end
  Ok(nil)
end

test("native deletion and departure authenticate owners, require204, retain unknown outcomes and fence late responses") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn stale_action_proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("account_stale_action")?
  let original = create(path)?
  let sealed = load_blob(path, "profile/v1")?
  let statement = account_deletion(path)?
  erase_account_export(Bytes.from_utf8(path))?
  let replacement = create(path)?
  let action = request(path, original)?
  assert(case native_account_delete(action) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(case native_account_discard(action) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(case native_account_capabilities(action) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(case forget_on_proof_at_profile(path, sealed, statement) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_profile(path)?, replacement))
  let profile = decode_client_profile(replacement)?
  let renewed = encode_client_profile(%{profile.entry |
      mailbox_token: Crypto.sha256(profile.entry.mailbox_token)
    },
    profile.account_id,
    profile.device_id)?
  let key = platform_key()?
  store_updated_blobs(path,
    ["profile/v1"],
    [seal_local(renewed, key, local_context("profile/v1")?)?])?
  # A same-key routine profile update permits presence checks, but cannot let an
  # old onboarding409 discard a changed record.
  assert(Bytes.to_hex(native_account_capabilities(request(path, replacement)?)?) == "0141435001")
  assert(case native_account_discard(request(path, replacement)?) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.to_hex(native_account_discard(request(path, renewed)?)?) == "0141445301")
  assert(Result.is_err(load_profile(path)))
  Ok(nil)
end

test("old UI actions and valid old signed proofs cannot affect replacement custody; discard requires the exact profile") do
  case stale_action_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn strict_boundary_proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("account_action_framing")?
  let public_profile = create(path)?
  let before = load_blob(path, "profile/v1")?
  let valid = request(path, public_profile)?
  let malformed = [
    Bytes.empty(),
    Bytes.from_hex("ffffffff")?,
    Bytes.concat(Bytes.from_hex("00000002")?, valid)?,
    Bytes.concat(valid, Bytes.from_hex("00")?)?,
    repeated(0, 40239)?,
    request("", public_profile)?,
    request("/tmp/unsafe\0path", public_profile)?,
    request(path, Bytes.empty())?,
    request(path, repeated(0, 36135)?)?,
    mobile_join([mobile_vector(Bytes.from_hex("ff")?)?, mobile_vector(public_profile)?],
      0,
      Bytes.empty())?
  ]
  for input in malformed do
    assert(Result.is_err(native_account_delete(input)))
    assert(Result.is_err(native_account_discard(input)))
    assert(Result.is_err(native_account_capabilities(input)))
  end
  let target = repeated(1, 16)?
  let device_request = mobile_join([
      mobile_vector(Bytes.from_utf8(path))?,
      mobile_vector(Bytes.from_utf8("invalid view"))?
    ],
    0,
    Bytes.empty())?
  let triple = Bytes.concat(device_request, mobile_vector(target)?)?
  for input in [
    Bytes.empty(),
    Bytes.from_hex("ffffffff")?,
    Bytes.concat(Bytes.from_hex("00000002")?, device_request)?,
    Bytes.concat(device_request, Bytes.from_hex("00")?)?,
    repeated(0, 309365)?
  ] do
    assert(Result.is_err(native_devices_renew(input)))
  end
  for input in [
    Bytes.empty(),
    Bytes.from_hex("ffffffff")?,
    Bytes.concat(Bytes.from_hex("00000003")?, triple)?,
    Bytes.concat(triple, Bytes.from_hex("00")?)?,
    repeated(0, 309385)?,
    Bytes.concat(device_request, mobile_vector(repeated(1, 15)?)?)?
  ] do
    assert(Result.is_err(native_device_revoke(input)))
  end
  assert(Bytes.secure_equals(load_blob(path, "profile/v1")?, before))
  assert(Bytes.secure_equals(load_profile(path)?, public_profile))
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

test("typed account and device boundaries reject counted, trailing, oversized and malformed input before mutation") do
  case strict_boundary_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
