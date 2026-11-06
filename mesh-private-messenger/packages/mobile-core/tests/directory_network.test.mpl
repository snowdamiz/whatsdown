from Mobile.DirectoryNetwork import synchronize_directory_prekeys
from MobileCore import create_account_export, erase_account_export
from Mobile.Codec import mobile_join, mobile_vector
from Prekeys.Pool import (
  PrekeyPublishResponse,
  decode_prekey_publish,
  encode_prekey_publish_response,
  prekey_publish_signing_bytes
)
from Transport.Packet import decode_client_profile
from Tests.Support import database_path

fn configured(port :: Int) -> Bool do
  Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("1\n1\nhttp://127.0.0.1:"
      <> Int.to_string(port)
      <> "\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream"))
end

fn response(input :: Request,
  path :: String,
  account :: Bytes,
  device :: Bytes,
  key :: Bytes,
  mode :: Int) -> Response do
  if Request.header(input, "cookie") != None || Request.header(input, "authorization") != None do
    return HTTP.response(400, "private headers")
  end
  let wire = Request.body_bytes(input)
  let publication = case decode_prekey_publish(wire) do
    Err(_) -> return HTTP.response(400, "malformed publication")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(publication.account_id, account)
    || !Bytes.secure_equals(publication.device_id, device) do
    return HTTP.response(403, "wrong identity")
  end
  let signed = case prekey_publish_signing_bytes(publication) do
    Err(_) -> return HTTP.response(400, "malformed signing bytes")
    Ok(value) -> value
  end
  case Crypto.verify(SigningPublicKey { bytes: key },
    signed,
    Signature { bytes: publication.signature }) do
    Ok(true) -> nil
    _ -> return HTTP.response(403, "invalid signature")
  end
  if mode == 2 do
    return HTTP.response_bytes(200, Bytes.from_utf8("invalid response"))
  end
  if mode == 3 do
    return HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted"))
  end
  if mode == 4 do
    case erase_account_export(Bytes.from_utf8(path)) do
      Err(_) -> return HTTP.response(500, "erase fixture")
      Ok(_) -> nil
    end
  end
  if mode == 8 do
    configured(20099)
  end
  let all_ids = List.map(publication.prekeys, fn(item) -> item.id end)
  let ids = if mode == 6 do
    [
      case U64.parse("99999999") do
        Err(_) -> return HTTP.response(500, "fixture ID")
        Ok(value) -> value
      end
    ]
  else if mode == 7 do
    List.take(all_ids, 32)
  else
    all_ids
  end
  let encoded = case encode_prekey_publish_response(PrekeyPublishResponse {
    account_id: if mode == 5 do
      Crypto.sha256(account)
    else
      account
    end,
    device_id: device,
    active_ids: ids
  }) do
    Err(_) -> return HTTP.response(500, "fixture")
    Ok(value) -> value
  end
  if mode == 1 && List.length(ids) > 0 do
    if !File.exists(path <> ".saved") do
      case File.write(path <> ".saved", Bytes.to_hex(Crypto.sha256(wire))) do
        Err(_) -> return HTTP.response(500, "save fixture")
        Ok(_) -> return HTTP.response(503, "lost acknowledgement")
      end
    end
    let original = case File.read(path <> ".saved") do
      Err(_) -> return HTTP.response(500, "read fixture")
      Ok(value) -> value
    end
    if original != Bytes.to_hex(Crypto.sha256(wire)) do
      return HTTP.response(409, "replacement publication")
    end
    return HTTP.response_bytes(429, encoded)
  end
  HTTP.response_bytes(if List.length(ids) == 0 do
      200
    else
      201
    end,
    encoded)
end

actor peer(port :: Int,
  path :: String,
  account :: Bytes,
  device :: Bytes,
  key :: Bytes,
  mode :: Int) do
  HTTP.router()
    |> HTTP.on_post("/v1/prekeys/one-time/batch",
      fn(input) -> response(input, path, account, device, key, mode) end)
    |> HTTP.on_post("/untrusted", fn(_) -> HTTP.response(500, "redirect followed") end)
    |> HTTP.serve(port)
end

fn run_case(port :: Int, mode :: Int) -> Result<(), String> do
  let path = database_path("directory_network")?
  let profile = decode_client_profile(create_account_export(mobile_join([
      mobile_vector(Bytes.from_utf8(path))?,
      mobile_vector(Bytes.from_utf8("alice"))?
    ],
    0,
    Bytes.empty())?)?)?
  let _server = spawn(peer,
    port,
    path,
    profile.account_id,
    profile.device_id,
    profile.credential.signing_public_key,
    mode)
  Timer.sleep(100)
  assert(configured(port))
  if mode == 0 do
    assert(synchronize_directory_prekeys(path)? == 64)
  else if mode == 1 do
    assert(Result.is_err(synchronize_directory_prekeys(path)))
    assert(synchronize_directory_prekeys(path)? == 64)
  else
    assert(Result.is_err(synchronize_directory_prekeys(path)))
  end
  erase_account_export(Bytes.from_utf8(path))?
  if File.exists(path <> ".saved") do
    File.delete(path <> ".saved")?
  end
  Ok(nil)
end

fn proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  run_case(20011, 0)?
  run_case(20012, 1)?
  run_case(20013, 2)?
  run_case(20014, 3)?
  run_case(20015, 4)?
  run_case(20016, 5)?
  run_case(20017, 6)?
  run_case(20018, 7)?
  run_case(20019, 8)?
  Ok(nil)
end

test("native prekey sync authenticates publications and recovers the same durable keys from a lost acknowledgement") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

from Mobile.DirectoryNetwork import register_directory
from Mobile.Account import directory_entry_for, account_deletion
from Mobile.Profile import load_profile
from MobileCore import (
  create_signup_draft_export,
  directory_register_export,
  prekeys_synchronize_export
)
from Privacy.Edge import decode_stamped_request, verify_request_stamp
from Mobile.Codec import current_time
from Tests.Support import install_security_config

fn registration_response(input :: Request,
  path :: String,
  entry :: Bytes,
  proof :: Bytes,
  mode :: Int) -> Response do
  if Request.header(input, "cookie") != None || Request.header(input, "authorization") != None do
    return HTTP.response(400, "unexpected private headers")
  end
  let parsed = case decode_stamped_request(Request.body_bytes(input), 36006) do
    Err(_) -> return HTTP.response(400, "missing work")
    Ok(value) -> value
  end
  let (stamp, payload) = parsed
  if !Bytes.secure_equals(payload, entry) do
    return HTTP.response(400, "wrong directory identity")
  end
  case verify_request_stamp("mesh-msg/v1/work/register",
    payload,
    stamp,
    case current_time() do
      Err(_) -> return HTTP.response(500, "clock")
      Ok(value) -> value
    end,
    case U64.parse("300000") do
      Err(_) -> return HTTP.response(500, "window")
      Ok(value) -> value
    end,
    1) do
    Ok(true) -> nil
    _ -> return HTTP.response(403, "work rejected")
  end
  case File.write(path <> ".registered", "called") do
    Err(_) -> return HTTP.response(500, "fixture marker")
    Ok(_) -> nil
  end
  if mode == 1 do
    HTTP.response(409, "unavailable")
  else if mode == 2 do
    HTTP.response_bytes(410, Bytes.from_utf8("forged removal"))
  else if mode == 3 do
    HTTP.response_bytes(410, proof)
  else if mode == 4 do
    HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted"))
  else if mode == 5 do
    case erase_account_export(Bytes.from_utf8(path)) do
      Err(_) -> HTTP.response(500, "fixture erase")
      Ok(_) -> do
        File.write(path <> ".erased", "done")
        HTTP.response(201, "")
      end
    end
  else
    HTTP.response(201, "")
  end
end

actor registration_peer(port :: Int,
  path :: String,
  entry :: Bytes,
  account :: Bytes,
  device :: Bytes,
  key :: Bytes,
  proof :: Bytes,
  mode :: Int) do
  HTTP.router()
    |> HTTP.on_put("/v1/devices/register",
      fn(input) -> registration_response(input, path, entry, proof, mode) end)
    |> HTTP.on_post("/v1/prekeys/one-time/batch",
      fn(input) -> response(input, path, account, device, key, 0) end)
    |> HTTP.serve(port)
end

fn enable_policy_transport() -> Bool!String do
  let key = Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("policy fixture service")))
  let witness = Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("policy fixture witness")))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    Bytes.from_utf8("3\n"
      <> key
      <> "\n"
      <> key
      <> "\n1\n1\n1\noutside "
      <> witness
      <> " Outside\n-\n0\nhttps://127.0.0.1:9\n2\n1\n1\noutside "
      <> witness
      <> " Outside")))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0101")?))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/issuer-tls-root/v1"),
    Bytes.from_hex("01000000000000")?))
  Ok(true)
end

fn registration_case(port :: Int, mode :: Int) -> Result<(), String> do
  let path = database_path("native_registration")?
  let request = mobile_join([
      mobile_vector(Bytes.from_utf8(path))?,
      mobile_vector(Bytes.from_utf8("alice"))?
    ],
    0,
    Bytes.empty())?
  let encoded = if mode == 7 do
    enable_policy_transport()?
    create_signup_draft_export(request)?
  else
    create_account_export(request)?
  end
  let profile = decode_client_profile(encoded)?
  if mode != 7 do
    assert(install_security_config(profile.account_id,
      Crypto.sha256(profile.account_id),
      Crypto.sha256(profile.device_id),
      profile.account_id,
      1))
  end
  if mode == 6 do
    enable_policy_transport()?
  end
  let entry = directory_entry_for(path)?
  let removal = account_deletion(path)?
  let _server = spawn(registration_peer,
    port,
    path,
    entry,
    profile.account_id,
    profile.device_id,
    profile.credential.signing_public_key,
    removal,
    mode)
  Timer.sleep(100)
  assert(configured(port))
  if mode == 0 do
    assert(Bytes.to_hex(directory_register_export(Bytes.from_utf8(path))?) == "01445247004000")
    assert(Bytes.to_hex(prekeys_synchronize_export(Bytes.from_utf8(path))?) == "0144504b0040")
    # A reconnect re-registers its same identity and reconciles the persisted pool.
    assert(register_directory(path)?.active_prekeys == 64)
  else if mode == 3 do
    assert(Bytes.to_hex(directory_register_export(Bytes.from_utf8(path))?) == "01445247000001")
    assert(Result.is_err(load_profile(path)))
  else
    case register_directory(path) do
      Ok(_) -> assert(false)
      Err(error) -> do
        if mode == 1 do
          assert(error == "registration_refused")
        end
        if mode == 2 do
          assert(error == "unproven_removal")
        end
        if mode == 5 do
          assert(error == "directory_identity_changed")
          assert(File.exists(path <> ".erased"))
          assert(Result.is_err(load_profile(path)))
        end
        if mode == 6 do
          assert(error == "credit_transport_unavailable")
        end
        if mode == 7 do
          assert(error == "paid_signup_draft_pending")
        end
      end
    end
    if mode == 2 do
      assert(Bytes.secure_equals(load_profile(path)?, encoded))
    end
  end
  if mode == 6 || mode == 7 do
    assert(!File.exists(path <> ".registered"))
  end
  erase_account_export(Bytes.from_utf8(path))?
  if File.exists(path <> ".registered") do
    File.delete(path <> ".registered")?
  end
  if File.exists(path <> ".erased") do
    File.delete(path <> ".erased")?
  end
  Ok(nil)
end

fn registration_proof() -> Result<(), String> do
  assert(Result.is_err(directory_register_export(Bytes.empty())))
  assert(Result.is_err(prekeys_synchronize_export(Bytes.from_utf8("/tmp/invalid\0path"))))
  assert(Test.install_in_memory_secure_store())
  for mode in [0, 1, 2, 3, 4, 5, 6, 7] do
    registration_case(20031 + mode, mode)?
  end
  Ok(nil)
end

test("native registration owns work, removal authentication, retry and policy failure without a JS transport") do
  case registration_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
