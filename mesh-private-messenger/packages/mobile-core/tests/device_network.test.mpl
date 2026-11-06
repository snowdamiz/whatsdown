from Mobile.DeviceNetwork import native_devices_renew, native_device_revoke
from Mobile.Codec import mobile_join, mobile_vector, current_time
from Mobile.Profile import load_profile
from MobileCore import (
  create_account_export,
  directory_entry_export,
  create_link_request_export,
  authorize_device_link_for_set_export,
  complete_device_link_export,
  install_group_transparency_for_test,
  renew_devices_for_test,
  erase_account_export
)
from Tests.Support import database_path
from Tests.GroupConsistencySupport import signed_transparency_view
from Transparency.Merkle import leaf_hash
from Transport.Packet import ClientProfile, decode_client_profile
from Protocol.V1 import DirectoryEntry, DeviceSet
from Protocol.DirectoryWire import (
  decode_directory_entry,
  encode_device_set,
  decode_device_revocation
)
from Mobile.Account import account_deletion
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs
from Mobile.Platform import native_security_config
from Transparency.Config import encode_security_config
from Protocol.IdentityWire import decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Prekeys.Bundle import normalize_prekey_bundle
from Identity.Device import verify_device_revocation
from Privacy.Edge import decode_stamped_request, verify_request_stamp

fn request(parts :: List<Bytes>) -> Bytes!String do
  mobile_join(for value in parts do
      mobile_vector(value)?
    end,
    0,
    Bytes.empty())
end

fn configured(port :: Int) -> Bool do
  Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("1\n1\nhttp://127.0.0.1:"
      <> Int.to_string(port)
      <> "\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream"))
end

fn logged(path :: String) -> DirectoryEntry!String do
  let entry = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(path))?) do
    Err(_) -> return Err("fixture entry")
    Ok(value) -> value
  end
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> return Err("fixture bundle")
    Ok(value) -> value
  end
  let normalized = case normalize_prekey_bundle(bundle) do
    Err(_) -> return Err("fixture normalization")
    Ok(value) -> value
  end
  let encoded = case encode_prekey_bundle(normalized) do
    Err(_) -> return Err("fixture bundle encoding")
    Ok(value) -> value
  end
  Ok(%{entry | prekey_bundle: encoded})
end

fn set_wire(root :: DirectoryEntry,
  devices :: List<DirectoryEntry>,
  sequence :: String) -> Bytes!String do
  case encode_device_set(DeviceSet {
    version: 1,
    username: root.username,
    account_identity: root.account_identity,
    sequence: U64.parse(sequence)?,
    devices: devices,
    revoked_device_ids: []
  }) do
    Err(_) -> Err("fixture set")
    Ok(value)
  end
end

fn install(paths :: List<String>, devices :: Bytes) -> Result<(), String> do
  let view = signed_transparency_view([leaf_hash(devices)?])?
  for path in paths do
    assert(install_group_transparency_for_test(path,
      view.checkpoint,
      view.consistency,
      view.service_public_key,
      view.witness_a_public_key,
      view.witness_b_public_key,
      devices)?)
  end
  Ok(nil)
end

fn linked_fixture(root_path :: String, linked_path :: String) -> (Bytes, ClientProfile)!String do
  let root_profile = create_account_export(request([
    Bytes.from_utf8(root_path),
    Bytes.from_utf8("alice")
  ])?)?
  let root = logged(root_path)?
  let first = set_wire(root, [root], "1")?
  install([root_path], first)?
  let pending = create_link_request_export(Bytes.from_utf8(linked_path))?
  let authorization = authorize_device_link_for_set_export(request([
    Bytes.from_utf8(root_path),
    first,
    pending
  ])?)?
  complete_device_link_export(request([Bytes.from_utf8(linked_path), authorization])?)?
  let devices = set_wire(root, [root, logged(linked_path)?], "2")?
  install([root_path, linked_path], devices)?
  Ok((devices, decode_client_profile(root_profile)?))
end

fn renewal_response(input :: Request, path :: String, profile :: ClientProfile) -> Response do
  if Request.header(input, "cookie") != None || Request.header(input, "authorization") != None do
    return HTTP.response(400, "private header")
  end
  let (stamp, payload) = case decode_stamped_request(Request.body_bytes(input), 36006) do
    Err(_) -> return HTTP.response(400, "invalid stamp")
    Ok(value) -> value
  end
  let valid_work = case verify_request_stamp("mesh-msg/v1/work/register",
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
    Err(_) -> false
    Ok(value) -> value
  end
  if !valid_work do
    return HTTP.response(402, "invalid work")
  end
  let entry = case decode_directory_entry(payload) do
    Err(_) -> return HTTP.response(400, "invalid entry")
    Ok(value) -> value
  end
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> return HTTP.response(400, "invalid bundle")
    Ok(value) -> value
  end
  let credential = case decode_device_credential(bundle.device_credential) do
    Err(_) -> return HTTP.response(400, "invalid credential")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(credential.account_id, profile.account_id) do
    return HTTP.response(403, "wrong account")
  end
  let sequence = U64.to_string(credential.directory_sequence)
  if sequence != "4" && sequence != "5" do
    return HTTP.response(409, "wrong order")
  end
  let label = path <> ".entry-" <> sequence
  let digest = Bytes.to_hex(Crypto.sha256(payload))
  File.write(path <> ".wire-" <> sequence, Bytes.to_hex(payload))
  if File.exists(label) do
    let previous = case File.read(label) do
      Err(_) -> return HTTP.response(500, "read")
      Ok(value) -> value
    end
    if previous != digest do
      return HTTP.response(409, "changed pending entry")
    end
  else
    File.write(label, digest)
    if sequence == "5" do
      return HTTP.response(503, "unknown acknowledgement")
    end
  end
  HTTP.response(200, "")
end

actor renewal_peer(port :: Int, path :: String, profile :: ClientProfile) do
  HTTP.router()
    |> HTTP.on_put("/v1/devices/register", fn(input) -> renewal_response(input, path, profile) end)
    |> HTTP.serve(port)
end

fn exact_renewal_proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("device_network_root")?
  let linked = database_path("device_network_linked")?
  let (first, profile) = linked_fixture(path, linked)?
  let root = logged(path)?
  let asked = renew_devices_for_test(linked, first, 91 * 86400000)?
  assert(List.length(asked) == 1)
  let asking = case decode_directory_entry(List.head(asked)) do
    Err(_) -> return Err("fixture asking entry")
    Ok(value) -> value
  end
  let devices = set_wire(root, [root, asking], "3")?
  install([path, linked], devices)?
  assert(List.length(renew_devices_for_test(path, devices, 91 * 86400000)?) == 2)
  let _server = spawn(renewal_peer, 22410, path, profile)
  Timer.sleep(100)
  assert(configured(22410))
  let action = request([Bytes.from_utf8(path), devices])?
  assert(Bytes.to_hex(native_devices_renew(action)?) == "01444e520101f700")
  Timer.sleep(20)
  assert(Bytes.to_hex(native_devices_renew(action)?) == "01444e5202000000")
  assert(case renew_devices_for_test(path, devices, 0) do
    Err("renewal_publication_pending") -> true
    _ -> false
  end)
  # An HTTP acknowledgement alone is not the witnessed successor. The same
  # input must still recover exactly the same two canonical entries in order.
  assert(Bytes.to_hex(native_devices_renew(action)?) == "01444e5202000000")
  let renewed_root = case decode_directory_entry(Bytes.from_hex(File.read(path <> ".wire-4")?)?) do
    Err(_) -> return Err("fixture witnessed root")
    Ok(value) -> value
  end
  let renewed_linked = case decode_directory_entry(Bytes.from_hex(File.read(path
    <> ".wire-5")?)?) do
    Err(_) -> return Err("fixture witnessed linked")
    Ok(value) -> value
  end
  let successor = set_wire(root, [renewed_root, renewed_linked], "5")?
  install([path, linked], successor)?
  assert(Bytes.to_hex(native_devices_renew(request([
    Bytes.from_utf8(path),
    successor
  ])?)?) == "01444e5200000000")
  assert(Result.is_err(load_blob(path, "device-publication/v1")))
  assert(Bytes.secure_equals(decode_client_profile(load_profile(path)?)?.account_id,
    profile.account_id))
  erase_account_export(Bytes.from_utf8(path))?
  erase_account_export(Bytes.from_utf8(linked))?
  Ok(nil)
end

fn mutation_response(input :: Request,
  path :: String,
  profile :: ClientProfile,
  target :: Bytes,
  mode :: Int,
  port :: Int) -> Response do
  if Request.header(input, "cookie") != None || Request.header(input, "authorization") != None do
    return HTTP.response(400, "private header")
  end
  let wire = Request.body_bytes(input)
  let revocation = case decode_device_revocation(wire) do
    Err(_) -> return HTTP.response(400, "malformed revocation")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(revocation.device_id, target)
    || U64.to_string(revocation.sequence) != "3" do
    return HTTP.response(400, "wrong native target")
  end
  case verify_device_revocation(profile.account, revocation) do
    Ok(true) -> nil
    _ -> return HTTP.response(403, "invalid native signature")
  end
  let digest = Bytes.to_hex(Crypto.sha256(wire))
  if File.exists(path <> ".called") do
    let previous = case File.read(path <> ".called") do
      Err(_) -> return HTTP.response(500, "read")
      Ok(value) -> value
    end
    if previous != digest do
      return HTTP.response(409, "changed retry")
    end
  end
  File.write(path <> ".called", digest)
  if mode == 1 do
    return HTTP.response(403, "")
  end
  if mode == 2 do
    return HTTP.response(410, "")
  end
  if mode == 3 do
    return HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted"))
  end
  if mode == 4 do
    return HTTP.response(500, String.repeat("x", 1025))
  end
  if mode == 5 do
    erase_account_export(Bytes.from_utf8(path))
    let creation = case request([Bytes.from_utf8(path), Bytes.from_utf8("bob")]) do
      Err(_) -> return HTTP.response(500, "fixture request")
      Ok(value) -> value
    end
    let replacement = case create_account_export(creation) do
      Err(_) -> return HTTP.response(500, "fixture replacement")
      Ok(value) -> value
    end
    File.write(path <> ".replacement", Bytes.to_hex(replacement))
  end
  if mode == 6 do
    configured(port + 100)
  end
  if mode == 7 && !File.exists(path <> ".unknown") do
    File.write(path <> ".unknown", "unknown response")
    return HTTP.response(503, "")
  end
  HTTP.response(200, "")
end

actor revocation_peer(port :: Int,
  path :: String,
  profile :: ClientProfile,
  target :: Bytes,
  mode :: Int) do
  HTTP.router()
    |> HTTP.on_post("/v1/devices/revoke",
      fn(input) -> mutation_response(input, path, profile, target, mode, port) end)
    |> HTTP.on_post("/untrusted",
      fn(_) do
        File.write(path <> ".redirected", "unsafe redirect")
        HTTP.response(500, "redirect followed")
      end)
    |> HTTP.serve(port)
end

fn revocation_case(port :: Int, mode :: Int) -> Result<(), String> do
  let path = database_path("device_revoke_root")?
  let linked = database_path("device_revoke_linked")?
  let (devices, profile) = linked_fixture(path, linked)?
  let target = decode_client_profile(load_profile(linked)?)?.device_id
  let _server = spawn(revocation_peer, port, path, profile, target, mode)
  Timer.sleep(100)
  assert(configured(port))
  let action = request([Bytes.from_utf8(path), devices, target])?
  let result = native_device_revoke(action)
  if mode == 0 do
    assert(Bytes.to_hex(result?) == "0144525600c8")
    # Acknowledgement does not manufacture a witnessed new device set.
    let root = logged(path)?
    let revoked = case encode_device_set(DeviceSet {
      version: 1,
      username: root.username,
      account_identity: root.account_identity,
      sequence: U64.parse("3")?,
      devices: [root],
      revoked_device_ids: [target]
    }) do
      Err(_) -> return Err("fixture revoked set")
      Ok(value) -> value
    end
    install([path], revoked)?
    File.delete(path <> ".called")?
    assert(Bytes.to_hex(native_device_revoke(request([
      Bytes.from_utf8(path),
      revoked,
      target
    ])?)?) == "0144525600c8")
    assert(!File.exists(path <> ".called"))
  else if mode == 7 do
    assert(Result.is_err(result))
    assert(Bytes.to_hex(native_device_revoke(action)?) == "0144525600c8")
  else
    assert(Result.is_err(result))
  end
  if mode == 5 do
    assert(Bytes.to_hex(load_profile(path)?) == File.read(path <> ".replacement")?)
  else
    assert(Bytes.secure_equals(decode_client_profile(load_profile(path)?)?.account_id,
      profile.account_id))
  end
  assert(!File.exists(path <> ".redirected"))
  erase_account_export(Bytes.from_utf8(path))?
  erase_account_export(Bytes.from_utf8(linked))?
  Ok(nil)
end

fn revocation_proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  for mode in 0..8 do
    revocation_case(22430 + mode, mode)?
  end
  Ok(nil)
end

test("native revocation keeps signatures and targets private, rejects unproven410, and fences retries and replacement") do
  case revocation_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn refusal_response(input :: Request,
  path :: String,
  mode :: Int,
  proof :: Bytes,
  port :: Int) -> Response do
  case decode_stamped_request(Request.body_bytes(input), 36006) do
    Err(_) -> return HTTP.response(400, "invalid stamped entry")
    Ok(_) -> nil
  end
  File.write(path <> ".called", "native renewal")
  if mode == 0 do
    return HTTP.response(409, "")
  end
  if mode == 1 do
    return HTTP.response_bytes(410, proof)
  end
  if mode == 2 do
    return HTTP.response(410, "untrusted removal")
  end
  if mode == 3 do
    return HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted"))
  end
  if mode == 4 do
    return HTTP.response(500, String.repeat("x", 1025))
  end
  if mode == 5 || mode == 6 do
    erase_account_export(Bytes.from_utf8(path))
    if mode == 5 do
      let creation = case request([Bytes.from_utf8(path), Bytes.from_utf8("bob")]) do
        Err(_) -> return HTTP.response(500, "fixture request")
        Ok(value) -> value
      end
      let replacement = case create_account_export(creation) do
        Err(_) -> return HTTP.response(500, "fixture replacement")
        Ok(value) -> value
      end
      File.write(path <> ".replacement", Bytes.to_hex(replacement))
    end
  end
  if mode == 7 do
    configured(port + 100)
  end
  HTTP.response(200, "")
end

actor renewal_refusal_peer(port :: Int, path :: String, mode :: Int, proof :: Bytes) do
  HTTP.router()
    |> HTTP.on_put("/v1/devices/register",
      fn(input) -> refusal_response(input, path, mode, proof, port) end)
    |> HTTP.on_put("/untrusted",
      fn(_) do
        File.write(path <> ".redirected", "unsafe redirect")
        HTTP.response(500, "redirect followed")
      end)
    |> HTTP.serve(port)
end

fn renewal_refusal_case(port :: Int, mode :: Int) -> Result<(), String> do
  let path = database_path("renewal_response_fence")?
  create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8("alice")])?)?
  let profile = decode_client_profile(load_profile(path)?)?
  let root = logged(path)?
  let devices = set_wire(root, [root], "1")?
  install([path], devices)?
  assert(List.length(renew_devices_for_test(path, devices, 91 * 86400000)?) == 1)
  let proof = account_deletion(path)?
  let _server = spawn(renewal_refusal_peer, port, path, mode, proof)
  Timer.sleep(100)
  assert(configured(port))
  if mode == 8 do
    let config = native_security_config()?
    assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
      encode_security_config(%{config |
        version: 3,
        log_version: 2,
        legacy_threshold: config.threshold,
        legacy_witnesses: config.witnesses,
        issuer_origin: "https://127.0.0.1:9"
      })?))
    assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0100")?))
    assert(Test.set_push_token(Bytes.from_utf8("messenger/issuer-tls-root/v1"),
      Bytes.from_hex("01000000000000")?))
  end
  let result = native_devices_renew(request([Bytes.from_utf8(path), devices])?)
  if mode == 0 do
    assert(Bytes.to_hex(result?) == "01444e5200019900")
  else if mode == 1 do
    assert(Bytes.to_hex(result?) == "01444e5200019a01")
  else if mode == 3 do
    assert(Bytes.to_hex(result?) == "01444e5200013300")
  else if mode == 8 do
    assert(case result do
      Err("credit_transport_unavailable") -> true
      _ -> false
    end)
    assert(!File.exists(path <> ".called"))
  else
    assert(Result.is_err(result))
  end
  if mode == 1 || mode == 6 do
    assert(Result.is_err(load_profile(path)))
  else if mode == 5 do
    assert(Bytes.to_hex(load_profile(path)?) == File.read(path <> ".replacement")?)
  else
    assert(Bytes.secure_equals(decode_client_profile(load_profile(path)?)?.account_id,
      profile.account_id))
    assert(Bytes.length(load_blob(path, "device-publication/v1")?) > 0)
  end
  assert(!File.exists(path <> ".redirected"))
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

fn refusal_proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  for mode in 0..9 do
    renewal_refusal_case(22450 + mode, mode)?
  end
  Ok(nil)
end

test("renewal authenticates410 before guarded erasure, retains refusals, and never falls back after policy transport failure") do
  case refusal_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("unknown partial renewal publication replays the exact ordered signed entries until a witnessed successor") do
  case exact_renewal_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
