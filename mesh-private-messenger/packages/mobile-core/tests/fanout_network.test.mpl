from Mobile.Platform import native_security_config
from Transparency.Config import encode_security_config
from Mobile.AttachmentRecipients import require_attachment_authorization
from Mobile.FanoutNetwork import native_fanout_send, parse_fanout_action
from MobileCore import (
  create_account_export,
  directory_entry_export,
  erase_account_export,
  outbox_list_export,
  group_create_export,
  group_add_export,
  group_key_package_export,
  group_invitations_export,
  receive_initial_export,
  receive_message_export
)
from Mobile.Codec import current_time
from Mobile.Profile import load_profile
from Mobile.DirectoryResolve import resolve_directory_device_set_at_profile
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_blobs, store_record_changes
from Tests.Support import append, vector, database_path, repeated, install_security_config
from Tests.GroupLifecycleWire import group_vectors, output_list
from Prekeys.Bundle import normalize_prekey_bundle
from Prekeys.Pool import decode_prekey_claim
from Privacy.Edge import decode_stamped_request, verify_request_stamp
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set, decode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import DeviceSet
from Transport.Packet import decode_client_profile
from Transparency.Merkle import (
  leaf_hash_for,
  merkle_root_for,
  sign_tree_checkpoint_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness
)
from Transparency.Wire import (
  TransparencyEvidence,
  encode_transparency_evidence,
  decode_transparency_evidence,
  decode_transparency_lookup
)

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("fixture signer")
    Ok(value)
  end
end

struct FixtureDevice do
  devices :: Bytes
  bundle :: Bytes
end

fn fixture_device(path :: String) -> FixtureDevice!String do
  let entry = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(path))?) do
    Err(_) -> return Err("fixture entry")
    Ok(value) -> value
  end
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> return Err("fixture account")
    Ok(value) -> value
  end
  let claimed = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> return Err("fixture bundle")
    Ok(value) -> value
  end
  let base = case normalize_prekey_bundle(claimed) do
    Err(_) -> return Err("fixture base bundle")
    Ok(value) -> value
  end
  let wire = case encode_prekey_bundle(base) do
    Err(_) -> return Err("fixture base wire")
    Ok(value) -> value
  end
  let devices = case encode_device_set(DeviceSet {
    version: 1,
    username: entry.username,
    account_identity: entry.account_identity,
    sequence: account.directory_sequence,
    devices: [%{entry | prekey_bundle: wire}],
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("fixture devices")
    Ok(value) -> value
  end
  Ok(FixtureDevice { devices: devices, bundle: entry.prekey_bundle })
end

fn evidence(devices :: Bytes,
  leaves :: List<Bytes>,
  index :: Int,
  previous :: Bool,
  now :: U64,
  signer :: borrow SigningPrivateKey,
  public :: Bytes,
  a :: borrow SigningPrivateKey,
  b :: borrow SigningPrivateKey) -> Bytes!String do
  let checkpoint = sign_tree_checkpoint_for(1,
    signer,
    public,
    U64.parse("1")?,
    U64.parse("2")?,
    merkle_root_for(1, leaves)?,
    repeated(0, 32)?,
    now)?
  encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: devices,
    inclusion: compact_inclusion_proof_for(1, leaves, index)?,
    consistency: compact_consistency_proof_for(1,
      if previous do
        leaves
      else
        []
      end,
      leaves)?,
    checkpoint: checkpoint,
    witnesses: [
      sign_witness("witness-a", a, checkpoint)?,
      sign_witness("witness-b", b, checkpoint)?
    ]
  })
end

fn stamp_valid(input :: Request, domain :: String, limit :: Int) -> Bytes!String do
  if Request.header(input, "authorization") != None
    || Request.header(input, "cookie") != None
    || Request.header(input, "content-type") != Some("application/octet-stream") do
    return Err("fixture privacy headers")
  end
  let (stamp, body) = decode_stamped_request(Request.body_bytes(input), limit)?
  if !verify_request_stamp(domain, body, stamp, current_time()?, U64.parse("300000")?, 1)? do
    return Err("fixture work")
  end
  Ok(body)
end

fn replace_account(path :: String) -> Result<(), String> do
  erase_account_export(Bytes.from_utf8(path))?
  create_account_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("replacement")])?)?
  Ok(nil)
end

fn resolve_reply(input :: Request,
  path :: String,
  peer_first :: Bytes,
  peer_same :: Bytes,
  local_first :: Bytes,
  local_same :: Bytes,
  mode :: Int) -> Response do
  let body = case stamp_valid(input, "mesh-msg/v1/work/resolve", 76) do
    Err(error) -> return HTTP.response(400, error)
    Ok(value) -> value
  end
  let lookup = case decode_transparency_lookup(body) do
    Err(error) -> return HTTP.response(400, error)
    Ok(value) -> value
  end
  File.write(path <> ".resolve", "requested")
  let peer_evidence = case decode_transparency_evidence(peer_first) do
    Err(error) -> return HTTP.response(500, error)
    Ok(value) -> value
  end
  let peer_devices = case decode_device_set(peer_evidence.entry_bytes) do
    Err(_) -> return HTTP.response(500, "fixture peer devices")
    Ok(value) -> value
  end
  let peer_account = case decode_account_identity(peer_devices.account_identity) do
    Err(_) -> return HTTP.response(500, "fixture peer identity")
    Ok(value) -> value
  end
  if mode == 7 do
    case replace_account(path) do
      Err(error) -> return HTTP.response(500, error)
      Ok(_) -> nil
    end
  end
  HTTP.response_bytes(200,
    if lookup.username == "bob"
      || lookup.username == "@" <> Bytes.to_hex(peer_account.account_id) do
      if lookup.previous_tree_size == 0 do
        peer_first
      else
        peer_same
      end
    else if lookup.previous_tree_size == 0 do
      local_first
    else
      local_same
    end)
end

fn claim_reply(input :: Request, path :: String, bundle :: Bytes, mode :: Int) -> Response do
  let body = case stamp_valid(input, "mesh-msg/v1/work/prekey-claim", 100) do
    Err(error) -> return HTTP.response(400, error)
    Ok(value) -> value
  end
  let claim = case decode_prekey_claim(body) do
    Err(error) -> return HTTP.response(400, error)
    Ok(value) -> value
  end
  let id = Bytes.to_hex(claim.reservation_id)
  let old = File.read(path <> ".claim")
  case old do
    Ok(previous) -> if previous != id do
      return HTTP.response(409, "claim changed")
    end
    Err(_) -> nil
  end
  File.write(path <> ".claim", id)
  if mode == 1 do
    return HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted"))
  end
  if mode == 5 && Result.is_err(old) do
    return HTTP.response(503, "ambiguous first response")
  end
  if mode == 6 do
    case replace_account(path) do
      Err(error) -> return HTTP.response(500, error)
      Ok(_) -> nil
    end
  end
  if mode == 8 do
    Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
      Bytes.from_utf8("1\n1\nhttp://127.0.0.1:9\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream"))
  end
  let output = if mode == 3 do
    case repeated(0, 19313) do
      Err(_) -> return HTTP.response(500, "fixture allocation")
      Ok(value) -> value
    end
  else if mode == 4 do
    Bytes.from_utf8("forged claimed bundle")
  else
    bundle
  end
  if mode == 2 do
    HTTP.response_bytes(200, output)
  else
    HTTP.response_bytes_with_headers(200, output, Map.put(Map.new(), "Cache-Control", "no-store"))
  end
end

actor peer(port :: Int,
  path :: String,
  first :: Bytes,
  same :: Bytes,
  local_first :: Bytes,
  local_same :: Bytes,
  bundle :: Bytes,
  mode :: Int) do
  HTTP.router()
    |> HTTP.on_post("/v1/devices/resolve",
      fn(input) -> resolve_reply(input, path, first, same, local_first, local_same, mode) end)
    |> HTTP.on_post("/v1/prekeys/bundle", fn(input) -> claim_reply(input, path, bundle, mode) end)
    |> HTTP.on_post("/untrusted",
      fn(_) do
        File.write(path <> ".redirect", "followed")
        HTTP.response(500, "redirect followed")
      end)
    |> HTTP.serve(port)
end

fn action(path :: String, profile :: Bytes, expected_peer :: Bytes) -> Bytes!String do
  group_vectors([
    Bytes.from_utf8(path),
    profile,
    Bytes.from_utf8("bob"),
    repeated(1, 1)?,
    Bytes.from_utf8("native bounded fanout"),
    expected_peer,
    Bytes.empty()
  ])
end

fn run_case(mode :: Int) -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let signer = pair()?
  let a = pair()?
  let b = pair()?
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> return Err("fixture delivery")
    Ok(value) -> value
  end
  assert(install_security_config(signer.public_key.bytes,
    a.public_key.bytes,
    b.public_key.bytes,
    delivery.public_key.bytes,
    1))
  let path = database_path("native_fanout")?
  let bob = database_path("native_fanout_peer")?
  let profile = create_account_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("alice")
  ])?)?
  let bob_profile = create_account_export(group_vectors([
    Bytes.from_utf8(bob),
    Bytes.from_utf8("bob")
  ])?)?
  let local = fixture_device(path)?
  let remote = fixture_device(bob)?
  let leaves = [leaf_hash_for(1, remote.devices)?, leaf_hash_for(1, local.devices)?]
  let now = current_time()?
  let first = evidence(remote.devices,
    leaves,
    0,
    false,
    now,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key)?
  let same = evidence(remote.devices,
    leaves,
    0,
    true,
    now,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key)?
  let local_first = evidence(local.devices,
    leaves,
    1,
    false,
    now,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key)?
  let local = evidence(local.devices,
    leaves,
    1,
    true,
    now,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key)?
  let port = 24270 + mode
  let server = spawn(peer, port, path, first, same, local_first, local, remote.bundle, mode)
  Timer.sleep(50)
  let network = Bytes.from_utf8("1\n1\nhttp://127.0.0.1:#{port}\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream")
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), network))
  let security = encode_security_config(native_security_config()?)?
  let companion = Bytes.from_utf8("1\n"
    <> Bytes.to_hex(Crypto.sha256(network))
    <> "\n"
    <> Bytes.to_hex(Crypto.sha256(security))
    <> "\n1\noff\n0")
  assert(Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"), companion))
  if mode == 12 do
    let preflight = group_vectors([
      Bytes.from_utf8(path),
      profile,
      Bytes.from_utf8("bob"),
      repeated(4, 1)?,
      Bytes.empty(),
      Bytes.empty(),
      Bytes.empty()
    ])?
    let ticket = native_fanout_send(preflight)?
    assert(Bytes.length(ticket) > 40 && Bytes.length(ticket) < 40000)
    require_attachment_authorization(path, ticket)?
    let key = platform_key()?
    let fork_label = "transparency-fork/v1"
    store_updated_blobs(path,
      [fork_label],
      [
        seal_local(Bytes.from_utf8("synthetic retained verified fork"),
          key,
          local_context(fork_label)?)?
      ])?
    assert(require_attachment_authorization(path, ticket) == Err("transparency_fork_detected"))
    store_record_changes(path, [], [], [fork_label])?
    require_attachment_authorization(path, ticket)?
    assert(!File.exists(path <> ".claim"))
    assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(path))?)?) == 0)
    assert(Result.is_err(require_attachment_authorization(bob, ticket)))
    assert(Result.is_err(require_attachment_authorization(path, append(ticket, repeated(0, 1)?)?)))
    replace_account(path)?
    assert(Result.is_err(require_attachment_authorization(path, ticket)))
    File.delete(path)?
    File.delete(bob)?
    File.delete(path <> ".resolve")?
    return Ok(nil)
  end
  if mode == 11 do
    let sealed = load_blob(path, "profile/v1")?
    resolve_directory_device_set_at_profile(path, "bob", sealed)?
    resolve_directory_device_set_at_profile(path, "alice", sealed)?
    let group = group_create_export(Bytes.from_utf8(path))?
    let invite = group_vectors([
      Bytes.from_utf8(path),
      profile,
      Bytes.from_utf8("bob"),
      repeated(2, 1)?,
      group,
      Bytes.empty(),
      Bytes.empty()
    ])?
    assert(Bytes.to_hex(native_fanout_send(invite)?) == "01464e4f00")
    let outgoing = output_list(outbox_list_export(Bytes.from_utf8(path))?)?
    assert(List.length(outgoing) == 1)
    native_fanout_send(invite)?
    assert(Bytes.secure_equals(List.head(output_list(outbox_list_export(Bytes.from_utf8(path))?)?),
      List.head(outgoing)))
    receive_initial_export(group_vectors([Bytes.from_utf8(bob), List.head(outgoing)])?)?
    let record = List.head(output_list(group_invitations_export(Bytes.from_utf8(bob))?)?)
    let reference = List.head(output_list(record)?)
    let accept = group_vectors([
      Bytes.from_utf8(bob),
      bob_profile,
      Bytes.from_utf8("alice"),
      repeated(3, 1)?,
      reference,
      Bytes.empty(),
      Bytes.empty()
    ])?
    assert(Bytes.to_hex(native_fanout_send(accept)?) == "01464e4f00")
    let acceptance = output_list(outbox_list_export(Bytes.from_utf8(bob))?)?
    assert(List.length(acceptance) == 1)
    native_fanout_send(accept)?
    assert(Bytes.secure_equals(List.head(output_list(outbox_list_export(Bytes.from_utf8(bob))?)?),
      List.head(acceptance)))
    receive_message_export(group_vectors([Bytes.from_utf8(path), List.head(acceptance)])?)?
    let ready = List.head(output_list(group_invitations_export(Bytes.from_utf8(path))?)?)
    assert(Bytes.to_hex(List.get(output_list(ready)?, 4)) == "03")
    group_add_export(group_vectors([
      Bytes.from_utf8(path),
      group,
      remote.devices,
      group_key_package_export(Bytes.from_utf8(bob))?
    ])?)?
    let before_group_preflight = outbox_list_export(Bytes.from_utf8(path))?
    let claim_before = File.read(path <> ".claim")?
    let group_ticket = native_fanout_send(group_vectors([
      Bytes.from_utf8(path),
      profile,
      Bytes.from_utf8("alice"),
      repeated(5, 1)?,
      group,
      Bytes.empty(),
      Bytes.empty()
    ])?)?
    require_attachment_authorization(path, group_ticket)?
    assert(Bytes.secure_equals(before_group_preflight, outbox_list_export(Bytes.from_utf8(path))?))
    assert(File.read(path <> ".claim")? == claim_before)
    File.delete(path)?
    File.delete(bob)?
    for suffix in [".resolve", ".claim"] do
      if File.exists(path <> suffix) do
        File.delete(path <> suffix)?
      end
    end
    return Ok(nil)
  end
  if mode == 9 do
    replace_account(path)?
  end
  let request = action(path,
    profile,
    if mode == 10 do
      repeated(99, 32)?
    else
      Bytes.empty()
    end)?
  let result = native_fanout_send(request)
  if mode == 0 || mode == 5 do
    if mode == 5 do
      assert(Result.is_err(result))
      assert(File.exists(path <> ".claim"))
      assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(path))?)?) == 0)
    end
    let output = if mode == 5 do
      native_fanout_send(request)?
    else
      result?
    end
    assert(Bytes.to_hex(output) == "01464e4f00")
    assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(path))?)?) == 1)
    assert(File.exists(path <> ".claim"))
  else
    assert(Result.is_err(result))
    assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(path))?)?) == 0)
    if mode == 6 || mode == 7 || mode == 9 do
      assert(decode_client_profile(load_profile(path)?)?.username == "replacement")
      assert(Result.is_err(load_blob(path, "sessions/v1")))
    end
    if mode == 9 do
      assert(!File.exists(path <> ".resolve"))
    end
    if mode == 10 do
      assert(!File.exists(path <> ".claim"))
    end
  end
  assert(!File.exists(path <> ".redirect"))
  for suffix in [".resolve", ".claim", ".redirect"] do
    if File.exists(path <> suffix) do
      File.delete(path <> suffix)?
    end
  end
  File.delete(path)?
  File.delete(bob)?
  Ok(nil)
end

test("typed native fanout performs witnessed lookup and pinned prekey HTTP without exposing wire") do
  case run_case(0) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("native fanout rejects redirects cacheable oversized and forged prekey responses") do
  for mode in 1..5 do
    case run_case(mode) do
      Err(error) -> do
        println(error)
        assert(false)
      end
      Ok(_) -> assert(true)
    end
  end
end

test("an ambiguous prekey claim retries the same persisted reservation ID") do
  case run_case(5) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("replacement and configuration races never commit stale fanout or touch replacement ratchets") do
  for mode in 6..11 do
    case run_case(mode) do
      Err(error) -> do
        println(error)
        assert(false)
      end
      Ok(_) -> assert(true)
    end
  end
end

fn framing_proof() -> Result<(), String> do
  let fields = [
    Bytes.from_utf8("/native/morse.db"),
    Bytes.from_utf8("public profile"),
    Bytes.from_utf8("bob"),
    repeated(1, 1)?,
    Bytes.from_utf8("hello"),
    Bytes.empty(),
    Bytes.empty()
  ]
  let valid = group_vectors(fields)?
  assert(parse_fanout_action(valid)?.username == "bob")
  assert(Result.is_err(parse_fanout_action(append(valid, repeated(0, 1)?)?)))
  assert(Result.is_err(parse_fanout_action(append(repeated(0, 4)?, valid)?)))
  for user in ["https://evil.invalid", "@bad", "a/b", "bob?x", "BOB"] do
    assert(Result.is_err(parse_fanout_action(group_vectors([
      List.get(fields, 0),
      List.get(fields, 1),
      Bytes.from_utf8(user),
      List.get(fields, 3),
      List.get(fields, 4),
      Bytes.empty(),
      Bytes.empty()
    ])?)))
  end
  for kind in [0, 2, 3, 4] do
    assert(Result.is_err(parse_fanout_action(group_vectors([
      List.get(fields, 0),
      List.get(fields, 1),
      Bytes.from_utf8("bob"),
      repeated(kind, 1)?,
      List.get(fields, 4),
      Bytes.empty(),
      Bytes.empty()
    ])?)))
  end
  assert(Result.is_err(parse_fanout_action(group_vectors([
    List.get(fields, 0),
    List.get(fields, 1),
    Bytes.from_utf8("bob"),
    repeated(1, 1)?,
    repeated(65, 32001)?,
    Bytes.empty(),
    Bytes.empty()
  ])?)))
  Ok(nil)
end

test("typed fanout framing rejects authority selectors truncated count prefixes and oversized intent") do
  case framing_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("native group invitation retries and recipient preflight preserve the outbox and prekey claims") do
  case run_case(11) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("native attachment preflight verifies recipients without claiming prekeys or queueing envelopes") do
  case run_case(12) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
