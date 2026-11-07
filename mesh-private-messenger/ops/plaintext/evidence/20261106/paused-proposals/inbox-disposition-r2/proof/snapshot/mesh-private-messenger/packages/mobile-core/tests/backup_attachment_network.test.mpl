from Mobile.BackupAttachmentReader import (
  D4BackupAttachmentReader, BackupAttachmentChunk,
  capture_backup_attachment_reader, backup_attachment_manifest,
  fetch_backup_attachment_chunk, require_backup_attachment_reader_current_on
)
from Mobile.BackupAuthority import capture_backup_authority_with_key
from Mobile.Attachments import decode_reference
from Mobile.Profile import open_device, load_profile
from MobileCore import erase_account_export, create_account_export
from Mobile.Codec import current_time
from Storage.Keys import platform_key
from Storage.Records import store_updated_blobs
from Storage.Blobs import load_blob
from Tests.BackupArchiveFixture import d4_core_fixture, d4_core_cleanup, D4CoreFixture
from Tests.BackupAttachmentFixture import (
  backup_attachment_fixture_material, backup_attachment_fixture_damage
)
from Tests.GroupConsistencySupport import request
from Tests.Support import repeated
from Transport.Packet import decode_client_profile
from Transparency.Config import encode_security_config

fn network_observe(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY finite equality availability and refusal over authored synthetic captured-reader fixtures; no real attachment metadata content keys error payloads source authority or unrelated caller control is disclosed")
end

fn retire_reader(reader :: consume D4BackupAttachmentReader) do
  nil
end

fn configure_reader(f :: D4CoreFixture, port :: Int) -> Unit!String do
  let network = Bytes.from_utf8("2\n1\nhttps://core.example\nhttps://edge.example\nhttp://127.0.0.1:"
    <> Int.to_string(port) <> "\nwss://core.example/v1/mailbox/stream\n1")
  let companion = Bytes.from_utf8(String.join([
    "1", Bytes.to_hex(Crypto.sha256(network)),
    Bytes.to_hex(Crypto.sha256(encode_security_config(f.config)?)),
    "2", "off", "0"
  ], "\n"))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/rpc-tls-roots/v1"), Bytes.from_hex("0100")?))
  if !Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), network)
    || !Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"), companion)
    || !Test.set_push_token(Bytes.from_utf8("messenger/issuer-tls-root/v1"), Bytes.from_hex("01000000000000")?) do
    return Err("reader_fixture_configuration")
  end
  Ok(nil)
end

# The missing constructor has its own positive assertion below. This test-only
# assembly isolates fetch RED while retaining an actual verified D4 capture and
# the actual current device opened before any callback mutation. It grants no
# public/native authority and is never used by an application operation.
fn fixture_reader(f :: D4CoreFixture,
  key :: borrow StorageKey) -> D4BackupAttachmentReader!String do
  let authority = capture_backup_authority_with_key(f.path, f.public_profile, key)?
  let profile = decode_client_profile(f.public_profile)?
  let device = open_device(profile, key, f.path)?
  Ok(D4BackupAttachmentReader {
    authority: authority,
    device: device,
    issuer_tls_frame: Some(Bytes.from_hex("01000000000000")?)
  })
end

# A500 setup fallback cannot qualify as a tested guard refusal: every intended
# response/mutation must leave exact per-case readiness after its readback.
fn fixture_reply_ready(path :: String, mode :: Int, response :: Response) -> Response do
  case File.write(path <> ".reader-action-ready", Int.to_string(mode)) do
    Err(_) -> HTTP.response(500, "fixture readiness write failed")
    Ok(_) -> response
  end
end

fn fixture_change_token(selector :: String, before :: Bytes, updated :: Bytes) -> Unit!String do
  let key = Bytes.from_utf8(selector)
  let observed = Host.push_get_token(key)?
  if !Bytes.secure_equals(observed, before) || Bytes.secure_equals(before, updated) do
    return Err("reader_fixture_token_before")
  end
  if !Test.set_push_token(key, updated) do return Err("reader_fixture_token_write") end
  if !Bytes.secure_equals(Host.push_get_token(key)?, updated) do
    return Err("reader_fixture_token_after")
  end
  Ok(nil)
end

fn fixture_change_row(path :: String, label :: String) -> Unit!String do
  let before = load_blob(path, label)?
  let updated = Bytes.from_utf8("changed original ciphertext")
  if Bytes.secure_equals(before, updated) do return Err("reader_fixture_row_before") end
  store_updated_blobs(path, [label], [updated])?
  if !Bytes.secure_equals(load_blob(path, label)?, updated) do return Err("reader_fixture_row_after") end
  Ok(nil)
end

fn fixture_replace_account(path :: String, before :: Bytes) -> Unit!String do
  if !Bytes.secure_equals(load_profile(path)?, before) do return Err("reader_fixture_profile_before") end
  let prior = decode_client_profile(before)?
  erase_account_export(Bytes.from_utf8(path))?
  let created = create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8("readerreplacement")])?)?
  let updated = load_profile(path)?
  let current = decode_client_profile(updated)?
  if !Bytes.secure_equals(created, updated) || Bytes.secure_equals(before, updated)
    || Bytes.secure_equals(prior.account_id, current.account_id)
    || Bytes.secure_equals(prior.device_id, current.device_id) do
    return Err("reader_fixture_profile_after")
  end
  Ok(nil)
end

fn fixture_response(input :: Request,
  path :: String,
  capability :: String,
  wire :: Bytes,
  mode :: Int,
  original_profile :: Bytes,
  original_frames :: List<Bytes>) -> Response do
  case File.write(path <> ".reader-requested", "1") do
    Err(_) -> return HTTP.response(500, "fixture marker failed")
    Ok(_) -> nil
  end
  if Request.header(input, "x-object-capability") != Some(capability)
    || Request.header(input, "content-type") != Some("application/octet-stream")
    || Request.header(input, "cache-control") != Some("no-store")
    || Request.header(input, "authorization") != None
    || Request.header(input, "cookie") != None
    || Bytes.length(Request.body_bytes(input)) != 0 do
    return HTTP.response(400, "fixture request refused")
  end
  if mode == 1 do
    let damaged = case backup_attachment_fixture_damage(wire) do
      Err(_) -> return HTTP.response(500, "fixture damage failed")
      Ok(value) -> value
    end
    if Bytes.length(damaged) != Bytes.length(wire) || Bytes.secure_equals(damaged, wire) do
      return HTTP.response(500, "fixture damage unchanged")
    end
    return fixture_reply_ready(path, mode, HTTP.response_bytes(200, damaged))
  else if mode == 2 do
    let oversized = case repeated(1, 65577) do
      Err(_) -> return HTTP.response(500, "fixture bound failed")
      Ok(value) -> value
    end
    if Bytes.length(oversized) != 65577 do return HTTP.response(500, "fixture bound unchanged") end
    return fixture_reply_ready(path, mode, HTTP.response_bytes(200, oversized))
  else if mode == 3 do
    return fixture_reply_ready(path, mode,
      HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted")))
  else if mode == 4 do
    case fixture_replace_account(path, original_profile) do
      Err(_) -> return HTTP.response(500, "fixture replacement failed")
      Ok(_) -> nil
    end
  else if mode == 5 || mode == 6 || mode == 9 || mode == 10 do
    let selector = if mode == 5 do "messenger/network/v1" else if mode == 6 do
      "messenger/issuer-tls-root/v1" else if mode == 9 do "messenger/config/v1" else "messenger/ohttp/v1" end
    let index = if mode == 5 do 0 else if mode == 6 do 3 else if mode == 9 do 1 else 2 end
    case fixture_change_token(selector, List.get(original_frames, index), Bytes.from_utf8("changed native resource")) do
      Err(_) -> return HTTP.response(500, "fixture native resource change failed")
      Ok(_) -> nil
    end
  else if mode == 7 || mode == 8 || mode == 16 do
    let label = if mode == 7 do "ohttp-revision/v1" else if mode == 8 do
      "device-identity-key/v1" else "device-signing-key/v1" end
    case fixture_change_row(path, label) do
      Err(_) -> return HTTP.response(500, "fixture row change failed")
      Ok(_) -> nil
    end
  else if mode == 11 do
    return fixture_reply_ready(path, mode, HTTP.response(404, "untrusted missing-object response body"))
  else if mode == 12 do
    return fixture_reply_ready(path, mode, HTTP.response(410, "untrusted gone-object response body"))
  else if mode == 13 do
    return fixture_reply_ready(path, mode, HTTP.response(403, "untrusted capability-refusal response body"))
  end
  fixture_reply_ready(path, mode, HTTP.response_bytes(200, wire))
end

# A followed redirect receives the valid original wire, so refusal cannot be
# accidentally satisfied by an unrelated500 fallback at the redirected route.
fn fixture_redirect(path :: String, wire :: Bytes) -> Response do
  case File.write(path <> ".reader-redirect-followed", "1") do
    Err(_) -> HTTP.response_bytes(200, wire)
    Ok(_) -> HTTP.response_bytes(200, wire)
  end
end

fn fixture_qualified(mode :: Int, result :: Bool, requested :: Bool,
  action_ready :: Bool, redirected :: Bool) -> Bool do
  result && !redirected && if mode == 14 || mode == 15 do
    !requested && !action_ready
  else
    requested && action_ready
  end
end

actor reader_peer(port :: Int,
  route :: String,
  path :: String,
  capability :: String,
  wire :: Bytes,
  mode :: Int,
  original_profile :: Bytes,
  original_frames :: List<Bytes>) do
  HTTP.router()
    |> HTTP.on_get(route, fn(input) -> fixture_response(input, path, capability, wire, mode, original_profile, original_frames) end)
    |> HTTP.on_get(String.slice(route, 0, String.length(route) - 1) <> "2",
      fn(input) -> fixture_response(input, path, capability, wire, mode, original_profile, original_frames) end)
    |> HTTP.on_get("/untrusted", fn(_) -> fixture_redirect(path, wire) end)
    |> HTTP.serve_on("127.0.0.1", port)
end

fn matches_reader(raw :: Result<Plaintext<BackupAttachmentChunk>, String>,
  expected :: Int) -> Plaintext<Bool> do
  case raw do
    Err(_) -> expected == 0
    Ok(value) -> case value do
      BackupAttachmentAvailable(bytes) -> expected == 1 && Bytes.secure_equals(bytes, Bytes.from_utf8("x"))
      BackupAttachmentUnavailable -> expected == 2
      BackupAttachmentExpired -> expected == 3
    end
  end
end

fn network_case(mode :: Int) -> Bool!String do
  let f = d4_core_fixture()?
  let port = 22230 + mode
  configure_reader(f, port)?
  let key = platform_key()?
  let reader = fixture_reader(f, key)?
  let expires = if mode == 14 do U64.parse("0")? else U64.parse("4102444800000")? end
  let material = backup_attachment_fixture_material(reader.device, 1, expires)?
  let decoded = decode_reference(material.reference)?
  let _peer = spawn(reader_peer, port,
    "/v1/objects/#{Bytes.to_hex(decoded.object_id)}/parts/1",
    f.path, Bytes.to_hex(decoded.download_capability), material.wire, mode,
    f.public_profile, [reader.authority.context.network_frame,
      reader.authority.context.security_frame, reader.authority.context.companion_frame,
      Bytes.from_hex("01000000000000")?])
  Timer.sleep(40)
  let expected = if mode == 0 do 1 else if mode == 11 || mode == 12 do 2 else if mode == 14 do 3 else 0 end
  let result = network_observe(matches_reader(fetch_backup_attachment_chunk(f.path,
    key, reader, material.reference, if mode == 15 do material.index + 1 else material.index end), expected))
  retire_reader(reader)
  Secret.destroy(key)
  let requested = File.exists(f.path <> ".reader-requested")
  let action_ready = case File.read(f.path <> ".reader-action-ready") do
    Err(_) -> false
    Ok(value) -> value == Int.to_string(mode)
  end
  let redirected = File.exists(f.path <> ".reader-redirect-followed")
  for suffix in [".reader-requested", ".reader-action-ready", ".reader-redirect-followed"] do
    if File.exists(f.path <> suffix) do File.delete(f.path <> suffix)? end
  end
  d4_core_cleanup(f)?
  Ok(fixture_qualified(mode, result, requested, action_ready, redirected))
end

test("captured backup reader uses actual fixed-origin bounded HTTP and known exact plaintext") do
  assert(Result.unwrap_or(network_case(0), false))
end

test("captured backup reader refuses response tamper oversized redirect and every original custody or native-frame drift") do
  assert(fixture_qualified(1, true, true, true, false))
  assert(!fixture_qualified(1, true, true, false, false))
  assert(!fixture_qualified(3, true, true, true, true))
  assert(!fixture_qualified(1, true, false, true, false))
  assert(fixture_qualified(14, true, false, false, false))
  assert(!fixture_qualified(14, true, true, true, false))
  for mode in 1..11 do
    assert(Result.unwrap_or(network_case(mode), false))
  end
  assert(Result.unwrap_or(network_case(13), false))
  assert(Result.unwrap_or(network_case(16), false))
end

test("captured backup reader exposes only protected missing-object outcomes and never requests an expired manifest") do
  for mode in [11, 12, 14] do
    assert(Result.unwrap_or(network_case(mode), false))
  end
  assert(Result.unwrap_or(network_case(15), false))
end

fn constructor_proof() -> Bool!String do
  let f = d4_core_fixture()?
  configure_reader(f, 22259)?
  let key = platform_key()?
  let authority = capture_backup_authority_with_key(f.path, f.public_profile, key)?
  let result = case capture_backup_attachment_reader(f.path, authority, key) do
    Err(_) -> false
    Ok(reader) -> do
      retire_reader(reader)
      true
    end
  end
  Secret.destroy(key)
  d4_core_cleanup(f)?
  Ok(result)
end

test("backup reader constructor opens retained device only from the original verified captured key rows") do
  assert(Result.unwrap_or(constructor_proof(), false))
end

fn metadata_fence_proof() -> Bool!String do
  let f = d4_core_fixture()?
  configure_reader(f, 22260)?
  let key = platform_key()?
  let reader = fixture_reader(f, key)?
  let material = backup_attachment_fixture_material(reader.device, 4, U64.parse("4102444800000")?)?
  let metadata = case backup_attachment_manifest(reader, material.reference) do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value.filename, Bytes.from_utf8("authored-reader.bin"))
      && Bytes.secure_equals(value.mime_type, Bytes.from_utf8("application/octet-stream"))
      && value.plaintext_size == 1 && value.chunk_count == 1 && value.version == 4
  end
  let observed = network_observe(metadata)
  let database = Sqlite.open(f.path)?
  Sqlite.execute(database, "BEGIN IMMEDIATE", [])?
  let fenced = Result.is_ok(require_backup_attachment_reader_current_on(database, key, reader))
  Sqlite.rollback(database)
  Sqlite.close(database)
  retire_reader(reader)
  Secret.destroy(key)
  d4_core_cleanup(f)?
  Ok(observed && fenced)
end

test("backup reader retains private authenticated metadata and accepts original supplied-writer fence") do
  assert(Result.unwrap_or(metadata_fence_proof(), false))
end
