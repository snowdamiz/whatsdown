##! Owned synthetic HTTP assets, actual current-device HPKE/EAM/chunks/history.
from Tests.BackupArchiveFixture import D4CoreFixture
from Tests.BackupAttachmentPreflightFixture import (
  PreflightFileMaterial,
  preflight_fixture,
  preflight_install_direct,
  preflight_install_group,
  preflight_files,
  preflight_file_spec
)
from Tests.BackupAttachmentFixture import backup_attachment_fixture_damage
from Tests.Support import repeated, append
from Mobile.Profile import open_device
from Identity.Device import DeviceKeys
from Transport.Packet import decode_client_profile
from Attachments.Protocol import (
  AttachmentManifest,
  generate_attachment_key,
  seal_manifest,
  seal_bound_chunk
)
from Mobile.Attachments import encode_reference
from Mobile.Types import MobileAttachmentReference
from Mobile.Codec import current_time, mobile_join, mobile_vector
from Storage.Keys import platform_key
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs
from Transparency.Config import encode_security_config

pub struct CaptureServingAsset do
  object_id :: Bytes
  capability :: Bytes
  chunks :: List<Bytes>
  part_count :: Int
  expires_at :: U64
end

pub struct CaptureFixtureFile do
  material :: PreflightFileMaterial
  chunks :: List<Bytes>
  plaintext :: Bytes
  serving :: CaptureServingAsset
end

pub fn capture_configure(f :: D4CoreFixture, port :: Int) -> Unit!String do
  let network = Bytes.from_utf8("2\n1\nhttps://core.example\nhttps://edge.example\nhttp://127.0.0.1:"
    <> Int.to_string(port)
    <> "\nwss://core.example/v1/mailbox/stream\n1")
  let companion = Bytes.from_utf8(String.join([
      "1",
      Bytes.to_hex(Crypto.sha256(network)),
      Bytes.to_hex(Crypto.sha256(encode_security_config(f.config)?)),
      "2",
      "off",
      "0"
    ],
    "\n"))
  if !Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), network)
    || !Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"), companion) do
    return Err("capture_fixture_network")
  end
  Ok(nil)
end

fn capture_concat(parts :: List<Bytes>) -> Bytes!String do
  case Bytes.concat_many(parts, 16777216) do
    Err(_) -> Err("capture_fixture_extent")
    Ok(value) -> Ok(value)
  end
end

fn capture_material_with_secret(device :: borrow DeviceKeys,
  secret :: borrow SecretBytes,
  tag :: Int,
  version :: Int,
  parts :: List<Bytes>,
  expires :: U64) -> CaptureFixtureFile!String do
  if List.length(parts) < 1 || List.length(parts) > 256 do
    return Err("capture_fixture_parts")
  end
  let plaintext = capture_concat(parts)?
  let object_id = repeated(tag, 32)?
  let capability = repeated(tag + 2, 32)?
  let manifest = AttachmentManifest {
    version: version,
    attachment_id: object_id,
    chunk_size: if version == 4 do
      65536
    else
      Bytes.length(List.head(parts))
    end,
    chunk_count: List.length(parts),
    plaintext_size: Bytes.length(plaintext),
    filename: Bytes.from_utf8("fixture.bin"),
    mime_type: Bytes.from_utf8("application/octet-stream"),
    expires_at: expires
  }
  let encrypted = case seal_manifest(secret, manifest) do
    Err(_) -> return Err("capture_fixture_manifest")
    Ok(value) -> value
  end
  let wrapped = case Crypto.hpke_seal_secret(device.identity_public_key,
    Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap"),
    append(Bytes.from_utf8("mesh-msg/v1/attachment-reference"), object_id)?,
    secret) do
    Err(_) -> return Err("capture_fixture_wrap")
    Ok(value) -> value
  end
  let chunks = for index in 0..List.length(parts) do
    case seal_bound_chunk(secret, encrypted, index, List.get(parts, index)) do
      Err(_) -> return Err("capture_fixture_chunk")
      Ok(value) -> value
    end
  end
  let reference = encode_reference(MobileAttachmentReference {
    object_id: object_id,
    download_capability: capability,
    encrypted_manifest: encrypted,
    wrapped_key: wrapped
  })?
  Ok(CaptureFixtureFile {
    material: PreflightFileMaterial {
      reference: reference,
      manifest: manifest,
      chunk: List.head(chunks)
    },
    chunks: chunks,
    plaintext: plaintext,
    serving: CaptureServingAsset {
      object_id: object_id,
      capability: capability,
      chunks: chunks,
      part_count: List.length(parts),
      expires_at: expires
    }
  })
end

fn capture_material(device :: borrow DeviceKeys,
  tag :: Int,
  version :: Int,
  parts :: List<Bytes>,
  expires :: U64) -> CaptureFixtureFile!String do
  let secret = case generate_attachment_key() do
    Err(_) -> return Err("capture_fixture_secret")
    Ok(value) -> value
  end
  let result = capture_material_with_secret(device, secret, tag, version, parts, expires)
  Secret.destroy(secret)
  result
end

fn capture_retire_device(device :: consume DeviceKeys) do
  nil
end

fn capture_files_with_device(device :: borrow DeviceKeys,
  kind :: Int,
  mode :: Int,
  expires :: U64) -> List<CaptureFixtureFile>!String do
  if mode == 14 || mode == 15 do
    return Ok([capture_material(device, 61, 4, [Bytes.from_utf8("x")], expires)?])
  end
  let first = capture_material(device,
    61,
    1,
    [Bytes.from_utf8("ab"), Bytes.from_utf8("c")],
    expires)?
  let second = capture_material(device, 71, 4, [Bytes.from_utf8("x")], expires)?
  if kind == 2 do
    Ok([first, second, capture_material(device, 81, 4, [Bytes.from_utf8("z")], expires)?])
  else
    Ok([first, second])
  end
end

fn capture_files_with_key(f :: D4CoreFixture,
  kind :: Int,
  mode :: Int,
  expires :: U64,
  key :: borrow StorageKey) -> List<CaptureFixtureFile>!String do
  let profile = decode_client_profile(f.public_profile)?
  let device = open_device(profile, key, f.path)?
  let result = capture_files_with_device(device, kind, mode, expires)
  capture_retire_device(device)
  result
end

pub fn capture_files(f :: D4CoreFixture,
  kind :: Int,
  mode :: Int,
  expires :: U64) -> List<CaptureFixtureFile>!String do
  # Aggregate-only fixtures have authenticated legal advertised metadata, no
  # content assets. Any object request is an assertion failure, never a500 guard.
  if mode == 16 || mode == 17 do
    let specs = [preflight_file_spec(61, 4, 8388608)?, preflight_file_spec(71, 1, 8388608)?]
    let materials = preflight_files(f, specs)?
    let ordered = if mode == 17 do
      List.reverse(materials)
    else
      materials
    end
    let ordered_specs = if mode == 17 do
      List.reverse(specs)
    else
      specs
    end
    return Ok(for index in 0..List.length(ordered) do
      let spec = List.get(ordered_specs, index)
      CaptureFixtureFile {
        material: List.get(ordered, index),
        chunks: [],
        plaintext: Bytes.empty(),
        serving: CaptureServingAsset {
          object_id: repeated(spec.tag, 32)?,
          capability: repeated(spec.tag + 2, 32)?,
          chunks: [],
          part_count: (spec.size + 65535) / 65536,
          expires_at: spec.expires_at
        }
      }
    end)
  end
  let key = platform_key()?
  let result = capture_files_with_key(f, kind, mode, expires, key)
  Secret.destroy(key)
  result
end

pub fn capture_install(f :: D4CoreFixture,
  kind :: Int,
  files :: List<CaptureFixtureFile>,
  sparse :: Bool) -> Bytes!String do
  if kind == 2 do
    preflight_install_group(f,
      for file in files do
        file.material
      end)
  else
    preflight_install_direct(f,
      for file in files do
        file.material.reference
      end,
      sparse)?
    repeated(71, 16)
  end
end

fn capture_cipher_rows_hash_path(path :: String) -> String!String do
  let database = Sqlite.open(path)?
  let raw_rows = Sqlite.query_values_v2(database,
    "SELECT record_hash, ciphertext FROM encrypted_blobs ORDER BY record_hash",
    [],
    33554432)
  let raw_index = Sqlite.query_values(database,
    "SELECT database_id, key_check FROM encrypted_blob_index",
    [])
  Sqlite.close(database)
  let metadata = raw_index?
  if List.length(metadata) != 1 do
    return Err("capture_fixture_snapshot_index")
  end
  let index = case (Map.get(List.head(metadata), "database_id"),
    Map.get(List.head(metadata), "key_check")) do
    (Binary(id), Binary(check)) -> append(id, check)?
    _ -> return Err("capture_fixture_snapshot_shape")
  end
  let parts = [mobile_vector(index)?]
    ++ List.flatten(for row in raw_rows? do
      case (Map.get(row, "record_hash"), Map.get(row, "ciphertext")) do
        (Text(hash), Binary(ciphertext)) -> [
          mobile_vector(Bytes.from_utf8(hash))?,
          mobile_vector(ciphertext)?
        ]
        _ -> return Err("capture_fixture_snapshot_shape")
      end
    end)
  Ok(Bytes.to_hex(Crypto.sha256(mobile_join(parts, 0, Bytes.empty())?)))
end

pub fn capture_cipher_rows_hash(f :: D4CoreFixture) -> String!String do
  capture_cipher_rows_hash_path(f.path)
end

fn capture_append_trace(path :: String, value :: String) -> Unit!String do
  let previous = if File.exists(path <> ".capture-trace") do
    File.read(path <> ".capture-trace")?
  else
    ""
  end
  File.write(path <> ".capture-trace", previous <> value <> "\n")
end

fn capture_mutate_history(path :: String, label :: String) -> Unit!String do
  let before = load_blob(path, label)?
  let updated = backup_attachment_fixture_damage(before)?
  if Bytes.secure_equals(before, updated) do
    return Err("capture_fixture_mutation_noop")
  end
  store_updated_blobs(path, [label], [updated])?
  if !Bytes.secure_equals(load_blob(path, label)?, updated) do
    return Err("capture_fixture_mutation_readback")
  end
  File.write(path <> ".capture-mutated-rows", capture_cipher_rows_hash_path(path)?)
end

fn capture_mutate_native() -> Unit!String do
  let selector = Bytes.from_utf8("messenger/network/v1")
  let before = Host.push_get_token(selector)?
  let updated = Bytes.from_utf8("changed native network resource")
  if Bytes.secure_equals(before, updated) || !Test.set_push_token(selector, updated) do
    return Err("capture_fixture_native_mutation")
  end
  if !Bytes.secure_equals(Host.push_get_token(selector)?, updated) do
    return Err("capture_fixture_native_readback")
  end
  Ok(nil)
end

fn capture_wait_expiry(expires :: U64, started :: U64, attempt :: Int) -> Unit!String do
  let now = current_time()?
  if U64.compare(now, started) < 0 do
    return Err("capture_fixture_clock_rollback")
  end
  if U64.compare(now, expires) >= 0 do
    return Ok(nil)
  end
  if attempt >= 200 do
    return Err("capture_fixture_expiry_wait")
  end
  Timer.sleep(50)
  capture_wait_expiry(expires, started, attempt + 1)
end

fn capture_response(request :: Request,
  path :: String,
  source_label :: String,
  assets :: List<CaptureServingAsset>,
  asset :: Int,
  part :: Int,
  mode :: Int) -> Response do
  let file = List.get(assets, asset)
  if Request.header(request, "x-object-capability") != Some(Bytes.to_hex(file.capability))
    || Request.header(request, "content-type") != Some("application/octet-stream")
    || Request.header(request, "cache-control") != Some("no-store")
    || Request.header(request, "authorization") != None
    || Request.header(request, "cookie") != None
    || Bytes.length(Request.body_bytes(request)) != 0 do
    return HTTP.response(400, "fixture request refused")
  end
  if part >= List.length(file.chunks) do
    case capture_append_trace(path, "UNEXPECTED_OBJECT_REQUEST") do
      _ -> nil
    end
    return HTTP.response(500, "metadata-only asset requested")
  end
  let wire = List.get(file.chunks, part)
  let response = if asset == 0 && part == 0 && mode == 1 do
    let damaged = case backup_attachment_fixture_damage(wire) do
      Err(_) -> return HTTP.response(500, "fixture damage unavailable")
      Ok(value) -> value
    end
    if Bytes.length(damaged) != Bytes.length(wire) || Bytes.secure_equals(damaged, wire) do
      return HTTP.response(500, "fixture damage unchanged")
    end
    HTTP.response_bytes(200, damaged)
  else if asset == 0 && part == 0 && mode == 2 do
    let oversized = case repeated(1, 65577) do
      Err(_) -> return HTTP.response(500, "fixture bound unavailable")
      Ok(value) -> value
    end
    HTTP.response_bytes(200, oversized)
  else if asset == 0 && part == 0 && mode == 3 do
    HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/capture-untrusted"))
  else if asset == 0 && part == 0 && mode == 4 do
    HTTP.response(403, "untrusted refusal body")
  else if asset == 0 && part == 0 && mode == 5 do
    HTTP.response_bytes(200, List.head(List.get(assets, 1).chunks))
  else if asset == 1 && (mode == 11 || mode == 12) do
    HTTP.response(if mode == 11 do
        404
      else
        410
      end,
      "untrusted unavailable body")
  else
    HTTP.response_bytes(200, wire)
  end
  if asset == 0 && part == 0 && mode == 6 do
    case capture_mutate_history(path, source_label) do
      Err(_) -> return HTTP.response(500, "fixture mutation unavailable")
      Ok(_) -> nil
    end
  else if asset == 0 && part == 0 && mode == 7 do
    case capture_mutate_native() do
      Err(_) -> return HTTP.response(500, "fixture native mutation unavailable")
      Ok(_) -> nil
    end
  else if mode == 14 do
    let before = case current_time() do
      Err(_) -> return HTTP.response(500, "fixture time unavailable")
      Ok(value) -> value
    end
    if U64.compare(before, file.expires_at) >= 0 do
      return HTTP.response(500, "fixture request arrived after expiry")
    end
    case capture_wait_expiry(file.expires_at, before, 0) do
      Err(_) -> return HTTP.response(500, "fixture expiry unavailable")
      Ok(_) -> nil
    end
  end
  case capture_append_trace(path, Int.to_string(asset) <> ":" <> Int.to_string(part)) do
    Err(_) -> return HTTP.response(500, "fixture trace unavailable")
    Ok(_) -> nil
  end
  case File.write(path <> ".capture-action-ready", Int.to_string(mode)) do
    Err(_) -> HTTP.response(500, "fixture readiness unavailable")
    Ok(_) -> response
  end
end

actor capture_peer(port :: Int,
  path :: String,
  source_label :: String,
  assets :: List<CaptureServingAsset>,
  mode :: Int) do
  let base = HTTP.router()
    |> HTTP.on_get("/capture-fixture-ready",
      fn(_) -> HTTP.response(200, "owned capture fixture") end)
    |> HTTP.on_get("/capture-untrusted",
      fn(_) do
        case File.write(path <> ".capture-redirect-followed", "1") do
          _ -> nil
        end
        HTTP.response_bytes(200, List.head(List.head(assets).chunks))
      end)
  let router = List.reduce(for asset in 0..List.length(assets) do
      asset
    end,
    base,
    fn(current, asset) do
      let expected = List.get(assets, asset)
      List.reduce(for part in 0..expected.part_count do
          part
        end,
        current,
        fn(previous, part) -> HTTP.on_get(previous,
          "/v1/objects/#{Bytes.to_hex(expected.object_id)}/parts/#{part + 1}",
          fn(request) -> capture_response(request,
            path,
            source_label,
            assets,
            asset,
            part,
            mode) end) end)
    end)
  HTTP.serve_on(router, "127.0.0.1", port)
end

fn capture_wait_health(port :: Int, attempt :: Int) -> Unit!String do
  let request = Http.build(:get,
    "http://127.0.0.1:" <> Int.to_string(port) <> "/capture-fixture-ready")
    |> Http.timeout(100)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(128)
  let ready = case Http.send(request) do
    Err(_) -> false
    Ok(response) -> response.status == 200 && response.body == "owned capture fixture"
  end
  if ready do
    return Ok(nil)
  end
  if attempt >= 20 do
    return Err("capture_fixture_listener_unavailable")
  end
  Timer.sleep(20)
  capture_wait_health(port, attempt + 1)
end

pub fn capture_start_peer(port :: Int,
  f :: D4CoreFixture,
  files :: List<CaptureFixtureFile>,
  mode :: Int) -> Unit!String do
  # Narrow public serving projection only; never capture a manifest, plaintext
  # comparison value or the original source snapshot in an HTTP actor.
  let assets = for file in files do
    file.serving
  end
  let _peer = spawn(capture_peer, port, f.path, f.source_label, assets, mode)
  capture_wait_health(port, 0)?
  println("CAPTURE_OBJECT_FIXTURE_READY")
  Ok(nil)
end
