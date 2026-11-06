from Mobile.DirectoryResolve import resolve_directory_device_set, native_directory_resolve
from MobileCore import (
  create_account_export,
  directory_entry_export,
  erase_account_export,
  verify_transparency_export
)
from Mobile.Platform import native_security_config
from Mobile.Profile import load_profile
from Mobile.Codec import current_time, mobile_write_u64
from Privacy.Edge import decode_stamped_request, verify_request_stamp
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.V1 import DeviceSet
from Tests.Support import append, vector, database_path, install_security_config, repeated
from Transparency.Config import encode_security_config
from Transparency.C2spText import checkpoint_note_text
from Transparency.Merkle import (
  WitnessAttestation,
  TransparencyCheckpoint,
  checkpoint_hash,
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
  encode_checkpoint,
  decode_transparency_lookup
)
from Storage.Blobs import load_blob

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("fixture signer")
    Ok(value)
  end
end

fn witness(key :: borrow SigningPrivateKey,
  id :: String,
  checkpoint :: TransparencyCheckpoint,
  now :: U64) -> WitnessAttestation!String do
  if checkpoint.version == 1 do
    return sign_witness(id, key, checkpoint)
  end
  let seconds = U64.parse(Int.to_string(U64.to_int(now)? / 1000))?
  let statement = Bytes.from_utf8("cosignature/v1\ntime "
    <> U64.to_string(seconds)
    <> "\n"
    <> checkpoint_note_text(encode_checkpoint(checkpoint)?)?)
  let signature = case Crypto.sign(key, statement) do
    Err(_) -> return Err("fixture cosignature")
    Ok(value) -> value.bytes
  end
  Ok(WitnessAttestation {
    witness_id: id,
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    signature: append(mobile_write_u64(seconds)?, signature)?
  })
end

fn evidence(version :: Int,
  entry :: Bytes,
  signer :: borrow SigningPrivateKey,
  service_public :: Bytes,
  a :: borrow SigningPrivateKey,
  b :: borrow SigningPrivateKey,
  now :: U64,
  old :: Int) -> Bytes!String do
  let leaves = [leaf_hash_for(version, entry)?]
  let checkpoint = sign_tree_checkpoint_for(version,
    signer,
    service_public,
    U64.parse("1")?,
    U64.parse("1")?,
    merkle_root_for(version, leaves)?,
    repeated(0, 32)?,
    now)?
  encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: entry,
    inclusion: compact_inclusion_proof_for(version, leaves, 0)?,
    consistency: compact_consistency_proof_for(version,
      if old == 0 do
        []
      else
        leaves
      end,
      leaves)?,
    checkpoint: checkpoint,
    witnesses: [
      witness(a, "witness-a", checkpoint, now)?,
      witness(b, "witness-b", checkpoint, now)?
    ]
  })
end

fn fixture_new_account(path :: String) -> Bytes!String do
  create_account_export(append(vector(Bytes.from_utf8(path))?,
    vector(Bytes.from_utf8("replacement"))?)?)
end

fn fixture_request(path :: String, evidence :: Bytes) -> Bytes!String do
  append(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?,
    vector(evidence)?)
end

fn reply(input :: Request,
  path :: String,
  version :: Int,
  first :: Bytes,
  same :: Bytes,
  mode :: Int) -> Response do
  if Request.header(input, "authorization") != None || Request.header(input, "cookie") != None do
    return HTTP.response(400, "private headers")
  end
  let (stamp, body) = case decode_stamped_request(Request.body_bytes(input), 76) do
    Err(_) -> return HTTP.response(400, "missing work")
    Ok(value) -> value
  end
  let lookup = case decode_transparency_lookup(body) do
    Err(_) -> return HTTP.response(400, "bad lookup")
    Ok(value) -> value
  end
  case verify_request_stamp("mesh-msg/v1/work/resolve",
    body,
    stamp,
    case current_time() do
      Ok(value) -> value
      Err(_) -> return HTTP.response(500, "clock")
    end,
    case U64.parse("300000") do
      Ok(value) -> value
      Err(_) -> return HTTP.response(500, "window")
    end,
    1) do
    Ok(true) -> nil
    _ -> return HTTP.response(403, "work rejected")
  end
  File.write(path <> ".v#{version}", Int.to_string(lookup.previous_tree_size))
  if version == 2 && (mode == 5 || mode == 6 || (mode == 8 && lookup.previous_tree_size > 0)) do
    return HTTP.response(404,
      if mode == 6 do
        "transparency_v2_not_active "
      else
        "transparency_v2_not_active"
      end)
  end
  if mode == 1 do
    return HTTP.response_bytes(200, Bytes.from_utf8("malformed evidence"))
  end
  if mode == 2 do
    return HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted"))
  end
  if mode == 9 do
    return case Bytes.repeat(0, 570419) do
      Err(_) -> HTTP.response(500, "fixture allocation")
      Ok(oversized) -> HTTP.response_bytes(200, oversized)
    end
  end
  if mode == 10 do
    Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
      Bytes.from_utf8("1\n1\nhttp://127.0.0.1:9\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream"))
  end
  if mode == 16 && lookup.previous_tree_size == 0 do
    # Another authenticated lookup wins after this request selected its basis.
    let request = case fixture_request(path, first) do
      Err(_) -> return HTTP.response(500, "fixture input")
      Ok(value) -> value
    end
    case verify_transparency_export(request) do
      Err(error) -> return HTTP.response(500, error)
      Ok(_) -> nil
    end
  end
  if mode == 4 || mode == 15 do
    case erase_account_export(Bytes.from_utf8(path)) do
      Err(_) -> return HTTP.response(500, "erase fixture")
      Ok(_) -> nil
    end
    if mode == 15 do
      case fixture_new_account(path) do
        Err(_) -> return HTTP.response(500, "replacement fixture")
        Ok(_) -> nil
      end
    end
  end
  HTTP.response_bytes(200,
    if lookup.previous_tree_size == 0 do
      first
    else
      same
    end)
end

actor resolve_peer(port :: Int,
  path :: String,
  first1 :: Bytes,
  same1 :: Bytes,
  first2 :: Bytes,
  same2 :: Bytes,
  mode :: Int) do
  HTTP.router()
    |> HTTP.on_post("/v1/devices/resolve",
      fn(input) -> reply(input, path, 1, first1, same1, mode) end)
    |> HTTP.on_post("/v2/devices/resolve",
      fn(input) -> reply(input,
        path,
        2,
        if mode == 7 do
          first1
        else
          first2
        end,
        same2,
        mode) end)
    |> HTTP.on_post("/untrusted",
      fn(_) do
        File.write(path <> ".redirect", "bad")
        HTTP.response(500, "followed")
      end)
    |> HTTP.serve(port)
end

fn run_case(mode :: Int) -> Result<(), String> do
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
  if mode >= 5 && mode <= 8 do
    let config = native_security_config()?
    assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
      encode_security_config(%{config |
        version: 3,
        log_version: 2,
        legacy_threshold: config.threshold,
        legacy_witnesses: config.witnesses
      })?))
  end
  let path = database_path("native_resolve")?
  create_account_export(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?)?
  let entry = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(path))?) do
    Err(_) -> return Err("fixture directory entry")
    Ok(value) -> value
  end
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> return Err("fixture account")
    Ok(value) -> value
  end
  let devices = case encode_device_set(DeviceSet {
    version: 1,
    username: entry.username,
    account_identity: entry.account_identity,
    sequence: account.directory_sequence,
    devices: [entry],
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("fixture device set")
    Ok(value) -> value
  end
  let now = current_time()?
  let stamp = if mode == 13 do
    U64.subtract(now, U64.parse("300001")?)?
  else if mode == 14 do
    U64.add(now, U64.parse("90000")?)?
  else
    now
  end
  let first1 = evidence(1,
    devices,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key,
    stamp,
    0)?
  let same1 = evidence(1,
    devices,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key,
    stamp,
    1)?
  let first2 = evidence(2,
    devices,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key,
    stamp,
    0)?
  let same2 = evidence(2,
    devices,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key,
    stamp,
    1)?
  let attacker = pair()?
  let first1 = if mode == 11 do
    evidence(1,
      devices,
      attacker.private_key,
      attacker.public_key.bytes,
      a.private_key,
      b.private_key,
      stamp,
      0)?
  else if mode == 12 do
    evidence(1,
      devices,
      signer.private_key,
      signer.public_key.bytes,
      attacker.private_key,
      b.private_key,
      stamp,
      0)?
  else
    first1
  end
  let port = 20100 + mode
  let _server = spawn(resolve_peer, port, path, first1, same1, first2, same2, mode)
  Timer.sleep(75)
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("1\n1\nhttp://127.0.0.1:#{port}\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream")))
  # Native direct regression uses an explicit companion bound to BOTH parents.
  let network = case Host.push_get_token(Bytes.from_utf8("messenger/network/v1")) do
    Err(_) -> return Err("fixture network")
    Ok(value) -> value
  end
  let security = encode_security_config(native_security_config()?)?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"),
    Bytes.from_utf8("1\n"
      <> Bytes.to_hex(Crypto.sha256(network))
      <> "\n"
      <> Bytes.to_hex(Crypto.sha256(security))
      <> "\n1\noff\n0")))
  let result = if mode == 0 do
    native_directory_resolve(append(vector(Bytes.from_utf8(path))?,
      vector(Bytes.from_utf8("alice"))?)?)
  else
    resolve_directory_device_set(path,
      if mode == 3 do
        "bob"
      else
        "alice"
      end)
  end
  if mode == 0 || mode == 5 || mode == 8 || mode == 16 do
    assert(Bytes.secure_equals(result?, devices))
    let checkpoint = load_blob(path, "transparency-checkpoint/v1")?
    if mode != 8 do
      assert(Bytes.secure_equals(resolve_directory_device_set(path,
          if mode == 0 do
            "@" <> Bytes.to_hex(account.account_id)
          else
            "alice"
          end)?,
        devices))
      assert(Bytes.secure_equals(load_blob(path, "transparency-checkpoint/v1")?, checkpoint))
    else
      assert(Result.is_err(resolve_directory_device_set(path, "alice")))
      assert(!File.exists(path <> ".v1"))
    end
  else
    assert(Result.is_err(result))
    assert(Result.is_err(load_blob(path, "transparency-checkpoint/v1")))
    if mode == 4 do
      assert(Result.is_err(load_profile(path)))
    end
    if mode == 15 do
      assert(Result.is_ok(load_profile(path)))
    end
    if mode == 6 || mode == 7 do
      assert(!File.exists(path <> ".v1"))
    end
  end
  if mode == 16 do
    assert(File.read(path <> ".v1")? == "1")
  end
  assert(!File.exists(path <> ".redirect"))
  erase_account_export(Bytes.from_utf8(path))?
  for suffix in [".v1", ".v2"] do
    if File.exists(path <> suffix) do
      File.delete(path <> suffix)?
    end
  end
  File.delete(path)?
  Ok(nil)
end

test("native resolution owns signed work, admission, strict fallback and durable checkpoint basis") do
  assert(Test.install_in_memory_secure_store())
  for mode in 0..17 do
    case run_case(mode) do
      Err(error) -> do
        println("resolve mode #{mode}: #{error}")
        assert(false)
      end
      Ok(_) -> nil
    end
  end
end

fn invalid_inputs() -> Result<(), String> do
  let path = vector(Bytes.from_utf8("/native/morse.db"))?
  let name = vector(Bytes.from_utf8("alice"))?
  let valid = append(path, name)?
  for input in [
    Bytes.empty(),
    path,
    append(valid, repeated(0, 1)?)?,
    append(vector(repeated(255, 1)?)?, name)?,
    append(vector(Bytes.from_utf8("/native/morse\0.db"))?, name)?,
    append(path, vector(repeated(97, 66)?)?)?,
    repeated(0, 4170)?
  ] do
    assert(Result.is_err(native_directory_resolve(input)))
  end
  Ok(nil)
end

test("native resolution rejects malformed bounded two-vector input before network I/O") do
  assert(Result.is_ok(invalid_inputs()))
end
