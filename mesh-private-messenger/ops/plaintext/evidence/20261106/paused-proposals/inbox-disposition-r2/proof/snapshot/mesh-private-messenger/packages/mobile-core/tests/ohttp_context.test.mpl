from Mobile.OhttpContext import (
  capture_native_ohttp_context,
  capture_native_ohttp_context_bounded,
  require_current_ohttp_context_bounded,
  require_current_ohttp_context,
  require_ohttp_completion_time,
  fetch_guarded_ohttp_prekey
)
from Mobile.Account import create_account
from Mobile.Types import MobileAccountRequest
from Mobile.Codec import mobile_join, mobile_vector, current_time
from Tests.Support import database_path
from Mobile.OhttpPins import MobileOhttpKey
from Ohttp.Keys import OhttpKeyConfig, encode_key_config
from Transparency.Config import decode_security_config, encode_security_config
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs, erase_local_state
from Storage.AccountGuard import load_account_basis, commit_account_changes
from Storage.Keys import platform_key, seal_local, local_context

fn bytes(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn network() -> Bytes do
  bytes("2\n1\nhttps://core.example\nhttp://127.0.0.1:24467\nhttps://objects.example\nwss://stream.example/v1/mailbox/stream\n16")
end

fn security() -> Bytes do
  bytes("1\n"
    <> String.repeat("11", 32)
    <> "\n"
    <> String.repeat("22", 32)
    <> "\n"
    <> String.repeat("33", 32)
    <> "\n31e1f05a740102751261153ed490fd94a675258c3b8e30b373beaabfba281550\n8")
end

fn frame(revision :: String, net :: Bytes, sec :: Bytes) -> Bytes!String do
  let canonical = encode_security_config(decode_security_config(sec)?)?
  Ok(bytes("1\n"
    <> Bytes.to_hex(Crypto.sha256(net))
    <> "\n"
    <> Bytes.to_hex(Crypto.sha256(canonical))
    <> "\n"
    <> revision
    <> "\noff\n0"))
end

fn install(revision :: String) -> Result<(), String> do
  assert(Test.set_push_token(bytes("messenger/network/v1"), network()))
  assert(Test.set_push_token(bytes("messenger/config/v1"), security()))
  assert(Test.set_push_token(bytes("messenger/ohttp/v1"), frame(revision, network(), security())?))
  assert(Test.set_push_token(bytes("messenger/rpc-tls-roots/v1"), Bytes.from_hex("0100")?))
  Ok(nil)
end

fn created(label :: String) -> String!String do
  let path = database_path(label)?
  create_account(MobileAccountRequest { database_path: bytes(path), username: bytes("alice") })?
  Ok(path)
end

fn profile(path :: String) -> Bytes!String do
  load_blob(path, "profile/v1")
end

fn fence(path :: String) -> Bytes!String do
  load_blob(path, "ohttp-revision/v1")
end

fn fails(value :: Result<(), String>, message :: String) -> Bool do
  case value do
    Err(error) -> error == message
    Ok(_) -> false
  end
end

fn revisions() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  install("7")?
  let path = created("ohttp-revision")?
  let original = profile(path)?
  let context = capture_native_ohttp_context(path, original)?
  assert(!context.pins.required)
  let first = fence(path)?
  let again = capture_native_ohttp_context(path, original)?
  assert(Bytes.secure_equals(first, fence(path)?))
  require_current_ohttp_context(path, again)?
  # Root authority belongs to the captured operation, including explicit-off
  # mode. It must retire the old operation without changing the OHTTP fence.
  assert(Test.set_push_token(bytes("messenger/rpc-tls-roots/v1"), bytes("changed RPC authority")))
  assert(fails(require_current_ohttp_context(path, again), "account_state_changed"))
  assert(Bytes.secure_equals(first, fence(path)?))
  assert(Test.set_push_token(bytes("messenger/rpc-tls-roots/v1"), Bytes.from_hex("0100")?))
  require_current_ohttp_context(path, again)?
  install("6")?
  assert(case capture_native_ohttp_context(path, original) do
    Err("ohttp_revision_rollback") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(first, fence(path)?))
  let changed = bytes(Bytes.to_utf8(network())? <> "x")
  assert(Test.set_push_token(bytes("messenger/ohttp/v1"), frame("7", changed, security())?))
  assert(Result.is_err(capture_native_ohttp_context(path, original)))
  assert(Bytes.secure_equals(first, fence(path)?))
  # Valid new full config, same account/revision but different companion identity.
  let net = bytes(String.replace(Bytes.to_utf8(network())?, "objects.example", "other.example"))
  assert(Test.set_push_token(bytes("messenger/network/v1"), net))
  assert(Test.set_push_token(bytes("messenger/ohttp/v1"), frame("7", net, security())?))
  assert(case capture_native_ohttp_context(path, original) do
    Err("ohttp_revision_rebind") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(first, fence(path)?))
  install("8")?
  let newer = capture_native_ohttp_context(path, original)?
  let winner = fence(path)?
  assert(!Bytes.secure_equals(first, winner))
  assert(fails(require_current_ohttp_context(path, context), "account_state_changed"))
  assert(Bytes.secure_equals(winner, fence(path)?))
  require_current_ohttp_context(path, newer)?
  # Authenticated old-account row is deliberately retained during replacement.
  erase_local_state(path)?
  create_account(MobileAccountRequest { database_path: bytes(path), username: bytes("alice") })?
  let replacement = profile(path)?
  # Restore only the previous authenticated fence as the explicit residual;
  # the replacement account otherwise has its complete normally-created custody.
  store_updated_blobs(path, ["ohttp-revision/v1"], [winner])?
  install("1")?
  let reset = capture_native_ohttp_context(path, replacement)?
  let reset_fence = fence(path)?
  assert(!Bytes.secure_equals(reset_fence, winner))
  assert(fails(require_current_ohttp_context(path, newer), "account_state_changed"))
  assert(Bytes.secure_equals(profile(path)?, replacement))
  assert(Bytes.secure_equals(fence(path)?, reset_fence))
  require_current_ohttp_context(path, reset)?
  assert(Result.is_err(capture_native_ohttp_context(path, original)))
  store_updated_blobs(path, ["ohttp-revision/v1"], [bytes("corrupt sealed row")])?
  assert(Result.is_err(capture_native_ohttp_context(path, replacement)))
  assert(Bytes.secure_equals(profile(path)?, replacement))
  Ok(true)
end

fn native_sources() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  install("1")?
  let path = created("ohttp-sources")?
  let original = profile(path)?
  let context = capture_native_ohttp_context(path, original)?
  let bounded = capture_native_ohttp_context_bounded(path, original)?
  for selector in ["messenger/network/v1", "messenger/config/v1", "messenger/ohttp/v1", "messenger/rpc-tls-roots/v1"] do
    install("1")?
    assert(Test.set_push_token(bytes(selector), bytes("changed raw frame")))
    assert(fails(require_current_ohttp_context(path, context), "account_state_changed"))
    assert(fails(require_current_ohttp_context_bounded(path, bounded), "account_state_changed"))
  end
  install("1")?
  assert(Result.is_err(fetch_guarded_ohttp_prekey(path, context, bytes("no direct request"), 100)))
  let saved = fence(path)?
  assert(Test.set_push_token(bytes("messenger/ohttp/v1"), Bytes.empty()))
  assert(Result.is_err(capture_native_ohttp_context(path, original)))
  assert(Bytes.secure_equals(saved, fence(path)?))
  # Absent callback resource and a malformed one are distinct from validated off.
  assert(Test.install_in_memory_secure_store())
  assert(Test.set_push_token(bytes("messenger/network/v1"), network()))
  assert(Test.set_push_token(bytes("messenger/config/v1"), security()))
  let missing_path = created("ohttp-missing")?
  assert(Result.is_err(capture_native_ohttp_context(missing_path, profile(missing_path)?)))
  assert(Result.is_err(fence(missing_path)))
  Ok(true)
end

fn clock_bounds() -> Bool!String do
  let key = case Crypto.x25519_from_seed(bytes(String.repeat("x", 32))) do
    Err(_) -> return Err("fixture key")
    Ok(value) -> value
  end
  let selected = Some(MobileOhttpKey {
    config: OhttpKeyConfig { key_id: 37, public_key: key.public_key },
    not_before_ms: wide("1000")?,
    not_after_ms: wide("2000")?
  })
  require_ohttp_completion_time(wide("1500")?, selected, wide("1500")?)?
  require_ohttp_completion_time(wide("1500")?, selected, wide("1999")?)?
  assert(fails(require_ohttp_completion_time(wide("1500")?, selected, wide("1499")?),
    "ohttp_clock_rollback"))
  assert(fails(require_ohttp_completion_time(wide("1500")?, selected, wide("2000")?),
    "ohttp_key_expired"))
  assert(fails(require_ohttp_completion_time(wide("1500")?, selected, wide("0")?),
    "ohttp_clock_rollback"))
  assert(Result.is_err(require_ohttp_completion_time(wide("1500")?,
    selected,
    wide("18446744073709551615")?)))
  require_ohttp_completion_time(wide("1500")?, None, wide("2000")?)?
  Ok(true)
end

test("account-scoped OHTTP highwater survives reopen and refuses rollback/rebind/stale reset") do
  case revisions() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> do
      assert(value)
      println("m3-context-revisions:passed")
    end
  end
end

test("native OHTTP context compares all four raw resources and requires explicit validated off") do
  case native_sources() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> do
      assert(value)
      println("m3-context-native_sources:passed")
    end
  end
end

test("completion rejects rollback and exact selected-key expiry using bounded fixture clocks") do
  case clock_bounds() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> do
      assert(value)
      println("m3-context-clock_bounds:passed")
    end
  end
end

fn tampered_contexts() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  install("1")?
  let path = created("ohttp-context-tampering")?
  let original = profile(path)?
  let context = capture_native_ohttp_context(path, original)?
  let durable = fence(path)?
  let changed_origin = %{context |
    pins: %{context.pins | network: %{context.pins.network | edge_origin: "http://127.0.0.1:24468"}}
  }
  assert(case require_current_ohttp_context(path, changed_origin) do
    Err("invalid_ohttp_context") -> true
    _ -> false
  end)
  let no_fence = %{context | basis: %{context.basis | labels: [], records: []}}
  assert(case require_current_ohttp_context(path, no_fence) do
    Err("invalid_ohttp_context") -> true
    _ -> false
  end)
  let stale_identity = %{context | pins: %{context.pins | identity: bytes(String.repeat("x", 32))}}
  assert(case require_current_ohttp_context(path, stale_identity) do
    Err("invalid_ohttp_context") -> true
    _ -> false
  end)
  let key = case Crypto.x25519_from_seed(bytes(String.repeat("x", 32))) do
    Err(_) -> return Err("fixture key")
    Ok(value) -> value
  end
  let selected = Some(MobileOhttpKey {
    config: OhttpKeyConfig { key_id: 255, public_key: key.public_key },
    not_before_ms: wide("0")?,
    not_after_ms: wide("18446744073709551615")?
  })
  assert(case require_current_ohttp_context(path, %{context | selected_key: selected}) do
    Err("invalid_ohttp_context") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(fence(path)?, durable))
  assert(Bytes.secure_equals(profile(path)?, original))
  Ok(true)
end

test("ordinary copied contexts cannot replace origin/key or authenticated fence identity") do
  case tampered_contexts() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> do
      assert(value)
      println("m3-context-tampered_contexts:passed")
    end
  end
end
