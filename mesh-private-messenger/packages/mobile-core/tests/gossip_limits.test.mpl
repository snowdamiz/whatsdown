from Mobile.Codec import current_time
from Mobile.Gossip import observe_gossip, pending_gossip, clear_gossip_writes
from Mobile.Transparency import store_transparency_origin
from Mobile.TransparencySafety import require_log_changes_allowed
from MobileCore import install_group_checkpoint_for_test
from Mobile.Platform import native_security_config
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Storage.Records import store_updated_blobs
from Tests.Support import database_path, repeated, install_security_config
from Tests.GroupConsistencySupport import signing_pair
from Transparency.Config import SecurityConfig, encode_security_config
from Transparency.Gossip import CheckpointHint, encode_hint
from Transparency.Merkle import (
  compact_consistency_proof_for,
  sign_tree_checkpoint_for,
  merkle_root_for
)
from Transparency.Wire import (
  encode_checkpoint,
  encode_consistency_proof,
  decode_transparency_tree_query
)
from Protocol.V1 import InnerEnvelope, ProtocolExtension

actor proof_server(proof :: Bytes, calls :: String, version :: Int, port :: Int) do
  let route = if version == 2 do
    "/v2/transparency/consistency"
  else
    "/v1/transparency/consistency"
  end
  HTTP.router()
    |> HTTP.on_post(route,
      fn(request :: Request) do
        case File.append(calls, "x") do
          Err(_) -> HTTP.response(500, "counter failed")
          Ok(_) -> case decode_transparency_tree_query(Request.body_bytes(request)) do
            Ok(query) -> if query.previous_tree_size == 3 && query.new_tree_size == 7 do
              HTTP.response_bytes_with_headers(200,
                proof,
                Map.put(Map.new(), "Content-Type", "application/octet-stream"))
            else
              HTTP.response(400, "wrong range")
            end
            Err(_) -> HTTP.response(400, "invalid range")
          end
        end
      end)
    |> HTTP.serve(port)
end

fn clear_pending(path :: String, peer :: Bytes) -> Bytes!String do
  let key = platform_key()?
  let (_, pending) = pending_gossip(path, key, peer)?
  let (labels, blobs) = clear_gossip_writes(path, key, peer)?
  store_updated_blobs(path, labels, blobs)?
  Ok(pending)
end

fn proof(version :: Int, port :: Int) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let signer = signing_pair()?
  assert(install_security_config(signer.public_key.bytes,
    repeated(31, 32)?,
    repeated(32, 32)?,
    repeated(33, 32)?,
    8))
  let config = native_security_config()?
  if version == 2 do
    assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
      encode_security_config(%{config |
        version: 3,
        log_version: 2,
        legacy_witnesses: config.witnesses,
        legacy_threshold: config.threshold
      })?))
  end
  let path = database_path("gossip-limits-#{version}")?
  ensure_schema(path)?
  let key = platform_key()?
  let calls = path <> ".calls"
  File.write(calls, "")?
  let leaves = for n in 0..7 do
    Crypto.sha256(Bytes.from_utf8("leaf/#{n}"))
  end
  let old = List.take(leaves, 3)
  let now = current_time()?
  let checkpoint = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    U64.parse("4")?,
    U64.parse("3")?,
    merkle_root_for(version, old)?,
    repeated(0, 32)?,
    now)?
  install_group_checkpoint_for_test(path, encode_checkpoint(checkpoint)?)?
  store_transparency_origin(path, key, "http://127.0.0.1:#{port}")?
  let _server = spawn(proof_server,
    encode_consistency_proof(compact_consistency_proof_for(version, old, leaves)?)?,
    calls,
    version,
    port)
  Timer.sleep(100)
  let peer = repeated(1, 32)?
  let hello = InnerEnvelope {
    version: 1,
    sender_account_id: peer,
    sender_device_id: repeated(2, 16)?,
    recipient_device_id: repeated(3, 16)?,
    conversation_id: repeated(4, 16)?,
    client_message_id: repeated(5, 16)?,
    client_timestamp: now,
    message_type: 1,
    body: Bytes.empty(),
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: [
      ProtocolExtension {
        id: 2,
        mandatory: false,
        value: encode_hint(CheckpointHint {
          tree_size: U64.parse("7")?,
          tree_root: merkle_root_for(version, leaves)?
        })?
      }
    ]
  }
  observe_gossip(path, key, hello, now)?
  assert(File.read(calls)? == "x")
  assert(Bytes.length(clear_pending(path, peer)?) == 0)
  observe_gossip(path, key, hello, U64.add(now, U64.parse("86400000")?)?)?
  assert(File.read(calls)? == "x")
  let invented = %{hello |
    extensions: [
      ProtocolExtension {
        id: 2,
        mandatory: false,
        value: encode_hint(CheckpointHint {
          tree_size: U64.parse("5")?,
          tree_root: repeated(9, 32)?
        })?
      }
    ]
  }
  observe_gossip(path, key, invented, now)?
  assert(File.read(calls)? == "x")
  assert(Bytes.length(clear_pending(path, peer)?) == 0)
  observe_gossip(path, key, invented, U64.add(now, U64.parse("3600000")?)?)?
  assert(File.read(calls)? == "xx")
  assert(Bytes.length(clear_pending(path, peer)?) == 60)
  observe_gossip(path, key, invented, U64.add(now, U64.parse("7200000")?)?)?
  assert(File.read(calls)? == "xxx")
  assert(Bytes.length(clear_pending(path, peer)?) == 0)
  observe_gossip(path, key, invented, U64.add(now, U64.parse("90000000")?)?)?
  assert(File.read(calls)? == "xxxx")
  assert(Bytes.length(clear_pending(path, peer)?) == 60)
  require_log_changes_allowed(path, key)?
  File.delete(calls)?
  File.delete(path)?
  Ok(true)
end

test("gossip verifies exact-range proofs and persists hourly and daily budgets in both log profiles") do
  case proof(1, 18999) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
  case proof(2, 19000) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
