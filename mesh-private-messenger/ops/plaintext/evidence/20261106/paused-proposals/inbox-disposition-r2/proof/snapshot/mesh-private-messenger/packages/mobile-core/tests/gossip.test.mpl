from Mobile.Gossip import observe_gossip, pending_gossip, outgoing_gossip_hint, clear_gossip_writes
from Mobile.TransparencySafety import retained_fork, require_log_changes_allowed
from Mobile.Codec import current_time
from Mobile.Platform import native_security_config
from MobileCore import install_group_checkpoint_for_test
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_blobs
from Tests.Support import database_path, install_security_config, repeated
from Transparency.Gossip import (
  CheckpointHint,
  GossipControl,
  encode_hint,
  encode_gossip,
  decode_gossip
)
from Transparency.Fork import ForkProof, decode_fork, fork_same_size
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  WitnessAttestation,
  sign_witness,
  sign_tree_checkpoint_for
)
from Transparency.Wire import encode_checkpoint, encode_witnesses
from Transparency.Config import SecurityConfig, WitnessPin, witness_set_id, encode_security_config
from Protocol.V1 import InnerEnvelope, ProtocolExtension

fn envelope(peer :: Bytes,
  device :: Bytes,
  kind :: Int,
  body :: Bytes,
  extensions :: List<ProtocolExtension>) -> InnerEnvelope!String do
  Ok(InnerEnvelope {
    version: 1,
    sender_account_id: peer,
    sender_device_id: device,
    recipient_device_id: repeated(8, 16)?,
    conversation_id: repeated(9, 16)?,
    client_message_id: repeated(10, 16)?,
    client_timestamp: current_time()?,
    message_type: kind,
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: extensions
  })
end

fn consume_pending(path :: String, peer :: Bytes) -> Bytes!String do
  let wrapping_key = platform_key()?
  let (_, body) = pending_gossip(path, wrapping_key, peer)?
  let (labels, blobs) = clear_gossip_writes(path, wrapping_key, peer)?
  store_updated_blobs(path, labels, blobs)?
  Ok(body)
end

fn proof(version :: Int) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("fixture signer failed")
    Ok(value) -> value
  end
  assert(install_security_config(signer.public_key.bytes,
    repeated(31, 32)?,
    repeated(32, 32)?,
    repeated(33, 32)?,
    8))
  if version == 2 do
    let config = native_security_config()?
    assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
      encode_security_config(%{config |
        version: 3,
        log_version: 2,
        legacy_witnesses: config.witnesses,
        legacy_threshold: config.threshold
      })?))
  end
  let alice = database_path("gossip-alice")?
  let bob = database_path("gossip-bob")?
  ensure_schema(alice)?
  ensure_schema(bob)?
  let key = platform_key()?
  let now = current_time()?
  let peer_a = repeated(1, 32)?
  let peer_b = repeated(2, 32)?
  let device = repeated(3, 16)?
  let checkpoint = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    U64.parse("4")?,
    U64.parse("8")?,
    repeated(4, 32)?,
    repeated(0, 32)?,
    now)?
  install_group_checkpoint_for_test(alice, encode_checkpoint(checkpoint)?)?
  install_group_checkpoint_for_test(bob, encode_checkpoint(checkpoint)?)?
  let hint = outgoing_gossip_hint(alice, key)?
  assert(Bytes.length(hint) == 40)
  let hello = envelope(peer_a,
    device,
    1,
    Bytes.from_utf8("hello"),
    [ProtocolExtension { id: 2, mandatory: false, value: hint }])?
  observe_gossip(bob, key, hello, now)?
  assert(Bytes.length(consume_pending(bob, peer_a)?) == 0)
  # The legacy/RFC migration may have the same size with another root. Both
  # signatures are genuine, but they describe different log hash profiles.
  let migrating_peer = repeated(7, 32)?
  let migrating = %{hello |
    sender_account_id: migrating_peer,
    extensions: [
      ProtocolExtension {
        id: 2,
        mandatory: false,
        value: encode_hint(CheckpointHint {
          tree_size: checkpoint.tree_size,
          tree_root: repeated(8, 32)?
        })?
      }
    ]
  }
  observe_gossip(bob, key, migrating, now)?
  let migration_id = case decode_gossip(consume_pending(bob, migrating_peer)?)? do
    CheckpointRequest(id, _) -> id
    _ -> return Err("expected migration checkpoint request")
  end
  let other_profile = sign_tree_checkpoint_for(if version == 1 do
      2
    else
      1
    end,
    signer.private_key,
    signer.public_key.bytes,
    checkpoint.sequence,
    checkpoint.tree_size,
    repeated(8, 32)?,
    repeated(0, 32)?,
    now)?
  observe_gossip(bob,
    key,
    envelope(migrating_peer,
      device,
      5,
      encode_gossip(CheckpointAnswer(migration_id, other_profile, List.new(), true))?,
      List.new())?,
    now)?
  require_log_changes_allowed(bob, key)?
  consume_pending(bob, migrating_peer)?
  # An invented hint can trigger one request, never a freeze. The daily budget
  # survives queue consumption, replay, another device, and a backward clock.
  let invented = %{hello |
    extensions: [
      ProtocolExtension {
        id: 2,
        mandatory: false,
        value: encode_hint(CheckpointHint {
          tree_size: checkpoint.tree_size,
          tree_root: repeated(5, 32)?
        })?
      }
    ]
  }
  observe_gossip(bob, key, invented, now)?
  let request = consume_pending(bob, peer_a)?
  let id = case decode_gossip(request)? do
    CheckpointRequest(id, _) -> id
    _ -> return Err("expected checkpoint request")
  end
  require_log_changes_allowed(bob, key)?
  observe_gossip(bob, key, %{invented | sender_device_id: repeated(6, 16)?}, now)?
  observe_gossip(bob, key, invented, U64.subtract(now, U64.parse("1000")?)?)?
  assert(Bytes.length(consume_pending(bob, peer_a)?) == 0)
  # A service-signature forgery is ignored without a reciprocal answer.
  let tampered = %{checkpoint | tree_root: repeated(5, 32)?}
  observe_gossip(bob,
    key,
    envelope(peer_a,
      device,
      5,
      encode_gossip(CheckpointAnswer(id, tampered, List.new(), true))?,
      List.new())?,
    now)?
  require_log_changes_allowed(bob, key)?
  assert(Bytes.length(consume_pending(bob, peer_a)?) == 0)
  # Two real divergent signatures make a portable proof on both phones. Each
  # phone answers through the authenticated channel, never through a server.
  let forked = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    U64.parse("4")?,
    U64.parse("8")?,
    repeated(5, 32)?,
    repeated(0, 32)?,
    now)?
  let signed = for index in 0..16 do
    let witness = case Crypto.signing_generate() do
      Err(_) -> return Err("fixture witness failed")
      Ok(value) -> value
    end
    let id = "witness-#{index + 10}"
    (WitnessKey { witness_id: id, public_key: witness.public_key.bytes },
      sign_witness(id, witness.private_key, checkpoint)?,
      sign_witness(id, witness.private_key, forked)?)
  end
  let pins = for (pin, _, _) in signed do
    pin
  end
  let configured_pins = for pin in pins do
    WitnessPin {
      witness_id: pin.witness_id,
      public_key: pin.public_key,
      operator_label: pin.witness_id
    }
  end
  let config = native_security_config()?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(%{config |
      version: 3,
      log_version: 2,
      witnesses: configured_pins,
      threshold: 9,
      set_id: witness_set_id(configured_pins, 9)?,
      legacy_witnesses: configured_pins,
      legacy_threshold: 9
    })?))
  let label = "transparency-witnesses/v2"
  for path in [alice, bob] do
    let signatures = for (_, original, forked_signature) in signed do
      if path == alice do
        forked_signature
      else
        original
      end
    end
    store_updated_blobs(path,
      [label],
      [seal_local(encode_witnesses(signatures)?, key, local_context(label)?)?])?
  end
  install_group_checkpoint_for_test(alice, encode_checkpoint(forked)?)?
  observe_gossip(alice, key, envelope(peer_b, device, 5, request, List.new())?, now)?
  let answer = consume_pending(alice, peer_b)?
  observe_gossip(bob, key, envelope(peer_a, device, 5, answer, List.new())?, now)?
  let reciprocal = consume_pending(bob, peer_a)?
  observe_gossip(alice, key, envelope(peer_b, device, 5, reciprocal, List.new())?, now)?
  for path in [alice, bob] do
    let evidence = retained_fork(path, key)?
    assert(Bytes.length(evidence) > 0)
    let decoded = decode_fork(evidence)?
    assert(Bytes.secure_equals(decoded.finder, repeated(0, 32)?))
    assert(List.length(decoded.attestations) == 32)
    assert(fork_same_size(decoded, signer.public_key, pins)?.witnesses == pins)
    case require_log_changes_allowed(path, key) do
      Err(error) -> assert(error == "transparency_fork_detected")
      Ok(_) -> assert(false)
    end
    assert(Bytes.length(consume_pending(path,
      if path == alice do
        peer_b
      else
        peer_a
      end)?) == 0)
    File.delete(path)?
  end
  Ok(true)
end

test("checkpoint gossip ignores unsigned lies and retains signed forks on both phones") do
  case proof(1) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
  case proof(2) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
