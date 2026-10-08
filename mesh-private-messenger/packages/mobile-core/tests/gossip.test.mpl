from MobileCore import load_profile_export, start_conversation_export
from Mobile.Healing import peer_session_features
from Mobile.TrustAlarm import trust_alarm_gate
from Protocol.EnvelopeWire import decode_inner_envelope, encode_inner_envelope
from Protocol.V1 import InnerEnvelope, ProtocolExtension
from Tests.AnchorSupport import (
  DetailAlarm,
  FakeAnswer,
  alarm_kind,
  details,
  drive,
  install_anchor_config,
  lookup,
  outcome,
  random_leaf,
  service_public_key,
  signed_checkpoint
)
from Tests.GossipSupport import (
  GossipPair,
  account_id,
  asked_count,
  canary_checkpoint,
  canary_key,
  canary_lookup,
  canary_witness_id,
  canary_witnesses,
  consistency_asks,
  control,
  deliver,
  drain,
  forget_pair,
  frk_finder,
  frk_implicated,
  gossip_pair,
  gossip_run,
  hear,
  history_count,
  honest,
  install_canary_config,
  introduce,
  invented_hint,
  pending,
  raw_extension,
  say,
  split,
  witness_key
)
from Tests.GroupConsistencySupport import ConsistencyAccount, account_fixture, request, wide
from Tests.Support import repeated
from Transparency.CompactWire import WitnessCosignature
from Transparency.Gossip import (
  GossipAnswer,
  GossipHint,
  gossip_encode_answer,
  gossip_encode_hint,
  gossip_hint_extension
)
from Transparency.Merkle import TransparencyCheckpoint, WitnessKey, leaf_hash, sign_checkpoint

fn hour_ms() -> Int do
  3_600_000
end

fn day_ms() -> Int do
  86_400_000
end

fn frk_kind(bytes :: Bytes) -> Int do
  case Bytes.get(bytes, 4) do
    Ok(kind) -> kind
    Err(_) -> 0
  end
end

fn root_of(value :: TransparencyCheckpoint) -> Bytes do
  value.tree_root
end

fn gate_open(path :: String) -> Bool do
  case trust_alarm_gate(path) do
    Ok(_) -> true
    Err(_) -> false
  end
end

fn show(result :: Result<Bool, String>) do
  case result do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

# Both phones look themselves and each other up under their own checkpoint of
# a log whose first two leaves are their device sets.

fn look_up(pair :: GossipPair,
  ann_leaves :: List<Bytes>,
  ann_view :: TransparencyCheckpoint,
  bea_leaves :: List<Bytes>,
  bea_view :: TransparencyCheckpoint) -> Result<(), String> do
  lookup(pair.ann.path, "ann", pair.ann.device_set, ann_leaves, 0, 0, ann_view)?
  lookup(pair.ann.path,
    "bea",
    pair.bea.device_set,
    ann_leaves,
    1,
    List.length(ann_leaves),
    ann_view)?
  lookup(pair.bea.path, "bea", pair.bea.device_set, bea_leaves, 1, 0, bea_view)?
  lookup(pair.bea.path,
    "ann",
    pair.ann.device_set,
    bea_leaves,
    0,
    List.length(bea_leaves),
    bea_view)?
  Ok(nil)
end

fn log_of(pair :: GossipPair, extra :: Int) -> List<Bytes>!String do
  let tail = for _ in 0..extra do
    random_leaf()?
  end
  Ok([leaf_hash(pair.ann.device_set)?, leaf_hash(pair.bea.device_set)?] ++ tail)
end

fn consistent_views() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  assert(install_anchor_config(false)?)
  let pair = gossip_pair("gossip-quiet")?
  let leaves = log_of(pair, 3)?
  let small = List.take(leaves, 3)
  look_up(pair, small, signed_checkpoint(1, small)?, leaves, signed_checkpoint(2, leaves)?)?
  # A message request carries Ann's hint too, but a stranger is not heard.
  assert(introduce(pair)? == 0)
  hear(pair.ann.path, say(pair.bea.path, pair.ann_profile, "hi ann")?)?
  hear(pair.bea.path, say(pair.ann.path, pair.bea_profile, "hi bea")?)?
  let respond = fn kind, tag, target, body -> honest(leaves, kind, tag, target, body) end
  # Each phone proves the other's newer or older view a prefix of its own with
  # one consistency proof, and nothing else happens.
  assert(consistency_asks(gossip_run(pair.ann.path, 0, respond)?) == 1)
  assert(consistency_asks(gossip_run(pair.bea.path, 0, respond)?) == 1)
  assert(List.length(drain(pair.ann.path)?) == 0)
  assert(List.length(drain(pair.bea.path)?) == 0)
  assert(alarm_kind(pair.ann.path)? == 0 && alarm_kind(pair.bea.path)? == 0)
  # A pair already verified is skipped, whenever it comes again.
  hear(pair.ann.path, say(pair.bea.path, pair.ann_profile, "again")?)?
  hear(pair.bea.path, say(pair.ann.path, pair.bea_profile, "again")?)?
  assert(pending(pair.ann.path)? == 0 && pending(pair.bea.path)? == 0)
  assert(List.length(gossip_run(pair.bea.path, 2 * hour_ms(), respond)?) == 0)
  assert(gate_open(pair.ann.path) && gate_open(pair.bea.path))
  forget_pair(pair)?
  Ok(true)
end

test("two phones on consistent views stay quiet") do
  show(consistent_views())
end

fn fork_of(alarms :: List<DetailAlarm>) -> Bytes!String do
  case List.filter(alarms, fn alarm -> alarm.kind == 3 && alarm.active end) do
    [alarm] -> case alarm.frks do
      [frk] -> Ok(frk.bytes)
      _ -> Err("expected one proof")
    end
    _ -> Err("expected one contact fork alarm")
  end
end

fn morse_witnesses() -> List<WitnessKey>!String do
  Ok([witness_key("witness-a", 92)?, witness_key("witness-b", 93)?, witness_key("witness-c", 94)?])
end

fn relay_status(alarms :: List<DetailAlarm>, url :: String) -> Int do
  let found = List.flat_map(alarms,
    fn alarm -> List.flat_map(alarm.frks,
      fn frk -> List.filter(frk.relays, fn relay -> relay.url == url end) end) end)
  case found do
    relay :: _ -> relay.status
    [] -> -1
  end
end

fn forked_views() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  assert(install_anchor_config(false)?)
  let pair = gossip_pair("gossip-fork")?
  # One service key signs two logs of the same size: each phone was shown one.
  let shown_ann = log_of(pair, 1)?
  let shown_bea = [List.get(shown_ann, 0), List.get(shown_ann, 1), random_leaf()?]
  look_up(pair,
    shown_ann,
    signed_checkpoint(1, shown_ann)?,
    shown_bea,
    signed_checkpoint(1, shown_bea)?)?
  introduce(pair)?
  hear(pair.bea.path, say(pair.ann.path, pair.bea_profile, "how are you?")?)?
  let for_ann = fn kind, tag, target, body -> honest(shown_ann, kind, tag, target, body) end
  let for_bea = fn kind, tag, target, body -> honest(shown_bea, kind, tag, target, body) end
  # Same size, another root: no proof can exist, so Bea asks Ann at once.
  assert(consistency_asks(gossip_run(pair.bea.path, 0, for_bea)?) == 0)
  assert(deliver(pair.bea.path, pair.ann.path)? == 1)
  # Ann answers with her signed checkpoint and asks for Bea's.
  gossip_run(pair.ann.path, 0, for_ann)?
  assert(deliver(pair.ann.path, pair.bea.path)? == 1)
  let bea_run = gossip_run(pair.bea.path, 0, for_bea)?
  assert(asked_count(bea_run, 4, "") == 1)
  assert(deliver(pair.bea.path, pair.ann.path)? == 1)
  let ann_run = gossip_run(pair.ann.path, 0, for_ann)?
  assert(asked_count(ann_run, 4, "") == 1)
  assert(List.length(drain(pair.ann.path)?) == 0)
  # Both phones hold a proof the judge accepts, naming both witnesses that
  # signed both versions, and a finder address from the app's hook.
  let bea_alarms = details(pair.bea.path)?
  let ann_alarms = details(pair.ann.path)?
  let bea_frk = fork_of(bea_alarms)?
  let ann_frk = fork_of(ann_alarms)?
  assert(frk_implicated(bea_frk, service_public_key()?, morse_witnesses()?)? == [
      "witness-a",
      "witness-b"
    ])
  assert(frk_implicated(ann_frk, service_public_key()?, morse_witnesses()?)? == [
      "witness-a",
      "witness-b"
    ])
  assert(!Bytes.secure_equals(frk_finder(bea_frk)?, repeated(0, 32)?))
  # The alarm blocks new sessions on both phones and was filed with the relays.
  assert(alarm_kind(pair.ann.path)? == 3 && alarm_kind(pair.bea.path)? == 3)
  assert(!gate_open(pair.ann.path) && !gate_open(pair.bea.path))
  assert(relay_status(bea_alarms, "https://relay-a.test") == 1)
  assert(relay_status(ann_alarms, "https://relay-a.test") == 1)
  # The control messages never became chat messages.
  assert(history_count(pair.ann.path, pair.bea_profile)? == 2)
  assert(history_count(pair.bea.path, pair.ann_profile)? == 2)
  forget_pair(pair)?
  Ok(true)
end

test("two phones on forked views both build a valid FRK and raise the alarm") do
  show(forked_views())
end

fn random_root() -> Bytes!String do
  random_leaf()
end

fn quiet_pair(label :: String) -> GossipPair!String do
  assert(install_anchor_config(false)?)
  let pair = gossip_pair(label)?
  let leaves = log_of(pair, 1)?
  let view = signed_checkpoint(1, leaves)?
  look_up(pair, leaves, view, leaves, view)?
  introduce(pair)?
  Ok(pair)
end

fn quiet(kind :: Int, tag :: String, target :: String, body :: Bytes) -> FakeAnswer do
  honest(List.new(), kind, tag, target, body)
end

fn invented_hints() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let pair = quiet_pair("gossip-invented")?
  let respond = fn kind, tag, target, body -> quiet(kind, tag, target, body) end
  # Ann's phone is hostile: it claims a root Bea's log never had.
  invented_hint(pair.bea.path,
    pair.ann_profile,
    pair.bea_profile,
    GossipHint { tree_size: 3, root: random_root()? })?
  gossip_run(pair.bea.path, 0, respond)?
  assert(List.length(drain(pair.bea.path)?) == 1)
  # More invented hints the same day cost nothing more.
  invented_hint(pair.bea.path,
    pair.ann_profile,
    pair.bea_profile,
    GossipHint { tree_size: 3, root: random_root()? })?
  gossip_run(pair.bea.path, 0, respond)?
  gossip_run(pair.bea.path, hour_ms(), respond)?
  assert(List.length(drain(pair.bea.path)?) == 0)
  # The next day the same contact is asked once more.
  gossip_run(pair.bea.path, day_ms() + hour_ms(), respond)?
  assert(List.length(drain(pair.bea.path)?) == 1)
  # Nothing is blocked: Bea can still start a new chat.
  assert(alarm_kind(pair.bea.path)? == 0 && gate_open(pair.bea.path))
  let cat = account_fixture("gossip-invented-cat", "cat")?
  start_conversation_export(request([
    Bytes.from_utf8(pair.bea.path),
    load_profile_export(Bytes.from_utf8(cat.path))?,
    Bytes.from_utf8("hi")
  ])?)?
  forget_pair(pair)?
  Ok(true)
end

test("an invented hint never blocks and is asked about only once a day") do
  show(invented_hints())
end

fn forged_answer(ask_back :: Bool) -> Bytes!String do
  # Signed by another key under the pinned service key's name.
  let other = case Crypto.signing_from_seed(repeated(99, 32)?) do
    Err(_) -> Err("test signing key generation failed")
    Ok(value)
  end?
  let signed = sign_checkpoint(other.private_key,
    other.public_key.bytes,
    wide(1)?,
    [random_leaf()?, random_leaf()?, random_leaf()?],
    repeated(0, 32)?,
    wide(DateTime.to_unix_ms(DateTime.utc_now()))?)?
  let forged = %{signed | service_public_key: service_public_key()?}
  gossip_encode_answer(GossipAnswer {
    checkpoint: forged,
    witnesses: List.new(),
    ask_back: ask_back
  })
end

fn bad_signature() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let pair = quiet_pair("gossip-forged")?
  let respond = fn kind, tag, target, body -> quiet(kind, tag, target, body) end
  control(pair.bea.path, pair.ann_profile, pair.bea_profile, forged_answer(true)?)?
  # Dropped: nothing to compare, no answer sent back, nothing raised.
  assert(pending(pair.bea.path)? == 0)
  gossip_run(pair.bea.path, 0, respond)?
  assert(List.length(drain(pair.bea.path)?) == 0)
  assert(alarm_kind(pair.bea.path)? == 0 && gate_open(pair.bea.path))
  # And that contact is not asked anything again that day.
  invented_hint(pair.bea.path,
    pair.ann_profile,
    pair.bea_profile,
    GossipHint { tree_size: 3, root: random_root()? })?
  gossip_run(pair.bea.path, hour_ms(), respond)?
  assert(List.length(drain(pair.bea.path)?) == 0)
  gossip_run(pair.bea.path, day_ms() + hour_ms(), respond)?
  assert(List.length(drain(pair.bea.path)?) == 1)
  forget_pair(pair)?
  Ok(true)
end

test("a checkpoint with a bad service signature is dropped") do
  show(bad_signature())
end

fn old_client() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let pair = quiet_pair("gossip-old")?
  let hint = GossipHint { tree_size: 3, root: random_root()? }
  let contact = ProtocolExtension { id: 1, mandatory: false, value: repeated(9, 32)? }
  let features = ProtocolExtension { id: 3, mandatory: false, value: repeated(7, 1)? }
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: account_id(pair.ann_profile)?,
    sender_device_id: repeated(1, 16)?,
    recipient_device_id: repeated(2, 16)?,
    conversation_id: repeated(3, 16)?,
    client_message_id: repeated(4, 16)?,
    client_timestamp: wide(1)?,
    message_type: 1,
    body: Bytes.from_utf8("still readable"),
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: [contact, gossip_hint_extension(hint)?, features]
  }
  # The decoder every build shares keeps an unknown optional extension byte
  # for byte and reads the rest as before.
  let encoded = case encode_inner_envelope(inner) do
    Err(_) -> Err("inner envelope did not encode")
    Ok(value)
  end?
  let decoded = case decode_inner_envelope(encoded) do
    Err(_) -> Err("inner envelope did not decode")
    Ok(value)
  end?
  assert(Bytes.to_utf8(decoded.body)? == "still readable")
  assert(peer_session_features(decoded.extensions) == 7)
  assert(List.length(decoded.extensions) == 3)
  let kept = List.get(decoded.extensions, 1)
  assert(kept.id == 2 && Bytes.secure_equals(kept.value, gossip_encode_hint(hint)?))
  # A malformed hint, or none at all, is ignored.
  raw_extension(pair.bea.path,
    pair.ann_profile,
    pair.bea_profile,
    [ProtocolExtension { id: 2, mandatory: false, value: repeated(1, 41)? }])?
  raw_extension(pair.bea.path, pair.ann_profile, pair.bea_profile, [contact])?
  assert(pending(pair.bea.path)? == 0)
  forget_pair(pair)?
  Ok(true)
end

test("an old client ignores extension 2, and a malformed hint is ignored") do
  show(old_client())
end

fn proof_limit() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  assert(install_anchor_config(false)?)
  let pair = gossip_pair("gossip-hourly")?
  let leaves = log_of(pair, 4)?
  let view = signed_checkpoint(1, List.take(leaves, 3))?
  look_up(pair, List.take(leaves, 3), view, List.take(leaves, 3), view)?
  introduce(pair)?
  let respond = fn kind, tag, target, body -> honest(leaves, kind, tag, target, body) end
  let four = signed_checkpoint(2, List.take(leaves, 4))?
  let five = signed_checkpoint(3, List.take(leaves, 5))?
  invented_hint(pair.bea.path,
    pair.ann_profile,
    pair.bea_profile,
    GossipHint { tree_size: 4, root: root_of(four) })?
  assert(consistency_asks(gossip_run(pair.bea.path, 0, respond)?) == 1)
  # A newer view from the same conversation within the hour waits its turn.
  invented_hint(pair.bea.path,
    pair.ann_profile,
    pair.bea_profile,
    GossipHint { tree_size: 5, root: root_of(five) })?
  assert(consistency_asks(gossip_run(pair.bea.path, 30 * 60_000, respond)?) == 0)
  assert(pending(pair.bea.path)? == 1)
  assert(consistency_asks(gossip_run(pair.bea.path, hour_ms() + 60_000, respond)?) == 1)
  assert(pending(pair.bea.path)? == 0)
  assert(List.length(drain(pair.bea.path)?) == 0)
  forget_pair(pair)?
  Ok(true)
end

test("at most one consistency proof per conversation per hour") do
  show(proof_limit())
end

# Plan §11.3: two canary phones are shown two conflicting canary checkpoints
# and message each other. The anchor check is off in their build. T3 cosigned
# both versions. Ann was shown a forged key for cat; Bea the real one.

struct Drill do
  pair :: GossipPair
  shown_ann :: List<Bytes>
  shown_bea :: List<Bytes>
end

fn drill_world() -> Drill!String do
  assert(install_canary_config()?)
  let pair = gossip_pair("gossip-drill")?
  let cat = account_fixture("gossip-drill-cat", "cat")?
  let forged_cat = account_fixture("gossip-drill-forged-cat", "cat")?
  let base = [leaf_hash(pair.ann.device_set)?, leaf_hash(pair.bea.device_set)?]
  let shown_ann = base ++ [leaf_hash(forged_cat.device_set)?]
  let shown_bea = base ++ [leaf_hash(cat.device_set)?, random_leaf()?, random_leaf()?]
  let ann_view = canary_checkpoint(1, shown_ann)?
  let bea_view = canary_checkpoint(2, shown_bea)?
  canary_lookup(pair.ann.path, "ann", pair.ann.device_set, shown_ann, 0, 0, ann_view, [0, 2])?
  canary_lookup(pair.ann.path, "bea", pair.bea.device_set, shown_ann, 1, 3, ann_view, [0, 2])?
  canary_lookup(pair.ann.path, "cat", forged_cat.device_set, shown_ann, 2, 3, ann_view, [0, 2])?
  canary_lookup(pair.bea.path, "bea", pair.bea.device_set, shown_bea, 1, 0, bea_view, [1, 2])?
  canary_lookup(pair.bea.path, "ann", pair.ann.device_set, shown_bea, 0, 5, bea_view, [1, 2])?
  canary_lookup(pair.bea.path, "cat", cat.device_set, shown_bea, 2, 5, bea_view, [1, 2])?
  Ok(Drill { pair: pair, shown_ann: shown_ann, shown_bea: shown_bea })
end

fn drill() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let world = drill_world()?
  let pair = world.pair
  let directory = fn kind, tag, target, body -> split(world.shown_ann,
    world.shown_bea,
    kind,
    tag,
    target,
    body) end
  introduce(pair)?
  hear(pair.ann.path, say(pair.bea.path, pair.ann_profile, "hi ann")?)?
  hear(pair.bea.path, say(pair.ann.path, pair.bea_profile, "hi bea")?)?
  # Neither view proves a prefix of the other, so each phone asks the other.
  gossip_run(pair.ann.path, 0, directory)?
  gossip_run(pair.bea.path, 0, directory)?
  assert(deliver(pair.ann.path, pair.bea.path)? == 1)
  assert(deliver(pair.bea.path, pair.ann.path)? == 1)
  gossip_run(pair.ann.path, 0, directory)?
  gossip_run(pair.bea.path, 0, directory)?
  assert(deliver(pair.ann.path, pair.bea.path)? == 1)
  assert(deliver(pair.bea.path, pair.ann.path)? == 1)
  # Each now holds the other's signed checkpoint. The next consistency proof
  # for the conversation is allowed an hour after the first; it fails, and the
  # leaf each phone looked up (cat's) reads differently in the other version.
  gossip_run(pair.ann.path, hour_ms() + 60_000, directory)?
  gossip_run(pair.bea.path, hour_ms() + 60_000, directory)?
  let ann_frk = fork_of(details(pair.ann.path)?)?
  let bea_frk = fork_of(details(pair.bea.path)?)?
  assert(frk_kind(ann_frk) == 2 && frk_kind(bea_frk) == 2)
  assert(frk_implicated(ann_frk, canary_key()?, canary_witnesses()?)? == [canary_witness_id(2)])
  assert(frk_implicated(bea_frk, canary_key()?, canary_witnesses()?)? == [canary_witness_id(2)])
  # From gossip alone: the anchor check is off in this build.
  drive(pair.ann.path, directory)?
  assert(outcome(pair.ann.path)? == 7)
  assert(alarm_kind(pair.ann.path)? == 3 && alarm_kind(pair.bea.path)? == 3)
  forget_pair(pair)?
  Ok(true)
end

test("gossip drill: two canary phones on conflicting checkpoints both build a valid FRK") do
  show(drill())
end
