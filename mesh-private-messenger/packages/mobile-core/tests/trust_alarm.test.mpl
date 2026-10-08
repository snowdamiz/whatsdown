import File
from Tests.AnchorSupport import (
  AnchorTrace,
  DetailAlarm,
  DetailFrk,
  DetailRelay,
  FakeAccount,
  FakeAnswer,
  FakeProvider,
  account,
  address,
  address_bytes,
  alarm_kind,
  bytes_of,
  details,
  drive,
  fake_directory,
  fake_relay,
  fake_rpc,
  finder_address,
  install_anchor_config,
  join,
  judge,
  le,
  log_account,
  log_data,
  lookup,
  now_seconds,
  outcome,
  provider,
  random_leaf,
  relay_urls,
  ring_account,
  ring_entry,
  ring_header,
  rpc_urls,
  seeded,
  service_public_key,
  signed_checkpoint
)
from Tests.GroupConsistencySupport import ConsistencyAccount, account_fixture, wide
from Tests.Support import repeated
from Transparency.Fork import ForkLog, ForkRingEntry, fork_decode, fork_proof_hash, fork_verify
from Transparency.Merkle import TransparencyCheckpoint, WitnessKey, checkpoint_hash, leaf_hash

# The phone was shown a forked log: its view holds a fake entry for bea at
# leaf 1, while the public record (anchored on chain) holds the real one.

struct Fork do
  phone :: ConsistencyAccount
  contact :: ConsistencyAccount
  fake :: ConsistencyAccount
  public_leaves :: List<Bytes>
  view_leaves :: List<Bytes>
  view :: TransparencyCheckpoint
  public :: TransparencyCheckpoint
end

fn forked(label :: String, same_size :: Bool) -> Fork!String do
  assert(install_anchor_config(true)?)
  let phone = account_fixture(label, "ann")?
  let contact = account_fixture(label <> "-contact", "bea")?
  let fake = account_fixture(label <> "-fake", "bea")?
  let public_leaves = [
    leaf_hash(phone.device_set)?,
    leaf_hash(contact.device_set)?,
    random_leaf()?,
    random_leaf()?,
    random_leaf()?
  ]
  let view_leaves = [leaf_hash(phone.device_set)?, leaf_hash(fake.device_set)?]
  let view = signed_checkpoint(1, view_leaves)?
  lookup(phone.path, "ann", phone.device_set, view_leaves, 0, 0, view)?
  lookup(phone.path, "bea", fake.device_set, view_leaves, 1, 2, view)?
  let public = if same_size do
    signed_checkpoint(2, List.take(public_leaves, 2))?
  else
    signed_checkpoint(2, public_leaves)?
  end
  Ok(Fork {
    phone: phone,
    contact: contact,
    fake: fake,
    public_leaves: public_leaves,
    view_leaves: view_leaves,
    view: view,
    public: public
  })
end

fn cleanup(value :: Fork) -> Result<(), String> do
  File.delete(value.phone.path)?
  File.delete(value.contact.path)?
  File.delete(value.fake.path)?
  Ok(nil)
end

fn proof_account(frk :: Bytes, paid_to :: Bytes) -> FakeAccount!String do
  let data = join([
    bytes_of([5, 1, 255, 2, 0, 0, 0, 0])?,
    address_bytes(202)?,
    fork_proof_hash(frk)?,
    paid_to,
    le(777, 8)?
  ])?
  Ok(account(address(240)?, judge()?, data))
end

fn chain(public :: TransparencyCheckpoint,
  extra :: List<FakeAccount>) -> List<FakeAccount>!String do
  Ok([
    log_account(log_data("morse-main", false)?)?,
    ring_account(ring_header("morse-main", 1, 1, public, 500)?,
      [0],
      [ring_entry(public, 500, 3, 0)?])?
  ]
    ++ extra)
end

fn providers(accounts :: List<FakeAccount>) -> List<FakeProvider> do
  for url in rpc_urls() do
    provider(url, accounts, now_seconds())
  end
end

# A directory that cannot connect the phone's view to the public record
# refuses the consistency query; its leaf proofs are the public record's.

fn respond(chain_providers :: List<FakeProvider>,
  leaves :: List<Bytes>,
  refuse :: Bool,
  relays_up :: Bool,
  bounties :: Bool) -> Fun(Int, String, String, Bytes) -> FakeAnswer do
  fn kind, tag, target, body -> if kind == 1 do
    fake_rpc(chain_providers, target, body)
  else if kind == 2 do
    fake_directory(leaves, refuse, target, body)
  else if kind == 3 do
    fake_relay(target, body, relays_up)
  else if bounties do
    FakeAnswer { status: 200, body: finder_address(tag) }
  else
    FakeAnswer { status: 200, body: Bytes.empty() }
  end end
end

fn fork_log() -> ForkLog!String do
  Ok(ForkLog {
    service_public_key: service_public_key()?,
    witnesses: [
      WitnessKey { witness_id: "witness-a", public_key: seeded(92)?.public_key.bytes },
      WitnessKey { witness_id: "witness-b", public_key: seeded(93)?.public_key.bytes },
      WitnessKey { witness_id: "witness-c", public_key: seeded(94)?.public_key.bytes }
    ]
  })
end

fn ring(public :: TransparencyCheckpoint) -> ForkRingEntry!String do
  Ok(ForkRingEntry {
    sequence: public.sequence,
    tree_size: public.tree_size,
    root: public.tree_root,
    checkpoint_hash: checkpoint_hash(public)?,
    cosign_bitmap: 3
  })
end

fn only_alarm(path :: String) -> DetailAlarm!String do
  let alarms = details(path)?
  if List.length(alarms) != 1 do
    Err("expected one alarm, found #{List.length(alarms)}")
  else
    Ok(List.head(alarms))
  end
end

fn statuses(frk :: DetailFrk) -> List<Int> do
  List.map(frk.relays, fn relay -> relay.status end)
end

fn relay_posts(traces :: List<AnchorTrace>) -> List<AnchorTrace> do
  List.filter(traces, fn trace -> trace.kind == 3 end)
end

fn contradiction_proof() -> Bool!String do
  let value = forked("alarm-fork", false)?
  let world = providers(chain(value.public, List.new())?)
  let traces = drive(value.phone.path, respond(world, value.public_leaves, true, false, true))?
  assert(outcome(value.phone.path)? == 5)
  assert(alarm_kind(value.phone.path)? == 1)
  let alarm = only_alarm(value.phone.path)?
  assert(alarm.active)
  # Leaf 0 (ann) reads the same in both versions; leaf 1 (bea) does not, so
  # one complete contradiction proof, checked as the judge would check it.
  assert(List.length(alarm.frks) == 1)
  let frk = List.head(alarm.frks)
  assert(frk.complete)
  let evidence = fork_decode(frk.bytes)?
  assert(evidence.kind == 2 && evidence.leaf_index == 1 && evidence.ring_index == 0)
  assert(Bytes.secure_equals(evidence.finder, finder_address("finder:0")))
  let implicated = fork_verify(evidence, fork_log()?, Some(ring(value.public)?))?
  assert(implicated == ["witness-a", "witness-b"])
  # Filed to every pinned relay: a took it, b refused it, c was down.
  assert(List.map(relay_posts(traces), fn trace -> trace.target end) == List.map(relay_urls(),
      fn url -> url <> "/v1/fork-evidence" end))
  assert(List.all(relay_posts(traces), fn trace -> Bytes.secure_equals(trace.body, frk.bytes) end))
  assert(statuses(frk) == [1, 2, 0])
  # The next run retries c, keeps the one alarm, and reads the chain: the
  # proof landed, paying an address other than the one the phone named.
  let paid = providers(chain(value.public, [proof_account(frk.bytes, address_bytes(230)?)?])?)
  let again = drive(value.phone.path, respond(paid, value.public_leaves, true, true, true))?
  assert(List.length(relay_posts(again)) == 1)
  let later = only_alarm(value.phone.path)?
  let landed = List.head(later.frks)
  assert(statuses(landed) == [1, 2, 1])
  assert(landed.landed)
  assert(Bytes.secure_equals(landed.paid_to, address_bytes(230)?))
  assert(!Bytes.secure_equals(landed.paid_to, evidence.finder))
  cleanup(value)?
  Ok(true)
end

fn same_size_proof() -> Bool!String do
  let value = forked("alarm-same", true)?
  let world = providers(chain(value.public, List.new())?)
  let traces = drive(value.phone.path, respond(world, value.public_leaves, false, true, false))?
  assert(outcome(value.phone.path)? == 5)
  # Two roots for one size: no directory proof needed.
  assert(List.length(List.filter(traces, fn trace -> trace.kind == 2 end)) == 0)
  let frk = List.head(only_alarm(value.phone.path)?.frks)
  let evidence = fork_decode(frk.bytes)?
  assert(evidence.kind == 1)
  # Without the bounty setting the finder address is zeros.
  assert(Bytes.secure_equals(evidence.finder, repeated(0, 32)?))
  assert(fork_verify(evidence, fork_log()?, Some(ring(value.public)?))? == [
      "witness-a",
      "witness-b"
    ])
  cleanup(value)?
  Ok(true)
end

# New sessions and key changes stop while an alarm is active; the contact the
# phone already holds still refreshes.

fn gate_proof() -> Bool!String do
  let value = forked("alarm-gate", false)?
  let world = providers(chain(value.public, List.new())?)
  drive(value.phone.path, respond(world, value.public_leaves, true, false, false))?
  assert(alarm_kind(value.phone.path)? == 1)
  let stranger = account_fixture("alarm-gate-stranger", "cyd")?
  let grown = value.view_leaves ++ [leaf_hash(stranger.device_set)?]
  let next = signed_checkpoint(2, grown)?
  case lookup(value.phone.path, "cyd", stranger.device_set, grown, 2, 2, next) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "trust_alarm_active")
  end
  assert(Bytes.secure_equals(lookup(value.phone.path,
      "bea",
      value.fake.device_set,
      grown,
      1,
      2,
      next)?,
    value.fake.device_set))
  File.delete(stranger.path)?
  cleanup(value)?
  Ok(true)
end

# A refused proof between versions that are in fact consistent raises the
# alarm; a later check that proves them consistent clears it (a real fork
# never can), keeping the record.

fn cleared_proof() -> Bool!String do
  assert(install_anchor_config(true)?)
  let phone = account_fixture("alarm-clear", "ann")?
  let leaves = [leaf_hash(phone.device_set)?, random_leaf()?, random_leaf()?]
  let view = signed_checkpoint(1, List.take(leaves, 1))?
  lookup(phone.path, "ann", phone.device_set, List.take(leaves, 1), 0, 0, view)?
  let public = signed_checkpoint(2, leaves)?
  let world = providers(chain(public, List.new())?)
  drive(phone.path, respond(world, leaves, true, true, false))?
  assert(alarm_kind(phone.path)? == 1)
  # Its one leaf reads the same publicly: nothing to prove, nothing filed.
  assert(List.length(only_alarm(phone.path)?.frks) == 0)
  drive(phone.path, respond(world, leaves, false, true, false))?
  assert(outcome(phone.path)? == 1)
  assert(alarm_kind(phone.path)? == 0)
  assert(!only_alarm(phone.path)?.active)
  File.delete(phone.path)?
  Ok(true)
end

fn run(name :: String, value :: Result<Bool, String>) -> Bool do
  case value do
    Err(error) -> do
      println(name <> ": " <> error)
      false
    end
    Ok(result) -> result
  end
end

test("a forked view: the refused proof is a mismatch, a valid FRK is filed and its landing read") do
  assert(Test.install_in_memory_secure_store())
  assert(run("contradiction", contradiction_proof()))
end

test("two roots for one size prove a fork without the directory; no bounty, no finder") do
  assert(Test.install_in_memory_secure_store())
  assert(run("same size", same_size_proof()))
end

test("an active alarm stops new keys but not a contact already held") do
  assert(Test.install_in_memory_secure_store())
  assert(run("gate", gate_proof()))
end

test("a later consistent check clears a mismatch that was only a refusal") do
  assert(Test.install_in_memory_secure_store())
  assert(run("cleared", cleared_proof()))
end
