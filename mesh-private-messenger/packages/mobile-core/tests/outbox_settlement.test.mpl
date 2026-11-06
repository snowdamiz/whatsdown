from Storage.OutboxSettlement import OutboxSettlementSnapshot, commit_outbox_settlement
from Storage.Blobs import ensure_schema, load_blob
from Storage.Records import store_blobs, store_updated_blobs, erase_local_state
from Tests.Support import database_path

fn fixture() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("outbox_settlement")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed profile")
  let index = Bytes.from_utf8("sealed original index")
  let delivery = Bytes.from_utf8("sealed original delivery links")
  let envelope = Bytes.from_utf8("sealed original envelope")
  let newer = Bytes.from_utf8("sealed index with another newly queued envelope")
  let next = Bytes.from_utf8("sealed remaining index")
  let changed = Bytes.from_utf8("sealed accepted delivery")
  let row = "outbox-envelope/v1/01010101010101010101010101010101"
  store_blobs(path,
    ["profile/v1", "outbox/v1", "delivery/v1", row],
    [profile, index, delivery, envelope])?
  let before = OutboxSettlementSnapshot {
    profile: profile,
    index: index,
    postage: Bytes.empty(),
    delivery: delivery,
    guarded_labels: [row],
    guarded_blobs: [envelope]
  }
  store_updated_blobs(path, ["outbox/v1"], [newer])?
  assert(Result.is_err(commit_outbox_settlement(path,
    before,
    next,
    ["delivery/v1"],
    [changed],
    [row])))
  assert(Bytes.secure_equals(load_blob(path, "outbox/v1")?, newer))
  assert(Bytes.secure_equals(load_blob(path, "delivery/v1")?, delivery))
  assert(Bytes.secure_equals(load_blob(path, row)?, envelope))
  store_updated_blobs(path, ["outbox/v1"], [index])?
  store_blobs(path, ["postage-queue/v1"], [Bytes.from_utf8("sealed kind8 ownership")])?
  assert(Result.is_err(commit_outbox_settlement(path,
    before,
    next,
    ["delivery/v1"],
    [changed],
    [row])))
  assert(Bytes.secure_equals(load_blob(path, row)?, envelope))
  erase_local_state(path)?
  assert(Result.is_err(commit_outbox_settlement(path,
    before,
    next,
    ["delivery/v1"],
    [changed],
    [row])))
  assert(Result.is_err(load_blob(path, "outbox/v1")))
  store_blobs(path,
    ["profile/v1", "outbox/v1", "delivery/v1", row],
    [Bytes.from_utf8("sealed replacement profile"), index, delivery, envelope])?
  assert(Result.is_err(commit_outbox_settlement(path,
    before,
    next,
    ["delivery/v1"],
    [changed],
    [row])))
  assert(Bytes.secure_equals(load_blob(path, row)?, envelope))
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("outbox settlement cannot overwrite appended mail, newly paid ownership or replacement custody") do
  case fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

from Storage.OutboxGuard import OutboxBasis, PreparedOutboxIndex
from Storage.Records import store_outbound

fn enqueue_fixture() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("outbox_enqueue")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed custody")
  let index = Bytes.from_utf8("sealed index before acknowledgement")
  let delivery = Bytes.from_utf8("sealed links before acknowledgement")
  let newer = Bytes.from_utf8("sealed index after acknowledgement")
  let original_sessions = Bytes.from_utf8("sealed sessions before stale send")
  store_blobs(path,
    ["profile/v1", "outbox/v1", "delivery/v1", "sessions/v1"],
    [profile, index, delivery, original_sessions])?
  let prepared = PreparedOutboxIndex {
    value: Bytes.from_utf8("sealed stale send's replacement index"),
    before: OutboxBasis {
      profile: profile,
      index: index,
      postage: Bytes.empty(),
      delivery: delivery
    }
  }
  store_updated_blobs(path, ["outbox/v1"], [newer])?
  assert(Result.is_err(store_outbound(path,
    [],
    [],
    Bytes.from_utf8("stale sessions"),
    [],
    [],
    ["outbox-envelope/v1/new"],
    [Bytes.from_utf8("new sealed envelope")],
    prepared)))
  assert(Bytes.secure_equals(load_blob(path, "outbox/v1")?, newer))
  assert(Bytes.secure_equals(load_blob(path, "sessions/v1")?, original_sessions))
  assert(Result.is_err(load_blob(path, "outbox-envelope/v1/new")))
  let current = %{prepared | before: %{prepared.before | index: newer}}
  store_outbound(path,
    [],
    [],
    Bytes.from_utf8("fresh sessions"),
    [],
    [],
    ["outbox-envelope/v1/new"],
    [Bytes.from_utf8("new sealed envelope")],
    current)?
  assert(Bytes.secure_equals(load_blob(path, "outbox/v1")?, prepared.value))
  assert(Bytes.secure_equals(load_blob(path, "sessions/v1")?, Bytes.from_utf8("fresh sessions")))
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("a stale send cannot restore an acknowledged index or partially advance sessions") do
  case enqueue_fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

from Storage.Credits import (
  CreditWalletIdentity,
  CreditCacheWrite,
  load_credit_wallet,
  commit_credit_wallet_with_cache
)
from Storage.Keys import platform_key
from Mobile.CreditState import CreditWallet, CreditRecord
from Mobile.PostageQueue import postage_outbox_guards
from Tests.Support import repeated

fn postage_fixture() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("postage_free_settlement")?
  let who = CreditWalletIdentity {
    account_id: repeated(11, 32)?,
    device_id: repeated(12, 16)?,
    service_key: repeated(13, 32)?,
    purpose: 1
  }
  let first = load_credit_wallet(path, key, who)?
  let profile = Bytes.from_utf8("sealed profile")
  let index = Bytes.from_utf8("sealed fanout index")
  let delivery = Bytes.from_utf8("sealed fanout delivery links")
  store_blobs(path, ["profile/v1", "outbox/v1", "delivery/v1"], [profile, index, delivery])?
  let guards = postage_outbox_guards(path)?
  let queue = CreditCacheWrite {
    label: "postage-queue/v1",
    previous: Bytes.empty(),
    value: Bytes.from_utf8("sealed kind8 queue ownership")
  }
  let wallet = CreditWallet {
    revision: U64.parse("1")?,
    records: [
      CreditRecord {
        kind: 8,
        id: repeated(21, 32)?,
        metadata: Bytes.from_utf8("test-only opaque intent"),
        payload: Bytes.from_utf8("test-only sealed intent")
      }
    ]
  }
  # The free sender commits after the paid fanout was read, before ownership CAS.
  store_updated_blobs(path, ["outbox/v1"], [Bytes.from_utf8("sealed settled index")])?
  assert(Result.is_err(commit_credit_wallet_with_cache(path,
    key,
    who,
    first,
    wallet,
    [queue] ++ guards)))
  assert(load_credit_wallet(path, key, who)?.wallet.revision == U64.parse("0")?)
  assert(Result.is_err(load_blob(path, "postage-queue/v1")))
  store_updated_blobs(path, ["outbox/v1"], [index])?
  store_updated_blobs(path, ["delivery/v1"], [Bytes.from_utf8("sealed changed fanout links")])?
  assert(Result.is_err(commit_credit_wallet_with_cache(path,
    key,
    who,
    first,
    wallet,
    [queue] ++ guards)))
  assert(load_credit_wallet(path, key, who)?.wallet.revision == U64.parse("0")?)
  store_updated_blobs(path, ["delivery/v1"], [delivery])?
  commit_credit_wallet_with_cache(path, key, who, first, wallet, [queue] ++ guards)?
  assert(load_credit_wallet(path, key, who)?.wallet.revision == U64.parse("1")?)
  assert(Bytes.secure_equals(load_blob(path, "outbox/v1")?, index))
  assert(Bytes.secure_equals(load_blob(path, "delivery/v1")?, delivery))
  assert(Bytes.secure_equals(load_blob(path, "postage-queue/v1")?, queue.value))
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("paid postage cannot take stale fanout ownership after free settlement") do
  case postage_fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn await_file(path :: String, attempts :: Int) -> Bool do
  if File.exists(path) do
    case File.read(path) do
      Ok(value) -> if String.length(value) > 0 do
        return true
      end
      Err(_) -> nil
    end
  end
  if attempts == 0 do
    false
  else
    Timer.sleep(5)
    await_file(path, attempts - 1)
  end
end

actor contender(path :: String, before :: OutboxSettlementSnapshot, index :: Int) do
  let name = path <> ".#{index}"
  File.write(name <> ".ready", "ready")
  if await_file(path <> ".go", 1000) do
    let value = Bytes.from_utf8("sealed consistent settlement #{index}")
    let committed = commit_outbox_settlement(path, before, value, ["delivery/v1"], [value], [])
    File.write(name <> ".done",
      case committed do
        Ok(_) -> "ok"
        Err(error) -> error
      end)
  end
end

fn concurrent_fixture() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("outbox_ack_race")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed original custody")
  let index = Bytes.from_utf8("sealed original index")
  let delivery = Bytes.from_utf8("sealed original delivery")
  let envelope = Bytes.from_utf8("sealed original envelope")
  let row = "outbox-envelope/v1/original"
  store_blobs(path,
    ["profile/v1", "outbox/v1", "delivery/v1", row],
    [profile, index, delivery, envelope])?
  let before = OutboxSettlementSnapshot {
    profile: profile,
    index: index,
    postage: Bytes.empty(),
    delivery: delivery,
    guarded_labels: [row],
    guarded_blobs: [envelope]
  }
  for index in 0..8 do
    let _worker = spawn(contender, path, before, index)
    nil
  end
  for index in 0..8 do
    assert(await_file(path <> ".#{index}.ready", 1000))
  end
  File.write(path <> ".go", "go")?
  let results = for index in 0..8 do
    let name = path <> ".#{index}"
    assert(await_file(name <> ".done", 1000))
    let value = File.read(name <> ".done")?
    File.delete(name <> ".ready")?
    File.delete(name <> ".done")?
    value
  end
  assert(List.length(List.filter(results, fn(value) -> value == "ok" end)) == 1)
  assert(List.all(results, fn(value) -> value == "ok" || value == "outbox_state_changed" end))
  let winner = load_blob(path, "outbox/v1")?
  assert(Bytes.secure_equals(winner, load_blob(path, "delivery/v1")?))
  assert(Bytes.secure_equals(load_blob(path, row)?, envelope))
  # A fresh exact basis may remove the final frame and update delivery atomically.
  commit_outbox_settlement(path,
    %{before | index: winner, delivery: winner},
    Bytes.empty(),
    ["delivery/v1"],
    [Bytes.from_utf8("sealed final delivery")],
    [row])?
  assert(Result.is_err(load_blob(path, "outbox/v1")))
  assert(Result.is_err(load_blob(path, row)))
  assert(Bytes.secure_equals(load_blob(path, "delivery/v1")?,
    Bytes.from_utf8("sealed final delivery")))
  File.delete(path <> ".go")?
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("eight stale outbox settlers commit one consistent bundle and a fresh final acknowledgement succeeds") do
  case concurrent_fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

from Mobile.ContactAddress import (
  learned_contact_address_writes,
  refused_address_snapshot,
  deposit_address
)
from Protocol.V1 import ProtocolExtension
from Storage.Records import store_record_changes

fn alias_fixture() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("outbox_alias_rotation")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed current custody")
  let index = Bytes.from_utf8("sealed current outbox")
  store_blobs(path, ["profile/v1", "outbox/v1"], [profile, index])?
  let public = repeated(31, 32)?
  let old_alias = repeated(32, 32)?
  let new_alias = repeated(33, 32)?
  let (labels, blobs, removed) = learned_contact_address_writes(path,
    key,
    public,
    [ProtocolExtension { id: 1, mandatory: false, value: old_alias }])?
  store_record_changes(path, labels, blobs, removed)?
  let stale = refused_address_snapshot(path, key, old_alias)?
  assert(List.length(stale.labels) == 2)
  let (next_labels, next_blobs, next_removed) = learned_contact_address_writes(path,
    key,
    public,
    [ProtocolExtension { id: 1, mandatory: false, value: new_alias }])?
  store_record_changes(path, next_labels, next_blobs, next_removed)?
  let before = OutboxSettlementSnapshot {
    profile: profile,
    index: index,
    postage: Bytes.empty(),
    delivery: Bytes.empty(),
    guarded_labels: stale.labels,
    guarded_blobs: stale.previous
  }
  assert(Result.is_err(commit_outbox_settlement(path, before, Bytes.empty(), [], [], stale.labels)))
  assert(Bytes.secure_equals(deposit_address(path, key, public)?, new_alias))
  assert(List.length(refused_address_snapshot(path, key, old_alias)?.labels) == 0)
  let current = refused_address_snapshot(path, key, new_alias)?
  commit_outbox_settlement(path,
    %{before | guarded_labels: current.labels, guarded_blobs: current.previous},
    Bytes.empty(),
    [],
    [],
    current.labels)?
  assert(Bytes.secure_equals(deposit_address(path, key, public)?, public))
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("late refusal of a rotated contact alias cannot remove the new deposit address") do
  case alias_fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
