import File
from Tests.AnchorSupport import (
  AnchorTrace,
  FakeAccount,
  FakeAnswer,
  FakeProvider,
  account,
  address,
  address_bytes,
  alarm_kind,
  bytes_of,
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
  ring_account,
  ring_entry,
  ring_header,
  rpc_urls,
  signed_checkpoint,
  status_section
)
from Tests.GroupConsistencySupport import ConsistencyAccount, account_fixture
from Tests.Support import repeated
from Transparency.Merkle import TransparencyCheckpoint, leaf_hash

# A phone that looked up itself (ann) and a contact (bea) at a two-leaf
# checkpoint of a log that has since grown to five leaves.

struct World do
  phone :: ConsistencyAccount
  contact :: ConsistencyAccount
  leaves :: List<Bytes>
  public :: TransparencyCheckpoint
end

fn world(label :: String) -> World!String do
  assert(install_anchor_config(true)?)
  let phone = account_fixture(label, "ann")?
  let contact = account_fixture(label <> "-contact", "bea")?
  let leaves = [
    leaf_hash(phone.device_set)?,
    leaf_hash(contact.device_set)?,
    random_leaf()?,
    random_leaf()?,
    random_leaf()?
  ]
  let view = signed_checkpoint(1, List.take(leaves, 2))?
  lookup(phone.path, "ann", phone.device_set, List.take(leaves, 2), 0, 0, view)?
  lookup(phone.path, "bea", contact.device_set, List.take(leaves, 2), 1, 2, view)?
  Ok(World {
    phone: phone,
    contact: contact,
    leaves: leaves,
    public: signed_checkpoint(2, leaves)?
  })
end

fn cleanup(value :: World) -> Result<(), String> do
  File.delete(value.phone.path)?
  File.delete(value.contact.path)?
  Ok(nil)
end

fn witness_data(status :: Int, vault :: Int) -> Bytes!String do
  join([bytes_of([3, 1, 255, status])?, repeated(0, 228)?, address_bytes(vault)?, repeated(0, 72)?])
end

fn token_data(amount :: Int) -> Bytes!String do
  join([address_bytes(205)?, repeated(0, 32)?, le(amount, 8)?])
end

fn token_owner() -> String do
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
end

# The judge's Config (USDC mint only) and the bonds: $50,000 for the directory,
# $10,000 each for witness-a and witness-b, witness-c slashed and emptied.

fn bond_accounts() -> List<FakeAccount>!String do
  let config = join([bytes_of([1, 1])?, repeated(0, 38)?, address_bytes(205)?, repeated(0, 120)?])?
  Ok([
    account(address(206)?, judge()?, config),
    account(address(204)?, token_owner(), token_data(50_000_000_000)?),
    account(address(210)?, judge()?, witness_data(1, 220)?),
    account(address(211)?, judge()?, witness_data(1, 221)?),
    account(address(212)?, judge()?, witness_data(3, 222)?),
    account(address(220)?, token_owner(), token_data(10_000_000_000)?),
    account(address(221)?, token_owner(), token_data(10_000_000_000)?),
    account(address(222)?, token_owner(), token_data(0)?)
  ])
end

fn chain(name :: String,
  slashed :: Bool,
  entry :: TransparencyCheckpoint,
  header_entry :: TransparencyCheckpoint) -> List<FakeAccount>!String do
  Ok([
    log_account(log_data(name, slashed)?)?,
    ring_account(ring_header(name, 1, 1, header_entry, 500)?, [0], [ring_entry(entry, 500, 3, 0)?])?
  ]
    ++ bond_accounts()?)
end

fn honest(accounts :: List<FakeAccount>, age_seconds :: Int) -> List<FakeProvider> do
  for url in rpc_urls() do
    provider(url, accounts, now_seconds() - age_seconds)
  end
end

fn respond(providers :: List<FakeProvider>,
  leaves :: List<Bytes>) -> Fun(Int, String, String, Bytes) -> FakeAnswer do
  fn kind, tag, target, body -> if kind == 1 do
    fake_rpc(providers, target, body)
  else if kind == 2 do
    fake_directory(leaves, false, target, body)
  else if kind == 3 do
    fake_relay(target, body, true)
  else
    FakeAnswer { status: 200, body: finder_address(tag) }
  end end
end

fn replaced(item :: FakeAccount, target :: String, data :: Bytes) -> FakeAccount do
  if item.address == target do
    %{item | data: data}
  else
    item
  end
end

fn with_data(accounts :: List<FakeAccount>, target :: String, data :: Bytes) -> List<FakeAccount> do
  List.map(accounts, fn item -> replaced(item, target, data) end)
end

fn rpc_traces(traces :: List<AnchorTrace>, tag :: String) -> List<AnchorTrace> do
  List.filter(traces, fn trace -> trace.kind == 1 && trace.tag == tag end)
end

fn byte(value :: Bytes, offset :: Int) -> Int do
  case Bytes.get(value, offset) do
    Ok(found) -> found
    Err(_) -> -1
  end
end

fn u64_at(value :: Bytes, offset :: Int) -> Int do
  case Bytes.read_u64_be(value, offset) do
    Ok(wide) -> case U64.to_int(wide) do
      Ok(found) -> found
      Err(_) -> -1
    end
    Err(_) -> -1
  end
end

fn agree_proof() -> Bool!String do
  let value = world("anchor-agree")?
  let providers = honest(chain("morse-main", false, value.public, value.public)?, 40)
  let traces = drive(value.phone.path, respond(providers, value.leaves))?
  assert(outcome(value.phone.path)? == 1)
  assert(alarm_kind(value.phone.path)? == 0)
  # Two random pinned providers, each asked once, and only pinned ones.
  let log_reads = rpc_traces(traces, "log")
  assert(List.length(log_reads) == 2)
  assert(List.get(log_reads, 0).target != List.get(log_reads, 1).target)
  assert(List.all(List.filter(traces, fn trace -> trace.kind == 1 end),
    fn trace -> List.contains(rpc_urls(), trace.target) end))
  # The directory proved the phone's two leaves are a prefix of the anchor's five.
  assert(List.length(List.filter(traces,
    fn trace -> trace.kind == 2 && trace.target == "/v1/transparency/consistency" end)) == 1)
  assert(List.length(List.filter(traces, fn trace -> trace.kind == 3 end)) == 0)
  let check = case status_section(value.phone.path, 2)? do
    Some(body) -> body
    None -> Bytes.empty()
  end
  # The block time of the last anchor (40 seconds before the providers were set up).
  let anchored = u64_at(check, 9) / 1000
  assert(anchored <= now_seconds() - 40 && anchored >= now_seconds() - 100)
  assert(u64_at(check, 17) == 500)
  assert(u64_at(check, 25) == 5)
  cleanup(value)?
  Ok(true)
end

fn bonds_proof() -> Bool!String do
  let value = world("anchor-bonds")?
  let providers = honest(chain("morse-main", false, value.public, value.public)?, 40)
  drive(value.phone.path, respond(providers, value.leaves))?
  let bonds = case status_section(value.phone.path, 3)? do
    Some(body) -> body
    None -> Bytes.empty()
  end
  # available, counted, not slashed, one slashed witness.
  assert(byte(bonds, 0) == 1 && byte(bonds, 1) == 1 && byte(bonds, 2) == 0 && byte(bonds, 3) == 1)
  # The directory's $50,000 in USDC, its USD value known.
  assert(byte(bonds, 4) == 1 && u64_at(bonds, 5) == 50_000_000_000 && byte(bonds, 13) == 1)
  assert(u64_at(bonds, 14) == 50_000_000_000)
  assert(byte(bonds, 22) == 3)
  # Rows: witness-a (Active, $10,000), witness-b, witness-c (Slashed, nothing left).
  let row = 23 + 4 + 9
  assert(byte(bonds, row) == 1
    && byte(bonds, row + 1) == 1
    && u64_at(bonds, row + 2) == 10_000_000_000)
  let last = row + 1 + 18 + 4 + 9 + 1 + 18 + 4 + 9
  assert(byte(bonds, last) == 3 && byte(bonds, last + 1) == 0)
  # Providers that disagree on the vaults make the counter unavailable, never a
  # guess; the check itself is unaffected.
  let base = chain("morse-main", false, value.public, value.public)?
  let disagreeing = for index in 0..3 do
    provider(List.get(rpc_urls(), index),
      with_data(base, address(204)?, token_data(50_000_000_000 + index)?),
      now_seconds())
  end
  drive(value.phone.path, respond(disagreeing, value.leaves))?
  assert(outcome(value.phone.path)? == 1)
  let unavailable = case status_section(value.phone.path, 3)? do
    Some(body) -> body
    None -> Bytes.empty()
  end
  assert(byte(unavailable, 0) == 0)
  cleanup(value)?
  Ok(true)
end

fn canary_proof() -> Bool!String do
  let value = world("anchor-canary")?
  let providers = honest(chain("morse-canary", false, value.public, value.public)?, 40)
  drive(value.phone.path, respond(providers, value.leaves))?
  assert(outcome(value.phone.path)? == 1)
  let bonds = case status_section(value.phone.path, 3)? do
    Some(body) -> body
    None -> Bytes.empty()
  end
  # The canary log is checked but never counted.
  assert(byte(bonds, 1) == 0)
  cleanup(value)?
  Ok(true)
end

fn stale_proof() -> Bool!String do
  let value = world("anchor-stale")?
  let providers = honest(chain("morse-main", false, value.public, value.public)?, 3 * 3600)
  drive(value.phone.path, respond(providers, value.leaves))?
  assert(outcome(value.phone.path)? == 2)
  assert(alarm_kind(value.phone.path)? == 0)
  cleanup(value)?
  Ok(true)
end

fn forged_entry(value :: World) -> TransparencyCheckpoint!String do
  Ok(%{value.public | tree_root: repeated(66, 32)?})
end

fn disagree_proof() -> Bool!String do
  let value = world("anchor-disagree")?
  let other = signed_checkpoint(3, value.leaves)?
  let third = signed_checkpoint(4, value.leaves)?
  let providers = [
    provider("https://rpc-1.test/v1",
      chain("morse-main", false, value.public, value.public)?,
      now_seconds()),
    provider("https://rpc-2.test/v1",
      chain("morse-main", false, value.public, other)?,
      now_seconds()),
    provider("https://rpc-3.test/v1",
      chain("morse-main", false, value.public, third)?,
      now_seconds())
  ]
  let traces = drive(value.phone.path, respond(providers, value.leaves))?
  # Three different ring headers: a warning, never a pass.
  assert(outcome(value.phone.path)? == 3)
  assert(List.length(rpc_traces(traces, "ring")) == 3)
  assert(alarm_kind(value.phone.path)? == 0)
  cleanup(value)?
  Ok(true)
end

fn liar_proof() -> Bool!String do
  let value = world("anchor-liar")?
  let forged = forged_entry(value)?
  # One provider forges the ring entry: the other two outvote it.
  let one = [
    provider("https://rpc-1.test/v1",
      chain("morse-main", false, value.public, value.public)?,
      now_seconds()),
    provider("https://rpc-2.test/v1",
      chain("morse-main", false, forged, value.public)?,
      now_seconds()),
    provider("https://rpc-3.test/v1",
      chain("morse-main", false, value.public, value.public)?,
      now_seconds())
  ]
  drive(value.phone.path, respond(one, value.leaves))?
  assert(outcome(value.phone.path)? == 1)
  assert(alarm_kind(value.phone.path)? == 0)
  # When every provider serves the forgery, the directory's proof cannot
  # connect the phone's view to it: a mismatch, with its evidence kept.
  let all = honest(chain("morse-main", false, forged, value.public)?, 0)
  drive(value.phone.path, respond(all, value.leaves))?
  assert(outcome(value.phone.path)? == 5)
  assert(alarm_kind(value.phone.path)? == 1)
  cleanup(value)?
  Ok(true)
end

fn unavailable_proof() -> Bool!String do
  let value = world("anchor-down")?
  let providers = List.map(honest(chain("morse-main", false, value.public, value.public)?, 0),
    fn value -> %{value | up: false} end)
  drive(value.phone.path, respond(providers, value.leaves))?
  assert(outcome(value.phone.path)? == 4)
  assert(alarm_kind(value.phone.path)? == 0)
  cleanup(value)?
  Ok(true)
end

fn slashed_proof() -> Bool!String do
  let value = world("anchor-slashed")?
  let providers = honest(chain("morse-main", true, value.public, value.public)?, 0)
  drive(value.phone.path, respond(providers, value.leaves))?
  assert(outcome(value.phone.path)? == 6)
  assert(alarm_kind(value.phone.path)? == 2)
  # The slashed key is refused for new lookups; a contact already verified
  # still refreshes, so existing chats keep working.
  let stranger = account_fixture("anchor-slashed-stranger", "cyd")?
  let grown = List.take(value.leaves, 2) ++ [leaf_hash(stranger.device_set)?]
  let next = signed_checkpoint(2, grown)?
  case lookup(value.phone.path, "cyd", stranger.device_set, grown, 2, 2, next) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "trust_alarm_active")
  end
  assert(Bytes.secure_equals(lookup(value.phone.path,
      "bea",
      value.contact.device_set,
      grown,
      1,
      2,
      next)?,
    value.contact.device_set))
  File.delete(stranger.path)?
  cleanup(value)?
  Ok(true)
end

fn off_proof() -> Bool!String do
  let value = world("anchor-off")?
  assert(install_anchor_config(false)?)
  let traces = drive(value.phone.path, respond(List.new(), value.leaves))?
  assert(List.length(traces) == 0)
  assert(outcome(value.phone.path)? == 7)
  cleanup(value)?
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

test("agreeing providers: the check passes and records the last public checkpoint") do
  assert(Test.install_in_memory_secure_store())
  assert(run("agree", agree_proof()))
end

test("the bond counter reads morse-main's bonds and slashes from the chain") do
  assert(Test.install_in_memory_secure_store())
  assert(run("bonds", bonds_proof()))
end

test("the canary log is checked but never counted") do
  assert(Test.install_in_memory_secure_store())
  assert(run("canary", canary_proof()))
end

test("a public record older than two hours is stale and blocks nothing") do
  assert(Test.install_in_memory_secure_store())
  assert(run("stale", stale_proof()))
end

test("providers that disagree give rpc_disagree, never a pass") do
  assert(Test.install_in_memory_secure_store())
  assert(run("disagree", disagree_proof()))
end

test("a lying provider is outvoted; a forged record every provider serves is a mismatch") do
  assert(Test.install_in_memory_secure_store())
  assert(run("liar", liar_proof()))
end

test("no provider answering is rpc_unavailable") do
  assert(Test.install_in_memory_secure_store())
  assert(run("unavailable", unavailable_proof()))
end

test("a slashed service key is refused for new lookups") do
  assert(Test.install_in_memory_secure_store())
  assert(run("slashed", slashed_proof()))
end

test("without an anchor the check is off and reads nothing") do
  assert(Test.install_in_memory_secure_store())
  assert(run("off", off_proof()))
end
