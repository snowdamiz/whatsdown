from Binary.Reader import BinaryReader, reader
from Credits.CreditFrames import credits_attach
from Credits.CreditToken import credits_decode_token
from Credits.MailboxExtras import MailboxPolicy, credits_encode_policy, credits_verify_policy
from Credits.IssuerKey import (
  IssuerKey,
  credits_decode_issuer_key,
  credits_encode_issuer_key,
  credits_key_valid_at
)
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.Records import store_record_changes
from Protocol.V1 import DeviceCredential, DirectoryEntry
from Transport.Packet import ClientProfile
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_u16,
  tcodec_take_u32,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u16,
  tcodec_u32,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)

##! Mobile.CreditsStore: this device's credits (protocol/credits-v1.md
##! "Client"), sealed under the storage key like everything else it keeps.
##!
##! - "credits/v1/keys" (CKS): the issuer keys this device accepted from the
##!   transparency log, and when it last fetched them.
##! - "credits/v1/shelves" (CSH): an index of shelves. A shelf holds up to 150
##!   tokens of one key that became spendable at one time (a purchase's tokens,
##!   10 minutes after it was issued), and says whether they are suspect: back
##!   from a request whose answer did not say whether they were spent.
##! - "credits/v1/shelf/<id>" (CTK): a shelf's tokens.
##! - "credits/v1/reservations" (CRI) and "credits/v1/reservation/<hex>" (CRS):
##!   tokens taken for one request, kept until its answer says what became of
##!   them. A retry of the same request (same purpose) sends the same tokens,
##!   so tokens only ever share a fate with the tokens they were sent with.
##!
##! Tokens are chosen at random from every spendable token, so the order a
##! device spends them in says nothing about when it bought them.

pub struct CreditShelf do
  id :: Int
  count :: Int
  key_id :: Bytes
  available_at :: Int
  suspect :: Bool
end

pub struct CreditShelves do
  next_id :: Int
  shelves :: List<CreditShelf>
end

pub struct CreditHeld do
  token :: Bytes
  suspect :: Bool
end

pub struct CreditReservation do
  id :: Bytes
  purpose :: Bytes
  action :: Int
  attempts :: Int
  created_at :: Int
  held :: List<CreditHeld>
end

## `keys`: listed now, and spent. `retired`: listed before and gone from the
## listing inside their window (revoked, or a listing that left them out):
## their tokens are kept, unspent, until the window ends or they come back.

pub struct CreditKeys do
  fetched_at :: Int
  keys :: List<IssuerKey>
  retired :: List<IssuerKey>
end

## Labels, blobs and removed labels for one transaction.

pub struct CreditWrites do
  labels :: List<String>
  blobs :: List<Bytes>
  removed :: List<String>
end

struct TakenShelf do
  state :: BinaryReader
  value :: CreditShelf
end

pub fn credits_shelf_capacity() -> Int do
  150
end

## Spending waits this long after a purchase (plan §6.10).

pub fn credits_cooldown_ms() -> Int do
  600000
end

## A request with no answer for this long gave its tokens back (as suspect).

pub fn credits_pending_ms() -> Int do
  3600000
end

# Mobile.Codec's helpers, here because a module cannot import both it and
# Transparency.Codec (their last segments collide).

pub fn credits_random(length :: Int) -> Bytes!String do
  case Crypto.random_bytes(length) do
    Err(_) -> Err("random_generation_failed")
    Ok(value)
  end
end

pub fn credits_zeroes(length :: Int) -> Bytes!String do
  case Bytes.repeat(0, length) do
    Err(_) -> Err("credits_allocation_failed")
    Ok(value)
  end
end

pub fn credits_clock() -> U64!String do
  case U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()))) do
    Err(_) -> Err("invalid_wide_integer")
    Ok(value)
  end
end

pub fn credits_no_writes() -> CreditWrites do
  CreditWrites { labels: List.new(), blobs: List.new(), removed: List.new() }
end

pub fn credits_merge_writes(left :: CreditWrites, right :: CreditWrites) -> CreditWrites do
  CreditWrites {
    labels: left.labels ++ right.labels,
    blobs: left.blobs ++ right.blobs,
    removed: left.removed ++ right.removed
  }
end

fn flag(value :: Bool) -> Bytes!String do
  tcodec_u8(if value do
    1
  else
    0
  end)
end

pub fn credits_load_sealed(database_path :: String,
  wrapping_key :: borrow StorageKey,
  label :: String) -> Bytes!String do
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_local(blob, wrapping_key, local_context(label)?)
  end
end

pub fn credits_sealed_write(label :: String,
  value :: Bytes,
  wrapping_key :: borrow StorageKey) -> CreditWrites!String do
  Ok(CreditWrites {
    labels: [label],
    blobs: [seal_local(value, wrapping_key, local_context(label)?)?],
    removed: List.new()
  })
end

## This device's signed price for message requests (MBP), if it set one.

pub fn credits_inbox_label() -> String do
  "credits/v1/inbox"
end

pub fn credits_postage_label(mailbox_token :: Bytes) -> String do
  "credits/v1/postage/#{Bytes.to_hex(Crypto.sha256(mailbox_token))}"
end

## Remembers the price a device asks, from a prekey claim answer (PKC): its
## signing key and signed policy when the policy verifies, else nothing.

pub fn credits_note_policy(path :: String,
  profile :: ClientProfile,
  policy :: Option<MailboxPolicy>) -> Result<(), String> do
  let wrapping_key = platform_key()?
  let label = credits_postage_label(profile.entry.mailbox_token)
  let valid = case policy do
    None
    Some(value) -> if Bytes.secure_equals(value.mailbox_hash,
      Crypto.sha256(profile.entry.mailbox_token))
      && credits_verify_policy(value, profile.credential.signing_public_key) do
      Some(value)
    else
      None
    end
  end
  case valid do
    None -> store_record_changes(path, List.new(), List.new(), [label])
    Some(value) -> do
      let record = tcodec_join([
        profile.credential.signing_public_key,
        credits_encode_policy(value)?
      ])?
      store_record_changes(path,
        [label],
        [seal_local(record, wrapping_key, local_context(label)?)?],
        List.new())
    end
  end
end

# Issuer keys.

fn keys_label() -> String do
  "credits/v1/keys"
end

fn encode_key_list(keys :: List<IssuerKey>) -> Bytes!String do
  let entries = for key in keys do
    tcodec_vector(credits_encode_issuer_key(key)?)?
  end
  tcodec_join([tcodec_u8(List.length(keys))?] ++ entries)
end

pub fn credits_encode_keys(value :: CreditKeys) -> Bytes!String do
  tcodec_join([
    tcodec_u8(1)?,
    Bytes.from_utf8("CKS"),
    tcodec_u64(value.fetched_at)?,
    encode_key_list(value.keys)?,
    encode_key_list(value.retired)?
  ])
end

fn take_keys(state :: BinaryReader,
  count :: Int,
  output :: List<IssuerKey>) -> (BinaryReader, List<IssuerKey>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let entry = tcodec_take_vector(state, 1024)?
    take_keys(entry.state, count, List.append(output, credits_decode_issuer_key(entry.value)?))
  end
end

pub fn credits_load_keys(database_path :: String,
  wrapping_key :: borrow StorageKey) -> CreditKeys!String do
  let encoded = credits_load_sealed(database_path, wrapping_key, keys_label())?
  if Bytes.length(encoded) == 0 do
    Ok(CreditKeys { fetched_at: 0, keys: List.new(), retired: List.new() })
  else
    let state = tcodec_start(encoded, 65536, 1, "CKS")?
    let fetched = tcodec_take_u64(state)?
    let count = tcodec_take_u8(fetched.state)?
    let (after_keys, keys) = take_keys(count.state, count.value, List.new())?
    let retired_count = tcodec_take_u8(after_keys)?
    let (rest, retired) = take_keys(retired_count.state, retired_count.value, List.new())?
    tcodec_done(rest)?
    Ok(CreditKeys { fetched_at: fetched.value, keys: keys, retired: retired })
  end
end

pub fn credits_keys_write(value :: CreditKeys,
  wrapping_key :: borrow StorageKey) -> CreditWrites!String do
  credits_sealed_write(keys_label(), credits_encode_keys(value)?, wrapping_key)
end

pub fn credits_key_id(key :: IssuerKey) -> Bytes do
  Crypto.sha256(key.spki)
end

## The accepted key with this ID, if any.

pub fn credits_find_key(keys :: List<IssuerKey>, key_id :: Bytes) -> Option<IssuerKey> do
  List.find(keys, fn key -> Bytes.secure_equals(credits_key_id(key), key_id) end)
end

fn spendable_key(keys :: List<IssuerKey>, key_id :: Bytes, now :: Int) -> Bool do
  case credits_find_key(keys, key_id) do
    Some(key) -> credits_key_valid_at(key, now)
    None -> false
  end
end

# Shelves.

fn shelves_label() -> String do
  "credits/v1/shelves"
end

fn shelf_label(id :: Int) -> String do
  "credits/v1/shelf/#{Int.to_string(id)}"
end

fn encode_shelves(value :: CreditShelves) -> Bytes!String do
  let rows = for shelf in value.shelves do
    tcodec_join([
      tcodec_u32(shelf.id)?,
      tcodec_u16(shelf.count)?,
      shelf.key_id,
      tcodec_u64(shelf.available_at)?,
      flag(shelf.suspect)?
    ])?
  end
  tcodec_join([
    tcodec_u8(1)?,
    Bytes.from_utf8("CSH"),
    tcodec_u32(value.next_id)?,
    tcodec_u32(List.length(value.shelves))?
  ]
    ++ rows)
end

fn take_shelf(state :: BinaryReader) -> TakenShelf!String do
  let id = tcodec_take_u32(state)?
  let count = tcodec_take_u16(id.state)?
  let key_id = tcodec_take_fixed(count.state, 32)?
  let available = tcodec_take_u64(key_id.state)?
  let suspect = tcodec_take_u8(available.state)?
  Ok(TakenShelf {
    state: suspect.state,
    value: CreditShelf {
      id: id.value,
      count: count.value,
      key_id: key_id.value,
      available_at: available.value,
      suspect: suspect.value == 1
    }
  })
end

fn take_shelves(state :: BinaryReader,
  count :: Int,
  output :: List<CreditShelf>) -> (BinaryReader, List<CreditShelf>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let shelf = take_shelf(state)?
    take_shelves(shelf.state, count, List.append(output, shelf.value))
  end
end

pub fn credits_load_shelves(database_path :: String,
  wrapping_key :: borrow StorageKey) -> CreditShelves!String do
  let encoded = credits_load_sealed(database_path, wrapping_key, shelves_label())?
  if Bytes.length(encoded) == 0 do
    Ok(CreditShelves { next_id: 1, shelves: List.new() })
  else
    let state = tcodec_start(encoded, 65536, 1, "CSH")?
    let next = tcodec_take_u32(state)?
    let count = tcodec_take_u32(next.state)?
    let (rest, shelves) = take_shelves(count.state, count.value, List.new())?
    tcodec_done(rest)?
    Ok(CreditShelves { next_id: next.value, shelves: shelves })
  end
end

fn encode_tokens(tokens :: List<Bytes>) -> Bytes!String do
  tcodec_join([tcodec_u8(1)?, Bytes.from_utf8("CTK"), tcodec_u16(List.length(tokens))?] ++ tokens)
end

fn take_tokens(state :: BinaryReader,
  count :: Int,
  output :: List<Bytes>) -> (BinaryReader, List<Bytes>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let token = tcodec_take_fixed(state, 354)?
    take_tokens(token.state, count, List.append(output, token.value))
  end
end

fn load_shelf(database_path :: String,
  wrapping_key :: borrow StorageKey,
  id :: Int) -> List<Bytes>!String do
  let encoded = credits_load_sealed(database_path, wrapping_key, shelf_label(id))?
  let state = tcodec_start(encoded, 65536, 1, "CTK")?
  let count = tcodec_take_u16(state)?
  let (rest, tokens) = take_tokens(count.state, count.value, List.new())?
  tcodec_done(rest)?
  Ok(tokens)
end

pub fn credits_shelves_write(value :: CreditShelves,
  wrapping_key :: borrow StorageKey) -> CreditWrites!String do
  credits_sealed_write(shelves_label(), encode_shelves(value)?, wrapping_key)
end

fn shelve_from(tokens :: List<Bytes>,
  key_id :: Bytes,
  available_at :: Int,
  suspect :: Bool,
  shelves :: CreditShelves,
  writes :: CreditWrites,
  wrapping_key :: borrow StorageKey) -> (CreditShelves, CreditWrites)!String do
  if List.length(tokens) == 0 do
    Ok((shelves, writes))
  else
    let part = List.take(tokens, credits_shelf_capacity())
    let id = shelves.next_id
    let shelf = CreditShelf {
      id: id,
      count: List.length(part),
      key_id: key_id,
      available_at: available_at,
      suspect: suspect
    }
    let written = credits_sealed_write(shelf_label(id), encode_tokens(part)?, wrapping_key)?
    shelve_from(List.drop(tokens, credits_shelf_capacity()),
      key_id,
      available_at,
      suspect,
      CreditShelves { next_id: id + 1, shelves: List.append(shelves.shelves, shelf) },
      credits_merge_writes(writes, written),
      wrapping_key)
  end
end

## New shelves for tokens of one key; the caller writes the index.

pub fn credits_shelve(tokens :: List<Bytes>,
  key_id :: Bytes,
  available_at :: Int,
  suspect :: Bool,
  shelves :: CreditShelves,
  wrapping_key :: borrow StorageKey) -> (CreditShelves, CreditWrites)!String do
  shelve_from(tokens, key_id, available_at, suspect, shelves, credits_no_writes(), wrapping_key)
end

fn token_key_id(token :: Bytes) -> Bytes!String do
  Ok(credits_decode_token(token)?.token_key_id)
end

fn held_by_key(held :: List<CreditHeld>, suspect :: Bool) -> List<(Bytes, List<Bytes>)>!String do
  let keyed = for value in held when value.suspect == suspect do
    (token_key_id(value.token)?, value.token)
  end
  let ids = List.reduce(keyed,
    List.new(),
    fn found, pair -> case pair do
      (id, _) -> if List.any(found, fn known -> Bytes.secure_equals(known, id) end) do
        found
      else
        List.append(found, id)
      end
    end end)
  Ok(for id in ids do
    (id,
      for (key, token) in keyed when Bytes.secure_equals(key, id) do
        token
      end)
  end)
end

fn shelve_groups(groups :: List<(Bytes, List<Bytes>)>,
  suspect :: Bool,
  shelves :: CreditShelves,
  writes :: CreditWrites,
  wrapping_key :: borrow StorageKey) -> (CreditShelves, CreditWrites)!String do
  case groups do
    [] -> Ok((shelves, writes))
    head :: tail -> do
      let (id, tokens) = head
      let (next, written) = credits_shelve(tokens, id, 0, suspect, shelves, wrapping_key)?
      shelve_groups(tail, suspect, next, credits_merge_writes(writes, written), wrapping_key)
    end
  end
end

## Puts held tokens back on shelves, spendable now; `suspect` marks them all.

pub fn credits_return(held :: List<CreditHeld>,
  mark_suspect :: Bool,
  shelves :: CreditShelves,
  wrapping_key :: borrow StorageKey) -> (CreditShelves, CreditWrites)!String do
  let marked = for value in held do
    CreditHeld { token: value.token, suspect: value.suspect || mark_suspect }
  end
  let (after_clean, clean_writes) = shelve_groups(held_by_key(marked, false)?,
    false,
    shelves,
    credits_no_writes(),
    wrapping_key)?
  let (after_suspect, suspect_writes) = shelve_groups(held_by_key(marked, true)?,
    true,
    after_clean,
    credits_no_writes(),
    wrapping_key)?
  Ok((after_suspect, credits_merge_writes(clean_writes, suspect_writes)))
end

## Shelves whose key is neither listed nor retired, or whose window ended, go
## with their tokens. `keys` is both lists. Returns the kept shelves and the
## removed labels.

pub fn credits_prune_shelves(shelves :: CreditShelves,
  keys :: List<IssuerKey>,
  now :: Int) -> (CreditShelves, CreditWrites) do
  let kept = List.filter(shelves.shelves, fn shelf -> spendable_key(keys, shelf.key_id, now) end)
  let gone = List.filter(shelves.shelves, fn shelf -> !spendable_key(keys, shelf.key_id, now) end)
  (CreditShelves { next_id: shelves.next_id, shelves: kept },
    CreditWrites {
      labels: List.new(),
      blobs: List.new(),
      removed: for shelf in gone do
        shelf_label(shelf.id)
      end
    })
end

## Balance counts: (spendable now, cooling down, earliest end of a cool-down).

pub fn credits_counts(shelves :: CreditShelves,
  keys :: List<IssuerKey>,
  now :: Int) -> (Int, Int, Int) do
  let valid = List.filter(shelves.shelves, fn shelf -> spendable_key(keys, shelf.key_id, now) end)
  let ready = List.filter(valid, fn shelf -> shelf.available_at <= now end)
  let cooling = List.filter(valid, fn shelf -> shelf.available_at > now end)
  let soonest = List.reduce(cooling,
    0,
    fn(found, shelf) do
      if found == 0 || shelf.available_at < found do
        shelf.available_at
      else
        found
      end
    end)
  (List.reduce(ready, 0, fn(total, shelf) do total + shelf.count end),
    List.reduce(cooling, 0, fn(total, shelf) do total + shelf.count end),
    soonest)
end

## Tokens that stop counting soonest: (how many, when their key's window ends).

pub fn credits_expiring(shelves :: CreditShelves,
  keys :: List<IssuerKey>,
  now :: Int) -> (Int, Int) do
  let windows = for shelf in shelves.shelves when spendable_key(keys, shelf.key_id, now) do
    case credits_find_key(keys, shelf.key_id) do
      Some(key) -> (key.not_after, shelf.count)
      None -> (0, 0)
    end
  end
  let first = List.reduce(windows,
    0,
    fn found, pair -> case pair do
      (ends, _) -> if found == 0 || ends < found do
        ends
      else
        found
      end
    end end)
  let count = List.reduce(windows,
    0,
    fn sum, pair -> case pair do
      (ends, tokens) -> if ends == first do
        sum + tokens
      else
        sum
      end
    end end)
  (count, first)
end

# Random choice.

fn random_below(limit :: Int) -> Int!String do
  case Bytes.read_u32_be(credits_random(4)?, 0) do
    Err(_) -> Err("random_generation_failed")
    Ok(value) -> case U64.to_int(value) do
      Err(_) -> Err("random_generation_failed")
      # 32 random bits: the bias against limits of a few thousand is negligible.
      Ok(output) -> Ok(output % limit)
    end
  end
end

# Which shelf position `index` (over the listed shelves, minus what is already
# taken from each) falls on.

fn shelf_at(shelves :: List<CreditShelf>,
  taken :: List<Int>,
  index :: Int,
  position :: Int) -> Int do
  let left = List.get(shelves, position).count - List.get(taken, position)
  if index < left || position + 1 >= List.length(shelves) do
    position
  else
    shelf_at(shelves, taken, index - left, position + 1)
  end
end

fn increment(values :: List<Int>, position :: Int) -> List<Int> do
  for index in 0..List.length(values) do
    if index == position do
      List.get(values, index) + 1
    else
      List.get(values, index)
    end
  end
end

fn draw(shelves :: List<CreditShelf>,
  taken :: List<Int>,
  remaining :: Int,
  count :: Int) -> List<Int>!String do
  if count <= 0 do
    Ok(taken)
  else
    let position = shelf_at(shelves, taken, random_below(remaining)?, 0)
    draw(shelves, increment(taken, position), remaining - 1, count - 1)
  end
end

fn total(shelves :: List<CreditShelf>) -> Int do
  List.reduce(shelves, 0, fn(sum, shelf) do sum + shelf.count end)
end

## How many tokens to take from each of `shelves`, uniformly at random over
## every token on them.

pub fn credits_draw(shelves :: List<CreditShelf>, count :: Int) -> List<Int>!String do
  let zeros = for _shelf in shelves do
    0
  end
  if count > total(shelves) do
    Err("credits_insufficient")
  else
    draw(shelves, zeros, total(shelves), count)
  end
end

fn take_from(database_path :: String,
  wrapping_key :: borrow StorageKey,
  shelves :: List<CreditShelf>,
  counts :: List<Int>,
  index :: Int,
  held :: List<CreditHeld>,
  kept :: List<CreditShelf>,
  writes :: CreditWrites) -> (List<CreditHeld>, List<CreditShelf>, CreditWrites)!String do
  if index >= List.length(shelves) do
    Ok((held, kept, writes))
  else
    let shelf = List.get(shelves, index)
    let count = List.get(counts, index)
    if count == 0 do
      take_from(database_path,
        wrapping_key,
        shelves,
        counts,
        index + 1,
        held,
        List.append(kept, shelf),
        writes)
    else
      let tokens = load_shelf(database_path, wrapping_key, shelf.id)?
      if List.length(tokens) != shelf.count do
        Err("invalid_credit_store")
      else
        let taken = for token in List.take(tokens, count) do
          CreditHeld { token: token, suspect: shelf.suspect }
        end
        let rest = List.drop(tokens, count)
        let (next_kept, written) = if List.length(rest) == 0 do
          (kept,
            CreditWrites {
              labels: List.new(),
              blobs: List.new(),
              removed: [shelf_label(shelf.id)]
            })
        else
          (List.append(kept, %{shelf | count: List.length(rest)}),
            credits_sealed_write(shelf_label(shelf.id), encode_tokens(rest)?, wrapping_key)?)
        end
        take_from(database_path,
          wrapping_key,
          shelves,
          counts,
          index + 1,
          held ++ taken,
          next_kept,
          credits_merge_writes(writes, written))
      end
    end
  end
end

fn eligible(shelf :: CreditShelf, keys :: List<IssuerKey>, now :: Int) -> Bool do
  shelf.available_at <= now && spendable_key(keys, shelf.key_id, now)
end

## Takes `count` spendable tokens at random: clean ones first, suspect ones
## only to make up the count. Returns them, the shelves left, and the writes.

pub fn credits_take(database_path :: String,
  wrapping_key :: borrow StorageKey,
  shelves :: CreditShelves,
  keys :: List<IssuerKey>,
  count :: Int,
  now :: Int) -> (List<CreditHeld>, CreditShelves, CreditWrites)!String do
  let clean = List.filter(shelves.shelves,
    fn shelf -> !shelf.suspect && eligible(shelf, keys, now) end)
  let suspect = List.filter(shelves.shelves,
    fn shelf -> shelf.suspect && eligible(shelf, keys, now) end)
  let other = List.filter(shelves.shelves, fn shelf -> !eligible(shelf, keys, now) end)
  let from_clean = Math.min(count, total(clean))
  if from_clean + total(suspect) < count do
    return Err("credits_insufficient")
  end
  let listed = clean ++ suspect
  let counts = credits_draw(clean, from_clean)? ++ credits_draw(suspect, count - from_clean)?
  let (held, kept, writes) = take_from(database_path,
    wrapping_key,
    listed,
    counts,
    0,
    List.new(),
    other,
    credits_no_writes())?
  Ok((held, CreditShelves { next_id: shelves.next_id, shelves: kept }, writes))
end

# Reservations.

fn reservations_label() -> String do
  "credits/v1/reservations"
end

fn reservation_label(id :: Bytes) -> String do
  "credits/v1/reservation/#{Bytes.to_hex(id)}"
end

fn take_ids(state :: BinaryReader,
  count :: Int,
  output :: List<Bytes>) -> (BinaryReader, List<Bytes>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let id = tcodec_take_fixed(state, 16)?
    take_ids(id.state, count, List.append(output, id.value))
  end
end

pub fn credits_reservation_ids(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
  let encoded = credits_load_sealed(database_path, wrapping_key, reservations_label())?
  if Bytes.length(encoded) == 0 do
    Ok(List.new())
  else
    let state = tcodec_start(encoded, 65536, 1, "CRI")?
    let count = tcodec_take_u16(state)?
    let (rest, ids) = take_ids(count.state, count.value, List.new())?
    tcodec_done(rest)?
    Ok(ids)
  end
end

# Always written, never removed: one transaction may drop some IDs and add others.

fn ids_write(ids :: List<Bytes>, wrapping_key :: borrow StorageKey) -> CreditWrites!String do
  credits_sealed_write(reservations_label(),
    tcodec_join([tcodec_u8(1)?, Bytes.from_utf8("CRI"), tcodec_u16(List.length(ids))?] ++ ids)?,
    wrapping_key)
end

fn encode_reservation(value :: CreditReservation) -> Bytes!String do
  let rows = for held in value.held do
    tcodec_join([flag(held.suspect)?, held.token])?
  end
  tcodec_join([
    tcodec_u8(1)?,
    Bytes.from_utf8("CRS"),
    value.id,
    value.purpose,
    tcodec_u8(value.action)?,
    tcodec_u8(value.attempts)?,
    tcodec_u64(value.created_at)?,
    tcodec_u8(List.length(value.held))?
  ]
    ++ rows)
end

fn take_held(state :: BinaryReader,
  count :: Int,
  output :: List<CreditHeld>) -> (BinaryReader, List<CreditHeld>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let suspect = tcodec_take_u8(state)?
    let token = tcodec_take_fixed(suspect.state, 354)?
    take_held(token.state,
      count,
      List.append(output, CreditHeld { token: token.value, suspect: suspect.value == 1 }))
  end
end

pub fn credits_load_reservation(database_path :: String,
  wrapping_key :: borrow StorageKey,
  id :: Bytes) -> Option<CreditReservation>!String do
  let encoded = credits_load_sealed(database_path, wrapping_key, reservation_label(id))?
  if Bytes.length(encoded) == 0 do
    Ok(None)
  else
    let state = tcodec_start(encoded, 65536, 1, "CRS")?
    let stored_id = tcodec_take_fixed(state, 16)?
    let purpose = tcodec_take_fixed(stored_id.state, 32)?
    let action = tcodec_take_u8(purpose.state)?
    let attempts = tcodec_take_u8(action.state)?
    let created = tcodec_take_u64(attempts.state)?
    let count = tcodec_take_u8(created.state)?
    let (rest, held) = take_held(count.state, count.value, List.new())?
    tcodec_done(rest)?
    Ok(Some(CreditReservation {
      id: stored_id.value,
      purpose: purpose.value,
      action: action.value,
      attempts: attempts.value,
      created_at: created.value,
      held: held
    }))
  end
end

fn load_all(database_path :: String,
  wrapping_key :: borrow StorageKey,
  ids :: List<Bytes>,
  output :: List<CreditReservation>) -> List<CreditReservation>!String do
  case ids do
    [] -> Ok(output)
    head :: tail -> case credits_load_reservation(database_path, wrapping_key, head)? do
      Some(value) -> load_all(database_path, wrapping_key, tail, List.append(output, value))
      None -> load_all(database_path, wrapping_key, tail, output)
    end
  end
end

pub fn credits_reservations(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<CreditReservation>!String do
  load_all(database_path,
    wrapping_key,
    credits_reservation_ids(database_path, wrapping_key)?,
    List.new())
end

## The writes that keep `value` (new or updated).

pub fn credits_reservation_write(value :: CreditReservation,
  ids :: List<Bytes>,
  wrapping_key :: borrow StorageKey) -> CreditWrites!String do
  let listed = if List.any(ids, fn id -> Bytes.secure_equals(id, value.id) end) do
    ids
  else
    List.append(ids, value.id)
  end
  Ok(credits_merge_writes(credits_sealed_write(reservation_label(value.id),
      encode_reservation(value)?,
      wrapping_key)?,
    ids_write(listed, wrapping_key)?))
end

## The writes that forget reservation `id`.

pub fn credits_reservation_removal(id :: Bytes,
  ids :: List<Bytes>,
  wrapping_key :: borrow StorageKey) -> CreditWrites!String do
  let kept = List.filter(ids, fn known -> !Bytes.secure_equals(known, id) end)
  Ok(credits_merge_writes(CreditWrites {
      labels: List.new(),
      blobs: List.new(),
      removed: [reservation_label(id)]
    },
    ids_write(kept, wrapping_key)?))
end

## The request that carries a reservation's tokens in front of `body`.

pub fn credits_request(value :: CreditReservation, body :: Bytes) -> Bytes!String do
  credits_attach(for held in value.held do
      held.token
    end,
    body)
end

pub fn credits_count_held(value :: CreditReservation) -> Int do
  List.length(value.held)
end
