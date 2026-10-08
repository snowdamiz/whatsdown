import File
from Credits.CreditCrypto import credits_verify_token
from Credits.IssuerKey import IssuerKey, credits_epoch_at
from Credits.CreditFrames import CreditFrame, credits_detach
from Credits.MailboxExtras import (
  MailboxPolicy,
  MailboxRetention,
  credits_decode_policy,
  credits_decode_retention,
  credits_encode_retention_answer,
  credits_verify_policy,
  credits_verify_retention
)
from MobileCore import (
  create_account_export,
  credits_inbox_policy_export,
  credits_issue_export,
  credits_postage_export,
  credits_postage_quote_export,
  credits_quote_export,
  credits_refresh_keys_export,
  credits_register_at_export,
  credits_retention_export,
  credits_settle_export,
  credits_signup_export,
  credits_spend_export,
  credits_status_export,
  directory_entry_export
)
from Mobile.Codec import current_time, outer_bytes
from Mobile.Profile import load_profile
from Privacy.Edge import (
  RequestStamp,
  decode_sealed_delivery,
  decode_stamped_request,
  verify_request_stamp
)
from Protocol.V1 import DeviceCredential, DirectoryEntry
from Transport.Packet import ClientProfile, decode_client_profile
from Mobile.CreditsBuy import credits_store_writes
from Mobile.CreditsStore import (
  CreditShelf,
  CreditShelves,
  credits_load_shelves,
  credits_note_policy,
  credits_shelves_write
)
from Tests.AnchorSupport import random_leaf
from Tests.CreditsSupport import (
  credits_fake_hits,
  credits_fake_key,
  credits_fake_listing,
  credits_fake_mode,
  credits_fake_start,
  credits_fake_url,
  credits_fake_write,
  credits_install_config,
  credits_key_entry,
  credits_unwitnessed_listing
)
from Tests.GroupConsistencySupport import ConsistencyAccount, account_fixture, request
from Tests.Support import database_path, read_u32, repeated

fn run(name :: String, value :: Result<Bool, String>) -> Bool do
  case value do
    Err(error) -> do
      println(name <> ": " <> error)
      false
    end
    Ok(result) -> result
  end
end

fn byte(value :: Int) -> Bytes!String do
  repeated(value, 1)
end

fn at(value :: Bytes, offset :: Int) -> Int do
  case Bytes.get(value, offset) do
    Ok(found) -> found
    Err(_) -> -1
  end
end

fn slice(value :: Bytes, offset :: Int, length :: Int) -> Bytes!String do
  case Bytes.slice(value, offset, length) do
    Err(_) -> Err("test slice failed")
    Ok(output)
  end
end

fn now() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn url() -> Bytes do
  Bytes.from_utf8(credits_fake_url())
end

# A fresh device and a fresh fake issuer whose one key (test purpose, this
# epoch) is in the log the directory lists.

struct Device do
  path :: String
  key :: IssuerKey
end

fn device(label :: String, issuer :: String, purpose :: Int) -> Device!String do
  assert(Test.install_in_memory_secure_store())
  assert(credits_install_config("https://" <> issuer)?)
  credits_fake_mode("")?
  let key = credits_fake_key(issuer, purpose, credits_epoch_at(now()), true)?
  credits_fake_write("listing",
    credits_fake_listing([random_leaf()?, credits_key_entry(key)?], [1], 0)?)?
  Ok(Device { path: database_path(label)?, key: key })
end

fn refresh(path :: String) -> Int!String do
  Ok(at(credits_refresh_keys_export(request([Bytes.from_utf8(path), url()])?)?, 0))
end

fn quote(path :: String, pack :: Int, asset :: Int) -> Bytes!String do
  credits_quote_export(request([Bytes.from_utf8(path), url(), byte(pack)?, byte(asset)?])?)
end

fn issue(path :: String, purchase :: Bytes, payment :: String) -> Bytes!String do
  credits_issue_export(request([
    Bytes.from_utf8(path),
    url(),
    slice(purchase, 0, 16)?,
    Bytes.from_utf8(payment)
  ])?)
end

# The purchase inside an issue answer starts after its outcome byte; its
# quote ID sits after id16, the state, pack, asset, batch, amount, three times
# and the issued count (1 + 16 + 1 + 1 + 1 + 2 + 8 + 8 + 8 + 8 + 4).

fn quote_id(answer :: Bytes) -> Bytes!String do
  slice(answer, 58, 32)
end

struct Status do
  spendable :: Int
  cooling :: Int
end

fn status(path :: String) -> Status!String do
  let value = credits_status_export(request([Bytes.from_utf8(path)])?)?
  Ok(Status { spendable: read_u32(slice(value, 6, 4)?)?, cooling: read_u32(slice(value, 10, 4)?)? })
end

# Ten minutes on: every shelf spendable now.

fn cooled(path :: String) -> Result<(), String> do
  let storage = case StorageKey.platform() do
    Err(_) -> Err("storage key unavailable")
    Ok(value)
  end?
  let shelves = credits_load_shelves(path, storage)?
  let aged = CreditShelves {
    next_id: shelves.next_id,
    shelves: for shelf in shelves.shelves do
      %{shelf | available_at: 0}
    end
  }
  credits_store_writes(path, credits_shelves_write(aged, storage)?)
end

fn spend(path :: String, count :: Int, purpose :: Int) -> Bytes!String do
  credits_spend_export(request([Bytes.from_utf8(path), byte(count)?, repeated(purpose, 32)?])?)
end

fn tokens_of(spend :: Bytes) -> List<Bytes>!String do
  let count = at(spend, 16)
  let body = slice(spend, 21, Bytes.length(spend) - 21)?
  let tokens = for index in 0..count do
    slice(body, index * 354, 354)?
  end
  Ok(tokens)
end

fn settle_with(path :: String, spend :: Bytes, status :: Int, answer :: Bytes) -> Int!String do
  let code = case Bytes.from_list([status / 256, status % 256]) do
    Err(_) -> Err("test status failed")
    Ok(value)
  end?
  Ok(at(credits_settle_export(request([
      Bytes.from_utf8(path),
      slice(spend, 0, 16)?,
      code,
      answer
    ])?)?,
    0))
end

fn settle(path :: String, spend :: Bytes, status :: Int) -> Int!String do
  settle_with(path, spend, status, repeated(0, 1)?)
end

fn round_trip() -> Bool!String do
  credits_fake_start()
  let phone = device("credits-trip", "credits.test", 2)?
  assert(refresh(phone.path)? == 1)
  let purchase = quote(phone.path, 1, 1)?
  let answer = issue(phone.path,
    purchase,
    "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW")?
  assert(at(answer, 0) == 1)
  # State 4 (issued) with its 100 tokens.
  assert(at(answer, 17) == 4)
  let fresh = status(phone.path)?
  assert(fresh.spendable == 0 && fresh.cooling == 100)
  # Nothing is spendable for ten minutes after the purchase.
  assert(spend(phone.path, 1, 1) == Err("credits_insufficient"))
  cooled(phone.path)?
  let taken = spend(phone.path, 5, 1)?
  let tokens = tokens_of(taken)?
  assert(List.length(tokens) == 5)
  assert(List.all(for token in tokens do
      credits_verify_token(phone.key, token) == Ok(true)
    end,
    fn valid -> valid end))
  assert(settle(phone.path, taken, 201)? == 1)
  assert(status(phone.path)?.spendable == 95)
  # Asking again for an issued purchase answers it as it is.
  assert(at(issue(phone.path, purchase, "")?, 0) == 1)
  File.delete(phone.path)?
  Ok(true)
end

test("a paid quote is collected as verified tokens, spendable ten minutes later") do
  assert(run("round trip", round_trip()))
end

fn resubmission() -> Bool!String do
  credits_fake_start()
  let phone = device("credits-resubmit", "credits.test", 2)?
  assert(refresh(phone.path)? == 1)
  # The issuer signs, then its answer is lost: the core sends the same batch
  # again and gets the same signatures.
  let lost = quote(phone.path, 1, 2)?
  credits_fake_mode("lose:1")?
  let answer = issue(phone.path, lost, "")?
  assert(at(answer, 0) == 1)
  let (hits, batches) = credits_fake_hits(quote_id(answer)?)
  assert(hits == 2 && batches == 1)
  # Payment not final yet: nothing is stored, and a later call succeeds with
  # a new batch.
  let waiting = quote(phone.path, 1, 3)?
  credits_fake_mode("pending:2")?
  assert(at(issue(phone.path, waiting, "")?, 0) == 2)
  assert(at(issue(phone.path, waiting, "")?, 0) == 2)
  let collected = issue(phone.path, waiting, "")?
  assert(at(collected, 0) == 1)
  # Every answer is lost: the purchase stays `issuing`. The next call sends a
  # new batch the issuer refuses (it signed the first), and only Morse can
  # help: the blinding states for the stored signatures are gone.
  let stranded = quote(phone.path, 1, 1)?
  credits_fake_mode("lose:3")?
  let interrupted = issue(phone.path, stranded, "")?
  assert(at(interrupted, 0) == 8 && at(interrupted, 17) == 3)
  credits_fake_mode("")?
  let refused = issue(phone.path, stranded, "")?
  assert(at(refused, 0) == 5 && at(refused, 17) == 8)
  # Trying again before Morse re-opens the quote changes nothing; after it
  # does, a fresh batch is signed and the purchase is issued.
  let still = issue(phone.path, stranded, "")?
  assert(at(still, 0) == 5 && at(still, 17) == 8)
  credits_fake_mode("reissue")?
  let finished = issue(phone.path, stranded, "")?
  assert(at(finished, 0) == 1 && at(finished, 17) == 4)
  credits_fake_mode("")?
  let status_now = status(phone.path)?
  assert(status_now.cooling == 300)
  File.delete(phone.path)?
  Ok(true)
end

test("lost answers are retried with the same batch, and a stranded one waits for Morse to re-open it") do
  assert(run("resubmission", resubmission()))
end

fn issuer_refusals() -> Bool!String do
  credits_fake_start()
  let phone = device("credits-refusals", "credits.test", 2)?
  assert(refresh(phone.path)? == 1)
  let expired = quote(phone.path, 1, 1)?
  credits_fake_mode("expired")?
  let gone = issue(phone.path, expired, "")?
  assert(at(gone, 0) == 3 && at(gone, 17) == 5)
  let short = quote(phone.path, 1, 1)?
  credits_fake_mode("unpaid")?
  let unpaid = issue(phone.path, short, "")?
  assert(at(unpaid, 0) == 4 && at(unpaid, 17) == 6)
  let later = quote(phone.path, 1, 1)?
  credits_fake_mode("down")?
  assert(at(issue(phone.path, later, "")?, 0) == 7)
  # A new epoch's key the device has not fetched: 412, refresh, collect.
  credits_fake_mode("")?
  let next = credits_fake_key("credits.test", 2, credits_epoch_at(now()) - 1, true)?
  assert(at(issue(phone.path, later, "")?, 0) == 6)
  credits_fake_write("listing",
    credits_fake_listing([credits_key_entry(phone.key)?, credits_key_entry(next)?], [0, 1], 0)?)?
  assert(refresh(phone.path)? == 2)
  File.delete(phone.path)?
  Ok(true)
end

test("an issuer refusal leaves the purchase in the state it names") do
  assert(run("refusals", issuer_refusals()))
end

fn key_rules() -> Bool!String do
  credits_fake_start()
  # A release build (the production issuer) takes live keys only.
  let release = device("credits-release", "credits.morseapp.io", 2)?
  assert(refresh(release.path)? == 0)
  let live = credits_fake_key("credits.morseapp.io", 1, credits_epoch_at(now()), true)?
  credits_fake_write("listing",
    credits_fake_listing([credits_key_entry(release.key)?, credits_key_entry(live)?], [0, 1], 0)?)?
  assert(refresh(release.path)? == 1)
  # A key whose evidence the pinned witnesses did not sign is not logged.
  let staging = device("credits-unlogged", "credits.test", 2)?
  credits_fake_write("listing", credits_unwitnessed_listing([credits_key_entry(staging.key)?])?)?
  assert(refresh(staging.path)? == 0)
  # Nor is a key of another issuer.
  let other = credits_fake_key("credits.other.test", 2, credits_epoch_at(now()), false)?
  credits_fake_write("listing", credits_fake_listing([credits_key_entry(other)?], [0], 0)?)?
  assert(refresh(staging.path)? == 0)
  # Without accepted keys there is nothing to quote for.
  assert(quote(staging.path, 1, 1) == Err("credits_keys_needed"))
  File.delete(release.path)?
  File.delete(staging.path)?
  Ok(true)
end

test("only logged keys of this build's issuer and purpose are accepted") do
  assert(run("key rules", key_rules()))
end

# A device holding one purchase of 100 spendable credits.

fn stocked(label :: String) -> Device!String do
  stocked_as(label, "")
end

# The same, on a device with an account (created first: an account starts
# from an empty store).

fn stocked_as(label :: String, username :: String) -> Device!String do
  credits_fake_start()
  let phone = device(label, "credits.test", 2)?
  if username != "" do
    create_account_export(request([Bytes.from_utf8(phone.path), Bytes.from_utf8(username)])?)?
  end
  assert(refresh(phone.path)? == 1)
  assert(at(issue(phone.path, quote(phone.path, 1, 1)?, "")?, 0) == 1)
  cooled(phone.path)?
  Ok(phone)
end

fn shelf_counts(path :: String) -> List<Int>!String do
  let storage = case StorageKey.platform() do
    Err(_) -> Err("storage key unavailable")
    Ok(value)
  end?
  Ok(List.map(credits_load_shelves(path, storage)?.shelves, fn shelf -> shelf.count end))
end

fn spend_one(path :: String, left :: Int) -> Result<(), String> do
  if left <= 0 do
    Ok(nil)
  else
    assert(settle(path, spend(path, 1, left)?, 201)? == 1)
    spend_one(path, left - 1)
  end
end

fn random_order() -> Bool!String do
  let phone = stocked("credits-random")?
  assert(at(issue(phone.path, quote(phone.path, 1, 1)?, "")?, 0) == 1)
  cooled(phone.path)?
  # Two purchases, one token at a time: both are drawn from.
  spend_one(phone.path, 24)?
  let counts = shelf_counts(phone.path)?
  assert(List.length(counts) == 2)
  assert(List.all(counts, fn count -> count < 100 end))
  assert(status(phone.path)?.spendable == 176)
  File.delete(phone.path)?
  Ok(true)
end

test("tokens are spent in random order across purchases") do
  assert(run("random order", random_order()))
end

fn refusals() -> Bool!String do
  let phone = stocked("credits-settle")?
  # Leave three credits.
  assert(settle(phone.path, spend(phone.path, 64, 1)?, 201)? == 1)
  assert(settle(phone.path, spend(phone.path, 33, 2)?, 201)? == 1)
  assert(status(phone.path)?.spendable == 3)
  # Refused before any redemption: back as they were.
  assert(settle(phone.path, spend(phone.path, 2, 3)?, 400)? == 2)
  # An answer that does not say: back, but suspect.
  assert(settle(phone.path, spend(phone.path, 1, 4)?, 403)? == 2)
  assert(status(phone.path)?.spendable == 3)
  # Two clean ones and the suspect one; a 409 means the suspect one was spent.
  let mixed = spend(phone.path, 3, 5)?
  assert(settle(phone.path, mixed, 409)? == 2)
  assert(status(phone.path)?.spendable == 2)
  # No answer: the same request later carries the same tokens, and a 409 then
  # means the first attempt spent them.
  let first = spend(phone.path, 2, 6)?
  assert(settle(phone.path, first, 0)? == 3)
  let again = spend(phone.path, 2, 6)?
  assert(tokens_of(first)? == tokens_of(again)?)
  assert(settle(phone.path, again, 409)? == 1)
  assert(status(phone.path)?.spendable == 0)
  File.delete(phone.path)?
  Ok(true)
end

test("an answer decides what became of a spend's tokens") do
  assert(run("refusals", refusals()))
end

fn keys_refresh_on_422() -> Bool!String do
  let phone = stocked("credits-422")?
  assert(settle(phone.path, spend(phone.path, 4, 1)?, 422)? == 4)
  assert(status(phone.path)?.spendable == 100)
  File.delete(phone.path)?
  Ok(true)
end

test("tokens a redeemer did not take as credits come back and ask for fresh keys") do
  assert(run("422", keys_refresh_on_422()))
end

fn revocation() -> Bool!String do
  let phone = stocked("credits-revoked")?
  let purchase = quote(phone.path, 1, 1)?
  assert(at(issue(phone.path, purchase, "")?, 0) == 1)
  assert(status(phone.path)?.cooling == 100)
  # The key leaves the listing inside its window: revoked. Its tokens are no
  # longer spent and its purchases can be collected again, under the
  # replacement.
  let replacement = credits_fake_key("credits.test", 2, credits_epoch_at(now()), true)?
  credits_fake_write("listing", credits_fake_listing([credits_key_entry(replacement)?], [0], 0)?)?
  assert(refresh(phone.path)? == 1)
  let emptied = status(phone.path)?
  assert(emptied.spendable == 0 && emptied.cooling == 0)
  credits_fake_mode("reissue")?
  let again = issue(phone.path, purchase, "")?
  assert(at(again, 0) == 1 && at(again, 17) == 4)
  assert(status(phone.path)?.cooling == 100)
  File.delete(phone.path)?
  Ok(true)
end

fn left_out() -> Bool!String do
  let phone = stocked("credits-left-out")?
  # A listing that leaves the key out (listing only a newer one): its tokens
  # stop being spent but stay.
  let newer = credits_fake_key("credits.test", 2, credits_epoch_at(now()), true)?
  credits_fake_write("listing", credits_fake_listing([credits_key_entry(newer)?], [0], 0)?)?
  assert(refresh(phone.path)? == 1)
  assert(status(phone.path)?.spendable == 0)
  assert(spend(phone.path, 1, 1) == Err("credits_insufficient"))
  # Collecting again, when the issuer still stands by the first batch, changes
  # nothing. The newest purchase starts after the status header, its count and
  # its length (53 + 1 + 4 bytes).
  let shown = credits_status_export(request([Bytes.from_utf8(phone.path)])?)?
  let offered = issue(phone.path, slice(shown, 58, 16)?, "")?
  assert(at(offered, 0) == 9 && at(offered, 17) == 4)
  # The key is listed again: everything is spendable, as before.
  credits_fake_write("listing",
    credits_fake_listing([credits_key_entry(phone.key)?, credits_key_entry(newer)?], [0, 1], 0)?)?
  assert(refresh(phone.path)? == 2)
  assert(status(phone.path)?.spendable == 100)
  File.delete(phone.path)?
  Ok(true)
end

test("a listing that leaves a key out keeps its tokens until it comes back") do
  assert(run("left out", left_out()))
end

test("a revoked key's tokens stop counting and its purchases are collected again") do
  assert(run("revocation", revocation()))
end

fn profile_of(path :: String) -> ClientProfile!String do
  decode_client_profile(load_profile(path)?)
end

fn account(label :: String, username :: String) -> String!String do
  let path = database_path(label)?
  create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8(username)])?)?
  Ok(path)
end

fn inbox_policy(path :: String, postage :: Int) -> Bytes!String do
  credits_inbox_policy_export(request([Bytes.from_utf8(path), byte(postage)?])?)
end

fn frame_of(spend :: Bytes) -> (CreditFrame, Bytes)!String do
  let body = slice(spend, 21, Bytes.length(spend) - 21)?
  case credits_detach(body)? do
    (Some(frame), rest) -> Ok((frame, rest))
    (None, _) -> Err("no CRD frame")
  end
end

fn inbox_price() -> Bool!String do
  let phone = stocked("credits-inbox")?
  let bob = account("credits-inbox-bob", "bob")?
  let profile = profile_of(bob)?
  let five = inbox_policy(bob, 5)?
  let policy = credits_decode_policy(five)?
  assert(policy.postage == 5)
  assert(Bytes.secure_equals(policy.mailbox_hash, Crypto.sha256(profile.entry.mailbox_token)))
  assert(credits_verify_policy(policy, profile.credential.signing_public_key))
  # The same price again is the policy already signed; a new one is newer.
  assert(Bytes.secure_equals(inbox_policy(bob, 5)?, five))
  let raised = credits_decode_policy(inbox_policy(bob, 25)?)?
  assert(raised.postage == 25 && raised.sequence > policy.sequence)
  assert(inbox_policy(bob, 3) == Err("invalid_credits_request"))
  File.delete(bob)?
  File.delete(phone.path)?
  Ok(true)
end

test("a device signs its price for message requests from strangers") do
  assert(run("inbox price", inbox_price()))
end

fn postage() -> Bool!String do
  let phone = stocked_as("credits-postage", "alice")?
  let bob_account = account_fixture("credits-postage-bob", "bob")?
  let bob = bob_account.path
  let bob_profile = profile_of(bob)?
  let priced = inbox_policy(bob, 5)?
  let policy = credits_decode_policy(priced)?
  # The price came with the prekey claim that starts the conversation, and is
  # shown before the first message is sent.
  credits_note_policy(phone.path, bob_profile, Some(policy))?
  let before = credits_postage_quote_export(request([
    Bytes.from_utf8(phone.path),
    bob_account.device_set
  ])?)?
  assert(at(before, 0) == 1 && at(before, 33) == 5)
  assert(Bytes.secure_equals(slice(before, 1, 32)?, bob_profile.entry.mailbox_token))
  let envelope = outer_bytes(bob_profile.entry.mailbox_token, 4, repeated(7, 64)?, current_time()?)?
  # The edge refused it (402, with the price): the app asks, then pays.
  let check = credits_postage_export(request([
    Bytes.from_utf8(phone.path),
    envelope,
    priced,
    byte(0)?
  ])?)?
  assert(at(check, 0) == 5)
  assert(read_u32(slice(check, 1, 4)?)? == 100)
  let paid = credits_postage_export(request([
    Bytes.from_utf8(phone.path),
    envelope,
    priced,
    byte(1)?
  ])?)?
  assert(at(paid, 16) == 5)
  let (frame, rest) = frame_of(paid)?
  assert(List.length(frame.tokens) == 5)
  assert(List.all(for token in frame.tokens do
      credits_verify_token(phone.key, token) == Ok(true)
    end,
    fn valid -> valid end))
  assert(case decode_sealed_delivery(rest) do
    Ok(_) -> true
    Err(_) -> false
  end)
  # A price signed by anyone but the recipient's device does not count.
  let alice_price = inbox_policy(phone.path, 1)?
  assert(credits_postage_export(request([
    Bytes.from_utf8(phone.path),
    envelope,
    alice_price,
    byte(0)?
  ])?) == Err("credits_policy_invalid"))
  assert(settle(phone.path, paid, 201)? == 1)
  assert(status(phone.path)?.spendable == 95)
  File.delete(bob)?
  File.delete(phone.path)?
  Ok(true)
end

test("a message request to a priced inbox pays the price the recipient signed") do
  assert(run("postage", postage()))
end

fn retention() -> Bool!String do
  let phone = stocked_as("credits-retention", "alice")?
  let profile = profile_of(phone.path)?
  let bought = credits_retention_export(request([Bytes.from_utf8(phone.path), byte(2)?])?)?
  assert(at(bought, 16) == 20)
  let (frame, rest) = frame_of(bought)?
  assert(List.length(frame.tokens) == 20)
  let signed = credits_decode_retention(rest)?
  assert(signed.periods == 2)
  assert(Bytes.secure_equals(signed.mailbox_hash, Crypto.sha256(profile.entry.mailbox_token)))
  assert(credits_verify_retention(signed, profile.credential.signing_public_key))
  let until = now() + 90 * 86400000
  assert(settle_with(phone.path, bought, 201, credits_encode_retention_answer(90, until)?)? == 1)
  let shown = credits_status_export(request([Bytes.from_utf8(phone.path)])?)?
  # retention_days (u16) sits after sold, purpose, three counts, three times
  # and the inbox price.
  assert(at(shown, 43) * 256 + at(shown, 44) == 90)
  assert(status(phone.path)?.spendable == 80)
  File.delete(phone.path)?
  Ok(true)
end

test("longer storage is bought for this device's mailbox with ten credits a period") do
  assert(run("retention", retention()))
end

fn signup() -> Bool!String do
  let phone = stocked_as("credits-signup", "alice")?
  let entry = directory_entry_export(Bytes.from_utf8(phone.path))?
  let skip = credits_signup_export(request([Bytes.from_utf8(phone.path)])?)?
  let (frame, rest) = frame_of(skip)?
  assert(List.length(frame.tokens) == 20)
  let (stamp, payload) = decode_stamped_request(rest, 65536)?
  assert(Bytes.secure_equals(payload, entry))
  assert(verify_request_stamp("mesh-msg/v1/work/register",
    payload,
    stamp,
    current_time()?,
    current_time()?,
    4)?)
  # A registration that fails (a taken name) spends nothing.
  assert(settle(phone.path, skip, 409)? == 2)
  assert(status(phone.path)?.spendable == 100)
  # The free way past a busy sign-up: work at the difficulty the 429 named.
  let harder = credits_register_at_export(request([Bytes.from_utf8(phone.path), byte(10)?])?)?
  let (hard_stamp, hard_payload) = decode_stamped_request(harder, 65536)?
  assert(verify_request_stamp("mesh-msg/v1/work/register",
    hard_payload,
    hard_stamp,
    current_time()?,
    current_time()?,
    10)?)
  assert(credits_register_at_export(request([
    Bytes.from_utf8(phone.path),
    byte(2)?
  ])?) == Err("invalid_credits_request"))
  File.delete(phone.path)?
  Ok(true)
end

test("a busy sign-up is skipped with twenty credits, or worked past for free") do
  assert(run("signup", signup()))
end
