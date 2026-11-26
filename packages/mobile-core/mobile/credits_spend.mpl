from Credits.CreditFrames import (
  credits_action_envelope,
  credits_action_file,
  credits_action_signup,
  credits_action_storage
)
from Credits.MailboxExtras import (
  MailboxPolicy,
  credits_decode_policy,
  credits_decode_retention_answer,
  credits_encode_policy,
  credits_postage_valid,
  credits_retention_price,
  credits_sign_policy,
  credits_sign_retention,
  credits_verify_policy
)
from Mobile.Account import directory_entry_for
from Mobile.ContactAddress import deposit_address
from Mobile.CreditsBuy import (
  credits_encode_purchase,
  credits_fields,
  credits_issuer_origin,
  credits_load_purchases,
  credits_now,
  credits_path,
  credits_small,
  credits_store_writes,
  credits_text
)
from Mobile.CreditsKeys import credits_build_purpose
from Mobile.CreditsStore import (
  CreditHeld,
  CreditReservation,
  CreditShelves,
  CreditWrites,
  credits_count_held,
  credits_random,
  credits_counts,
  credits_expiring,
  credits_inbox_label,
  credits_load_keys,
  credits_postage_label,
  credits_load_reservation,
  credits_load_sealed,
  credits_load_shelves,
  credits_merge_writes,
  credits_no_writes,
  credits_pending_ms,
  credits_request,
  credits_reservation_ids,
  credits_reservation_removal,
  credits_reservation_write,
  credits_reservations,
  credits_return,
  credits_sealed_write,
  credits_shelves_write,
  credits_take
)
from Mobile.DeviceSet import verified_device_set
from Mobile.Platform import native_security_config, stamped_request
from Mobile.Profile import load_profile, open_device
from Mobile.Sessions import load_session_ids, load_session_record
from Mobile.Transparency import fresh_account_device_set
from Privacy.Edge import (
  encode_sealed_delivery,
  encode_stamped_request,
  mint_request_stamp,
  seal_delivery
)
from Storage.Keys import platform_key
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u16,
  tcodec_u32,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)
from Identity.Device import DeviceKeys
from Mobile.Types import (
  MobileLoadedSession,
  MobileSecurityConfig,
  MobileSessionRecord,
  MobileVerifiedDeviceSet
)
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.V1 import DeviceCredential, DirectoryEntry, OuterEnvelope
from Security.Config import SecurityConfig
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.CreditsSpend: what credits pay for (protocol/credits-v1.md
##! "Extras", "Client"). Each export returns the request to send, with the
##! tokens already in its CRD frame; tokens never leave the core any other way.
##!
##! A spend is a reservation: `id16 || u8 credits || vector32(request)`. The
##! app sends the request and hands the answer's status to `credits_settle`,
##! which decides what became of the tokens:
##!
##! - spent (2xx; 402 for postage and storage, whose tokens the edge redeemed);
##! - given back as they were, when the refusal came before any redemption
##!   (400, 429; every refusal of a sign-up, which spends only when it succeeds);
##! - given back as suspect when the answer does not say (403, and 422, which
##!   also asks for fresh issuer keys): a suspect token is only ever sent
##!   beside clean ones when there are not enough clean ones, and a 409 then
##!   tells which it was;
##! - kept for a retry of the same request when there was no answer or a 5xx:
##!   the retry sends the same tokens, so they keep sharing one fate. Tokens
##!   of a request never retried within an hour go back as suspect.
##!
##! A 409 ("a token was already spent") on a retry means the first attempt
##! went through and spent them all; on a first attempt it drops the suspect
##! tokens it carried and gives the clean ones back.
##!
##! Settle answers u8: 1 spent, 2 given back, 3 kept for a retry, 4 given back
##! and the issuer keys need refreshing.

fn purpose_of(label :: String, value :: Bytes) -> Bytes!String do
  Ok(Crypto.sha256(tcodec_join([Bytes.from_utf8("morse-credits/v1/spend/" <> label), value])?))
end

fn stale_release(values :: List<CreditReservation>,
  ids :: List<Bytes>,
  shelves :: CreditShelves,
  writes :: CreditWrites,
  wrapping_key :: borrow StorageKey) -> (List<Bytes>, CreditShelves, CreditWrites)!String do
  case values do
    [] -> Ok((ids, shelves, writes))
    head :: tail -> do
      let (next, returned) = credits_return(head.held, true, shelves, wrapping_key)?
      let kept = List.filter(ids, fn id -> !Bytes.secure_equals(id, head.id) end)
      stale_release(tail,
        kept,
        next,
        credits_merge_writes(credits_merge_writes(writes, returned),
          credits_reservation_removal(head.id, ids, wrapping_key)?),
        wrapping_key)
    end
  end
end

fn encode_spend(value :: CreditReservation, request :: Bytes) -> Bytes!String do
  tcodec_join([value.id, tcodec_u8(credits_count_held(value))?, tcodec_vector(request)?])
end

## Takes `count` tokens for `purpose` (or the ones a request for the same
## purpose already carries) and returns the spend frame for `body`.

pub fn credits_reserve(path :: String,
  purpose :: Bytes,
  action :: Int,
  count :: Int,
  body :: Bytes) -> Bytes!String do
  reserve(path, purpose, action, count, Some(body))
end

fn reserve(path :: String,
  purpose :: Bytes,
  action :: Int,
  count :: Int,
  body :: Option<Bytes>) -> Bytes!String do
  if count < 1 || count > 64 do
    return Err("invalid_credits_request")
  end
  let wrapping_key = platform_key()?
  let now = credits_now()
  let all = credits_reservations(path, wrapping_key)?
  let existing = List.find(all,
    fn value -> Bytes.secure_equals(value.purpose, purpose)
      && value.action == action
      && credits_count_held(value) == count end)
  let stale = List.filter(all,
    fn value -> !Bytes.secure_equals(value.purpose, purpose)
      && value.created_at + credits_pending_ms() < now
      || Bytes.secure_equals(value.purpose, purpose) && credits_count_held(value) != count end)
  # Tokens of abandoned requests go back first, in their own transaction, so
  # the draw below can find them on their shelves.
  if List.length(stale) > 0 do
    let (_, returned_shelves, released) = stale_release(stale,
      credits_reservation_ids(path, wrapping_key)?,
      credits_load_shelves(path, wrapping_key)?,
      credits_no_writes(),
      wrapping_key)?
    credits_store_writes(path,
      credits_merge_writes(released, credits_shelves_write(returned_shelves, wrapping_key)?))?
  end
  let ids = credits_reservation_ids(path, wrapping_key)?
  let shelves = credits_load_shelves(path, wrapping_key)?
  let (reservation, taken_shelves, taken) = case existing do
    Some(value) -> (%{value | attempts: Math.min(value.attempts + 1, 255)},
      shelves,
      credits_no_writes())
    None -> do
      let keys = credits_load_keys(path, wrapping_key)?
      let (held, left, writes) = credits_take(path, wrapping_key, shelves, keys.keys, count, now)?
      (CreditReservation {
          id: credits_random(16)?,
          purpose: purpose,
          action: action,
          attempts: 1,
          created_at: now,
          held: held
        },
        left,
        writes)
    end
  end
  # A body gets its CRD frame here; without one the caller builds the frame
  # (the attachment grant does, from the tokens themselves).
  let request = case body do
    Some(value) -> credits_request(reservation, value)?
    None -> tcodec_join(for held in reservation.held do
      held.token
    end)?
  end
  credits_store_writes(path,
    credits_merge_writes(taken,
      credits_merge_writes(credits_shelves_write(taken_shelves, wrapping_key)?,
        credits_reservation_write(reservation, ids, wrapping_key)?)))?
  encode_spend(reservation, request)
end

# Settling.

fn spent_on_402(action :: Int) -> Bool do
  action == credits_action_envelope() || action == credits_action_storage()
end

# 1 spent, 2 back clean, 3 keep, 4 back suspect + keys, 5 back suspect, 6 resolve 409.

fn verdict(action :: Int, status :: Int) -> Int do
  if status >= 200 && status < 300 do
    1
  else if status == 0 || status >= 500 do
    3
  else if action == credits_action_signup() do
    if status == 422 do
      4
    else
      2
    end
  else if status == 402 && spent_on_402(action) do
    1
  else if status == 400 || status == 429 do
    2
  else if status == 422 do
    4
  else if status == 409 do
    6
  else
    5
  end
end

fn give_back(path :: String,
  value :: CreditReservation,
  held :: List<CreditHeld>,
  suspect :: Bool,
  extra :: CreditWrites,
  wrapping_key :: borrow StorageKey) -> Result<(), String> do
  let (shelves, returned) = credits_return(held,
    suspect,
    credits_load_shelves(path, wrapping_key)?,
    wrapping_key)?
  credits_store_writes(path,
    credits_merge_writes(credits_merge_writes(returned,
        credits_shelves_write(shelves, wrapping_key)?),
      credits_merge_writes(credits_reservation_removal(value.id,
          credits_reservation_ids(path, wrapping_key)?,
          wrapping_key)?,
        extra)))
end

fn retention_writes(action :: Int,
  status :: Int,
  answer :: Bytes,
  wrapping_key :: borrow StorageKey) -> CreditWrites!String do
  if action != credits_action_storage() || status != 201 do
    Ok(credits_no_writes())
  else
    case credits_decode_retention_answer(answer) do
      Err(_) -> Ok(credits_no_writes())
      Ok(_) -> credits_sealed_write(retention_label(), answer, wrapping_key)
    end
  end
end

fn retention_label() -> String do
  "credits/v1/retention"
end

fn apply(path :: String,
  value :: CreditReservation,
  decision :: Int,
  extra :: CreditWrites,
  wrapping_key :: borrow StorageKey) -> Int!String do
  if decision == 1 do
    credits_store_writes(path,
      credits_merge_writes(credits_reservation_removal(value.id,
          credits_reservation_ids(path, wrapping_key)?,
          wrapping_key)?,
        extra))?
    Ok(1)
  else if decision == 2 do
    give_back(path, value, value.held, false, extra, wrapping_key)?
    Ok(2)
  else if decision == 3 do
    Ok(3)
  else if decision == 4 || decision == 5 do
    give_back(path, value, value.held, true, extra, wrapping_key)?
    Ok(if decision == 4 do
      4
    else
      2
    end)
  else
    let clean = List.filter(value.held, fn held -> !held.suspect end)
    let any_suspect = List.any(value.held, fn held -> held.suspect end)
    if value.attempts > 1 || !any_suspect do
      apply(path, value, 1, extra, wrapping_key)
    else
      give_back(path, value, clean, false, extra, wrapping_key)?
      Ok(2)
    end
  end
end

## What became of a spend's tokens. Request: vector32(path) || vector32(id16)
## || vector32(u16 HTTP status, 0 for no answer) || vector32(answer body).

pub fn credits_settle(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 4)?
  let path = credits_path(List.get(fields, 0))?
  let id = List.get(fields, 1)
  let status_bytes = List.get(fields, 2)
  if Bytes.length(id) != 16 || Bytes.length(status_bytes) != 2 do
    return Err("invalid_credits_request")
  end
  let status = case (Bytes.get(status_bytes, 0), Bytes.get(status_bytes, 1)) do
    (Ok(high), Ok(low)) -> Ok(high * 256 + low)
    _ -> Err("invalid_credits_request")
  end?
  let wrapping_key = platform_key()?
  let value = case credits_load_reservation(path, wrapping_key, id)? do
    None -> return Err("credits_spend_unknown")
    Some(found) -> found
  end
  let extra = retention_writes(value.action, status, List.get(fields, 3), wrapping_key)?
  tcodec_u8(apply(path, value, verdict(value.action, status), extra, wrapping_key)?)
end

# Postage.

struct PostageSigner do
  key :: Bytes
  username :: String
end

fn session_signer(path :: String,
  wrapping_key :: borrow StorageKey,
  mailbox_token :: Bytes,
  ids :: List<Bytes>) -> Option<PostageSigner>!String do
  case ids do
    [] -> Ok(None)
    head :: tail -> do
      let loaded = load_session_record(path, wrapping_key, head)?
      if Bytes.secure_equals(loaded.record.peer_mailbox, mailbox_token) do
        let devices = fresh_account_device_set(path, wrapping_key, loaded.record.peer_account_id)?
        case List.find(devices.profiles,
          fn profile -> Bytes.secure_equals(profile.entry.mailbox_token, mailbox_token) end) do
          Some(profile) -> Ok(Some(PostageSigner {
            key: profile.credential.signing_public_key,
            username: loaded.record.peer_username
          }))
          None -> session_signer(path, wrapping_key, mailbox_token, tail)
        end
      else
        session_signer(path, wrapping_key, mailbox_token, tail)
      end
    end
  end
end

# The device key a price for `mailbox_token` must be signed with: from the
# prekey claim that started the conversation, else from a session with it.

fn postage_signer(path :: String,
  wrapping_key :: borrow StorageKey,
  mailbox_token :: Bytes) -> Option<PostageSigner>!String do
  let found = case session_signer(path,
    wrapping_key,
    mailbox_token,
    load_session_ids(path, wrapping_key)?) do
    Err(_) -> None
    Ok(value) -> value
  end
  case found do
    Some(value) -> Ok(Some(value))
    None -> do
      let stored = credits_load_sealed(path, wrapping_key, credits_postage_label(mailbox_token))?
      if Bytes.length(stored) < 32 do
        Ok(None)
      else
        Ok(Some(PostageSigner { key: Bytes.slice(stored, 0, 32)?, username: "" }))
      end
    end
  end
end

fn spendable(path :: String, wrapping_key :: borrow StorageKey) -> Int!String do
  let keys = credits_load_keys(path, wrapping_key)?
  let (ready, _, _) = credits_counts(credits_load_shelves(path, wrapping_key)?,
    keys.keys,
    credits_now())
  Ok(ready)
end

## An envelope the edge refused with 402 and the recipient's signed price.
## Request: vector32(path) || vector32(envelope) || vector32(MBP) ||
## vector32(u8 mode). Mode 0 checks: u8 postage || u32 spendable credits ||
## vector32(username, when known). Mode 1 pays: the spend frame for CRD || SED.

pub fn credits_postage(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 4)?
  let path = credits_path(List.get(fields, 0))?
  let envelope = List.get(fields, 1)
  let mode = credits_small(List.get(fields, 3))?
  credits_issuer_origin()?
  let outer = case decode_outer_envelope(envelope) do
    Err(_) -> Err("invalid_outer_envelope")
    Ok(value)
  end?
  let policy = case credits_decode_policy(List.get(fields, 2)) do
    Err(_) -> Err("credits_policy_invalid")
    Ok(value)
  end?
  let wrapping_key = platform_key()?
  let signer = case postage_signer(path, wrapping_key, outer.mailbox_token)? do
    None -> return Err("credits_policy_unverified")
    Some(value) -> value
  end
  if !Bytes.secure_equals(policy.mailbox_hash, Crypto.sha256(outer.mailbox_token))
    || !credits_verify_policy(policy, signer.key)
    || policy.postage == 0 do
    return Err("credits_policy_invalid")
  end
  if mode == 0 do
    tcodec_join([
      tcodec_u8(policy.postage)?,
      tcodec_u32(spendable(path, wrapping_key)?)?,
      tcodec_vector(Bytes.from_utf8(signer.username))?
    ])
  else
    let config = native_security_config()?
    let sealed = encode_sealed_delivery(seal_delivery(envelope,
      X25519PublicKey { bytes: config.delivery_public_key })?)?
    credits_reserve(path,
      purpose_of("postage", outer.envelope_id)?,
      credits_action_envelope(),
      policy.postage,
      sealed)
  end
end

fn stored_price(path :: String,
  wrapping_key :: borrow StorageKey,
  profile :: ClientProfile) -> Int!String do
  let stored = credits_load_sealed(path,
    wrapping_key,
    credits_postage_label(profile.entry.mailbox_token))?
  if Bytes.length(stored) <= 32 do
    Ok(0)
  else
    case credits_decode_policy(Bytes.slice(stored, 32, Bytes.length(stored) - 32)?) do
      Err(_) -> Ok(0)
      Ok(value) -> Ok(value.postage)
    end
  end
end

fn priced_rows(path :: String,
  wrapping_key :: borrow StorageKey,
  profiles :: List<ClientProfile>,
  output :: List<Bytes>) -> List<Bytes>!String do
  case profiles do
    [] -> Ok(output)
    profile :: rest -> do
      let token = profile.entry.mailbox_token
      let public = Bytes.secure_equals(deposit_address(path, wrapping_key, token)?, token)
      let price = if public do
        stored_price(path, wrapping_key, profile)?
      else
        0
      end
      let next = if price > 0 do
        List.append(output, tcodec_join([token, tcodec_u8(price)?])?)
      else
        output
      end
      priced_rows(path, wrapping_key, rest, next)
    end
  end
end

## What a first message to a peer costs, before it is sent: each of its
## devices that asks a price and has handed this device no contact address.
## Request: vector32(path) || vector32(peer device set). Answer: u8 n || n x
## (mailbox_token32 || u8 postage).

pub fn credits_postage_quote(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 2)?
  let path = credits_path(List.get(fields, 0))?
  let devices = verified_device_set(List.get(fields, 1))?
  let rows = priced_rows(path, platform_key()?, devices.profiles, List.new())?
  tcodec_join([tcodec_u8(List.length(rows))?] ++ rows)
end

# The mailbox extras this device signs for itself.

fn local_profile(path :: String) -> ClientProfile!String do
  decode_client_profile(load_profile(path)?)
end

fn inbox_price(path :: String, wrapping_key :: borrow StorageKey) -> (Int, Bytes)!String do
  let stored = credits_load_sealed(path, wrapping_key, credits_inbox_label())?
  if Bytes.length(stored) == 0 do
    Ok((0, Bytes.empty()))
  else
    let policy = credits_decode_policy(stored)?
    Ok((policy.postage, stored))
  end
end

## This device's price for message requests from strangers (0, 1, 5 or 25),
## signed for PUT /v1/mailbox/policy. The same price again answers the policy
## already signed. Request: vector32(path) || vector32(u8 postage).

pub fn credits_inbox_policy(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 2)?
  let path = credits_path(List.get(fields, 0))?
  let postage = credits_small(List.get(fields, 1))?
  if !credits_postage_valid(postage) do
    return Err("invalid_credits_request")
  end
  let wrapping_key = platform_key()?
  let (current, stored) = inbox_price(path, wrapping_key)?
  if Bytes.length(stored) > 0 && current == postage do
    return Ok(stored)
  end
  let previous = if Bytes.length(stored) == 0 do
    0
  else
    credits_decode_policy(stored)?.sequence
  end
  let profile = local_profile(path)?
  let device = open_device(profile, wrapping_key, path)?
  let signed = credits_sign_policy(device.signing_private_key,
    Crypto.sha256(profile.entry.mailbox_token),
    Math.max(credits_now(), previous + 1),
    postage)?
  credits_store_writes(path, credits_sealed_write(credits_inbox_label(), signed, wrapping_key)?)?
  Ok(signed)
end

## Longer storage for this device's mailbox: `periods` x 30 days (1 to 5) at
## 10 credits each, for POST /v1/mailbox/retention at the edge. Request:
## vector32(path) || vector32(u8 periods).

pub fn credits_retention(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 2)?
  let path = credits_path(List.get(fields, 0))?
  let periods = credits_small(List.get(fields, 1))?
  if periods < 1 || periods > 5 do
    return Err("invalid_credits_request")
  end
  credits_issuer_origin()?
  let wrapping_key = platform_key()?
  let profile = local_profile(path)?
  let device = open_device(profile, wrapping_key, path)?
  let frame = credits_sign_retention(device.signing_private_key,
    Crypto.sha256(profile.entry.mailbox_token),
    periods,
    credits_now())?
  credits_reserve(path,
    purpose_of("retention", profile.entry.mailbox_token)?,
    credits_action_storage(),
    credits_retention_price(periods),
    frame)
end

## Skipping a busy sign-up: CRD (20 credits) || PWR(DRE) at the pinned base
## difficulty, for PUT /v1/devices/register. Request: vector32(path).

pub fn credits_signup(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 1)?
  let path = credits_path(List.get(fields, 0))?
  credits_issuer_origin()?
  let entry = directory_entry_for(path)?
  credits_reserve(path,
    purpose_of("signup", entry)?,
    credits_action_signup(),
    20,
    stamped_request("mesh-msg/v1/work/register", entry)?)
end

## The registration minted at a higher difficulty (a 429's WRK), the free way
## past a busy sign-up. Request: vector32(path) || vector32(u8 difficulty).

pub fn credits_register_at(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 2)?
  let path = credits_path(List.get(fields, 0))?
  let difficulty = credits_small(List.get(fields, 1))?
  let config = native_security_config()?
  if difficulty < config.abuse_difficulty || difficulty > 24 do
    return Err("invalid_credits_request")
  end
  let entry = directory_entry_for(path)?
  let expires_at = case U64.parse(Int.to_string(credits_now() + 240000)) do
    Err(_) -> Err("invalid_credits_request")
    Ok(value)
  end?
  encode_stamped_request(mint_request_stamp("mesh-msg/v1/work/register",
      entry,
      expires_at,
      difficulty)?,
    entry)
end

## Tokens for a request whose own export attaches them: a large file's
## object grant (action 4), which Mobile.Attachments frames itself. Request:
## vector32(path) || vector32(u8 count) || vector32(purpose32: the same for
## every retry of one request). Answer: the spend frame, carrying the
## concatenated 354-byte tokens instead of a request.

pub fn credits_spend(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 3)?
  let path = credits_path(List.get(fields, 0))?
  let count = credits_small(List.get(fields, 1))?
  let purpose = List.get(fields, 2)
  if Bytes.length(purpose) != 32 do
    return Err("invalid_credits_request")
  end
  credits_issuer_origin()?
  reserve(path, purpose_of("file", purpose)?, credits_action_file(), count, None)
end

# Status.

fn retention(path :: String, wrapping_key :: borrow StorageKey) -> (Int, Int)!String do
  let stored = credits_load_sealed(path, wrapping_key, retention_label())?
  if Bytes.length(stored) == 0 do
    Ok((0, 0))
  else
    credits_decode_retention_answer(stored)
  end
end

fn purchases_rows(path :: String, wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
  let values = List.reverse(credits_load_purchases(path, wrapping_key)?)
  let rows = for value in values do
    tcodec_vector(credits_encode_purchase(value)?)?
  end
  Ok(rows)
end

## The Credits screen: u8 1 || "CST" || u8 sold (this build sells credits) ||
## u8 purpose (1 live, 2 test) || u32 spendable || u32 cooling || u64
## cooling_until_ms || u32 expiring || u64 expiring_at_ms || u64
## keys_fetched_ms || u8 inbox postage || u16 retention_days || u64
## retention_until_ms || u8 n || n x vector32(purchase), newest first.
## Request: vector32(path).

pub fn credits_status(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 1)?
  let path = credits_path(List.get(fields, 0))?
  let wrapping_key = platform_key()?
  let (sold, purpose) = case credits_issuer_origin() do
    Err(_) -> (0, 0)
    Ok(origin) -> (1, credits_build_purpose(origin))
  end
  let now = credits_now()
  let keys = credits_load_keys(path, wrapping_key)?
  let shelves = credits_load_shelves(path, wrapping_key)?
  let (ready, cooling, until) = credits_counts(shelves, keys.keys, now)
  let (expiring, expiring_at) = credits_expiring(shelves, keys.keys, now)
  let (postage, _) = inbox_price(path, wrapping_key)?
  let (days, entitled_until) = retention(path, wrapping_key)?
  let rows = purchases_rows(path, wrapping_key)?
  tcodec_join([
    tcodec_u8(1)?,
    Bytes.from_utf8("CST"),
    tcodec_u8(sold)?,
    tcodec_u8(purpose)?,
    tcodec_u32(ready)?,
    tcodec_u32(cooling)?,
    tcodec_u64(until)?,
    tcodec_u32(expiring)?,
    tcodec_u64(expiring_at)?,
    tcodec_u64(keys.fetched_at)?,
    tcodec_u8(postage)?,
    tcodec_u16(days)?,
    tcodec_u64(entitled_until)?,
    tcodec_u8(List.length(rows))?
  ]
    ++ rows)
end
