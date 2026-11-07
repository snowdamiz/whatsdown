from Mobile.PostagePolicyIntent import retain_postage_policy_intent, load_postage_policy_intent
from Mobile.CreditNonce import issued_credit_intent_nonce, require_fresh_credit_intent_nonce
from Mobile.Codec import mobile_write_u32
from Mobile.DeviceSet import verified_device_set
from Mobile.Transparency import require_transparency_device_set
from Mobile.PostageCandidates import postage_candidate, postage_message_id
from Mobile.History import postage_message_recipient
from Mobile.CreditWallet import credit_wallet_balance
from Credits.Action import decode_credit_action
from Credits.PostagePolicy import (
  PostagePolicy,
  decode_postage_policy,
  postage_policy_from_device_set,
  sign_postage_policy,
  encode_postage_policy
)
from Mobile.Codec import current_time, mobile_byte, mobile_write_u16, mobile_write_u64, mobile_utf8
from Mobile.CreditPostage import (
  CreditPostagePlan,
  prepare_credit_postage,
  recover_credit_postage,
  accept_credit_postage_response,
  credit_postage_inventory
)
from Mobile.CreditTransport import post_credit
from Transparency.Config import encode_security_config
from Mobile.Codec import mobile_read_u64
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.Platform import native_security_config
from Mobile.Profile import load_profile, open_account
from Mobile.Transparency import fresh_account_device_set
from Privacy.Edge import mint_request_stamp, encode_stamped_request
from Storage.Credits import CreditWalletIdentity, load_credit_wallet
from Storage.Keys import platform_key
from Transparency.Config import SecurityConfig
from Transport.Packet import decode_client_profile

struct NativePostageRequest do
  path :: String
  parts :: List<Bytes>
end

fn parsed_postage_request(input :: Bytes, count :: Int) -> NativePostageRequest!String do
  if Bytes.length(input) > 1100000 do
    return Err("invalid_credit_postage_request")
  end
  let parts = unpack_credit_parts(input, count, 541865)?
  if List.length(parts) != count
    || Bytes.length(List.head(parts)) < 1
    || Bytes.length(List.head(parts)) > 4096 do
    return Err("invalid_credit_postage_request")
  end
  Ok(NativePostageRequest {
    path: mobile_utf8(List.head(parts), "invalid_credit_postage_request")?,
    parts: parts
  })
end

fn postage_wallet_identity(path :: String,
  config :: SecurityConfig) -> CreditWalletIdentity!String do
  if config.issuer_origin == "-" || config.log_version != 2 do
    return Err("credits_disabled")
  end
  let selector = case Host.push_get_token(Bytes.from_utf8("messenger/credits/v1")) do
    Err(_) -> return Err("credits_disabled")
    Ok(value) -> value
  end
  if Bytes.length(selector) != 2 || Bytes.get(selector, 0)? != 1 || Bytes.get(selector, 1)? > 1 do
    return Err("credits_disabled")
  end
  let profile = decode_client_profile(load_profile(path)?)?
  Ok(CreditWalletIdentity {
    account_id: profile.account_id,
    device_id: profile.device_id,
    service_key: config.service_public_key,
    purpose: Bytes.get(selector, 1)?
  })
end

fn postage_output(value :: CreditPostagePlan, config :: SecurityConfig) -> Bytes!String do
  let now = current_time()?
  let expired = U64.compare(U64.divide(now, U64.parse("1000")?)?,
    decode_credit_action(value.spend.action)?.expires_at) >= 0
  let route = if value.spend.status != 0 do
    ""
  else if expired do
    "/v1/credits/postage/reconcile"
  else
    "/v1/credits/postage"
  end
  let body = if value.spend.status == 0 do
    let label = if expired do
      "mesh-msg/v1/work/postage/reconcile"
    else
      "mesh-msg/v1/work/postage"
    end
    encode_stamped_request(mint_request_stamp(label,
        value.batch,
        U64.add(now, U64.parse("240000")?)?,
        config.abuse_difficulty)?,
      value.batch)?
  else
    Bytes.empty()
  end
  pack_credit_parts([
    Bytes.from_hex("014d5053")?,
    value.nonce,
    value.spend.operation_id,
    mobile_byte(value.spend.status)?,
    mobile_write_u16(value.spend.credits)?,
    mobile_write_u64(value.spend.revision)?,
    Bytes.from_utf8(config.issuer_origin),
    Bytes.from_utf8(route),
    body
  ])
end

# Input is [database, nonce32, admitted DeviceSet, counted1..8 outbox IDs16].
# All encryption/selection occurs natively. Output contains only opaque PSB/PWR,
# aggregate count/status and the release-pinned origin, never CAP or reply keys.
pub fn native_credit_postage_prepare(input :: Bytes) -> Bytes!String do
  let parsed = parsed_postage_request(input, 4)?
  let config = native_security_config()?
  let who = postage_wallet_identity(parsed.path, config)?
  let wrapping = platform_key()?
  let ids = unpack_credit_parts(List.get(parsed.parts, 3), 8, 16)?
  let timestamp = current_time()?
  require_fresh_credit_intent_nonce(parsed.path,
    wrapping,
    who,
    3,
    List.get(parsed.parts, 1),
    timestamp)?
  postage_output(prepare_credit_postage(parsed.path,
      wrapping,
      who,
      List.get(parsed.parts, 1),
      List.get(parsed.parts, 2),
      ids,
      X25519PublicKey { bytes: config.delivery_public_key },
      timestamp)?,
    config)
end

pub fn native_credit_postage_recover(input :: Bytes) -> Bytes!String do
  let parsed = parsed_postage_request(input, 2)?
  let config = native_security_config()?
  let who = postage_wallet_identity(parsed.path, config)?
  let wrapping = platform_key()?
  postage_output(recover_credit_postage(parsed.path,
      wrapping,
      who,
      List.get(parsed.parts, 1),
      current_time()?)?,
    config)
end

pub fn native_credit_postage_receipt(input :: Bytes) -> Bytes!String do
  let parsed = parsed_postage_request(input, 3)?
  let config = native_security_config()?
  let who = postage_wallet_identity(parsed.path, config)?
  let wrapping = platform_key()?
  postage_output(accept_credit_postage_response(parsed.path,
      wrapping,
      who,
      List.get(parsed.parts, 1),
      List.get(parsed.parts, 2),
      current_time()?)?,
    config)
end

fn policy_output(policy :: PostagePolicy, config :: SecurityConfig) -> Bytes!String do
  pack_credit_parts([
    Bytes.from_hex("014d5050")?,
    policy.account_id,
    mobile_write_u64(policy.revision)?,
    mobile_write_u64(policy.expected_device_set_revision)?,
    mobile_byte(policy.credits)?,
    Bytes.from_utf8(config.issuer_origin),
    Bytes.from_utf8("/v1/credits/postage-policy"),
    encode_postage_policy(policy)?
  ])
end

# Public setting data comes only from the fresh witnessed cache. A linked
# device can read it; signing a change below additionally requires AccountKeys.
pub fn native_postage_policy_view(input :: Bytes) -> Bytes!String do
  let parsed = parsed_postage_request(input, 2)?
  let wrapping = platform_key()?
  let devices = fresh_account_device_set(parsed.path, wrapping, List.get(parsed.parts, 1))?
  let policy = postage_policy_from_device_set(devices.value)?
  let revision = case policy do
    None -> U64.parse("0")?
    Some(value) -> value.revision
  end
  let credits = case policy do
    None -> 0
    Some(value) -> value.credits
  end
  let profile = decode_client_profile(load_profile(parsed.path)?)?
  let pending = if Bytes.secure_equals(profile.account_id, devices.account.account_id) do
    let config = native_security_config()?
    let intent = case load_postage_policy_intent(parsed.path,
      wrapping,
      profile.account,
      profile.device_id,
      config) do
      Ok(value) -> Some(value)
      Err(error) -> if error == "local_state_not_found" do
        None
      else
        return Err(error)
      end
    end
    case intent do
      None -> Bytes.empty()
      Some(value) -> if U64.compare(value.revision, revision) > 0
        && value.expected_device_set_revision == devices.value.sequence do
        policy_output(value, config)?
      else
        Bytes.empty()
      end
    end
  else
    Bytes.empty()
  end
  pack_credit_parts([
    Bytes.from_hex("024d5056")?,
    devices.account.account_id,
    mobile_write_u64(revision)?,
    mobile_write_u64(devices.value.sequence)?,
    mobile_byte(credits)?,
    pending
  ])
end

# The signed PPY is public and safe to retry byte-for-byte. Its HTTP ack is
# never admission: refresh/verify directory evidence before displaying applied.
pub fn native_postage_policy_prepare(input :: Bytes) -> Bytes!String do
  let parsed = parsed_postage_request(input, 2)?
  let level = List.get(parsed.parts, 1)
  if Bytes.length(level) != 1 || !List.contains([0, 1, 5, 25], Bytes.get(level, 0)?) do
    return Err("invalid_postage_policy")
  end
  let config = native_security_config()?
  if config.issuer_origin == "-" || config.log_version != 2 do
    return Err("credits_disabled")
  end
  let profile = decode_client_profile(load_profile(parsed.path)?)?
  let wrapping = platform_key()?
  let devices = fresh_account_device_set(parsed.path, wrapping, profile.account_id)?
  let prior = case postage_policy_from_device_set(devices.value)? do
    None -> U64.parse("0")?
    Some(value) -> value.revision
  end
  let owner = open_account(profile, wrapping, parsed.path)?
  let policy = sign_postage_policy(owner,
    profile.device_id,
    U64.add(prior, U64.parse("1")?)?,
    devices.value.sequence,
    Bytes.get(level, 0)?,
    current_time()?)?
  let stored = retain_postage_policy_intent(parsed.path,
    wrapping,
    profile.account,
    profile.device_id,
    config,
    policy)?
  policy_output(decode_postage_policy(stored)?, config)
end

# Preview is read-only. The trigger selects one authenticated local delivery
# group, and the witnessed policy supplies its one account-wide count.
pub fn native_credit_postage_preview(input :: Bytes) -> Bytes!String do
  let parsed = parsed_postage_request(input, 3)?
  let config = native_security_config()?
  let who = postage_wallet_identity(parsed.path, config)?
  let wrapping = platform_key()?
  let devices = verified_device_set(List.get(parsed.parts, 1))?
  require_transparency_device_set(parsed.path, wrapping, devices)?
  let candidate = postage_candidate(parsed.path, wrapping, devices, List.get(parsed.parts, 2))?
  let policy = case postage_policy_from_device_set(devices.value)? do
    None -> return Err("credits_not_required")
    Some(value) -> value
  end
  if policy.credits == 0 do
    return Err("credits_not_required")
  end
  let nonce = issued_credit_intent_nonce(current_time()?)?
  let balance = credit_wallet_balance(parsed.path,
    wrapping,
    who,
    U64.divide(current_time()?, U64.parse("1000")?)?)?
  pack_credit_parts([
    Bytes.from_hex("014d5042")?,
    nonce,
    devices.account.account_id,
    Bytes.from_utf8(devices.value.username),
    candidate.message_id,
    candidate.trigger_id,
    pack_credit_parts(candidate.ids)?,
    mobile_write_u64(policy.revision)?,
    mobile_write_u64(devices.value.sequence)?,
    mobile_write_u16(policy.credits)?,
    mobile_byte(who.purpose)?,
    mobile_write_u32(balance.available)?,
    mobile_write_u32(balance.reserved)?
  ])
end

pub fn native_credit_postage_candidate(input :: Bytes) -> Bytes!String do
  let parsed = parsed_postage_request(input, 2)?
  let wrapping = platform_key()?
  let trigger = List.get(parsed.parts, 1)
  let message = postage_message_id(parsed.path, wrapping, trigger)?
  let recipient = postage_message_recipient(parsed.path, wrapping, message)?
  pack_credit_parts([
    Bytes.from_hex("014d5043")?,
    recipient.account_id,
    Bytes.from_utf8(recipient.username),
    message,
    trigger
  ])
end

pub fn native_credit_postage_inventory(input :: Bytes) -> Bytes!String do
  let parsed = parsed_postage_request(input, 1)?
  let config = native_security_config()?
  let who = postage_wallet_identity(parsed.path, config)?
  let wrapping = platform_key()?
  let rows = credit_postage_inventory(parsed.path, wrapping, who)?
  let revision = load_credit_wallet(parsed.path, wrapping, who)?.wallet.revision
  let encoded = for row in rows do
    pack_credit_parts([
      row.nonce,
      row.message_id,
      row.account_id,
      Bytes.from_utf8(row.username),
      row.operation_id,
      mobile_byte(row.status)?,
      mobile_write_u16(row.credits)?,
      mobile_write_u64(row.expires_at)?,
      pack_credit_parts(row.ids)?
    ])?
  end
  pack_credit_parts([
    Bytes.from_hex("014d5049")?,
    mobile_write_u64(revision)?,
    mobile_byte(who.purpose)?
  ]
    ++ encoded)
end

# One typed attempt against a saved encrypted postage journal. No URL, body or
# reply supplied by JavaScript can authorize or complete this operation.
pub fn native_credit_postage_continue(input :: Bytes) -> Bytes!String do
  let parsed = parsed_postage_request(input, 2)?
  let nonce = List.get(parsed.parts, 1)
  if Bytes.length(nonce) != 32 || Bytes.to_hex(nonce) == String.repeat("00", 32) do
    return Err("invalid_credit_postage_request")
  end
  let config = native_security_config()?
  let who = postage_wallet_identity(parsed.path, config)?
  let wrapping = platform_key()?
  let before = recover_credit_postage(parsed.path, wrapping, who, nonce, current_time()?)?
  let saved = postage_output(before, config)?
  if before.spend.status != 0 do
    return Ok(saved)
  end
  let fields = unpack_credit_parts(saved, 9, 600000)?
  let route = mobile_utf8(List.get(fields, 7), "invalid_credit_postage_request")?
  let response = post_credit(config, route, List.get(fields, 8))?
  if Bytes.length(response) != 564 do
    return Err("invalid_postage_reply")
  end
  let current_config = native_security_config()?
  let current_who = postage_wallet_identity(parsed.path, current_config)?
  if !Bytes.secure_equals(encode_security_config(config)?, encode_security_config(current_config)?)
    || !Bytes.secure_equals(who.account_id, current_who.account_id)
    || !Bytes.secure_equals(who.device_id, current_who.device_id)
    || who.purpose != current_who.purpose do
    return Err("postage_identity_changed")
  end
  let accepted = accept_credit_postage_response(parsed.path,
    wrapping,
    who,
    nonce,
    response,
    current_time()?)?
  postage_output(accepted, config)
end

# Input is [database, expected policy revision8, expected device-set revision8,
# level1]. The native core signs from the fresh witnessed cache. An HTTP ack
# remains only an ack; the caller must refresh and witness the published policy.
pub fn native_postage_policy_publish(input :: Bytes) -> Bytes!String do
  let parsed = parsed_postage_request(input, 4)?
  let revision = List.get(parsed.parts, 1)
  let device_revision = List.get(parsed.parts, 2)
  if Bytes.length(revision) != 8 || Bytes.length(device_revision) != 8 do
    return Err("invalid_postage_policy")
  end
  let level = List.get(parsed.parts, 3)
  if Bytes.length(level) != 1 || !List.contains([0, 1, 5, 25], Bytes.get(level, 0)?) do
    return Err("invalid_postage_policy")
  end
  let config = native_security_config()?
  if config.issuer_origin == "-" || config.log_version != 2 do
    return Err("credits_disabled")
  end
  let profile = decode_client_profile(load_profile(parsed.path)?)?
  let wrapping = platform_key()?
  let saved = load_postage_policy_intent(parsed.path,
    wrapping,
    profile.account,
    profile.device_id,
    config)?
  if saved.revision != mobile_read_u64(revision)?
    || saved.expected_device_set_revision != mobile_read_u64(device_revision)?
    || saved.credits != Bytes.get(level, 0)? do
    return Err("postage_policy_changed")
  end
  let devices = fresh_account_device_set(parsed.path, wrapping, profile.account_id)?
  let admitted = postage_policy_from_device_set(devices.value)?
  let current_revision = case admitted do
    None -> U64.parse("0")?
    Some(value) -> value.revision
  end
  if U64.compare(current_revision, saved.revision) >= 0 do
    let current_level = case admitted do
      None -> 0
      Some(value) -> value.credits
    end
    if current_level == saved.credits
      && U64.compare(devices.value.sequence, saved.expected_device_set_revision) > 0 do
      return Ok(Bytes.empty())
    end
    return Err("postage_policy_changed")
  end
  if U64.add(current_revision, U64.parse("1")?)? != saved.revision
    || devices.value.sequence != saved.expected_device_set_revision do
    return Err("postage_policy_changed")
  end
  let acknowledgement = post_credit(config,
    "/v1/credits/postage-policy",
    encode_postage_policy(saved)?)?
  if Bytes.length(acknowledgement) != 8 || mobile_read_u64(acknowledgement)? == U64.parse("0")? do
    return Err("invalid_postage_reply")
  end
  Ok(Bytes.empty())
end
