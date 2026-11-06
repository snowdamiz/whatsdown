from Mobile.CreditMaintenance import maintain_credit_storage
from Mobile.CreditPaymentNetwork import (
  CreditWalletPaymentPlan,
  prepare_credit_wallet_payment,
  commit_credit_wallet_payment,
  submit_credit_wallet_payment
)
from Transparency.AnchorChain import configured_anchor_pins
from Mobile.CreditAdmission import credit_discovery_plan, admit_credit_issuer
from Mobile.CreditPurchase import (
  CreditPurchasePlan,
  prepare_credit_purchase,
  prepare_credit_purchase_again,
  prepare_lightning_purchase,
  recover_credit_purchase,
  accept_credit_quote,
  record_credit_payment,
  finalize_credit_purchase,
  credit_purchase_ids
)
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.CreditWallet import (
  CreditSpendPlan,
  credit_wallet_balance,
  reserve_credit_spend,
  recover_credit_reservation
)
from Mobile.CreditWallet import (
  accept_credit_cancellation,
  accept_credit_attachment_receipt
)
from Mobile.SignupDraft import (
  rename_signup_draft,
  select_free_signup_draft,
  prepare_signup_draft,
  recover_signup_draft,
  complete_signup_draft,
  complete_free_signup_draft,
  require_free_registration_allowed
)
from Credits.Cancellation import decode_credit_cancellation
from Credits.SignupPolicy import (
  decode_credit_signup_policy,
  verify_credit_signup_policy,
  credit_signup_policy_price
)
from Mobile.Codec import (
  current_time,
  mobile_byte,
  mobile_read_u32,
  mobile_write_u16,
  mobile_write_u32,
  mobile_write_u64,
  mobile_utf8
)
from Mobile.Platform import native_security_config
from Mobile.CreditTransport import post_credit
from Mobile.Profile import load_profile
from Mobile.Account import directory_entry_for
from Privacy.Edge import encode_stamped_request, mint_request_stamp
from Mobile.Profile import open_device
from Credits.Action import decode_credit_action, encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  encode_credit_action_submission,
  decode_credit_action_receipt
)
from Credits.Retention import (
  sign_credit_retention_request,
  encode_credit_retention_request,
  credit_retention_action
)
from Credits.Wire import decode_credit_frame
from Credits.Issuance import decode_credit_quote
from Credits.Lightning import decode_lightning_quote
from Credits.Payment import solana_pay_url
from Mobile.CreditWallet import accept_credit_retention_receipt, pending_credit_retention
from Mobile.Codec import random_bytes
from Storage.Keys import platform_key
from Storage.Credits import CreditWalletIdentity
from Transparency.Config import SecurityConfig
from Transport.Packet import decode_client_profile

struct NativeCreditRequest do
  path :: String
  parts :: List<Bytes>
end

fn request(input :: Bytes, count :: Int) -> NativeCreditRequest!String do
  if Bytes.length(input) > 1100000 do
    return Err("invalid_credit_request")
  end
  let parts = unpack_credit_parts(input, count, 1050000)?
  if List.length(parts) != count
    || Bytes.length(List.head(parts)) < 1
    || Bytes.length(List.head(parts)) > 4096 do
    return Err("invalid_credit_request")
  end
  Ok(NativeCreditRequest {
    path: mobile_utf8(List.head(parts), "invalid_credit_request")?,
    parts: parts
  })
end

fn configured_purpose(config :: SecurityConfig) -> Int!String do
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
  Bytes.get(selector, 1)
end

pub fn require_credit_signup_enabled() -> Result<(), String> do
  configured_purpose(native_security_config()?)?
  Ok(())
end

fn identity(path :: String, config :: SecurityConfig) -> CreditWalletIdentity!String do
  let purpose = configured_purpose(config)?
  let profile = decode_client_profile(load_profile(path)?)?
  Ok(CreditWalletIdentity {
    account_id: profile.account_id,
    device_id: profile.device_id,
    service_key: config.service_public_key,
    purpose: purpose
  })
end

fn now() -> U64!String do
  U64.divide(current_time()?, U64.parse("1000")?)
end

fn lightning_network(purpose :: Int) -> Int!String do
  let value = case Host.push_get_token(Bytes.from_utf8("messenger/lightning/v1")) do
    Ok(bytes) -> bytes
    Err(_) -> return Err("lightning_configuration_required")
  end
  if Bytes.length(value) != 2 || Bytes.get(value, 0)? != 1 do
    return Err("lightning_configuration_required")
  end
  let network = Bytes.get(value, 1)?
  if (purpose == 0 && network != 0) || (purpose == 1 && (network < 1 || network > 4)) do
    return Err("lightning_configuration_required")
  end
  Ok(network)
end

# Native outputs are counted u32 vectors, like requests. These plans contain
# no account/device identifiers, cookies or authorization headers for the edge.
fn purchase_output(value :: CreditPurchasePlan, config :: SecurityConfig) -> Bytes!String do
  let route = if value.stage == 0 do
    if value.asset == 2 do
      "/v1/credits/lightning/quote"
    else
      "/v1/credits/quote"
    end
  else if value.stage == 2 do
    if value.asset == 2 do
      "/v1/credits/lightning/issue"
    else
      "/v1/credits/issue"
    end
  else
    ""
  end
  let body = if value.stage == 0 do
    value.quote_request
  else if value.stage == 2 do
    value.issue_request
  else
    Bytes.empty()
  end
  pack_credit_parts([
    Bytes.from_hex("024d4350")?,
    value.purchase_id,
    mobile_byte(value.stage)?,
    mobile_write_u16(value.credits)?,
    mobile_write_u64(value.revision)?,
    Bytes.from_utf8(config.issuer_origin),
    Bytes.from_utf8(route),
    body,
    value.quote,
    mobile_byte(value.asset)?
  ])
end

fn reservation_output(value :: CreditSpendPlan) -> Bytes!String do
  if decode_credit_action(value.action)?.kind == 3 do
    return Err("use_opaque_postage_builder")
  end
  pack_credit_parts([
    Bytes.from_hex("014d4352")?,
    value.operation_id,
    mobile_byte(value.status)?,
    mobile_write_u16(value.credits)?,
    mobile_write_u64(value.revision)?,
    value.action,
    value.request_body,
    value.frame
  ])
end

pub fn native_credit_discovery(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 1)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  let plan = credit_discovery_plan(parsed.path, wrapping, who, config)?
  pack_credit_parts([
    Bytes.from_hex("014d4344")?,
    Bytes.from_utf8(plan.origin),
    Bytes.from_utf8("/v1/credits/issuer"),
    plan.body
  ])
end

pub fn native_credit_admit(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  let id = admit_credit_issuer(parsed.path,
    wrapping,
    who,
    config,
    List.get(parsed.parts, 1),
    now()?)?
  pack_credit_parts([Bytes.from_hex("014d4341")?, id])
end


pub fn native_credit_discover_online(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 1)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  let plan = credit_discovery_plan(parsed.path, wrapping, who, config)?
  let response = post_credit(config, "/v1/credits/issuer", plan.body)?
  let id = admit_credit_issuer(parsed.path, wrapping, who, config, response, now()?)?
  pack_credit_parts([Bytes.from_hex("014d4341")?, id])
end

pub fn native_credit_purchase_continue(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  let id = List.get(parsed.parts, 1)
  let plan = recover_credit_purchase(parsed.path, wrapping, who, id)?
  if plan.stage != 0 && plan.stage != 2 do
    return purchase_output(plan, config)
  end
  let route = if plan.asset == 2 do
    if plan.stage == 0 do
      "/v1/credits/lightning/quote"
    else
      "/v1/credits/lightning/issue"
    end
  else
    if plan.stage == 0 do
      "/v1/credits/quote"
    else
      "/v1/credits/issue"
    end
  end
  let response = post_credit(config,
    route,
    if plan.stage == 0 do
      plan.quote_request
    else
      plan.issue_request
    end)?
  let updated = if plan.stage == 0 do
    accept_credit_quote(parsed.path, wrapping, who, id, response, now()?)?
  else
    finalize_credit_purchase(parsed.path, wrapping, who, id, response, now()?)?
  end
  purchase_output(updated, config)
end

pub fn native_credit_prepare(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  if Bytes.length(List.get(parsed.parts, 1)) != 4 || Bytes.length(List.get(parsed.parts, 2)) != 1 do
    return Err("invalid_credit_request")
  end
  let credits = mobile_read_u32(List.get(parsed.parts, 1))?
  let asset = Bytes.get(List.get(parsed.parts, 2), 0)?
  let wrapping = platform_key()?
  if asset == 2 do
    return purchase_output(prepare_lightning_purchase(parsed.path,
        wrapping,
        who,
        credits,
        lightning_network(who.purpose)?,
        now()?,
        false)?,
      config)
  end
  purchase_output(prepare_credit_purchase(parsed.path, wrapping, who, credits, asset, now()?)?,
    config)
end

pub fn native_credit_prepare_again(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  if Bytes.length(List.get(parsed.parts, 1)) != 4 || Bytes.length(List.get(parsed.parts, 2)) != 1 do
    return Err("invalid_credit_request")
  end
  let wrapping = platform_key()?
  if Bytes.get(List.get(parsed.parts, 2), 0)? == 2 do
    return purchase_output(prepare_lightning_purchase(parsed.path,
        wrapping,
        who,
        mobile_read_u32(List.get(parsed.parts, 1))?,
        lightning_network(who.purpose)?,
        now()?,
        true)?,
      config)
  end
  purchase_output(prepare_credit_purchase_again(parsed.path,
      wrapping,
      who,
      mobile_read_u32(List.get(parsed.parts, 1))?,
      Bytes.get(List.get(parsed.parts, 2), 0)?,
      now()?)?,
    config)
end

pub fn native_credit_quote(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  purchase_output(accept_credit_quote(parsed.path,
      wrapping,
      who,
      List.get(parsed.parts, 1),
      List.get(parsed.parts, 2),
      now()?)?,
    config)
end

pub fn native_credit_payment(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  purchase_output(record_credit_payment(parsed.path,
      wrapping,
      who,
      List.get(parsed.parts, 1),
      List.get(parsed.parts, 2),
      now()?)?,
    config)
end

pub fn native_credit_finalize(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  purchase_output(finalize_credit_purchase(parsed.path,
      wrapping,
      who,
      List.get(parsed.parts, 1),
      List.get(parsed.parts, 2),
      now()?)?,
    config)
end

pub fn native_credit_recover(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  purchase_output(recover_credit_purchase(parsed.path, wrapping, who, List.get(parsed.parts, 1))?,
    config)
end

pub fn native_credit_purchases(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 1)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  pack_credit_parts([Bytes.from_hex("014d434c")?]
    ++ credit_purchase_ids(parsed.path, wrapping, who)?)
end

pub fn native_credit_balance(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 1)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  let timestamp = now()?
  maintain_credit_storage(parsed.path, wrapping, who, timestamp)?
  let balance = credit_wallet_balance(parsed.path, wrapping, who, timestamp)?
  pack_credit_parts([
    Bytes.from_hex("034d4342")?,
    mobile_write_u32(balance.available)?,
    mobile_write_u32(balance.delayed)?,
    mobile_write_u32(balance.reserved)?,
    mobile_write_u32(balance.expired)?,
    mobile_write_u32(balance.pending_purchases)?,
    mobile_byte(who.purpose)?,
    mobile_byte(case lightning_network(who.purpose) do
      Ok(value) -> value
      Err(_) -> 255
    end)?
  ])
end

pub fn native_credit_reserve(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  if decode_credit_action(List.get(parsed.parts, 1))?.kind == 2 do
    return Err("use_native_retention_builder")
  end
  let wrapping = platform_key()?
  reservation_output(reserve_credit_spend(parsed.path,
    wrapping,
    who,
    List.get(parsed.parts, 1),
    List.get(parsed.parts, 2),
    now()?)?)
end

pub fn native_credit_reservation(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  reservation_output(recover_credit_reservation(parsed.path,
    wrapping,
    who,
    List.get(parsed.parts, 1))?)
end

fn retention_output(value :: CreditSpendPlan, config :: SecurityConfig) -> Bytes!String do
  let action = decode_credit_action(value.action)?
  if action.kind != 2 do
    return Err("unsupported_mobile_credit_action")
  end
  let body = encode_credit_action_submission(CreditActionSubmission {
    action: action,
    request_body: value.request_body,
    frame: decode_credit_frame(value.frame)?
  })?
  pack_credit_parts([
    Bytes.from_hex("014d4354")?,
    value.operation_id,
    mobile_byte(value.status)?,
    mobile_write_u64(value.revision)?,
    Bytes.from_utf8(config.issuer_origin),
    Bytes.from_utf8(if value.status == 0 do
      "/v1/credits/retention"
    else
      ""
    end),
    if value.status == 0 do
      body
    else
      Bytes.empty()
    end
  ])
end

pub fn native_credit_retention(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  if Bytes.length(List.get(parsed.parts, 1)) != 4 do
    return Err("invalid_credit_request")
  end
  let days = mobile_read_u32(List.get(parsed.parts, 1))?
  let wrapping = platform_key()?
  let profile = decode_client_profile(load_profile(parsed.path)?)?
  let mailbox_hash = Crypto.sha256(profile.entry.mailbox_token)
  case pending_credit_retention(parsed.path, wrapping, who, mailbox_hash)? do
    Some(saved) -> do
      if decode_credit_action(saved.action)?.quantity != U64.parse(Int.to_string(days))? do
        return Err("credit_retention_pending")
      end
      return retention_output(saved, config)
    end
    None -> nil
  end
  let device = open_device(profile, wrapping, parsed.path)?
  let issued = current_time()?
  let seconds = U64.divide(issued, U64.parse("1000")?)?
  let descriptor = sign_credit_retention_request(device.signing_private_key,
    mailbox_hash,
    random_bytes(32)?,
    days,
    U64.add(seconds, U64.parse("300")?)?,
    issued)?
  let action = encode_credit_action(credit_retention_action(descriptor)?)?
  retention_output(reserve_credit_spend(parsed.path,
      wrapping,
      who,
      action,
      encode_credit_retention_request(descriptor)?,
      seconds)?,
    config)
end

pub fn native_credit_retention_recover(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  retention_output(recover_credit_reservation(parsed.path,
      wrapping,
      who,
      List.get(parsed.parts, 1))?,
    config)
end

pub fn native_credit_receipt(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  let response = List.get(parsed.parts, 1)
  if Bytes.length(response) == 172 do
    let cancellation = decode_credit_cancellation(response)?
    let saved = recover_credit_reservation(parsed.path, wrapping, who, cancellation.operation_id)?
    if decode_credit_action(saved.action)?.kind == 3 do
      return Err("use_opaque_postage_builder")
    end
    return reservation_output(accept_credit_cancellation(parsed.path, wrapping, who, response)?)
  end
  let receipt = decode_credit_action_receipt(response)?
  let saved = recover_credit_reservation(parsed.path, wrapping, who, receipt.operation_id)?
  let completed = case decode_credit_action(saved.action)?.kind do
    1 -> accept_credit_attachment_receipt(parsed.path, wrapping, who, response)?
    2 -> do
      let profile = decode_client_profile(load_profile(parsed.path)?)?
      accept_credit_retention_receipt(parsed.path,
        wrapping,
        who,
        Crypto.sha256(profile.entry.mailbox_token),
        response)?
    end
    4 -> complete_signup_draft(parsed.path, wrapping, who, response)?
    _ -> return Err("unsupported_mobile_credit_action")
  end
  reservation_output(completed)
end

pub fn native_credit_action_recovery(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  let plan = recover_credit_reservation(parsed.path, wrapping, who, List.get(parsed.parts, 1))?
  let action = decode_credit_action(plan.action)?
  if action.kind == 3 do
    return Err("use_opaque_postage_builder")
  end
  let body = if plan.status == 0 do
    encode_credit_action_submission(CreditActionSubmission {
      action: action,
      request_body: plan.request_body,
      frame: decode_credit_frame(plan.frame)?
    })?
  else
    Bytes.empty()
  end
  pack_credit_parts([
    Bytes.from_hex("014d4345")?,
    plan.operation_id,
    mobile_byte(plan.status)?,
    mobile_byte(action.kind)?,
    mobile_write_u64(plan.revision)?,
    Bytes.from_utf8(config.issuer_origin),
    Bytes.from_utf8(if plan.status == 0 do
      "/v1/credits/reconcile"
    else
      ""
    end),
    body
  ])
end

pub fn native_credit_signup_policy(input :: Bytes) -> Bytes!String do
  request(input, 1)?
  let config = native_security_config()?
  configured_purpose(config)?
  pack_credit_parts([
    Bytes.from_hex("014d4359")?,
    Bytes.from_utf8(config.issuer_origin),
    Bytes.from_utf8("/v1/credits/signup-policy"),
    Bytes.empty()
  ])
end

pub fn native_credit_signup_policy_online(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 1)?
  let config = native_security_config()?
  configured_purpose(config)?
  let statement = post_credit(config, "/v1/credits/signup-policy", Bytes.empty())?
  let verified = unpack_credit_parts(native_credit_signup_policy_view(pack_credit_parts([
      Bytes.from_utf8(parsed.path),
      statement
    ])?)?,
    7,
    88)?
  pack_credit_parts([Bytes.from_hex("02535056")?] ++ List.drop(verified, 1) ++ [statement])
end

# This is an internal domain helper, never a host export. Bind the reply to the
# operation that authorized this HTTP attempt before the receipt verifier can
# touch any journal entry. Signature, frame and effect checks still run below.
pub fn apply_credit_action_response(path :: String,
  id :: Bytes,
  response :: Bytes) -> Bytes!String do
  let response_id = if Bytes.length(response) == 172 do
    decode_credit_cancellation(response)?.operation_id
  else
    decode_credit_action_receipt(response)?.operation_id
  end
  if Bytes.length(id) != 32 || !Bytes.secure_equals(id, response_id) do
    return Err("credit_response_operation_mismatch")
  end
  native_credit_receipt(pack_credit_parts([Bytes.from_utf8(path), response])?)
end

fn action_plan(path :: String, id :: Bytes, mode :: Int) -> Bytes!String do
  case mode do
    0 -> native_credit_retention_recover(pack_credit_parts([Bytes.from_utf8(path), id])?)
    1 -> native_credit_signup_recover(pack_credit_parts([Bytes.from_utf8(path)])?)
    2 -> native_credit_action_recovery(pack_credit_parts([Bytes.from_utf8(path), id])?)
    _ -> Err("invalid_credit_request")
  end
end

# Inputs select a saved journal operation and one typed action. The origin,
# route, authorization frame and receipt never come from JavaScript transport.
pub fn native_credit_action_continue(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let id = List.get(parsed.parts, 1)
  let selector = List.get(parsed.parts, 2)
  if Bytes.length(id) != 32 || Bytes.length(selector) != 1 do
    return Err("invalid_credit_request")
  end
  let mode = Bytes.get(selector, 0)?
  if mode > 2 do
    return Err("invalid_credit_request")
  end
  let config = native_security_config()?
  let saved = action_plan(parsed.path, id, mode)?
  let fields = unpack_credit_parts(saved, 8, 100000)?
  if !Bytes.secure_equals(List.get(fields, 1), id) do
    return Err("credit_operation_mismatch")
  end
  if Bytes.get(List.get(fields, 2), 0)? != 0 do
    return Ok(saved)
  end
  let route = case mode do
    0 -> "/v1/credits/retention"
    1 -> "/v1/credits/signup"
    _ -> "/v1/credits/reconcile"
  end
  let body = List.get(fields,
    if mode == 2 do
      7
    else
      6
    end)
  let response = post_credit(config, route, body)?
  apply_credit_action_response(parsed.path, id, response)?
  action_plan(parsed.path, id, mode)
end

pub fn native_credit_signup_policy_view(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let purpose = configured_purpose(config)?
  let policy = decode_credit_signup_policy(List.get(parsed.parts, 1))?
  let clock = now()?
  let core = SigningPublicKey { bytes: config.service_public_key }
  if !verify_credit_signup_policy(policy, core, purpose, clock)? do
    return Err("untrusted_credit_signup_policy")
  end
  let price = if policy.credits_enabled do
    credit_signup_policy_price(policy, core, purpose, clock)?
  else
    0
  end
  pack_credit_parts([
    Bytes.from_hex("01535056")?,
    mobile_byte(if policy.credits_enabled do
      1
    else
      0
    end)?,
    mobile_byte(policy.purpose)?,
    mobile_byte(policy.base_difficulty)?,
    mobile_byte(policy.current_difficulty)?,
    mobile_write_u16(price)?,
    mobile_write_u64(policy.expires_at)?
  ])
end

fn signup_output(value :: CreditSpendPlan, config :: SecurityConfig) -> Bytes!String do
  let action = decode_credit_action(value.action)?
  if action.kind != 4 do
    return Err("unsupported_mobile_credit_action")
  end
  let body = if value.status == 0 do
    encode_credit_action_submission(CreditActionSubmission {
      action: action,
      request_body: value.request_body,
      frame: decode_credit_frame(value.frame)?
    })?
  else
    Bytes.empty()
  end
  pack_credit_parts([
    Bytes.from_hex("014d4353")?,
    value.operation_id,
    mobile_byte(value.status)?,
    mobile_write_u64(value.revision)?,
    Bytes.from_utf8(config.issuer_origin),
    Bytes.from_utf8(if value.status == 0 do
      "/v1/credits/signup"
    else
      ""
    end),
    body
  ])
end

pub fn native_credit_signup(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  signup_output(prepare_signup_draft(parsed.path,
      wrapping,
      who,
      decode_credit_signup_policy(List.get(parsed.parts, 1))?,
      now()?)?,
    config)
end

pub fn native_credit_signup_recover(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 1)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  case recover_signup_draft(parsed.path, wrapping, who)? do
    None -> Err("credit_signup_not_started")
    Some(plan) -> signup_output(plan, config)
  end
end

pub fn native_signup_draft_rename(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let who = identity(parsed.path, native_security_config()?)?
  let wrapping = platform_key()?
  rename_signup_draft(parsed.path,
    wrapping,
    who,
    mobile_utf8(List.get(parsed.parts, 1), "invalid_username")?)
end

pub fn native_signup_draft_free(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 1)?
  let who = identity(parsed.path, native_security_config()?)?
  let wrapping = platform_key()?
  select_free_signup_draft(parsed.path, wrapping, who)
end

pub fn native_signup_draft_free_complete(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 1)?
  let who = identity(parsed.path, native_security_config()?)?
  let wrapping = platform_key()?
  complete_free_signup_draft(parsed.path, wrapping, who)
end

pub fn native_register_signup_policy(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let purpose = configured_purpose(config)?
  require_free_registration_allowed(parsed.path)?
  let policy = decode_credit_signup_policy(List.get(parsed.parts, 1))?
  let clock = current_time()?
  if !verify_credit_signup_policy(policy,
    SigningPublicKey { bytes: config.service_public_key },
    purpose,
    U64.divide(clock, U64.parse("1000")?)?)? do
    return Err("untrusted_credit_signup_policy")
  end
  let payload = directory_entry_for(parsed.path)?
  encode_stamped_request(mint_request_stamp("mesh-msg/v1/work/register",
      payload,
      U64.add(clock, U64.parse("240000")?)?,
      policy.current_difficulty)?,
    payload)
end

fn verified_payment_quote(parsed :: NativeCreditRequest,
  config :: SecurityConfig,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> Bytes!String do
  let pins = case Host.push_get_token(Bytes.from_utf8("messenger/wallet/v1")) do
    Err(_) -> return Err("wallet_configuration_required")
    Ok(value) -> value
  end
  if Bytes.length(pins) != 34 || Bytes.get(pins, 0)? != 1 || Bytes.get(pins, 1)? != who.purpose do
    return Err("wallet_configuration_required")
  end
  let plan = recover_credit_purchase(parsed.path, wrapping, who, List.get(parsed.parts, 1))?
  if plan.stage != 1 do
    return Err("credit_payment_not_pending")
  end
  # Recovery re-verifies stored CSQ against its witnessed issuer key. This
  # additionally applies current native mint/purpose/time and canonical ATA.
  let quote = decode_credit_quote(plan.quote)?
  let observed = now()?
  if observed >= quote.expires_at do
    return Err("credit_quote_expired")
  end
  solana_pay_url(quote, Bytes.slice(pins, 2, 32)?, who.purpose, observed)?
  Ok(plan.quote)
end

pub fn native_credit_payment_url(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  let purchase = recover_credit_purchase(parsed.path, wrapping, who, List.get(parsed.parts, 1))?
  if purchase.asset == 2 do
    if purchase.stage != 1 && purchase.stage != 2 do
      return Err("credit_payment_not_pending")
    end
    let quote = decode_lightning_quote(purchase.quote)?
    if quote.network != lightning_network(who.purpose)? || quote.purpose != who.purpose do
      return Err("lightning_configuration_required")
    end
    if now()? >= quote.expires_at do
      return Err("credit_quote_expired")
    end
    return Ok(Bytes.from_utf8("lightning:" <> quote.invoice))
  end
  let quote = verified_payment_quote(parsed, config, wrapping, who)?
  let pins = case Host.push_get_token(Bytes.from_utf8("messenger/wallet/v1")) do
    Err(_) -> return Err("wallet_configuration_required")
    Ok(value) -> value
  end
  Ok(Bytes.from_utf8(solana_pay_url(decode_credit_quote(quote)?,
    Bytes.slice(pins, 2, 32)?,
    who.purpose,
    now()?)?))
end

pub fn native_credit_wallet_quote(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  verified_payment_quote(parsed, config, wrapping, who)
end

# Trusted native wallet launchers use this operation. The quote is checked
# before marking the Lightning claim durable, and no URI is accepted as input.
pub fn native_credit_payment_handoff(input :: Bytes) -> Bytes!String do
  let uri = native_credit_payment_url(input)?
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  let id = List.get(parsed.parts, 1)
  let plan = recover_credit_purchase(parsed.path, wrapping, who, id)?
  if plan.asset == 2 do
    record_credit_payment(parsed.path, wrapping, who, id, Bytes.empty(), now()?)?
  end
  Ok(uri)
end

pub fn native_credit_payment_signature(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let text = mobile_utf8(List.get(parsed.parts, 2), "invalid_payment_signature")?
  if String.length(text) > 88 do
    return Err("invalid_payment_signature")
  end
  let signature = case Bytes.from_base58(text) do
    Err(_) -> return Err("invalid_payment_signature")
    Ok(value) -> value
  end
  if Bytes.length(signature) != 64 || Bytes.to_base58(signature) != text do
    return Err("invalid_payment_signature")
  end
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  purchase_output(record_credit_payment(parsed.path,
      wrapping,
      who,
      List.get(parsed.parts, 1),
      signature,
      now()?)?,
    config)
end

fn wallet_mint(who :: CreditWalletIdentity) -> Bytes!String do
  let pins = case Host.push_get_token(Bytes.from_utf8("messenger/wallet/v1")) do
    Err(_) -> return Err("wallet_configuration_required")
    Ok(value) -> value
  end
  if Bytes.length(pins) != 34 || Bytes.get(pins, 0)? != 1 || Bytes.get(pins, 1)? != who.purpose do
    return Err("wallet_configuration_required")
  end
  Ok(Bytes.slice(pins, 2, 32)?)
end

fn wallet_endpoints(config :: SecurityConfig) -> List<String>!String do
  case configured_anchor_pins(config)? do
    None -> Err("wallet_rpc_configuration_required")
    Some(pins) -> Ok(pins.endpoints)
  end
end

fn wallet_payment_output(value :: CreditWalletPaymentPlan) -> Bytes!String do
  pack_credit_parts([
    Bytes.from_hex("014d5752")?,
    value.purchase_id,
    mobile_byte(if value.status == 3 do
      1
    else
      0
    end)?,
    value.signature
  ])
end

# Private native orchestration only. The host consumes quote/hash directly and
# exposes only the final safe status/signature to JavaScript.
pub fn native_credit_wallet_prepare(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  let value = prepare_credit_wallet_payment(parsed.path,
    wrapping,
    who,
    List.get(parsed.parts, 1),
    wallet_mint(who)?,
    wallet_endpoints(config)?,
    List.get(parsed.parts, 2),
    now()?)?
  pack_credit_parts([
    Bytes.from_hex("014d5750")?,
    value.purchase_id,
    mobile_byte(if value.status >= 2 do
      1
    else
      0
    end)?,
    value.quote,
    value.blockhash,
    value.signature
  ])
end

pub fn native_credit_wallet_commit(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  wallet_payment_output(commit_credit_wallet_payment(parsed.path,
    wrapping,
    who,
    List.get(parsed.parts, 1),
    wallet_mint(who)?,
    List.get(parsed.parts, 2),
    wallet_endpoints(config)?,
    now()?)?)
end

pub fn native_credit_wallet_submit(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let config = native_security_config()?
  let who = identity(parsed.path, config)?
  let wrapping = platform_key()?
  wallet_payment_output(submit_credit_wallet_payment(parsed.path,
    wrapping,
    who,
    List.get(parsed.parts, 1),
    wallet_mint(who)?,
    wallet_endpoints(config)?,
    now()?)?)
end
