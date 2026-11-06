from Mobile.Profile import load_profile, directory_bytes
from Mobile.Platform import native_security_config
from Mobile.Transparency import fresh_account_device_set, transparency_device_set_label
from Mobile.TransparencySafety import require_log_changes_allowed
from Mobile.Codec import random_bytes
from Mobile.CreditState import CreditWallet
from Mobile.CreditWallet import (
  CreditSpendPlan,
  signup_credit_reservations,
  reserve_credit_signup_spend_guarded,
  accept_credit_signup_receipt_guarded,
  accept_credit_signup_receipt
)
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, local_context, seal_local
from Storage.SignupDraft import (
  SignupDraftSnapshot,
  open_signup_draft,
  load_signup_draft,
  seal_signup_draft
)
from Storage.Credits import (
  CreditWalletIdentity,
  CreditCacheWrite,
  load_credit_wallet,
  commit_credit_wallet_with_cache
)
from Transport.Packet import decode_client_profile, encode_client_profile
from Credits.Action import encode_credit_action
from Credits.ActionWire import decode_credit_action_receipt
from Credits.Signup import (
  CreditSignupRequest,
  encode_credit_signup_request,
  decode_credit_signup_request,
  credit_signup_action
)
from Credits.SignupPolicy import CreditSignupPolicy

pub fn signup_draft_state(path :: String) -> Int!String do
  let profile = decode_client_profile(load_profile(path)?)?
  let blob = case load_blob(path, "signup-draft/v1") do
    Err("local_state_not_found") -> return Ok(0)
    Err(error) -> return Err(error)
    Ok(value) -> value
  end
  let wrapping = platform_key()?
  open_signup_draft(blob, profile, wrapping)
end

pub fn require_free_registration_allowed(path :: String) -> Result<(), String> do
  if signup_draft_state(path)? == 1 do
    Err("paid_signup_draft_pending")
  else
    Ok(nil)
  end
end

fn snapshot(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> SignupDraftSnapshot!String do
  let value = load_signup_draft(path, wrapping)?
  if !Bytes.secure_equals(value.profile.account_id, who.account_id)
    || !Bytes.secure_equals(value.profile.device_id, who.device_id) do
    return Err("signup_draft_identity_changed")
  end
  Ok(value)
end

fn guards(value :: SignupDraftSnapshot,
  profile :: Bytes,
  draft :: Bytes) -> List<CreditCacheWrite> do
  [
    CreditCacheWrite { label: "profile/v1", previous: value.profile_blob, value: profile },
    CreditCacheWrite { label: "signup-draft/v1", previous: value.draft_blob, value: draft }
  ]
end

fn require_editable(value :: SignupDraftSnapshot) -> Result<(), String> do
  if value.mode == 0 do
    Err("signup_draft_required")
  else if value.mode == 3 do
    Err("signup_already_completed")
  else
    Ok(nil)
  end
end

fn require_unreserved(plans :: List<CreditSpendPlan>) -> Result<(), String> do
  if List.any(plans, fn(plan) do plan.status == 0 end) do
    Err("paid_signup_draft_pending")
  else if List.any(plans, fn(plan) do plan.status == 1 end) do
    Err("signup_already_completed")
  else
    Ok(nil)
  end
end

# The wallet revision fences reservation creation as well as profile edits.
# Both sealed profile and draft intent are committed in that same transaction.
pub fn rename_signup_draft(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  username :: String) -> Bytes!String do
  let value = snapshot(path, wrapping, who)?
  require_editable(value)?
  let before = load_credit_wallet(path, wrapping, who)?
  require_unreserved(signup_credit_reservations(before.wallet, wrapping, who)?)?
  let encoded = encode_client_profile(%{value.profile.entry | username: username},
    who.account_id,
    who.device_id)?
  let profile_blob = seal_local(encoded, wrapping, local_context("profile/v1")?)?
  let draft_blob = seal_signup_draft(encoded, value.mode, wrapping)?
  commit_credit_wallet_with_cache(path,
    wrapping,
    who,
    before,
    CreditWallet {
      revision: U64.add(before.wallet.revision, U64.parse("1")?)?,
      records: before.wallet.records
    },
    guards(value, profile_blob, draft_blob))?
  Ok(encoded)
end

# This transition is an explicit user choice. A later paid prepare never
# changes mode 2 back to paid, and an unresolved CAP blocks even an expired one.
pub fn select_free_signup_draft(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> Bytes!String do
  let value = snapshot(path, wrapping, who)?
  require_editable(value)?
  let before = load_credit_wallet(path, wrapping, who)?
  require_unreserved(signup_credit_reservations(before.wallet, wrapping, who)?)?
  commit_credit_wallet_with_cache(path,
    wrapping,
    who,
    before,
    CreditWallet {
      revision: U64.add(before.wallet.revision, U64.parse("1")?)?,
      records: before.wallet.records
    },
    guards(value, Bytes.empty(), seal_signup_draft(value.encoded_profile, 2, wrapping)?))?
  Ok(value.encoded_profile)
end

fn matching_profile(value :: SignupDraftSnapshot, plan :: CreditSpendPlan) -> Result<(), String> do
  if !Bytes.secure_equals(decode_credit_signup_request(plan.request_body)?.entry,
    directory_bytes(value.profile.entry)?) do
    Err("signup_draft_entry_changed")
  else
    Ok(nil)
  end
end

pub fn recover_signup_draft(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> Option<CreditSpendPlan>!String do
  let value = snapshot(path, wrapping, who)?
  let before = load_credit_wallet(path, wrapping, who)?
  let plans = signup_credit_reservations(before.wallet, wrapping, who)?
  let active = List.filter(plans, fn(plan) do plan.status == 0 || plan.status == 1 end)
  if List.length(active) > 1 do
    return Err("ambiguous_pending_signup")
  end
  if List.length(active) == 0 do
    return Ok(None)
  end
  let plan = List.head(active)
  if value.mode == 2 do
    return Err("signup_draft_free_selected")
  end
  if value.mode == 1 do
    matching_profile(value, plan)?
    if plan.status == 1 do
      # Repair a historical completed-wallet/old-marker state using the
      # authenticated stored CAR, without deleting or reserving tokens again.
      let revision = U64.add(before.wallet.revision, U64.parse("1")?)?
      commit_credit_wallet_with_cache(path,
        wrapping,
        who,
        before,
        CreditWallet { revision: revision, records: before.wallet.records },
        guards(value, Bytes.empty(), seal_signup_draft(value.encoded_profile, 3, wrapping)?))?
      return Ok(Some(%{plan | revision: revision}))
    end
  end
  Ok(Some(plan))
end

pub fn prepare_signup_draft(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  policy :: CreditSignupPolicy,
  now :: U64) -> CreditSpendPlan!String do
  let value = snapshot(path, wrapping, who)?
  if value.mode == 2 do
    return Err("signup_draft_free_selected")
  end
  if value.mode == 0 do
    return Err("signup_draft_required")
  end
  if value.mode == 3 do
    case recover_signup_draft(path, wrapping, who)? do
      Some(plan) when plan.status == 1 -> return Ok(plan)
      _ -> return Err("signup_already_completed")
    end
  end
  case recover_signup_draft(path, wrapping, who)? do
    Some(plan) when plan.status == 1 -> return Ok(plan)
    _ -> nil
  end
  let before = load_credit_wallet(path, wrapping, who)?
  let pending = List.filter(signup_credit_reservations(before.wallet, wrapping, who)?,
    fn(plan) do plan.status == 0 end)
  if List.length(pending) > 1 do
    return Err("ambiguous_pending_signup")
  end
  let body = if List.length(pending) == 1 do
    let plan = List.head(pending)
    matching_profile(value, plan)?
    plan.request_body
  else
    encode_credit_signup_request(CreditSignupRequest {
      operation_nonce: random_bytes(32)?,
      action_expires_at: U64.add(now, U64.parse("300")?)?,
      entry: directory_bytes(value.profile.entry)?
    })?
  end
  reserve_credit_signup_spend_guarded(path,
    wrapping,
    who,
    encode_credit_action(credit_signup_action(decode_credit_signup_request(body)?)?)?,
    body,
    policy,
    guards(value, Bytes.empty(), Bytes.empty()),
    now)
end

pub fn complete_signup_draft(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  response :: Bytes) -> CreditSpendPlan!String do
  let value = snapshot(path, wrapping, who)?
  if value.mode == 0 || value.mode == 3 do
    return accept_credit_signup_receipt(path, wrapping, who, response)
  end
  if value.mode != 1 do
    return Err("signup_draft_free_selected")
  end
  let receipt = decode_credit_action_receipt(response)?
  let plans = signup_credit_reservations(load_credit_wallet(path, wrapping, who)?.wallet,
    wrapping,
    who)?
  let plan = case List.find(plans,
    fn(plan) do Bytes.secure_equals(plan.operation_id, receipt.operation_id) end) do
    None -> return Err("credit_reservation_not_found")
    Some(found) -> found
  end
  matching_profile(value, plan)?
  accept_credit_signup_receipt_guarded(path,
    wrapping,
    who,
    response,
    guards(value, Bytes.empty(), seal_signup_draft(value.encoded_profile, 3, wrapping)?))
end

fn proof_guard(path :: String, label :: String) -> CreditCacheWrite!String do
  let previous = case load_blob(path, label) do
    Err("local_state_not_found") -> Bytes.empty()
    Err(error) -> return Err(error)
    Ok(value) -> value
  end
  Ok(CreditCacheWrite { label: label, previous: previous, value: Bytes.empty() })
end

# Completion requires an authenticated current directory view, never a caller
# assertion that registration succeeded. Capture all shared trust inputs before
# verification and commit their ciphertext guards with profile, mode and wallet.
pub fn complete_free_signup_draft(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> Bytes!String do
  let value = snapshot(path, wrapping, who)?
  if value.mode == 0 || value.mode == 3 do
    return Ok(value.encoded_profile)
  end
  if value.mode != 2 do
    return Err("signup_draft_free_not_selected")
  end
  if !Bytes.secure_equals(native_security_config()?.service_public_key, who.service_key) do
    return Err("signup_draft_service_changed")
  end
  let before = load_credit_wallet(path, wrapping, who)?
  require_unreserved(signup_credit_reservations(before.wallet, wrapping, who)?)?
  let cache = for label in [
    transparency_device_set_label(who.account_id),
    "transparency-checkpoint/v1",
    "transparency-view/v1",
    "transparency-view-chunk/v1/0",
    "transparency-view-chunk/v1/1",
    "transparency-view-chunk/v1/2",
    "transparency-witnesses/v2",
    "transparency-fork/v1",
    "anchor-schedule/v1"
  ] do
    proof_guard(path, label)?
  end
  require_log_changes_allowed(path, wrapping)?
  let devices = fresh_account_device_set(path, wrapping, who.account_id)?
  let entry = directory_bytes(value.profile.entry)?
  let live = for profile in devices.profiles do
    Bytes.secure_equals(profile.account_id, who.account_id)
      && Bytes.secure_equals(profile.device_id, who.device_id)
      && Bytes.secure_equals(directory_bytes(profile.entry)?, entry)
  end
  if !List.any(live, fn(matches) do matches end) do
    return Err("signup_draft_entry_unverified")
  end
  commit_credit_wallet_with_cache(path,
    wrapping,
    who,
    before,
    CreditWallet {
      revision: U64.add(before.wallet.revision, U64.parse("1")?)?,
      records: before.wallet.records
    },
    guards(value, Bytes.empty(), seal_signup_draft(value.encoded_profile, 3, wrapping)?) ++ cache)?
  Ok(value.encoded_profile)
end
