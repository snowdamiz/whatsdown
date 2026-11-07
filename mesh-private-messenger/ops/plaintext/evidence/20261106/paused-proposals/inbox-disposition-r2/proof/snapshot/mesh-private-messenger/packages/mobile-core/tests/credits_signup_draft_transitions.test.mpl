from Storage.Blobs import blob_record_hash
import File
from Mobile.Account import create_signup_draft_account
from Mobile.Types import MobileAccountRequest
from Mobile.Profile import load_profile, directory_bytes
from Mobile.SignupDraft import (
  signup_draft_state,
  require_free_registration_allowed,
  rename_signup_draft,
  select_free_signup_draft,
  prepare_signup_draft,
  recover_signup_draft,
  complete_signup_draft
)
from Mobile.CreditState import CreditWallet
from Mobile.CreditWallet import (
  add_credit_issuer,
  completed_credit_record,
  credit_wallet_balance,
  accept_credit_cancellation,
  signup_credit_reservations
)
from Storage.Credits import CreditWalletIdentity, load_credit_wallet, commit_credit_wallet
from Storage.Keys import platform_key
from Storage.Blobs import load_blob
from Storage.Records import store_updated_session
from Transport.Packet import decode_client_profile
from Credits.Issuer import CreditIssuerKey
from Credits.SignupPolicy import sign_credit_signup_policy
from Credits.Signup import (
  CreditSignupResult,
  decode_credit_signup_request,
  encode_credit_signup_result
)
from Credits.Action import decode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  sign_credit_action_receipt,
  encode_credit_action_receipt
)
from Credits.Cancellation import sign_credit_cancellation, encode_credit_cancellation
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Credits.Wire import decode_credit_frame
from Tests.Support import database_path, repeated

fn funded(path :: String,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  issuer :: CreditIssuerKey,
  signer :: borrow BlindRsaSecretKey,
  now :: U64) -> CreditWalletIdentity!String do
  let encoded = create_signup_draft_account(MobileAccountRequest {
    database_path: Bytes.from_utf8(path),
    username: Bytes.from_utf8("draft-owner")
  })?
  let profile = decode_client_profile(encoded)?
  let who = CreditWalletIdentity {
    account_id: profile.account_id,
    device_id: profile.device_id,
    service_key: service_key,
    purpose: 1
  }
  let before = load_credit_wallet(path, wrapping, who)?
  let base = add_credit_issuer(before.wallet, issuer, now, 1)?
  let purchased = U64.subtract(now, U64.parse("600")?)?
  let tokens = for _index in 0..20 do
    let pending = blind_credit(issuer, service_key, purchased)?
    let signature = sign_credit_request(signer, issuer, pending.request)?
    completed_credit_record(finalize_credit(issuer, pending, signature)?,
      issuer,
      purchased,
      wrapping,
      who)?
  end
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: U64.parse("1")?, records: base.records ++ tokens })?
  Ok(who)
end

fn marker_failure(path :: String, enabled :: Bool) -> Result<(), String> do
  let database = Sqlite.open(path)?
  if enabled do
    let hash = blob_record_hash(database, "signup-draft/v1")?
    Sqlite.execute(database,
      "CREATE TRIGGER fail_draft_transition BEFORE UPDATE ON encrypted_blobs WHEN NEW.record_hash = '"
        <> hash
        <> "' BEGIN SELECT RAISE(ABORT, 'test draft transition failure'); END",
      [])?
  else
    Sqlite.execute(database, "DROP TRIGGER fail_draft_transition", [])?
  end
  Sqlite.close(database)
  Ok(nil)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let core = case Crypto.signing_generate() do
    Err(_) -> return Err("core key failed")
    Ok(value) -> value
  end
  let signer = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(signer) do
    Err(_) -> return Err("RSA public failed")
    Ok(value) -> value
  end
  let now = U64.parse("25921000")?
  let issuer = CreditIssuerKey {
    epoch: U64.parse("10")?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: core.public_key.bytes
  }
  let policy = sign_credit_signup_policy(core.private_key, 1, true, 16, 17, now)?
  let path = database_path("draft_transition")?
  let who = funded(path, wrapping, core.public_key.bytes, issuer, signer, now)?
  let original = decode_client_profile(load_profile(path)?)?
  let key_before = load_blob(path, "account-signing-key/v1")?
  let device_before = load_blob(path, "device-signing-key/v1")?
  let renamed = decode_client_profile(rename_signup_draft(path, wrapping, who, "renamed-owner")?)?
  assert(renamed.entry.username == "renamed-owner")
  assert(Bytes.secure_equals(original.account_id, renamed.account_id)
    && Bytes.secure_equals(original.device_id, renamed.device_id))
  assert(Bytes.secure_equals(original.entry.prekey_bundle, renamed.entry.prekey_bundle)
    && Bytes.secure_equals(original.entry.mailbox_token, renamed.entry.mailbox_token))
  assert(Bytes.secure_equals(key_before, load_blob(path, "account-signing-key/v1")?))
  assert(Bytes.secure_equals(device_before, load_blob(path, "device-signing-key/v1")?))
  assert(credit_wallet_balance(path, wrapping, who, now)?.available == 20)
  let before_revision = load_credit_wallet(path, wrapping, who)?.wallet.revision
  let profile_before = load_blob(path, "profile/v1")?
  let draft_before = load_blob(path, "signup-draft/v1")?
  marker_failure(path, true)?
  assert(Result.is_err(rename_signup_draft(path, wrapping, who, "must-rollback")))
  assert(Bytes.secure_equals(profile_before, load_blob(path, "profile/v1")?)
    && Bytes.secure_equals(draft_before, load_blob(path, "signup-draft/v1")?))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == before_revision)
  marker_failure(path, false)?
  let pending = prepare_signup_draft(path, wrapping, who, policy, now)?
  assert(pending.status == 0 && pending.credits == 20)
  let recovered = case recover_signup_draft(path, wrapping, who)? do
    None -> return Err("pending draft lost")
    Some(value) -> value
  end
  assert(Bytes.secure_equals(pending.frame, recovered.frame)
    && Bytes.secure_equals(pending.request_body, recovered.request_body))
  let expired_retry = prepare_signup_draft(path,
    wrapping,
    who,
    policy,
    U64.add(now, U64.parse("1000")?)?)?
  assert(Bytes.secure_equals(expired_retry.request_body, pending.request_body))
  assert(Result.is_err(rename_signup_draft(path, wrapping, who, "must-block")))
  assert(Result.is_err(select_free_signup_draft(path, wrapping, who)))
  let submission = CreditActionSubmission {
    action: decode_credit_action(pending.action)?,
    request_body: pending.request_body,
    frame: decode_credit_frame(pending.frame)?
  }
  accept_credit_cancellation(path,
    wrapping,
    who,
    encode_credit_cancellation(sign_credit_cancellation(core.private_key,
      submission,
      submission.action.expires_at)?)?)?
  rename_signup_draft(path, wrapping, who, "free-owner")?
  select_free_signup_draft(path, wrapping, who)?
  assert(signup_draft_state(path)? == 2)
  require_free_registration_allowed(path)?
  assert(Result.is_err(prepare_signup_draft(path, wrapping, who, policy, now)))
  rename_signup_draft(path, wrapping, who, "free-renamed")?
  assert(signup_draft_state(path)? == 2
    && credit_wallet_balance(path, wrapping, who, now)?.available == 20)
  let done_path = database_path("draft_completed")?
  let done_who = funded(done_path, wrapping, core.public_key.bytes, issuer, signer, now)?
  let plan = prepare_signup_draft(done_path, wrapping, done_who, policy, now)?
  let done_submission = CreditActionSubmission {
    action: decode_credit_action(plan.action)?,
    request_body: plan.request_body,
    frame: decode_credit_frame(plan.frame)?
  }
  let result = encode_credit_signup_result(CreditSignupResult {
    account_id: done_who.account_id,
    entry_sha256: Crypto.sha256(decode_credit_signup_request(plan.request_body)?.entry)
  })?
  let receipt = encode_credit_action_receipt(sign_credit_action_receipt(core.private_key,
    done_submission,
    repeated(71, 32)?,
    now,
    result)?)?
  let old_pending_marker = load_blob(done_path, "signup-draft/v1")?
  let wallet_before = load_credit_wallet(done_path, wrapping, done_who)?.wallet.revision
  marker_failure(done_path, true)?
  assert(Result.is_err(complete_signup_draft(done_path, wrapping, done_who, receipt)))
  assert(signup_draft_state(done_path)? == 1
    && credit_wallet_balance(done_path, wrapping, done_who, now)?.reserved == 20)
  assert(load_credit_wallet(done_path, wrapping, done_who)?.wallet.revision == wallet_before)
  marker_failure(done_path, false)?
  assert(complete_signup_draft(done_path, wrapping, done_who, receipt)?.status == 1)
  assert(signup_draft_state(done_path)? == 3
    && credit_wallet_balance(done_path, wrapping, done_who, now)?.reserved == 0)
  assert(complete_signup_draft(done_path, wrapping, done_who, receipt)?.status == 1)
  assert(Result.is_err(rename_signup_draft(done_path, wrapping, done_who, "too-late")))
  assert(Result.is_err(select_free_signup_draft(done_path, wrapping, done_who)))
  # A durable CAR from an older version may coexist with a mode-1 marker.
  # Reopening and preparing repairs the marker from the verified CAR alone.
  store_updated_session(done_path, "signup-draft/v1", old_pending_marker)?
  assert(signup_draft_state(done_path)? == 1)
  let historical = prepare_signup_draft(done_path, wrapping, done_who, policy, now)?
  assert(historical.status == 1 && Bytes.secure_equals(historical.operation_id, plan.operation_id))
  assert(signup_draft_state(done_path)? == 3
    && credit_wallet_balance(done_path, wrapping, done_who, now)?.reserved == 0)
  # Independent actors reopen storage and race paid prepare with rename.
  # Successful prepares all receive one immutable CAP; a rename can only win
  # before that CAP exists. Losing CAS writes cannot reserve another batch.
  let race_path = database_path("draft_race")?
  let race_who = funded(race_path, wrapping, core.public_key.bytes, issuer, signer, now)?
  let results = Job.map([0, 1, 2, 3, 4, 5, 6, 7],
    fn(index) do
      let key = platform_key()?
      if index < 6 do
        let reserved = prepare_signup_draft(race_path, key, race_who, policy, now)?
        Ok("paid:" <> Bytes.to_hex(reserved.operation_id))
      else
        rename_signup_draft(race_path, key, race_who, "racing-owner")?
        Ok("renamed")
      end
    end)
  let final_plan = prepare_signup_draft(race_path, wrapping, race_who, policy, now)?
  let final_profile = decode_client_profile(load_profile(race_path)?)?
  let final_wallet = load_credit_wallet(race_path, wrapping, race_who)?.wallet
  let reservations = signup_credit_reservations(final_wallet, wrapping, race_who)?
  assert(List.length(reservations) == 1
    && credit_wallet_balance(race_path, wrapping, race_who, now)?.reserved == 20)
  for result in results do
    case result do
      Ok(Ok(value)) -> assert(value == "renamed"
        || value == "paid:" <> Bytes.to_hex(final_plan.operation_id))
      _ -> nil
    end
  end
  assert(Bytes.secure_equals(decode_credit_signup_request(final_plan.request_body)?.entry,
    directory_bytes(final_profile.entry)?))
  assert(Result.is_err(rename_signup_draft(race_path, wrapping, race_who, "after-reserve")))
  File.delete(race_path)?
  File.delete(path)?
  File.delete(done_path)?
  Ok(true)
end

test("paid signup draft transitions preserve funded identity and atomically bind reservation and completion") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
