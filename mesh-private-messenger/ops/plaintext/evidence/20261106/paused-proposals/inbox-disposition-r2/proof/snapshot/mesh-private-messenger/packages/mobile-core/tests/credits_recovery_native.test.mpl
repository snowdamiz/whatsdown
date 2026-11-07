import File
from MobileCore import (
  create_signup_draft_export,
  signup_draft_state_export,
  signup_draft_rename_export,
  signup_draft_free_export,
  signup_draft_free_complete_export,
  register_signup_policy_export,
  credit_signup_export,
  credit_signup_recover_export,
  credit_signup_policy_export,
  credit_signup_policy_view_export,
  credit_action_recovery_export,
  credit_receipt_export
)
from Credits.ActionWire import (
  CreditActionSubmission,
  encode_credit_action_submission,
  decode_credit_action_submission,
  sign_credit_action_receipt,
  encode_credit_action_receipt
)
from Credits.Cancellation import sign_credit_cancellation, encode_credit_cancellation
from Credits.Signup import (
  CreditSignupResult,
  decode_credit_signup_request,
  encode_credit_signup_result
)
from Credits.SignupPolicy import sign_credit_signup_policy, encode_credit_signup_policy
from Credits.Issuer import CreditIssuerKey
from Privacy.Edge import decode_stamped_request, verify_request_stamp
from Credits.Policy import issuer_epoch
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Mobile.Codec import current_time
from Mobile.Profile import directory_bytes, load_profile
from Mobile.CreditWallet import (
  add_credit_issuer,
  completed_credit_record,
  credit_wallet_balance
)
from Mobile.CreditState import CreditWallet, pack_credit_parts, unpack_credit_parts
from Storage.Credits import CreditWalletIdentity, load_credit_wallet, commit_credit_wallet
from Storage.Keys import platform_key
from Transport.Packet import decode_client_profile
from Transparency.Config import SecurityConfig, WitnessPin, witness_set_id, encode_security_config
from Tests.Support import append, vector, database_path, repeated

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test signing failed")
    Ok(value)
  end
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("native_action_recovery")?
  let core = pair()?
  let other = pair()?
  let witnesses = [
    WitnessPin { witness_id: "outside", public_key: repeated(51, 32)?, operator_label: "Outside" }
  ]
  let config = SecurityConfig {
    version: 3,
    wire_version: 3,
    minimum_session_suite: 1,
    service_public_key: core.public_key.bytes,
    delivery_public_key: repeated(52, 32)?,
    abuse_difficulty: 1,
    threshold: 1,
    witnesses: witnesses,
    set_id: witness_set_id(witnesses, 1)?,
    anchor_address: "-",
    anchor_program: "-",
    anchor_log_name: "-",
    rpc_urls: [],
    issuer_origin: "https://edge.example",
    log_version: 2,
    legacy_threshold: 1,
    legacy_witnesses: witnesses,
    relay_urls: [],
    slash_mint: "-"
  }
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(config)?))
  let disabled_path = database_path("disabled_paid_signup")?
  let disabled_request = append(vector(Bytes.from_utf8(disabled_path))?,
    vector(Bytes.from_utf8("disabled-draft"))?)?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0102")?))
  case create_signup_draft_export(disabled_request) do
    Err(error) -> assert(error == "credits_disabled")
    Ok(_) -> return Err("disabled native credits created an unreachable paid draft")
  end
  assert(Result.is_err(load_profile(disabled_path)))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0101")?))
  let path_packet = pack_credit_parts([Bytes.from_utf8(path)])?
  let policy_plan = unpack_credit_parts(credit_signup_policy_export(path_packet)?, 4, 4096)?
  assert(Bytes.to_hex(List.head(policy_plan)) == "014d4359")
  assert(Bytes.to_utf8(List.get(policy_plan, 1))? == "https://edge.example")
  assert(Bytes.to_utf8(List.get(policy_plan, 2))? == "/v1/credits/signup-policy")
  assert(Bytes.length(List.get(policy_plan, 3)) == 0)
  let now = U64.divide(current_time()?, U64.parse("1000")?)?
  let policy = sign_credit_signup_policy(core.private_key, 1, true, 16, 17, now)?
  let policy_wire = encode_credit_signup_policy(policy)?
  let view = unpack_credit_parts(credit_signup_policy_view_export(pack_credit_parts([
      Bytes.from_utf8(path),
      policy_wire
    ])?)?,
    7,
    64)?
  assert(Bytes.to_hex(List.head(view)) == "01535056")
  assert(Bytes.to_hex(List.get(view, 1)) == "01" && Bytes.to_hex(List.get(view, 2)) == "01")
  assert(Bytes.to_hex(List.get(view, 5)) == "0014")
  let forged = encode_credit_signup_policy(sign_credit_signup_policy(other.private_key,
    1,
    true,
    16,
    17,
    now)?)?
  assert(Result.is_err(credit_signup_policy_view_export(pack_credit_parts([
    Bytes.from_utf8(path),
    forged
  ])?)))
  let stale = encode_credit_signup_policy(sign_credit_signup_policy(core.private_key,
    1,
    true,
    16,
    17,
    U64.subtract(now, U64.parse("61")?)?)?)?
  assert(Result.is_err(credit_signup_policy_view_export(pack_credit_parts([
    Bytes.from_utf8(path),
    stale
  ])?)))
  # The policy must be available before creating a paid local draft.
  let original = decode_client_profile(create_signup_draft_export(append(vector(Bytes.from_utf8(path))?,
    vector(Bytes.from_utf8("native-recovery"))?)?)?)?
  let profile = decode_client_profile(signup_draft_rename_export(pack_credit_parts([
    Bytes.from_utf8(path),
    Bytes.from_utf8("native-renamed")
  ])?)?)?
  assert(Bytes.secure_equals(profile.account_id, original.account_id))
  assert(Bytes.secure_equals(profile.device_id, original.device_id))
  assert(profile.entry.username == "native-renamed")
  assert(Result.is_err(credit_signup_recover_export(path_packet)))
  assert(Result.is_err(register_signup_policy_export(pack_credit_parts([
    Bytes.from_utf8(path),
    policy_wire
  ])?)))
  let wrapping = platform_key()?
  let who = CreditWalletIdentity {
    account_id: profile.account_id,
    device_id: profile.device_id,
    service_key: core.public_key.bytes,
    purpose: 1
  }
  let signer = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(signer) do
    Err(_) -> return Err("test public failed")
    Ok(value) -> value
  end
  let issuer = CreditIssuerKey {
    epoch: issuer_epoch(now)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: core.public_key.bytes
  }
  let before = load_credit_wallet(path, wrapping, who)?
  let base = add_credit_issuer(before.wallet, issuer, now, 1)?
  let purchased = U64.subtract(now, U64.parse("600")?)?
  let tokens = for _index in 0..20 do
    let pending = blind_credit(issuer, who.service_key, purchased)?
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
    CreditWallet {
      revision: U64.add(before.wallet.revision, U64.parse("1")?)?,
      records: base.records ++ tokens
    })?
  let prepare_request = pack_credit_parts([Bytes.from_utf8(path), policy_wire])?
  let prepared = credit_signup_export(prepare_request)?
  let plan = unpack_credit_parts(prepared, 7, 88355)?
  assert(Bytes.to_hex(List.head(plan)) == "014d4353")
  assert(Bytes.to_hex(List.get(plan, 2)) == "00")
  assert(Bytes.to_utf8(List.get(plan, 4))? == "https://edge.example")
  assert(Bytes.to_utf8(List.get(plan, 5))? == "/v1/credits/signup")
  assert(Bytes.secure_equals(prepared, credit_signup_recover_export(path_packet)?))
  let same = unpack_credit_parts(credit_signup_export(prepare_request)?, 7, 88355)?
  assert(Bytes.secure_equals(List.get(plan, 1), List.get(same, 1)))
  assert(Bytes.secure_equals(List.get(plan, 6), List.get(same, 6)))
  assert(Result.is_err(signup_draft_free_export(path_packet)))
  assert(Result.is_err(signup_draft_rename_export(pack_credit_parts([
    Bytes.from_utf8(path),
    Bytes.from_utf8("pending-rename")
  ])?)))
  let submission = decode_credit_action_submission(List.get(plan, 6))?
  let signup = decode_credit_signup_request(submission.request_body)?
  assert(Bytes.secure_equals(signup.entry, directory_bytes(profile.entry)?))
  let recovery_request = pack_credit_parts([Bytes.from_utf8(path), List.get(plan, 1)])?
  let recovery = unpack_credit_parts(credit_action_recovery_export(recovery_request)?, 8, 88355)?
  assert(Bytes.to_hex(List.head(recovery)) == "014d4345")
  assert(Bytes.to_hex(List.get(recovery, 2)) == "00" && Bytes.to_hex(List.get(recovery, 3)) == "04")
  assert(Bytes.to_utf8(List.get(recovery, 5))? == "https://edge.example")
  assert(Bytes.to_utf8(List.get(recovery, 6))? == "/v1/credits/reconcile")
  assert(Bytes.secure_equals(List.get(recovery, 7), encode_credit_action_submission(submission)?))
  let cancellation = encode_credit_cancellation(sign_credit_cancellation(core.private_key,
    submission,
    signup.action_expires_at)?)?
  let forged_cancel = encode_credit_cancellation(sign_credit_cancellation(other.private_key,
    submission,
    signup.action_expires_at)?)?
  assert(Result.is_err(credit_receipt_export(pack_credit_parts([
    Bytes.from_utf8(path),
    forged_cancel
  ])?)))
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 20)
  let completed = unpack_credit_parts(credit_receipt_export(pack_credit_parts([
      Bytes.from_utf8(path),
      cancellation
    ])?)?,
    8,
    88355)?
  assert(Bytes.to_hex(List.head(completed)) == "014d4352"
    && Bytes.to_hex(List.get(completed, 2)) == "02")
  assert(credit_wallet_balance(path, wrapping, who, now)?.available == 20)
  let terminal = unpack_credit_parts(credit_action_recovery_export(recovery_request)?, 8, 88355)?
  assert(Bytes.to_hex(List.get(terminal, 2)) == "02")
  assert(Bytes.length(List.get(terminal, 6)) == 0 && Bytes.length(List.get(terminal, 7)) == 0)
  assert(Result.is_err(credit_signup_recover_export(path_packet)))
  let retry = unpack_credit_parts(credit_signup_export(prepare_request)?, 7, 88355)?
  assert(!Bytes.secure_equals(List.get(retry, 1), List.get(plan, 1)))
  let retry_submission = decode_credit_action_submission(List.get(retry, 6))?
  let result = encode_credit_signup_result(CreditSignupResult {
    account_id: profile.account_id,
    entry_sha256: Crypto.sha256(directory_bytes(profile.entry)?)
  })?
  let receipt = encode_credit_action_receipt(sign_credit_action_receipt(core.private_key,
    retry_submission,
    profile.account_id,
    now,
    result)?)?
  let done = unpack_credit_parts(credit_receipt_export(pack_credit_parts([
      Bytes.from_utf8(path),
      receipt
    ])?)?,
    8,
    88355)?
  assert(Bytes.to_hex(List.get(done, 2)) == "01")
  assert(Bytes.to_hex(signup_draft_state_export(Bytes.from_utf8(path))?) == "03")
  let recovered_done = unpack_credit_parts(credit_signup_recover_export(path_packet)?, 7, 88355)?
  assert(Bytes.to_hex(List.get(recovered_done, 2)) == "01")
  assert(Bytes.length(List.get(recovered_done, 5)) == 0
    && Bytes.length(List.get(recovered_done, 6)) == 0)
  let free_path = database_path("native_free_draft")?
  create_signup_draft_export(append(vector(Bytes.from_utf8(free_path))?,
    vector(Bytes.from_utf8("native-free-choice"))?)?)?
  signup_draft_free_export(pack_credit_parts([Bytes.from_utf8(free_path)])?)?
  assert(Bytes.to_hex(signup_draft_state_export(Bytes.from_utf8(free_path))?) == "02")
  assert(Result.is_err(signup_draft_free_complete_export(pack_credit_parts([
    Bytes.from_utf8(free_path)
  ])?)))
  assert(Result.is_err(credit_signup_export(pack_credit_parts([
    Bytes.from_utf8(free_path),
    policy_wire
  ])?)))
  let free_policy = encode_credit_signup_policy(sign_credit_signup_policy(core.private_key,
    1,
    false,
    1,
    5,
    now)?)?
  let free_request = register_signup_policy_export(pack_credit_parts([
    Bytes.from_utf8(free_path),
    free_policy
  ])?)?
  let (stamp, payload) = decode_stamped_request(free_request, 36006)?
  assert(Bytes.secure_equals(payload,
    directory_bytes(decode_client_profile(load_profile(free_path)?)?.entry)?))
  assert(verify_request_stamp("mesh-msg/v1/work/register",
    payload,
    stamp,
    current_time()?,
    U64.parse("300000")?,
    5)?)
  assert(Result.is_err(register_signup_policy_export(pack_credit_parts([
    Bytes.from_utf8(free_path),
    forged
  ])?)))
  assert(Result.is_err(register_signup_policy_export(pack_credit_parts([
    Bytes.from_utf8(free_path),
    stale
  ])?)))
  File.delete(free_path)?
  File.delete(path)?
  Ok(true)
end

test("native policy and reconciliation plans bind configured authority and release only authenticated exact reservations") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
