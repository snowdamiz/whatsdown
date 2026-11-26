from Api.Binary import (
  Admission,
  BinaryResult,
  CheckedRequest,
  acknowledge_request,
  admission_failure,
  check_request,
  bind_push_request,
  checkpoint_request,
  claim_prekey_request,
  consistency_request,
  delete_account_request,
  fetch_request,
  leave_device_request,
  inclusion_request,
  publish_prekeys_request,
  register_device_request,
  resolve_devices_request,
  revoke_device_request,
  spend_request,
  submit_configured_sealed_request,
  submit_request,
  submit_witness_request,
  unbind_push_request,
  witnesses_request
)
from Api.WitnessNetwork import (
  anchor_request,
  checkpoint_note_request,
  health_request,
  leaf_request,
  leaves_request,
  push_witnesses_request,
  registry_request,
  submit_anchor_request,
  submit_cosignature_request,
  witnesses_v2_request
)
from Runtime.CreditStats import credits_stats_record, credits_stats_snapshot
from Api.Signup import signup_request, signup_work_request
from Storage.SignupSurge import signup_surge_target
from Api.MailboxRoutes import (
  claim_with_policy_request,
  mailbox_policy_request,
  mailbox_retention_request
)
from Api.CreditRoutes import (
  credits_health_request,
  credits_totals_request,
  credits_issuer_keys_request,
  credits_issuer_leaf_request,
  credits_redeem_request
)
from Prekeys.Pool import decode_prekey_claim
from Privacy.Edge import internal_delivery_authorized, internal_delivery_token
from Runtime.Registry import get_pool
from Runtime.Workers import run_scheduled, transaction_in_progress
import RuntimeJobs

fn run_jobs(request :: Request, witness_only :: Bool) -> Response do
  if !RuntimeJobs.internal_request_authorized(request,
    Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    HTTP.response(401, "")
  else
    case transaction_in_progress(get_pool(), Request.body(request)) do
      Err(_) -> HTTP.response(503, "")
      Ok(true) -> HTTP.response(202, "")
      Ok(false) -> if witness_only do
        HTTP.response(200, "0")
      else
        case run_scheduled(get_pool()) do
          Err(_) -> HTTP.response(503, "")
          Ok(due) -> HTTP.response(200, Int.to_string(due))
        end
      end
    end
  end
end

pub fn handle_jobs(request :: Request) -> Response do
  run_jobs(request, false)
end

pub fn handle_witness_job(request :: Request) -> Response do
  run_jobs(request, true)
end

fn respond(result :: BinaryResult) -> Response do
  HTTP.response_bytes(result.status, result.body)
end

fn respond_no_store(result :: BinaryResult) -> Response do
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.put(Map.new(), "Cache-Control", "no-store"))
end

fn respond_json(result :: BinaryResult) -> Response do
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.put(Map.put(Map.new(), "Content-Type", "application/json; charset=utf-8"),
      "Cache-Control",
      "no-store"))
end

pub fn handle_health(_request :: Request) -> Response do
  respond_json(health_request(get_pool()))
end

# Register, resolve and prekey claim are anonymous, so each must arrive wrapped
# in proof of work minted for that endpoint. The limits are the largest body
# each inner codec accepts.

fn admitted_body(body :: Bytes, label :: String, maximum_payload :: Int) -> Admission!String do
  case check_request(label,
    body,
    maximum_payload,
    U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?,
    Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16))? do
    RequestMalformed -> Ok(AdmissionMalformed)
    RequestUnpaid -> Ok(AdmissionRefused)
    RequestPaid(payload, spent_key) -> spend_request(get_pool(), payload, spent_key)
  end
end

# Registration's difficulty rises under load, and 20 credits skip the rise
# (Api.Signup, protocol/credits-v1.md "Priority sign-up").

pub fn handle_register_device(request :: Request) -> Response do
  respond(signup_request(get_pool(),
    Request.body_bytes(request),
    DateTime.to_unix_ms(DateTime.utc_now()),
    Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16),
    signup_surge_target(),
    Env.get("MORSE_CREDITS_MODE", "off")))
end

pub fn handle_register_work(_request :: Request) -> Response do
  respond_no_store(signup_work_request(get_pool(),
    Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16),
    signup_surge_target()))
end

pub fn handle_resolve_devices(request :: Request) -> Response do
  respond(directory_resolve_result(Request.body_bytes(request)))
end

## A stamped lookup's answer, directly or through the OHTTP gateway.

pub fn directory_resolve_result(body :: Bytes) -> BinaryResult do
  case admitted_body(body, "mesh-msg/v1/work/resolve", 80) do
    Ok(Admitted(payload)) -> resolve_devices_request(get_pool(), payload)
    refused -> admission_failure(refused)
  end
end

pub fn handle_revoke_device(request :: Request) -> Response do
  respond(revoke_device_request(get_pool(), Request.body_bytes(request)))
end

# Signed by the account key, like a revocation, so it needs no proof of work.

pub fn handle_delete_account(request :: Request) -> Response do
  respond(delete_account_request(get_pool(), Request.body_bytes(request)))
end

# Signed by the departing device's own key, so it needs no proof of work either.

pub fn handle_leave_device(request :: Request) -> Response do
  respond(leave_device_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_submit(request :: Request) -> Response do
  respond(submit_request(get_pool(), Request.body_bytes(request)))
end

fn authorization_header(request :: Request) -> Option<String> do
  case Request.header(request, "Authorization") do
    None -> Request.header(request, "authorization")
    Some(value)
  end
end

pub fn handle_sealed_submit(request :: Request) -> Response do
  case internal_delivery_token(Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    Err(_) -> HTTP.response(503, "")
    Ok(secret) -> if !internal_delivery_authorized(authorization_header(request), secret) do
      HTTP.response(401, "")
    else
      case submit_configured_sealed_request(get_pool(), Request.body_bytes(request)) do
        Err(_) -> HTTP.response(500, "")
        Ok(result) -> respond(result)
      end
    end
  end
end

pub fn handle_fetch(request :: Request) -> Response do
  respond(fetch_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_acknowledge(request :: Request) -> Response do
  respond(acknowledge_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_push_bind(request :: Request) -> Response do
  respond(bind_push_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_push_unbind(request :: Request) -> Response do
  respond(unbind_push_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_prekeys_publish(request :: Request) -> Response do
  respond(publish_prekeys_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_prekey_claim(request :: Request) -> Response do
  respond_no_store(directory_prekey_claim_result(Request.body_bytes(request)))
end

## A stamped prekey claim's answer, directly or through the OHTTP gateway.

pub fn directory_prekey_claim_result(stamped :: Bytes) -> BinaryResult do
  case admitted_body(stamped, "mesh-msg/v1/work/prekey-claim", 100) do
    Ok(Admitted(body)) -> if Bytes.get(body, 0) == Ok(2) do
      # Version 2: the same claim, answered with the mailbox policy (PKC).
      claim_with_policy_request(get_pool(), body)
    else
      case decode_prekey_claim(body) do
        Err(_) -> BinaryResult { status: 400, body: Bytes.empty() }
        Ok(_) -> claim_prekey_request(get_pool(), body)
      end
    end
    refused -> admission_failure(refused)
  end
end

pub fn handle_transparency_checkpoint(_request :: Request) -> Response do
  respond(checkpoint_request(get_pool()))
end

pub fn handle_transparency_inclusion(request :: Request) -> Response do
  respond(inclusion_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_transparency_consistency(request :: Request) -> Response do
  respond(consistency_request(get_pool(), Request.body_bytes(request)))
end

fn header_contains(request :: Request, name :: String, value :: String) -> Bool do
  case Request.header(request, name) do
    None -> false
    Some(found) -> String.contains(String.to_lower(found), value)
  end
end

# v1 clients get KTW v1 as before; KTW v2 is asked for by media type.

pub fn handle_transparency_witnesses(request :: Request) -> Response do
  if header_contains(request, "Accept", "application/x-morse-attestation-v2") do
    respond(witnesses_v2_request(get_pool()))
  else
    respond(witnesses_request(get_pool()))
  end
end

fn now_seconds() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now()) / 1000
end

pub fn handle_transparency_witness_submit(request :: Request) -> Response do
  if header_contains(request, "Content-Type", "text/x-c2sp-cosignature") do
    respond(submit_cosignature_request(get_pool(), Request.body(request), now_seconds()))
  else
    respond(submit_witness_request(get_pool(), Request.body_bytes(request)))
  end
end

pub fn handle_transparency_note(_request :: Request) -> Response do
  let result = checkpoint_note_request(get_pool())
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.put(Map.new(), "Content-Type", "text/plain; charset=utf-8"))
end

pub fn handle_transparency_registry(_request :: Request) -> Response do
  respond_json(registry_request(get_pool()))
end

pub fn handle_transparency_anchor(request :: Request) -> Response do
  case Request.param(request, "sequence") do
    None -> respond_json(BinaryResult { status: 400, body: Bytes.empty() })
    Some(sequence) -> respond_json(anchor_request(get_pool(), sequence))
  end
end

pub fn handle_transparency_leaf(request :: Request) -> Response do
  respond(leaf_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_transparency_leaves(request :: Request) -> Response do
  case (Request.query(request, "start"), Request.query(request, "count")) do
    (Some(start), Some(count)) -> respond(leaves_request(get_pool(), start, count))
    _ -> respond(BinaryResult { status: 400, body: Bytes.empty() })
  end
end

fn internal_authorized(request :: Request) -> Bool do
  RuntimeJobs.internal_request_authorized(request, Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", ""))
end

pub fn handle_internal_anchor(request :: Request) -> Response do
  if !internal_authorized(request) do
    HTTP.response(401, "")
  else
    respond_json(submit_anchor_request(get_pool(), Request.body(request)))
  end
end

pub fn handle_internal_push_witnesses(request :: Request) -> Response do
  if !internal_authorized(request) do
    HTTP.response(401, "")
  else
    respond_json(push_witnesses_request(get_pool()))
  end
end

# Credits. The redeem route answers the privacy edge (the delivery token) and
# the object store (its own internal token); only the issuer appends its keys.

fn now_ms() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

pub fn handle_credits_redeem(request :: Request) -> Response do
  if !internal_authorized(request)
    && !RuntimeJobs.internal_request_authorized(request,
      Env.get("MESSENGER_OBJECT_INTERNAL_TOKEN", "")) do
    HTTP.response(401, "")
  else
    let started = now_ms()
    let result = credits_redeem_request(get_pool(),
      Env.get("MORSE_CREDITS_MODE", "off"),
      Request.body_bytes(request),
      started)
    credits_stats_record(now_ms() - started, result.status == 503)
    respond(result)
  end
end

pub fn handle_credits_health(_request :: Request) -> Response do
  respond_json(credits_health_request(get_pool(),
    Env.get("MORSE_CREDITS_MODE", "off"),
    credits_stats_snapshot(),
    now_ms()))
end

pub fn handle_credits_issuer_leaf(request :: Request) -> Response do
  if !RuntimeJobs.internal_request_authorized(request,
    Env.get("MORSE_CREDIT_ISSUER_INTERNAL_TOKEN", "")) do
    HTTP.response(401, "")
  else
    respond(credits_issuer_leaf_request(get_pool(), Request.body_bytes(request)))
  end
end

pub fn handle_credits_issuer_keys(request :: Request) -> Response do
  respond_no_store(credits_issuer_keys_request(get_pool(),
    Request.query(request, "previous_tree_size"),
    now_ms()))
end

# Mailbox extras. The policy is signed by the mailbox's device, so it needs no
# proof of work; storage arrives from the edge with its credits redeemed.

pub fn handle_mailbox_policy(request :: Request) -> Response do
  respond(mailbox_policy_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_mailbox_retention(request :: Request) -> Response do
  if !internal_authorized(request) do
    HTTP.response(401, "")
  else
    respond(mailbox_retention_request(get_pool(), Request.body_bytes(request), now_ms()))
  end
end

pub fn handle_credits_totals(request :: Request) -> Response do
  if !internal_authorized(request) do
    HTTP.response(401, "")
  else
    respond_json(credits_totals_request(get_pool(), Request.query(request, "week")))
  end
end
