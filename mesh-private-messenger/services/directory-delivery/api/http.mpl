from Api.Binary import Admission, BinaryResult, CheckedRequest, acknowledge_request, admission_failure, check_request, bind_push_request, checkpoint_request, claim_prekey_request, consistency_request, delete_account_request, fetch_request, leave_device_request, inclusion_request, publish_prekeys_request, register_device_request, resolve_devices_request, revoke_device_request, spend_request, submit_configured_sealed_request, submit_request, submit_witness_request, unbind_push_request, witnesses_request
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

pub fn handle_health(_request :: Request) -> Response do
  HTTP.response(200, "ok")
end

# Register, resolve and prekey claim are anonymous, so each must arrive wrapped
# in proof of work minted for that endpoint. The limits are the largest body
# each inner codec accepts.

fn admitted(request :: Request, label :: String, maximum_payload :: Int) -> Admission!String do
  case check_request(label,
    Request.body_bytes(request),
    maximum_payload,
    U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?,
    Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16))? do
    RequestMalformed -> Ok(AdmissionMalformed)
    RequestUnpaid -> Ok(AdmissionRefused)
    RequestPaid(payload, spent_key) -> spend_request(get_pool(), payload, spent_key)
  end
end

pub fn handle_register_device(request :: Request) -> Response do
  case admitted(request, "mesh-msg/v1/work/register", 36006) do
    Ok(Admitted(payload)) -> respond(register_device_request(get_pool(), payload))
    refused -> respond(admission_failure(refused))
  end
end

pub fn handle_resolve_devices(request :: Request) -> Response do
  case admitted(request, "mesh-msg/v1/work/resolve", 76) do
    Ok(Admitted(payload)) -> respond(resolve_devices_request(get_pool(), payload))
    refused -> respond(admission_failure(refused))
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
  case admitted(request, "mesh-msg/v1/work/prekey-claim", 100) do
    Ok(Admitted(body)) -> case decode_prekey_claim(body) do
      Err(_) -> respond_no_store(BinaryResult { status: 400, body: Bytes.empty() })
      Ok(_) -> respond_no_store(claim_prekey_request(get_pool(), body))
    end
    refused -> respond_no_store(admission_failure(refused))
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

pub fn handle_transparency_witnesses(_request :: Request) -> Response do
  respond(witnesses_request(get_pool()))
end

pub fn handle_transparency_witness_submit(request :: Request) -> Response do
  respond(submit_witness_request(get_pool(), Request.body_bytes(request)))
end
