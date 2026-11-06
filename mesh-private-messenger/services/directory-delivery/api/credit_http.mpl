from Api.Binary import BinaryResult
from Api.CreditRetention import credit_retention_request
from Api.CreditDiscovery import (
  credit_issuer_discovery_request,
  credit_issuer_candidate_request,
  credit_issuer_cursor_request
)
from Api.Credits import (
  credit_redeem_request,
  credit_issuer_announce_request,
  credit_issuer_admit_request,
  credit_prune_request
)
from Runtime.Registry import get_pool
import RuntimeJobs

pub fn handle_credit_retention(request :: Request) -> Response do
  binary_response(credit_retention_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_credit_issuer_discovery(request :: Request) -> Response do
  binary_response(credit_issuer_discovery_request(get_pool(), Request.body_bytes(request)))
end

fn binary_response(result :: BinaryResult) -> Response do
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.new()
      |> Map.put("Content-Type", "application/octet-stream")
      |> Map.put("Cache-Control", "no-store"))
end

pub fn handle_credit_issuer_candidate(request :: Request) -> Response do
  if !authorized(request, "MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN") do
    return binary_response(BinaryResult { status: 401, body: Bytes.empty() })
  end
  binary_response(credit_issuer_candidate_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_credit_issuer_cursor(request :: Request) -> Response do
  if !authorized(request, "MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN") do
    return binary_response(BinaryResult { status: 401, body: Bytes.empty() })
  end
  binary_response(credit_issuer_cursor_request(get_pool()))
end

fn respond(result :: BinaryResult) -> Response do
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.new()
      |> Map.put("Content-Type", "application/json")
      |> Map.put("Cache-Control", "no-store"))
end

fn authorized(request :: Request, name :: String) -> Bool do
  RuntimeJobs.internal_request_authorized(request, Env.get(name, ""))
end

pub fn handle_credit_redeem(request :: Request) -> Response do
  if !authorized(request, "MESSENGER_DELIVERY_INTERNAL_TOKEN") do
    return respond(BinaryResult { status: 401, body: Bytes.empty() })
  end
  respond(credit_redeem_request(get_pool(), Request.body_bytes(request)))
end

# Issuer administration is a different authority from consuming services.
# A witnessed append-only checkpoint does not grant semantic issuer approval.
pub fn handle_credit_issuer_announce(request :: Request) -> Response do
  if !authorized(request, "MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN") do
    return respond(BinaryResult { status: 401, body: Bytes.empty() })
  end
  respond(credit_issuer_announce_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_credit_issuer_admit(request :: Request) -> Response do
  if !authorized(request, "MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN") do
    return respond(BinaryResult { status: 401, body: Bytes.empty() })
  end
  respond(credit_issuer_admit_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_credit_prune(request :: Request) -> Response do
  if !authorized(request, "MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN") do
    return respond(BinaryResult { status: 401, body: Bytes.empty() })
  end
  respond(credit_prune_request(get_pool(), Request.body_bytes(request)))
end
