from Api.Anchors import anchor_receipt_request_for, record_anchor_receipt_request
from Api.AnchorWork import anchor_candidate_request_for, anchor_cosign_request
from Api.Binary import BinaryResult
from Runtime.Registry import get_pool
import RuntimeJobs

fn respond(result :: BinaryResult) -> Response do
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.new()
      |> Map.put("Content-Type", "application/json")
      |> Map.put("Cache-Control", "no-store"))
end

pub fn handle_anchor_candidate(request :: Request) -> Response do
  if !RuntimeJobs.internal_request_authorized(request,
    Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    return respond(BinaryResult { status: 401, body: Bytes.empty() })
  end
  let version = case Request.param(request, "version") do
    Some("1") -> 1
    Some("2") -> 2
    _ -> return respond(BinaryResult { status: 400, body: Bytes.empty() })
  end
  respond(anchor_candidate_request_for(get_pool(), version))
end

pub fn handle_anchor_cosigns(request :: Request) -> Response do
  if !RuntimeJobs.internal_request_authorized(request,
    Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    return respond(BinaryResult { status: 401, body: Bytes.empty() })
  end
  respond(anchor_cosign_request(get_pool(), Request.body_bytes(request)))
end

fn read_receipt(request :: Request, version :: Int) -> Response do
  let sequence = case Request.param(request, "sequence") do
    None -> return respond(BinaryResult { status: 400, body: Bytes.empty() })
    Some(value) -> value
  end
  respond(anchor_receipt_request_for(get_pool(), version, sequence))
end

pub fn handle_v1_anchor_receipt(request :: Request) -> Response do
  read_receipt(request, 1)
end

pub fn handle_v2_anchor_receipt(request :: Request) -> Response do
  read_receipt(request, 2)
end

pub fn handle_record_anchor_receipt(request :: Request) -> Response do
  # This route is not on the public gateway allowlist. Check authorization
  # before touching the registry, pool or body decoder.
  if !RuntimeJobs.internal_request_authorized(request,
    Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    return respond(BinaryResult { status: 401, body: Bytes.empty() })
  end
  respond(record_anchor_receipt_request(get_pool(), Request.body_bytes(request)))
end
