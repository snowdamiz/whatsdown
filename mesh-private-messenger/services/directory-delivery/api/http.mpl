from Api.Binary import BinaryResult, acknowledge_request, checkpoint_request, consistency_request, delivery_seed, fetch_request, inclusion_request, register_device_request, register_request, resolve_devices_request, resolve_request, revoke_device_request, submit_request, submit_sealed_request, submit_witness_request, witnesses_request
from Runtime.Registry import get_pool

fn respond(result :: BinaryResult) -> Response do
  HTTP.response_bytes(result.status, result.body)
end

pub fn handle_health(_request :: Request) -> Response do
  HTTP.response(200, "ok")
end

pub fn handle_register(request :: Request) -> Response do
  respond(register_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_resolve(request :: Request) -> Response do
  respond(resolve_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_register_device(request :: Request) -> Response do
  respond(register_device_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_resolve_devices(request :: Request) -> Response do
  respond(resolve_devices_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_revoke_device(request :: Request) -> Response do
  respond(revoke_device_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_submit(request :: Request) -> Response do
  respond(submit_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_sealed_submit(request :: Request) -> Response do
  case delivery_seed() do
    Err( _) -> HTTP.response(500, "")
    Ok( seed) -> respond(submit_sealed_request(get_pool(), Request.body_bytes(request), seed))
  end
end

pub fn handle_fetch(request :: Request) -> Response do
  respond(fetch_request(get_pool(), Request.body_bytes(request)))
end

pub fn handle_acknowledge(request :: Request) -> Response do
  respond(acknowledge_request(get_pool(), Request.body_bytes(request)))
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
