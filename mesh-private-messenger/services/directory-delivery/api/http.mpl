from Api.Binary import BinaryResult, acknowledge_request, bind_push_request, checkpoint_request, claim_prekey_request, consistency_request, fetch_request, inclusion_request, publish_prekeys_request, register_device_request, register_request, resolve_devices_request, resolve_request, revoke_device_request, submit_configured_sealed_request, submit_request, submit_witness_request, unbind_push_request, witnesses_request
from Privacy.Edge import internal_delivery_authorized, internal_delivery_token
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

fn authorization_header(request :: Request) -> Option < String > do
  case Request.header(request, "Authorization") do
    None -> Request.header(request, "authorization")
    Some( value) -> Some(value)
  end
end

pub fn handle_sealed_submit(request :: Request) -> Response do
  case internal_delivery_token(Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    Err( _) -> HTTP.response(503, "")
    Ok( secret) -> if !internal_delivery_authorized(authorization_header(request), secret) do
      HTTP.response(401, "")
    else
      case submit_configured_sealed_request(get_pool(), Request.body_bytes(request)) do
        Err( _) -> HTTP.response(500, "")
        Ok( result) -> respond(result)
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
  case Request.query(request, "request") do
    None -> HTTP.response(400, "")
    Some( encoded) -> case Bytes.from_hex(encoded) do
      Err( _) -> HTTP.response(400, "")
      Ok( body) -> respond(claim_prekey_request(get_pool(), body))
    end
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
