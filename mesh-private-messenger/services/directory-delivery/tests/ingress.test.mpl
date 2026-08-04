from Api.Router import build_router, direct_delivery_compatibility_enabled
from Privacy.Edge import internal_delivery_authorization, internal_delivery_authorized, internal_delivery_token

test("direct delivery compatibility is denied by default and requires exact opt in") do
  assert(!direct_delivery_compatibility_enabled(""))
  assert(!direct_delivery_compatibility_enabled("ENABLED"))
  assert(direct_delivery_compatibility_enabled("enabled"))
end

test("missing and wrong internal bearers are denied and the exact bearer succeeds") do
  let secret = "0123456789abcdef0123456789abcdef"
  case internal_delivery_token(secret) do
    Err( _) -> assert(false)
    Ok( validated) -> do
      case internal_delivery_authorization(validated) do
        Err( _) -> assert(false)
        Ok( value) -> assert(value == "Bearer " <> secret)
      end
      assert(internal_delivery_authorized(Some("Bearer " <> secret), validated))
      assert(!internal_delivery_authorized(None, validated))
      assert(!internal_delivery_authorized(Some("Bearer wrong"), validated))
    end
  end
end

test("service startup rejects a missing internal delivery token") do
  case internal_delivery_token("") do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
end

actor directory_router() do
  build_router()
    |> HTTP.serve(18994)
end

test("default router exposes neither GET prekey claims nor public direct delivery") do
  let _server = spawn(directory_router)
  Timer.sleep(100)
  case Http.build(:get, "http://127.0.0.1:18994/v1/prekeys/bundle")
    |> Http.max_response_bytes(1024)
    |> Http.send() do
    Err( _) -> assert(false)
    Ok( response) -> assert(response.status == 404)
  end
  case Http.build(:post, "http://127.0.0.1:18994/v1/prekeys/bundle")
    |> Http.body_bytes(Bytes.from_utf8("invalid"))
    |> Http.max_response_bytes(1024)
    |> Http.send() do
    Err( _) -> assert(false)
    Ok( response) -> do
      assert(response.status == 400)
      assert(Map.get(response.headers, "cache-control") == "no-store")
    end
  end
  case Http.build(:post, "http://127.0.0.1:18994/v1/envelopes/batch")
    |> Http.body_bytes(Bytes.from_utf8("hostile"))
    |> Http.send() do
    Err( _) -> assert(false)
    Ok( response) -> assert(response.status == 404)
  end
  Process.request_shutdown()
  Timer.sleep(50)
end
