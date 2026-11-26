from Api.Binary import forward_submission

fn accepts_authenticated_delivery(request :: Request) -> Response do
  let authorized = case Request.header(request, "Authorization") do
    None -> case Request.header(request, "authorization") do
      None -> false
      Some(value) -> value == "Bearer 0123456789abcdef0123456789abcdef"
    end
    Some(value) -> value == "Bearer 0123456789abcdef0123456789abcdef"
  end
  if authorized && Bytes.secure_equals(Request.body_bytes(request), Bytes.from_utf8("sealed")) do
    HTTP.response(202, "")
  else
    HTTP.response(401, "")
  end
end

actor delivery_core() do
  HTTP.router()
    |> HTTP.on_post("/internal/v1/envelopes/sealed", accepts_authenticated_delivery)
    |> HTTP.serve(18995)
end

test("privacy edge sends the matching internal bearer credential") do
  let _server = spawn(delivery_core)
  Timer.sleep(100)
  case forward_submission(Bytes.from_utf8("sealed"),
    "http://127.0.0.1:18995",
    "0123456789abcdef0123456789abcdef") do
    Err(_) -> assert(false)
    Ok(response) -> assert(response.status == 202)
  end
  Process.request_shutdown()
  Timer.sleep(50)
end
