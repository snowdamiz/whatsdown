##! Native credit transport: fixed routes, immutable issuer origin and trust.

from Mobile.NativeIssuerTls import issuer_tls_request
from Transparency.Config import SecurityConfig

pub fn post_credit(config :: SecurityConfig, route :: String, body :: Bytes) -> Bytes!String do
  if !List.contains([
      "/v1/credits/issuer",
      "/v1/credits/quote",
      "/v1/credits/issue",
      "/v1/credits/lightning/quote",
      "/v1/credits/lightning/issue",
      "/v1/credits/retention",
      "/v1/credits/signup-policy",
      "/v1/credits/signup",
      "/v1/credits/reconcile",
      "/v1/credits/postage",
      "/v1/credits/postage/reconcile",
      "/v1/credits/postage-policy"
    ],
    route)
    || Bytes.length(body) > 600000
    || config.issuer_origin == "-" do
    return Err("invalid_credit_plan")
  end
  # The origin was validated from native security resources. No URL, headers,
  # bearer credentials or body supplied by JavaScript reach this transport.
  let maximum = if route == "/v1/credits/postage-policy" do
    8
  else if List.contains(["/v1/credits/postage", "/v1/credits/postage/reconcile"], route) do
    564
  else
    600000
  end
  let request = Http.build(:post, config.issuer_origin <> route)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(body)
    |> Http.timeout(12000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(maximum)
  let trusted = issuer_tls_request(request, config.issuer_origin)?
  let response = case Http.send(trusted) do
    Ok(value) -> value
    Err(_) -> return Err("credit_transport_unavailable")
  end
  if response.status != 200
    && !(response.status == 201
      && List.contains([
          "/v1/credits/retention",
          "/v1/credits/signup",
          "/v1/credits/postage",
          "/v1/credits/postage/reconcile",
          "/v1/credits/postage-policy"
        ],
        route)) do
    return Err("credit_http_" <> Int.to_string(response.status))
  end
  Ok(response.body_bytes)
end
