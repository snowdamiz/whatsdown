##! Lightning (phase 4b) through an LND node's REST API: one invoice per
##! quote, paid when LND reports it SETTLED. Off unless MORSE_CREDIT_LND_URL
##! is set; the macaroon (invoice permissions only) is
##! MORSE_CREDIT_LND_MACAROON_HEX.

pub struct LightningInvoice do
  payment_request :: String
  r_hash :: Bytes
end

fn lnd_send(builder, macaroon :: String) -> HttpResponse!String do
  let authorized = if macaroon == "" do
    builder
  else
    Http.header(builder, "Grpc-Metadata-macaroon", macaroon)
  end
  case authorized
    |> Http.timeout(10000)
    |> Http.max_response_bytes(65536)
    |> Http.send() do
    Err(error) -> Err("lnd unreachable: #{error}")
    Ok(response) -> if response.status == 200 do
      Ok(response)
    else
      Err("lnd answered #{response.status}")
    end
  end
end

## A 15-minute invoice for `sats`.

pub fn issuer_lnd_invoice(lnd_url :: String,
  macaroon :: String,
  sats :: Int,
  memo :: String) -> LightningInvoice!String do
  let body = "{\"value\":\""
    <> Int.to_string(sats)
    <> "\",\"memo\":"
    <> Json.encode_string(memo)
    <> ",\"expiry\":\"900\"}"
  let response = lnd_send(Http.build(:post, lnd_url <> "/v1/invoices")
      |> Http.header("Content-Type", "application/json")
      |> Http.body(body),
    macaroon)?
  let parsed = Json.parse(response.body)?
  let r_hash = Bytes.from_base64(Json.as_string(Json.object_get(parsed, "r_hash")?)?)?
  if Bytes.length(r_hash) != 32 do
    Err("lnd answered an invalid payment hash")
  else
    Ok(LightningInvoice {
      payment_request: Json.as_string(Json.object_get(parsed, "payment_request")?)?,
      r_hash: r_hash
    })
  end
end

fn number(parsed :: Json, name :: String) -> Int!String do
  case String.to_int(Json.as_string(Json.object_get(parsed, name)?)?) do
    Some(value) -> Ok(value)
    None -> Err("invalid lnd number")
  end
end

## Some((sats paid, settle time in seconds)) once the invoice is SETTLED.

pub fn issuer_lnd_settled(lnd_url :: String,
  macaroon :: String,
  r_hash :: Bytes) -> Option<(Int, Int)>!String do
  let response = lnd_send(Http.build(:get, lnd_url <> "/v1/invoice/" <> Bytes.to_hex(r_hash)),
    macaroon)?
  let parsed = Json.parse(response.body)?
  if Json.as_string(Json.object_get(parsed, "state")?)? != "SETTLED" do
    Ok(None)
  else
    Ok(Some((number(parsed, "amt_paid_sat")?, number(parsed, "settle_date")?)))
  end
end
