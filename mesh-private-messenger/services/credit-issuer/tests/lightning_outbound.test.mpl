from Payment.LightningOutbound import (
  conversion_invoice,
  outbound_payment,
  outbound_payment_body,
  outbound_track_path
)
from Lightning.Invoice import parse_invoice

fn invoice() -> String do
  "lnbcrt50u1p4d3l06pp5fg0hmxq3l0l2yud3x20wcea3epf078sw2tz8swhgwyrf4yv60e5sdq4f4hhyum9yp3hyetyd968xcqzzsxqzuysp5xe8fr3fkk2pzgw5nkuy7y8k834jyq0e3e6kpa2vzykfhvaly5sts9qxpqysgqmhy4l6nwn2padyzpmek4hhme5ke5an3g0wasatmllw78wqnhwcjkrsa7zfrff4sttax2gw87lhjvux9wdn7ya0x2caumx57grdkyd9spgyzdct"
end

fn n(value :: String) -> U64!String do
  U64.parse(value)
end

fn cases() -> Bool!String do
  let parsed = parse_invoice(invoice())?
  let now = parsed.created_at
  let bound = conversion_invoice(invoice(), n("5000000")?, 2, parsed.payee, now, n("900")?)?
  assert(bound.payment_hash == parsed.payment_hash)
  for bad in [n("4999999")?, n("5000001")?] do
    assert(Result.is_err(conversion_invoice(invoice(), bad, 2, parsed.payee, now, n("900")?)))
  end
  assert(Result.is_err(conversion_invoice(invoice(),
    n("5000000")?,
    0,
    parsed.payee,
    now,
    n("900")?)))
  assert(Result.is_err(conversion_invoice(invoice(),
    n("5000000")?,
    2,
    parsed.payee,
    U64.add(now, n("61")?)?,
    n("900")?)))
  assert(Result.is_err(conversion_invoice(invoice(),
    n("5000000")?,
    2,
    parsed.payee,
    U64.subtract(now, n("1")?)?,
    n("900")?)))
  assert(Result.is_err(conversion_invoice(invoice(),
    n("5000000")?,
    2,
    parsed.payee,
    now,
    n("899")?)))
  let pending = "{\"result\":{\"status\":\"IN_FLIGHT\",\"payment_hash\":"
    <> Json.encode_string(Bytes.to_hex(parsed.payment_hash))
    <> "}}"
  assert(outbound_payment(pending, invoice(), n("1000")?)?.status == "IN_FLIGHT")
  assert(Result.is_err(outbound_payment(String.replace(pending, "IN_FLIGHT", "SUCCEEDED"),
    invoice(),
    n("1000")?)))
  assert(Result.is_err(outbound_payment(String.replace(pending,
      Bytes.to_hex(parsed.payment_hash),
      String.repeat("00", 32)),
    invoice(),
    n("1000")?)))
  let body = outbound_payment_body(invoice(), n("1000")?)?
  assert(Json.as_string(Json.object_get(Json.parse(body)?, "fee_limit_msat")?)? == "1000")
  assert(Json.as_bool(Json.object_get(Json.parse(body)?, "no_inflight_updates")?)?)
  assert(String.ends_with(List.head(String.split(outbound_track_path(parsed.payment_hash)?, "?")),
    "="))
  assert(Result.is_err(outbound_track_path(Bytes.empty())))
  Ok(true)
end

test("outbound Lightning binds exact provider invoice and refuses unproven success") do
  case cases() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
