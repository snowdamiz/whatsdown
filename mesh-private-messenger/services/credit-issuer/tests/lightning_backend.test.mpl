from Payment.LightningBackend import (
  LndConfig,
  validate_lnd_config,
  lnd_invoice_from_json,
  verify_lnd_identity
)
from Credits.Lightning import LightningQuote
from Lightning.Invoice import parse_invoice

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn fixture_invoice() -> String do
  "lnbcrt50u1p4d3l06pp5fg0hmxq3l0l2yud3x20wcea3epf078sw2tz8swhgwyrf4yv60e5sdq4f4hhyum9yp3hyetyd968xcqzzsxqzuysp5xe8fr3fkk2pzgw5nkuy7y8k834jyq0e3e6kpa2vzykfhvaly5sts9qxpqysgqmhy4l6nwn2padyzpmek4hhme5ke5an3g0wasatmllw78wqnhwcjkrsa7zfrff4sttax2gw87lhjvux9wdn7ya0x2caumx57grdkyd9spgyzdct"
end

fn config() -> LndConfig!String do
  let invoice = parse_invoice(fixture_invoice())?
  Ok(LndConfig {
    origin: "http://127.0.0.1:19877",
    macaroon: String.repeat("aa", 32),
    network: 2,
    purpose: 1,
    payee: invoice.payee
  })
end

fn record(state :: String,
  amount :: String,
  paid :: String,
  settled :: String,
  index :: String) -> String!String do
  let invoice = parse_invoice(fixture_invoice())?
  Ok("{\"state\":"
    <> Json.encode_string(state)
    <> ",\"r_hash\":"
    <> Json.encode_string(Bytes.to_base64(invoice.payment_hash))
    <> ",\"payment_request\":"
    <> Json.encode_string(fixture_invoice())
    <> ",\"value_msat\":"
    <> amount
    <> ",\"amt_paid_msat\":"
    <> paid
    <> ",\"creation_date\":"
    <> Json.encode_string(U64.to_string(invoice.created_at))
    <> ",\"expiry\":\"900\",\"settle_date\":"
    <> settled
    <> ",\"add_index\":\"1\",\"settle_index\":"
    <> index
    <> "}")
end

fn cases() -> Bool!String do
  let pinned = config()?
  let invoice = parse_invoice(fixture_invoice())?
  validate_lnd_config(pinned)?
  let identity = "{\"identity_pubkey\":"
    <> Json.encode_string(Bytes.to_hex(pinned.payee))
    <> ",\"chains\":[{\"chain\":\"bitcoin\",\"network\":\"regtest\"}],\"synced_to_chain\":true}"
  verify_lnd_identity(identity, pinned)?
  assert(Result.is_err(verify_lnd_identity(String.replace(identity, "regtest", "mainnet"), pinned)))
  assert(Result.is_err(verify_lnd_identity(String.replace(identity, "true", "false"), pinned)))
  for bad in [
    %{pinned | origin: "http://example.com"},
    %{pinned | origin: "https://example.com/x"},
    %{pinned | origin: "https://u@example.com"},
    %{pinned | origin: "https://example.com?x=1"},
    %{pinned | purpose: 0},
    %{pinned | macaroon: "aa\nInjected: yes"},
    %{pinned | macaroon: "zz"}
  ] do
    assert(Result.is_err(validate_lnd_config(bad)))
  end
  for state in ["OPEN", "ACCEPTED", "CANCELED"] do
    let value = lnd_invoice_from_json(record(state,
        "\"5000000\"",
        "\"5000000\"",
        "\"0\"",
        "\"0\"")?,
      invoice.payment_hash,
      pinned)?
    assert(value.state == state)
    assert(value.amount_msat == wide("5000000")?)
  end
  let settled_at = Json.encode_string(U64.to_string(U64.add(invoice.created_at, wide("10")?)?))
  let settled = record("SETTLED", "\"5000000\"", "\"5050000\"", settled_at, "\"1\"")?
  assert(lnd_invoice_from_json(settled,
    invoice.payment_hash,
    pinned)?.paid_msat == wide("5050000")?)
  for bad in [
    record("UNKNOWN", "\"5000000\"", "\"5000000\"", "\"0\"", "\"0\"")?,
    record("SETTLED", "\"5000000\"", "\"5000000\"", "\"0\"", "\"1\"")?,
    record("SETTLED", "\"5000000\"", "\"5000000\"", settled_at, "\"0\"")?,
    record("ACCEPTED", "5000000", "\"5000000\"", "\"0\"", "\"0\"")?,
    record("ACCEPTED", "\"5000001\"", "\"5000001\"", "\"0\"", "\"0\"")?,
    record("ACCEPTED", "\"5000000\"", "\"-1\"", "\"0\"", "\"0\"")?,
    record("ACCEPTED", "\"5000000\"", "\"1e7\"", "\"0\"", "\"0\"")?,
    record("ACCEPTED", "\"5000000\"", "\"05000000\"", "\"0\"", "\"0\"")?
  ] do
    assert(Result.is_err(lnd_invoice_from_json(bad, invoice.payment_hash, pinned)))
  end
  assert(Result.is_err(lnd_invoice_from_json(settled,
    Crypto.sha256(Bytes.from_utf8("another invoice")),
    pinned)))
  Ok(true)
end

test("Lightning backend pins its node and network and preserves exact authenticated invoice units") do
  case cases() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
