import File
from Mobile.CreditPurchase import prepare_credit_purchase, accept_credit_quote
from MobileCore import (
  create_account_export,
  credit_discovery_export,
  credit_prepare_export,
  credit_purchases_export,
  credit_recover_export,
  credit_balance_export
)
from MobileCore import (
  credit_retention_export,
  credit_retention_recover_export,
  credit_receipt_export
)
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from MobileCore import credit_quote_export
from MobileCore import (
  credit_payment_url_export,
  credit_payment_signature_export,
  credit_wallet_quote_export
)
from Credits.Issuance import CreditQuote, decode_credit_quote_request, encode_credit_quote
from Credits.QuoteAuth import sign_credit_quote, encode_signed_credit_quote
from Solana.Read import pubkey, spl_token_program
from Solana.Address import find_program_address
from Mobile.CreditWallet import completed_credit_record
from Mobile.CreditState import CreditWallet, pack_credit_parts, unpack_credit_parts
from Mobile.CreditWallet import add_credit_issuer
from Mobile.Codec import current_time, mobile_write_u32
from Credits.Issuer import CreditIssuerKey
from Credits.Policy import issuer_epoch
from Storage.Credits import CreditWalletIdentity, load_credit_wallet, commit_credit_wallet
from Storage.Keys import platform_key
from Transport.Packet import decode_client_profile
from Transparency.Config import SecurityConfig, WitnessPin, witness_set_id, encode_security_config
from Tests.Support import append, vector, database_path, repeated

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("credit_native")?
  let profile = decode_client_profile(create_account_export(append(vector(Bytes.from_utf8(path))?,
    vector(Bytes.from_utf8("credit-native"))?)?)?)?
  let pins = [
    WitnessPin { witness_id: "outside", public_key: repeated(55, 32)?, operator_label: "Outside" }
  ]
  let config = SecurityConfig {
    version: 3,
    wire_version: 3,
    minimum_session_suite: 1,
    service_public_key: repeated(54, 32)?,
    delivery_public_key: repeated(56, 32)?,
    abuse_difficulty: 1,
    threshold: 1,
    witnesses: pins,
    set_id: witness_set_id(pins, 1)?,
    anchor_address: "-",
    anchor_program: "-",
    anchor_log_name: "-",
    rpc_urls: [],
    issuer_origin: "https://edge.example",
    log_version: 2,
    legacy_threshold: 1,
    legacy_witnesses: pins,
    relay_urls: [],
    slash_mint: "-"
  }
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(config)?))
  let packet = pack_credit_parts([Bytes.from_utf8(path)])?
  assert(Result.is_err(credit_discovery_export(packet)))
  for selector in [
    Bytes.empty(),
    repeated(0, 2)?,
    Bytes.from_hex("0102")?,
    Bytes.from_hex("010100")?
  ] do
    assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), selector))
    assert(Result.is_err(credit_discovery_export(packet)))
  end
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0101")?))
  let discovery = unpack_credit_parts(credit_discovery_export(packet)?, 4, 4096)?
  assert(Bytes.to_hex(List.head(discovery)) == "014d4344")
  assert(Bytes.to_utf8(List.get(discovery, 1))? == "https://edge.example")
  assert(Bytes.to_utf8(List.get(discovery, 2))? == "/v1/credits/issuer")
  # The native boundary gets account/device identity from the encrypted profile.
  # Seed an authenticated-key fixture internally, never through an FFI SPKI API.
  let wrapping = platform_key()?
  let who = CreditWalletIdentity {
    account_id: profile.account_id,
    device_id: profile.device_id,
    service_key: config.service_public_key,
    purpose: 1
  }
  let signing = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(signing) do
    Err(_) -> return Err("test public failed")
    Ok(value) -> value
  end
  let now = U64.divide(current_time()?, U64.parse("1000")?)?
  let before = load_credit_wallet(path, wrapping, who)?
  let quote_pair = case Crypto.signing_generate() do
    Err(_) -> return Err("test quote key failed")
    Ok(value) -> value
  end
  let issuer = CreditIssuerKey {
    epoch: issuer_epoch(now)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: quote_pair.public_key.bytes
  }
  let base = add_credit_issuer(before.wallet, issuer, now, 1)?
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: U64.parse("1")?, records: base.records })?
  let prepared = unpack_credit_parts(credit_prepare_export(pack_credit_parts([
      Bytes.from_utf8(path),
      mobile_write_u32(100)?,
      Bytes.from_hex("00")?
    ])?)?,
    10,
    600000)?
  assert(Bytes.to_hex(List.head(prepared)) == "024d4350"
    && Bytes.to_hex(List.get(prepared, 2)) == "00")
  assert(Bytes.to_utf8(List.get(prepared, 6))? == "/v1/credits/quote"
    && Bytes.length(List.get(prepared, 7)) == 72)
  let ids = unpack_credit_parts(credit_purchases_export(packet)?, 2049, 32)?
  assert(List.length(ids) == 2 && Bytes.secure_equals(List.get(ids, 1), List.get(prepared, 1)))
  let recovered = unpack_credit_parts(credit_recover_export(pack_credit_parts([
      Bytes.from_utf8(path),
      List.get(ids, 1)
    ])?)?,
    10,
    600000)?
  assert(Bytes.secure_equals(List.get(recovered, 7), List.get(prepared, 7)))
  let quote_request = decode_credit_quote_request(List.get(prepared, 7))?
  let forged_quote = CreditQuote {
    quote_id: repeated(81, 32)?,
    deposit_owner: repeated(82, 32)?,
    destination: repeated(83, 32)?,
    mint: repeated(84, 32)?,
    asset: 0,
    amount: U64.parse("5000000")?,
    purpose: 1,
    credits: 100,
    issued_at: now,
    expires_at: U64.add(now, U64.parse("900")?)?,
    issuer_key_id: quote_request.issuer_key_id,
    batch_hash: quote_request.batch_hash
  }
  assert(Result.is_err(credit_quote_export(pack_credit_parts([
    Bytes.from_utf8(path),
    List.get(prepared, 1),
    encode_credit_quote(forged_quote)?
  ])?)))
  let associated = find_program_address(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?,
    [forged_quote.deposit_owner, spl_token_program()?.bytes, forged_quote.mint])?.address.bytes
  let quote = %{forged_quote | destination: associated}
  let signed = encode_signed_credit_quote(sign_credit_quote(quote_pair.private_key, quote)?)?
  credit_quote_export(pack_credit_parts([Bytes.from_utf8(path), List.get(prepared, 1), signed])?)?
  let payment = pack_credit_parts([Bytes.from_utf8(path), List.get(prepared, 1)])?
  assert(Result.is_err(credit_payment_url_export(payment)))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/wallet/v1"),
    Bytes.concat(Bytes.from_hex("0101")?, quote.mint)?))
  let url = Bytes.to_utf8(credit_payment_url_export(payment)?)?
  assert(String.starts_with(url, "solana:") && String.contains(url, "amount=5.000000"))
  assert(Bytes.secure_equals(credit_wallet_quote_export(payment)?, encode_credit_quote(quote)?))
  assert(Result.is_err(credit_payment_signature_export(pack_credit_parts([
    Bytes.from_utf8(path),
    List.get(prepared, 1),
    Bytes.from_utf8(" 111")
  ])?)))
  credit_payment_signature_export(pack_credit_parts([
    Bytes.from_utf8(path),
    List.get(prepared, 1),
    Bytes.from_utf8(Bytes.to_base58(repeated(76, 64)?))
  ])?)?
  assert(Result.is_err(credit_payment_url_export(payment)))
  assert(Result.is_err(credit_wallet_quote_export(payment)))
  let balance_packet = unpack_credit_parts(credit_balance_export(packet)?, 8, 64)?
  assert(List.length(balance_packet) == 8)
  assert(Bytes.to_hex(List.get(balance_packet, 0)) == "034d4342")
  assert(Bytes.to_hex(List.get(balance_packet, 6)) == "01")
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0100")?))
  let live_balance = unpack_credit_parts(credit_balance_export(packet)?, 8, 64)?
  assert(Bytes.to_hex(List.get(live_balance, 0)) == "034d4342")
  assert(Bytes.to_hex(List.get(live_balance, 6)) == "00")
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0101")?))
  let current = load_credit_wallet(path, wrapping, who)?
  let purchased = U64.subtract(now, U64.parse("600")?)?
  let tokens = for index in 0..10 do
    let pending = blind_credit(issuer, who.service_key, purchased)?
    let item = pending.request
    completed_credit_record(finalize_credit(issuer,
        pending,
        sign_credit_request(signing, issuer, item)?)?,
      issuer,
      purchased,
      wrapping,
      who)?
  end
  commit_credit_wallet(path,
    wrapping,
    who,
    current,
    CreditWallet {
      revision: U64.add(current.wallet.revision, U64.parse("1")?)?,
      records: current.wallet.records ++ tokens
    })?
  let retention_packet = pack_credit_parts([Bytes.from_utf8(path), mobile_write_u32(32)?])?
  let retention = unpack_credit_parts(credit_retention_export(retention_packet)?, 7, 100000)?
  assert(Bytes.to_hex(List.head(retention)) == "014d4354")
  assert(Bytes.to_utf8(List.get(retention, 5))? == "/v1/credits/retention")
  let retention_retry = unpack_credit_parts(credit_retention_export(retention_packet)?, 7, 100000)?
  assert(Bytes.secure_equals(List.get(retention_retry, 1), List.get(retention, 1)))
  assert(Bytes.secure_equals(List.get(retention_retry, 6), List.get(retention, 6)))
  assert(Result.is_err(credit_retention_export(pack_credit_parts([
    Bytes.from_utf8(path),
    mobile_write_u32(62)?
  ])?)))
  assert(Result.is_err(credit_receipt_export(pack_credit_parts([
    Bytes.from_utf8(path),
    Bytes.from_utf8("HTTP200isnotproof")
  ])?)))
  let retained = unpack_credit_parts(credit_retention_recover_export(pack_credit_parts([
      Bytes.from_utf8(path),
      List.get(retention, 1)
    ])?)?,
    7,
    100000)?
  assert(Bytes.secure_equals(List.get(retained, 6), List.get(retention, 6)))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0100")?))
  assert(Result.is_err(credit_recover_export(pack_credit_parts([
    Bytes.from_utf8(path),
    List.get(ids, 1)
  ])?)))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0101")?))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(%{config | issuer_origin: "-"})?))
  assert(Result.is_err(credit_recover_export(pack_credit_parts([
    Bytes.from_utf8(path),
    List.get(ids, 1)
  ])?)))
  assert(Result.is_err(credit_discovery_export(Bytes.concat(packet, Bytes.from_hex("00")?)?)))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(config)?))
  let old_path = database_path("credit_native_expired")?
  let old_profile = decode_client_profile(create_account_export(append(vector(Bytes.from_utf8(old_path))?,
    vector(Bytes.from_utf8("credit-expired"))?)?)?)?
  let old_who = %{who | account_id: old_profile.account_id, device_id: old_profile.device_id}
  let past = U64.subtract(now, U64.parse("1000")?)?
  let old_issuer = %{issuer | epoch: issuer_epoch(past)?}
  let old_before = load_credit_wallet(old_path, wrapping, old_who)?
  let old_base = add_credit_issuer(old_before.wallet, old_issuer, past, 1)?
  commit_credit_wallet(old_path,
    wrapping,
    old_who,
    old_before,
    CreditWallet { revision: U64.parse("1")?, records: old_base.records })?
  let old_plan = prepare_credit_purchase(old_path, wrapping, old_who, 100, 0, past)?
  let old_request = decode_credit_quote_request(old_plan.quote_request)?
  let old_quote = %{quote |
    issued_at: past,
    expires_at: U64.add(past, U64.parse("900")?)?,
    issuer_key_id: old_request.issuer_key_id,
    batch_hash: old_request.batch_hash
  }
  accept_credit_quote(old_path,
    wrapping,
    old_who,
    old_plan.purchase_id,
    encode_signed_credit_quote(sign_credit_quote(quote_pair.private_key, old_quote)?)?,
    past)?
  # The UI receives authenticated expiry status instead of conflating an
  # expired signed quote with malformed or unauthenticated payment data.
  case credit_payment_url_export(pack_credit_parts([
    Bytes.from_utf8(old_path),
    old_plan.purchase_id
  ])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "credit_quote_expired")
  end
  File.delete(old_path)?
  File.delete(path)?
  Ok(true)
end

test("native credit plans require signed native purpose and recover the committed prequote body") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
