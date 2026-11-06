from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  generate_account,
  generate_device,
  issue_device_credential
)
from Prekeys.Bundle import build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey
from Protocol.IdentityWire import encode_account_identity
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.DirectoryWire import encode_directory_entry
from Protocol.V1 import AccountIdentity, DirectoryEntry
from Credits.PostagePolicy import sign_postage_policy, encode_postage_policy
from Privacy.Edge import mint_request_stamp, encode_stamped_request

pub struct PricingPostageFixture do
  target :: Bytes
  registration :: Bytes
  policy_five :: Bytes
  policy_one :: Bytes
end

fn bytes(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("test bytes failed")
    Ok(value)
  end
end

fn now() -> U64!String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn entry(owner :: borrow AccountKeys,
  identity :: AccountIdentity,
  device :: borrow DeviceKeys,
  sequence :: String,
  token :: Int) -> DirectoryEntry!String do
  let created = now()?
  let expires = U64.add(created, U64.parse("86400000")?)?
  let credential = case issue_device_credential(owner,
    device,
    U64.parse("1")?,
    created,
    expires,
    U64.parse(sequence)?) do
    Err(_) -> return Err("test credential failed")
    Ok(value) -> value
  end
  let signed = case generate_signed_prekey(device, credential, U64.parse("1")?, expires) do
    Err(_) -> return Err("test prekey failed")
    Ok(value) -> value
  end
  let once = case generate_one_time_prekey(U64.parse("1")?) do
    Err(_) -> return Err("test prekey failed")
    Ok(value) -> value
  end
  let bundle = case build_prekey_bundle(credential, signed, once) do
    Err(_) -> return Err("test bundle failed")
    Ok(value) -> value
  end
  let account_bytes = case encode_account_identity(identity) do
    Err(_) -> return Err("test identity failed")
    Ok(value) -> value
  end
  let bundle_bytes = case encode_prekey_bundle(bundle) do
    Err(_) -> return Err("test bundle failed")
    Ok(value) -> value
  end
  Ok(DirectoryEntry {
    version: 1,
    username: "ledger-postage-owner",
    account_identity: account_bytes,
    prekey_bundle: bundle_bytes,
    mailbox_token: bytes(token, 32)?
  })
end

fn pricing_postage_fixture() -> PricingPostageFixture!String do
  let (owner, identity) = case generate_account(now()?, U64.parse("1")?) do
    Err(_) -> return Err("fixture account failed")
    Ok(value) -> value
  end
  let device = case generate_device() do
    Err(_) -> return Err("fixture device failed")
    Ok(value) -> value
  end
  let registration = case encode_directory_entry(entry(owner, identity, device, "1", 83)?) do
    Err(_) -> return Err("fixture registration failed")
    Ok(value) -> value
  end
  let expiry = U64.add(now()?, U64.parse("240000")?)?
  let stamped = encode_stamped_request(mint_request_stamp("mesh-msg/v1/work/register",
      registration,
      expiry,
      17)?,
    registration)?
  Ok(PricingPostageFixture {
    target: identity.account_id,
    registration: stamped,
    policy_five: encode_postage_policy(sign_postage_policy(owner,
      device.device_id,
      U64.parse("1")?,
      U64.parse("1")?,
      5,
      now()?)?)?,
    policy_one: encode_postage_policy(sign_postage_policy(owner,
      device.device_id,
      U64.parse("2")?,
      U64.parse("2")?,
      1,
      now()?)?)?
  })
end

from Credits.Action import CreditAction, encode_credit_action
from Credits.Issuer import CreditIssuerKey, encode_issuer_key, verify_issuer_key
from Credits.Policy import issuer_epoch
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Credits.Wire import CreditToken, CreditFrame, encode_credit_frame
from Transparency.Wire import (
  TransparencyEvidence,
  decode_checkpoint,
  encode_transparency_evidence,
  decode_transparency_evidence,
  encode_witnesses
)
from Transparency.Merkle import (
  leaf_hash_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness
)
from Transparency.Merkle import WitnessKey, WitnessAttestation, TransparencyCheckpoint

fn fail(error :: String) do
  io_eprintln(error)
  Process.exit(1)
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn pair(name :: String) -> SigningKeyPair!String do
  let seed = case Env.get_secret_hex(name) do
    Err(_) -> return Err("fixture signing seed unavailable")
    Ok(value) -> value
  end
  case Crypto.signing_from_secret(seed) do
    Err(_) -> Err("fixture signing failed")
    Ok(value)
  end
end

fn mint(secret :: borrow BlindRsaSecretKey,
  key :: CreditIssuerKey,
  service_key :: Bytes,
  now :: U64) -> CreditToken!String do
  let pending = blind_credit(key, service_key, now)?
  let response = sign_credit_request(secret, key, pending.request)?
  finalize_credit(key, pending, response)
end

fn typed_request(name :: String,
  kind :: Int,
  nonce :: Int,
  quantity :: Int,
  tokens :: List<CreditToken>,
  now :: U64,
  body_name :: String,
  target :: Bytes) -> String!String do
  let body = Bytes.from_utf8("credit fixture " <> body_name)
  let action = CreditAction {
    kind: kind,
    operation_nonce: Bytes.from_hex(String.repeat(if nonce < 10 do
        "0#{nonce}"
      else
        "#{nonce}"
      end,
      32))?,
    target: target,
    expires_at: U64.add(now, wide(600)?)?,
    quantity: wide(quantity)?,
    request_sha256: Crypto.sha256(body)
  }
  let frame = CreditFrame { binding: Crypto.sha256(body), tokens: tokens }
  Ok(Json.encode_string(name)
    <> ":{\"schema_version\":1,\"action\":"
    <> Json.encode_string(Bytes.to_hex(encode_credit_action(action)?))
    <> ",\"request_body\":"
    <> Json.encode_string(Bytes.to_hex(body))
    <> ",\"frame\":"
    <> Json.encode_string(Bytes.to_hex(encode_credit_frame(frame)?))
    <> "}")
end

fn request(name :: String,
  nonce :: Int,
  quantity :: Int,
  tokens :: List<CreditToken>,
  now :: U64,
  body_name :: String) -> String!String do
  typed_request(name,
    1,
    nonce,
    quantity,
    tokens,
    now,
    body_name,
    Bytes.from_hex(String.repeat("77", 32))?)
end

fn prepare() -> String!String do
  let now = wide(DateTime.to_unix_ms(DateTime.utc_now()) / 1000)?
  let secret = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("fixture RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(secret) do
    Err(_) -> return Err("fixture RSA public failed")
    Ok(value) -> value
  end
  let signer = pair("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX")?
  let key = CreditIssuerKey {
    epoch: issuer_epoch(now)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: signer.public_key.bytes
  }
  let first = mint(secret, key, signer.public_key.bytes, now)?
  let second = mint(secret, key, signer.public_key.bytes, now)?
  let fresh = mint(secret, key, signer.public_key.bytes, now)?
  let priced = mint(secret, key, signer.public_key.bytes, now)?
  let rogue_secret = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("fixture rogue RSA failed")
    Ok(value) -> value
  end
  let rogue_public = case Crypto.blind_rsa_public(rogue_secret) do
    Err(_) -> return Err("fixture rogue public failed")
    Ok(value) -> value
  end
  let rogue_key = %{key | spki: rogue_public.bytes}
  let rogue = mint(rogue_secret, rogue_key, signer.public_key.bytes, now)?
  let postage = pricing_postage_fixture()?
  let requests = [
    request("race_a", 1, 16777217, [first], now, "race_a")?,
    request("race_b", 2, 16777217, [first], now, "race_b")?,
    request("mixed", 3, 33554433, [fresh, first], now, "mixed")?,
    request("fresh", 4, 16777217, [fresh], now, "fresh")?,
    request("second", 5, 16777217, [second], now, "second")?,
    request("replacement_a", 1, 16777217, [second], now, "race_a")?,
    request("replacement_b", 2, 16777217, [second], now, "race_b")?,
    request("rogue", 6, 16777217, [rogue], now, "rogue")?,
    typed_request("postage", 3, 7, 0, [priced], now, "postage", postage.target)?,
    typed_request("signup",
      4,
      8,
      0,
      [priced],
      now,
      "signup",
      Bytes.from_hex(String.repeat("77", 32))?)?
  ]
  Ok("{\"leaf\":"
    <> Json.encode_string(Bytes.to_hex(encode_issuer_key(key)?))
    <> ",\"rogue_leaf\":"
    <> Json.encode_string(Bytes.to_hex(encode_issuer_key(rogue_key)?))
    <> ",\"postage_registration\":"
    <> Json.encode_string(Bytes.to_hex(postage.registration))
    <> ",\"postage_policy_five\":"
    <> Json.encode_string(Bytes.to_hex(postage.policy_five))
    <> ",\"postage_policy_one\":"
    <> Json.encode_string(Bytes.to_hex(postage.policy_one))
    <> ",\"requests\":{"
    <> String.join(requests, ",")
    <> "}}")
end

fn witness() -> String!String do
  let checkpoint = decode_checkpoint(Bytes.from_hex(Env.get("CREDIT_FIXTURE_CHECKPOINT", ""))?)?
  let leaf = Bytes.from_hex(Env.get("CREDIT_FIXTURE_LEAF", ""))?
  let leaves = [leaf_hash_for(2, leaf)?]
  let signed = attestations(checkpoint)?
  let evidence = TransparencyEvidence {
    entry_bytes: leaf,
    inclusion: compact_inclusion_proof_for(2, leaves, 0)?,
    consistency: compact_consistency_proof_for(2, [], leaves)?,
    checkpoint: checkpoint,
    witnesses: signed
  }
  Ok("{\"evidence\":"
    <> Json.encode_string(Bytes.to_hex(encode_transparency_evidence(evidence)?))
    <> ",\"unwitnessed\":"
    <> Json.encode_string(Bytes.to_hex(encode_transparency_evidence(%{evidence | witnesses: []})?))
    <> ",\"witness_a\":"
    <> Json.encode_string(Bytes.to_hex(encode_witnesses([List.get(signed, 0)])?))
    <> ",\"witness_b\":"
    <> Json.encode_string(Bytes.to_hex(encode_witnesses([List.get(signed, 1)])?))
    <> "}")
end

fn attestations(checkpoint :: TransparencyCheckpoint) -> List<WitnessAttestation>!String do
  let first = pair("CREDIT_FIXTURE_WITNESS_A_SEED")?
  let second = pair("CREDIT_FIXTURE_WITNESS_B_SEED")?
  Ok([
    sign_witness("witness-a", first.private_key, checkpoint)?,
    sign_witness("witness-b", second.private_key, checkpoint)?
  ])
end

fn attest() -> String!String do
  let checkpoint = decode_checkpoint(Bytes.from_hex(Env.get("CREDIT_FIXTURE_CHECKPOINT", ""))?)?
  let signed = attestations(checkpoint)?
  Ok("{\"witness_a\":"
    <> Json.encode_string(Bytes.to_hex(encode_witnesses([List.get(signed, 0)])?))
    <> ",\"witness_b\":"
    <> Json.encode_string(Bytes.to_hex(encode_witnesses([List.get(signed, 1)])?))
    <> "}")
end

fn verify_discovery() -> String!String do
  let evidence = decode_transparency_evidence(Bytes.from_hex(Env.get("CREDIT_FIXTURE_EVIDENCE",
    ""))?)?
  if !Bytes.secure_equals(evidence.entry_bytes,
    Bytes.from_hex(Env.get("CREDIT_FIXTURE_LEAF", ""))?) do
    return Err("discovery returned another issuer")
  end
  let signer = pair("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX")?
  let pins = [
    WitnessKey {
      witness_id: "witness-a",
      public_key: Bytes.from_hex(Env.get("MESSENGER_WITNESS_A_PUBLIC_KEY_HEX", ""))?
    },
    WitnessKey {
      witness_id: "witness-b",
      public_key: Bytes.from_hex(Env.get("MESSENGER_WITNESS_B_PUBLIC_KEY_HEX", ""))?
    }
  ]
  verify_issuer_key(evidence,
    signer.public_key,
    pins,
    2,
    Bytes.from_hex(Env.get("CREDIT_FIXTURE_PREVIOUS_CHECKPOINT", ""))?,
    wide(DateTime.to_unix_ms(DateTime.utc_now()) / 1000)?,
    1)?
  Ok("{\"verified\":true,\"tree_size\":"
    <> Json.encode_string(U64.to_string(evidence.checkpoint.tree_size))
    <> ",\"sequence\":"
    <> Json.encode_string(U64.to_string(evidence.checkpoint.sequence))
    <> "}")
end

fn main() do
  let result = case Env.get("CREDIT_FIXTURE_MODE", "prepare") do
    "witness" -> witness()
    "attest" -> attest()
    "verify" -> verify_discovery()
    _ -> prepare()
  end
  case result do
    Err(error) -> fail(error)
    Ok(value) -> println(value)
  end
end
