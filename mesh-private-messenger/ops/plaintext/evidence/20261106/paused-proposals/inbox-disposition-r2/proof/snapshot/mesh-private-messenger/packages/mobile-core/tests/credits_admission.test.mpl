import File
from Credits.Issuer import CreditIssuerKey, encode_issuer_key, issuer_key_id
from Credits.Discovery import decode_credit_issuer_query
from Mobile.CreditAdmission import credit_discovery_plan, admit_credit_issuer
from Mobile.CreditWallet import credit_issuer_keys
from Mobile.TransparencyCache import cached_checkpoint_bytes
from Storage.Credits import CreditWalletIdentity, load_credit_wallet
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated
from Transparency.Config import SecurityConfig, WitnessPin, witness_set_id, encode_security_config
from Transparency.Merkle import (
  checkpoint_hash,
  leaf_hash_for,
  merkle_root_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_tree_checkpoint_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence, encode_transparency_evidence, encode_checkpoint

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("credit_admission")?
  let service_pair = case Crypto.signing_generate() do
    Err(_) -> return Err("service key failed")
    Ok(value) -> value
  end
  let witness = case Crypto.signing_generate() do
    Err(_) -> return Err("witness key failed")
    Ok(value) -> value
  end
  let rsa = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("RSA key failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(rsa) do
    Err(_) -> return Err("RSA public failed")
    Ok(value) -> value
  end
  let pins = [
    WitnessPin {
      witness_id: "outside",
      public_key: witness.public_key.bytes,
      operator_label: "External"
    }
  ]
  let config = SecurityConfig {
    version: 3,
    wire_version: 3,
    minimum_session_suite: 1,
    service_public_key: service_pair.public_key.bytes,
    delivery_public_key: repeated(33, 32)?,
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
  let who = CreditWalletIdentity {
    account_id: repeated(31, 32)?,
    device_id: repeated(32, 16)?,
    service_key: service_pair.public_key.bytes,
    purpose: 1
  }
  let now = U64.parse("25921000")?
  let issuer = CreditIssuerKey {
    epoch: U64.parse("10")?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: Crypto.sha256(Bytes.from_utf8("test-only quote key"))
  }
  let entry = encode_issuer_key(issuer)?
  let tree = [leaf_hash_for(2, entry)?]
  let checkpoint = sign_tree_checkpoint_for(2,
    service_pair.private_key,
    service_pair.public_key.bytes,
    U64.parse("1")?,
    U64.parse("1")?,
    merkle_root_for(2, tree)?,
    repeated(0, 32)?,
    U64.multiply(now, U64.parse("1000")?)?)?
  let evidence = TransparencyEvidence {
    entry_bytes: entry,
    inclusion: compact_inclusion_proof_for(2, tree, 0)?,
    consistency: compact_consistency_proof_for(2, [], tree)?,
    checkpoint: checkpoint,
    witnesses: [sign_witness("outside", witness.private_key, checkpoint)?]
  }
  let discovery = credit_discovery_plan(path, key, who, config)?
  assert(discovery.origin == config.issuer_origin
    && decode_credit_issuer_query(discovery.body)?.previous_size == U64.parse("0")?)
  assert(Result.is_err(admit_credit_issuer(path,
    key,
    who,
    config,
    encode_transparency_evidence(%{evidence | witnesses: []})?,
    now)))
  assert(List.length(load_credit_wallet(path, key, who)?.wallet.records) == 0)
  assert(Bytes.length(cached_checkpoint_bytes(path, key)?) == 0)
  let admitted = admit_credit_issuer(path,
    key,
    who,
    config,
    encode_transparency_evidence(evidence)?,
    now)?
  assert(Bytes.secure_equals(admitted, issuer_key_id(issuer)?))
  assert(Bytes.secure_equals(cached_checkpoint_bytes(path, key)?, encode_checkpoint(checkpoint)?))
  assert(List.length(credit_issuer_keys(load_credit_wallet(path, key, who)?.wallet, 1)?) == 1)
  assert(decode_credit_issuer_query(credit_discovery_plan(path,
    key,
    who,
    config)?.body)?.previous_size == U64.parse("1")?)
  # A valid old key response cannot reset the existing global history baseline.
  assert(Result.is_err(admit_credit_issuer(path,
    key,
    who,
    config,
    encode_transparency_evidence(evidence)?,
    now)))
  assert(Result.is_err(admit_credit_issuer(path,
    key,
    who,
    %{config | issuer_origin: "-"},
    encode_transparency_evidence(evidence)?,
    now)))
  assert(Bytes.secure_equals(cached_checkpoint_bytes(path, key)?, encode_checkpoint(checkpoint)?))
  # A fresh authenticated checkpoint replaces the existing shared cache rows.
  # Re-admission retains one key and advances wallet and cursor together.
  let refreshed = sign_tree_checkpoint_for(2,
    service_pair.private_key,
    service_pair.public_key.bytes,
    U64.parse("2")?,
    U64.parse("1")?,
    merkle_root_for(2, tree)?,
    checkpoint_hash(checkpoint)?,
    U64.add(U64.multiply(now, U64.parse("1000")?)?, U64.parse("1000")?)?)?
  let fresh_evidence = %{evidence |
    checkpoint: refreshed,
    consistency: compact_consistency_proof_for(2, tree, tree)?,
    witnesses: [sign_witness("outside", witness.private_key, refreshed)?]
  }
  assert(Bytes.secure_equals(admit_credit_issuer(path,
      key,
      who,
      config,
      encode_transparency_evidence(fresh_evidence)?,
      U64.add(now, U64.parse("1")?)?)?,
    admitted))
  assert(Bytes.secure_equals(cached_checkpoint_bytes(path, key)?, encode_checkpoint(refreshed)?))
  assert(load_credit_wallet(path, key, who)?.wallet.revision == U64.parse("2")?)
  assert(List.length(credit_issuer_keys(load_credit_wallet(path, key, who)?.wallet, 1)?) == 1)
  File.delete(path)?
  Ok(true)
end

test("credit issuer admission uses native pins and the shared durable checkpoint cursor") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
