from Payment.SolConversionPacket import (
  SolConversionProfile,
  SolConversionPacket,
  conversion_native_mint,
  conversion_raydium_program,
  conversion_escrow,
  sol_conversion_profile_hash,
  sol_conversion_message,
  sol_conversion_packet
)
from Solana.Read import Pubkey, Hash, Signature
from Solana.Address import find_program_address
from Solana.Tx import serialize_legacy_message
from Solana.TransactionWrite import serialize_signed_legacy_transaction

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn profile(owner :: Bytes, payer :: Bytes) -> SolConversionProfile!String do
  let native = conversion_native_mint()?
  let ray = conversion_raydium_program()?
  let usdc = Pubkey { bytes: Bytes.from_hex(String.repeat("ff", 32))? }
  let amm = Pubkey { bytes: Crypto.sha256(Bytes.from_utf8("owned-unit-amm-config")) }
  let pool = find_program_address(ray,
    [Bytes.from_utf8("pool"), amm.bytes, native.bytes, usdc.bytes])?.address
  Ok(SolConversionProfile {
    treasury_config: Crypto.sha256(Bytes.from_utf8("original-config")),
    owner: Pubkey { bytes: owner },
    payer: Pubkey { bytes: payer },
    usdc: usdc,
    pool: pool,
    amm_config: amm,
    authority: find_program_address(ray, [Bytes.from_utf8("vault_and_lp_mint_auth_seed")])?.address,
    input_vault: find_program_address(ray,
      [Bytes.from_utf8("pool_vault"), pool.bytes, native.bytes])?.address,
    output_vault: find_program_address(ray,
      [Bytes.from_utf8("pool_vault"), pool.bytes, usdc.bytes])?.address,
    observation: find_program_address(ray, [Bytes.from_utf8("observation"), pool.bytes])?.address,
    oracle: Pubkey { bytes: Crypto.sha256(Bytes.from_utf8("owned-test-sol-oracle")) },
    amm_hash: Crypto.sha256(Bytes.from_utf8("unit-amm-pin-only-not-bank-admission")),
    raydium_code: Crypto.sha256(Bytes.from_utf8("unit-code-pin-only-not-bank-admission")),
    token_code: Crypto.sha256(Bytes.from_utf8("unit-token-pin-only-not-bank-admission")),
    rent: wide("2039280")?,
    maximum_fee: wide("100000")?
  })
end

fn cases() -> Bool!String do
  let owner = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture_key_failed")
  end
  let payer = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture_key_failed")
  end
  let p = profile(owner.public_key.bytes, payer.public_key.bytes)?
  let id = Crypto.sha256(Bytes.from_utf8("one-immutable-conversion-intent"))
  let hash = Hash { bytes: Crypto.sha256(Bytes.from_utf8("owned-blockhash")) }
  let message = sol_conversion_message(p, id, wide("1000000000")?, wide("148500000")?, hash)?
  let encoded = serialize_legacy_message(message)?
  assert(message.header.num_required_signatures == 2)
  assert(List.length(message.instructions) == 7)
  assert(Bytes.length(encoded) + 129 <= 1232)
  let a = case Crypto.sign(payer.private_key, encoded) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_sign_failed")
  end
  let b = case Crypto.sign(owner.private_key, encoded) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_sign_failed")
  end
  let wire = serialize_signed_legacy_transaction(message,
    [Signature { bytes: a.bytes }, Signature { bytes: b.bytes }])?
  let plan = SolConversionPacket {
    intent_id: id,
    profile_hash: sol_conversion_profile_hash(p)?,
    lamports: wide("1000000000")?,
    minimum: wide("148500000")?,
    blockhash: hash,
    message: encoded
  }
  assert(sol_conversion_packet(p, plan, wire)?.wire == wire)
  assert(Result.is_err(sol_conversion_packet(p, %{plan | minimum: wide("148499999")?}, wire)))
  assert(Result.is_err(sol_conversion_packet(p, plan, Bytes.concat(wire, Bytes.from_hex("00")?)?)))
  assert(Result.is_err(sol_conversion_profile_hash(%{p | payer: p.owner})))
  assert(Result.is_err(sol_conversion_profile_hash(%{p | input_vault: p.output_vault})))
  assert(Result.is_err(sol_conversion_profile_hash(%{p | raydium_code: Bytes.empty()})))
  assert(Result.is_err(sol_conversion_profile_hash(%{p | maximum_fee: wide("1000001")?})))
  assert(conversion_escrow(p, id)? != conversion_escrow(p,
      Crypto.sha256(Bytes.from_utf8("other-intent")))?)
  Secret.destroy(owner.private_key)
  Secret.destroy(payer.private_key)
  Ok(true)
end

test("constrained conversion packet is externally signed and rejects changed policy or bytes") do
  assert(cases() == Ok(true))
end
