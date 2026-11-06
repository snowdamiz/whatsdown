from Credits.Issuance import CreditQuote
from Payment.Verify import payment_token_address
from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Payment.TreasuryBatch import (
  treasury_batch_id,
  treasury_batch_member_hash,
  treasury_batch_message,
  canonical_treasury_ids
)
from Payment.TreasuryBatchTypes import TreasuryPaymentBatch
from Payment.TreasuryBatchOutcome import treasury_batch_fee, treasury_sum
from Storage.Treasury import TreasuryMovement
from Solana.Nonce import NonceAccountState
from Solana.Read import Pubkey, Hash
from Solana.Tx import serialize_legacy_message

fn batch_test_key(value :: Int) -> Bytes!String do
  let byte = Bytes.write_uint_le(Int.to_string(value), 1)?
  Bytes.from_hex(String.repeat(Bytes.to_hex(byte), 32))
end

fn batch_test_config() -> TreasuryChainConfig!String do
  Ok(TreasuryChainConfig {
    cluster: batch_test_key(31)?,
    providers_hash: batch_test_key(32)?,
    fee_payer: batch_test_key(33)?,
    nonce_address: batch_test_key(34)?,
    nonce_authority: batch_test_key(35)?,
    treasury_owner: batch_test_key(36)?,
    mint: batch_test_key(44)?,
    rewards_program: batch_test_key(37)?,
    rewards_pool: batch_test_key(38)?
  })
end

fn batch_test_member(index :: Int,
  asset :: Int,
  cfg :: TreasuryChainConfig) -> TreasuryMovement!String do
  let owner = batch_test_key(50 + index)?
  let target = batch_test_key(70 + index)?
  let mint = if asset == 0 do
    cfg.mint
  else
    batch_test_key(0)?
  end
  let source = if asset == 0 do
    payment_token_address(owner, mint)?
  else
    owner
  end
  let quote = CreditQuote {
    quote_id: batch_test_key(90 + index)?,
    deposit_owner: owner,
    destination: source,
    mint: mint,
    asset: asset,
    amount: U64.parse("5000000")?,
    purpose: 1,
    credits: 100,
    issued_at: U64.parse("1700000000")?,
    expires_at: U64.parse("1700000900")?,
    issuer_key_id: batch_test_key(40)?,
    batch_hash: batch_test_key(41)?
  }
  Ok(TreasuryMovement {
    movement_id: batch_test_key(10 + index)?,
    batch_id: Bytes.empty(),
    quote: quote,
    payment_signature: Bytes.from_hex(String.repeat("ee", 64))?,
    kind: 1,
    config_hash: treasury_config_hash(cfg)?,
    source: source,
    destination: if asset == 0 do
      payment_token_address(target, mint)?
    else
      target
    end,
    destination_owner: target,
    amount: U64.parse("4999999")?,
    ready_at: U64.parse("0")?,
    state: 0,
    message: Bytes.empty(),
    packet: Bytes.empty(),
    transaction_signature: Bytes.empty()
  })
end

fn batch_test_packet(asset :: Int) -> Bool!String do
  let cfg = batch_test_config()?
  let members = for index in 0..4 do
    batch_test_member(index, asset, cfg)?
  end
  let ids = for member in members do
    member.movement_id
  end
  let id = treasury_batch_id(cfg, ids)?
  assert(Bytes.secure_equals(id, treasury_batch_id(cfg, List.reverse(ids))?))
  assert(Result.is_err(canonical_treasury_ids([List.head(ids), List.head(ids)])))
  assert(Result.is_err(canonical_treasury_ids(ids ++ [batch_test_key(19)?])))
  let batch = TreasuryPaymentBatch {
    batch_id: id,
    config_hash: treasury_config_hash(cfg)?,
    member_hash: treasury_batch_member_hash(members)?,
    members: members,
    state: 0,
    nonce_address: cfg.nonce_address,
    nonce_value: batch_test_key(39)?,
    message: Bytes.empty(),
    packet: Bytes.empty(),
    transaction_signature: Bytes.empty(),
    fee: U64.parse("0")?,
    rent: U64.parse("0")?
  }
  let nonce = NonceAccountState {
    authority: Pubkey { bytes: cfg.nonce_authority },
    nonce: Hash { bytes: batch.nonce_value },
    lamports_per_signature: U64.parse("5000")?
  }
  if asset == 0 do
    assert(treasury_batch_message(batch, cfg, nonce) == Err("treasury_batch_packet_too_large"))
  else
    let message = treasury_batch_message(batch, cfg, nonce)?
    assert(message.header.num_required_signatures == 6)
    assert(Bytes.length(serialize_legacy_message(message)?) + 385 <= 1232)
    let changed = %{List.head(members) | amount: U64.parse("1")?}
    assert(Result.is_err(treasury_batch_message(%{batch |
        members: [changed] ++ List.drop(members, 1)
      },
      cfg,
      nonce)))
  end
  Ok(true)
end

test("immutable batch commitments retain all four members and enforce complete packet bounds") do
  assert(batch_test_packet(1) == Ok(true))
  assert(batch_test_packet(0) == Ok(true))
end

fn batch_fee_proof() -> Bool!String do
  let amounts = [
    U64.parse("0")?,
    U64.parse("1")?,
    U64.parse("20001")?,
    U64.parse("18446744073709551615")?
  ]
  for amount in amounts do
    for count in 1..5 do
      let shares = for index in 0..count do
        treasury_batch_fee(amount, count, index)?
      end
      assert(treasury_sum(shares)? == amount)
      for index in 1..count do
        assert(U64.compare(List.get(shares, index - 1), List.get(shares, index)) >= 0)
      end
    end
  end
  assert(Result.is_err(treasury_batch_fee(U64.parse("1")?, 0, 0)))
  Ok(true)
end

test("batch fee remainder allocation conserves every unit through u64 max") do
  assert(batch_fee_proof() == Ok(true))
end
