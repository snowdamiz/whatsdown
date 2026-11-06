from Payment.Verify import payment_token_address
from Storage.Treasury import TreasuryMovement
from Solana.Read import Pubkey, pubkey
from Solana.Tx import (
  AccountMeta,
  Instruction,
  LegacyMessage,
  transfer_checked_instruction,
  create_associated_token_idempotent_instruction,
  serialize_legacy_message
)
from Solana.Nonce import NonceAccountState, compile_durable_nonce_message

pub struct TreasuryChainConfig do
  cluster :: Bytes
  providers_hash :: Bytes
  mint :: Bytes
  treasury_owner :: Bytes
  fee_payer :: Bytes
  nonce_authority :: Bytes
  nonce_address :: Bytes
  rewards_program :: Bytes
  rewards_pool :: Bytes
end

fn treasury_key(value :: Bytes) -> Result<(), String> do
  if Bytes.length(value) != 32 || Bytes.to_hex(value) == String.repeat("00", 32) do
    return Err("invalid_treasury_config")
  end
  Ok(nil)
end

pub fn treasury_config_hash(config :: TreasuryChainConfig) -> Bytes!String do
  for key in [
    config.cluster,
    config.providers_hash,
    config.mint,
    config.treasury_owner,
    config.fee_payer,
    config.nonce_authority,
    config.nonce_address,
    config.rewards_program,
    config.rewards_pool
  ] do
    treasury_key(key)?
  end
  if Bytes.secure_equals(config.fee_payer, config.nonce_address)
    || Bytes.secure_equals(config.nonce_authority, config.nonce_address)
    || Bytes.secure_equals(config.treasury_owner, config.nonce_address) do
    return Err("invalid_treasury_config")
  end
  Ok(Crypto.sha256(Bytes.from_hex(Bytes.to_hex(Bytes.from_utf8("morse-credit-treasury-config-v1"))
    <> Bytes.to_hex(config.providers_hash)
    <> Bytes.to_hex(config.cluster)
    <> Bytes.to_hex(config.mint)
    <> Bytes.to_hex(config.treasury_owner)
    <> Bytes.to_hex(config.fee_payer)
    <> Bytes.to_hex(config.nonce_authority)
    <> Bytes.to_hex(config.nonce_address)
    <> Bytes.to_hex(config.rewards_program)
    <> Bytes.to_hex(config.rewards_pool))?))
end

# The signed message is reconstructed from immutable journal policy. There is
# no broad arbitrary-message signing operation in the operator interface.
pub fn treasury_transfer_instructions(movement :: TreasuryMovement,
  config :: TreasuryChainConfig) -> List<Instruction>!String do
  if !Bytes.secure_equals(treasury_config_hash(config)?, movement.config_hash)
    || movement.amount == U64.parse("0")?
    || (movement.kind != 0 && movement.kind != 1)
    || !Bytes.secure_equals(movement.source, movement.quote.destination)
    || (movement.kind == 0
      && !Bytes.secure_equals(movement.destination_owner, config.treasury_owner))
    || (movement.quote.asset == 0 && !Bytes.secure_equals(movement.quote.mint, config.mint)) do
    return Err("treasury_intent_mismatch")
  end
  # Reject account aliases whose fee/rent effects would obscure transfer deltas.
  for value in [
    movement.quote.deposit_owner,
    movement.source,
    movement.destination_owner,
    movement.destination
  ] do
    treasury_key(value)?
    if Bytes.secure_equals(value, config.fee_payer)
      || Bytes.secure_equals(value, config.nonce_address)
      || Bytes.secure_equals(value, config.nonce_authority) do
      return Err("unsupported_treasury_account_alias")
    end
  end
  let expected_destination = if movement.quote.asset == 0 do
    payment_token_address(movement.destination_owner, config.mint)?
  else
    movement.destination_owner
  end
  if !Bytes.secure_equals(movement.destination, expected_destination)
    || Bytes.secure_equals(movement.source, movement.destination) do
    return Err("treasury_destination_mismatch")
  end
  let payer = Pubkey { bytes: config.fee_payer }
  let owner = Pubkey { bytes: movement.quote.deposit_owner }
  let source = Pubkey { bytes: movement.source }
  let destination = Pubkey { bytes: movement.destination }
  let instructions = if movement.quote.asset == 0 do
    if !Bytes.secure_equals(movement.source,
      payment_token_address(movement.quote.deposit_owner, config.mint)?) do
      return Err("treasury_source_mismatch")
    end
    let mint = Pubkey { bytes: config.mint }
    [
      create_associated_token_idempotent_instruction(payer,
        destination,
        Pubkey { bytes: movement.destination_owner },
        mint)?,
      transfer_checked_instruction(source, mint, destination, owner, movement.amount, 6)?
    ]
  else if movement.quote.asset == 1 do
    if !Bytes.secure_equals(movement.source, movement.quote.deposit_owner) do
      return Err("treasury_source_mismatch")
    end
    [
      Instruction {
        program_id: pubkey("11111111111111111111111111111111")?,
        accounts: [
          AccountMeta { pubkey: owner, signer: true, writable: true },
          AccountMeta { pubkey: destination, signer: false, writable: true }
        ],
        data: Bytes.from_hex("02000000"
          <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(movement.amount), 8)?))?
      }
    ]
  else
    return Err("invalid_treasury_asset")
  end
  Ok(instructions)
end

pub fn treasury_message(movement :: TreasuryMovement,
  config :: TreasuryChainConfig,
  nonce :: NonceAccountState) -> LegacyMessage!String do
  if !Bytes.secure_equals(nonce.authority.bytes, config.nonce_authority) do
    return Err("treasury_nonce_authority_mismatch")
  end
  compile_durable_nonce_message(Pubkey { bytes: config.fee_payer },
    Pubkey { bytes: config.nonce_address },
    nonce,
    treasury_transfer_instructions(movement, config)?)
end
