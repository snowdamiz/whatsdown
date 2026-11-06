from Payment.Treasury import (
  TreasuryChainConfig,
  treasury_config_hash,
  treasury_transfer_instructions
)
from Payment.TreasuryBatchTypes import TreasuryPaymentBatch
from Storage.Treasury import TreasuryMovement
from Solana.Nonce import NonceAccountState, compile_durable_nonce_message
from Solana.Read import Pubkey
from Solana.Tx import Instruction, LegacyMessage, serialize_legacy_message

fn batch_id_order(left :: Bytes, right :: Bytes) -> Int do
  if Bytes.to_hex(left) < Bytes.to_hex(right) do
    -1
  else if Bytes.to_hex(left) > Bytes.to_hex(right) do
    1
  else
    0
  end
end

pub fn canonical_treasury_ids(ids :: List<Bytes>) -> List<Bytes>!String do
  if List.length(ids) < 1 || List.length(ids) > 4 do
    return Err("treasury_batch_size")
  end
  let ordered = List.sort(ids, batch_id_order)
  for index in 0..List.length(ordered) do
    if Bytes.length(List.get(ordered, index)) != 32
      || (index > 0
        && Bytes.secure_equals(List.get(ordered, index), List.get(ordered, index - 1))) do
      return Err("treasury_batch_membership")
    end
  end
  Ok(ordered)
end

pub fn treasury_batch_id(config :: TreasuryChainConfig, ids :: List<Bytes>) -> Bytes!String do
  let ordered = canonical_treasury_ids(ids)?
  let framed = List.reduce(ordered,
    Bytes.to_hex(Bytes.from_utf8("morse-credit-treasury-batch-v1"))
      <> Bytes.to_hex(treasury_config_hash(config)?),
    fn(acc, value) do acc <> Bytes.to_hex(value) end)
  Ok(Crypto.sha256(Bytes.from_hex(framed)?))
end

pub fn treasury_batch_member_hash(members :: List<TreasuryMovement>) -> Bytes!String do
  let ids = for member in members do
    member.movement_id
  end
  let ordered = canonical_treasury_ids(ids)?
  let initial = Bytes.to_hex(Bytes.from_utf8("morse-credit-treasury-batch-members-v1"))
  let rows = for index in 0..List.length(members) do
    let member = List.get(members, index)
    if !Bytes.secure_equals(member.movement_id, List.get(ordered, index)) do
      return Err("treasury_batch_order")
    end
    Bytes.to_hex(member.movement_id)
      <> Bytes.to_hex(member.config_hash)
      <> Bytes.to_hex(member.payment_signature)
      <> Bytes.to_hex(member.quote.quote_id)
      <> Bytes.to_hex(member.source)
      <> Bytes.to_hex(member.destination)
      <> Bytes.to_hex(member.destination_owner)
      <> Bytes.to_hex(member.quote.deposit_owner)
      <> Bytes.to_hex(member.quote.mint)
      <> Bytes.to_hex(Bytes.write_uint_le(Int.to_string(member.kind), 1)?)
      <> Bytes.to_hex(Bytes.write_uint_le(Int.to_string(member.quote.asset), 1)?)
      <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(member.amount), 8)?)
      <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(member.ready_at), 8)?)
  end
  Ok(Crypto.sha256(Bytes.from_hex(initial <> String.join(rows, ""))?))
end

pub fn treasury_batch_message(batch :: TreasuryPaymentBatch,
  config :: TreasuryChainConfig,
  nonce :: NonceAccountState) -> LegacyMessage!String do
  if !Bytes.secure_equals(treasury_batch_id(config,
      for member in batch.members do
        member.movement_id
      end)?,
    batch.batch_id)
    || !Bytes.secure_equals(treasury_batch_member_hash(batch.members)?, batch.member_hash)
    || !Bytes.secure_equals(treasury_config_hash(config)?, batch.config_hash)
    || !Bytes.secure_equals(nonce.authority.bytes, config.nonce_authority) do
    return Err("treasury_batch_mismatch")
  end
  let first = List.head(batch.members)
  for member in batch.members do
    if member.kind != first.kind
      || member.quote.asset != first.quote.asset
      || !Bytes.secure_equals(member.quote.mint, first.quote.mint) do
      return Err("treasury_batch_mixed_policy")
    end
    for other in batch.members do
      if Bytes.secure_equals(member.source, other.destination) do
        return Err("treasury_batch_account_alias")
      end
    end
  end
  let groups = for index in 0..List.length(batch.members) do
    let member = List.get(batch.members, index)
    let body = treasury_transfer_instructions(member, config)?
    let duplicate_destination = List.any(List.take(batch.members, index),
      fn(previous) do Bytes.secure_equals(previous.destination, member.destination) end)
    if member.quote.asset == 0 && duplicate_destination do
      List.drop(body, 1)
    else
      body
    end
  end
  let message = compile_durable_nonce_message(Pubkey { bytes: config.fee_payer },
    Pubkey { bytes: config.nonce_address },
    nonce,
    List.flatten(groups))?
  # Bound the complete signed packet before membership is reserved or keys are opened.
  if Bytes.length(serialize_legacy_message(message)?)
    + 1
    + 64 * message.header.num_required_signatures > 1232 do
    return Err("treasury_batch_packet_too_large")
  end
  Ok(message)
end
