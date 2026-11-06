from Solana.Read import Pubkey, AccountInfo, OptionalAccountsAtSlot, pubkey_equal
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.AnchorBatch import read_anchor_accounts
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.AnchorLog import AnchorLog, decode_anchor_log
from Transparency.AnchorBond import AnchorEconomics, decode_anchor_economics
from Transparency.SlashReceipt import (
  SlashReceipt,
  SlashWitness,
  decode_slash_receipt,
  slash_receipt_address
)

pub struct ConfirmedSlashReceipt do
  receipt :: SlashReceipt
  context_slot :: U64
end

pub struct SlashReceiptState do
  address :: Pubkey
  proof_hash :: Bytes
  receipt :: Option<SlashReceipt>
  context_slot :: U64
end

fn units(value :: U64) -> String do
  Json.encode_string(U64.to_string(value))
end

fn address(value :: Bytes) -> String do
  Json.encode_string(Bytes.to_base58(value))
end

pub fn slash_receipt_report(confirmed :: ConfirmedSlashReceipt) -> String do
  let value = confirmed.receipt
  let rows = for row in value.witnesses do
    """{"witness":#{address(row.witness)},"public_key":#{Json.encode_string(Bytes.to_hex(row.public_key))},"principal_units":#{units(row.principal)},"slashed_units":#{units(row.slashed)},"finder_units":#{units(row.finder_amount)}}"""
  end
  let anchored = if value.anchored do
    "true"
  else
    "false"
  end
  """{"schema_version":1,"log_id":#{Json.encode_string(Bytes.to_hex(value.log_id))},"proof_hash":#{Json.encode_string(Bytes.to_hex(value.proof_hash))},"kind":#{value.kind},"anchored":#{anchored},"finder":#{address(value.finder)},"submitter":#{address(value.submitter)},"mint":#{address(value.mint)},"decimals":6,"slashed_at":#{units(value.slashed_at)},"total_slashed_units":#{units(value.total_slashed)},"finder_units":#{units(value.finder_amount)},"directory_slashed_units":#{units(value.directory_slashed)},"context_slot":#{units(confirmed.context_slot)},"witnesses":[#{String.join(rows,
    ",")}]}"""
end

fn owned(value :: Option<AccountInfo>, owner :: Pubkey) -> Bytes!String do
  let account = case value do
    None -> return Err("slash_receipt_account_missing")
    Some(value) -> value
  end
  if account.executable
    || !pubkey_equal(account.owner, owner)
    || account.lamports == U64.parse("0")? do
    return Err("invalid_slash_receipt_account")
  end
  Ok(account.data)
end

# The RPC request derives every address from release pins and the local FRK
# hash. Agreement covers the receipt, immutable log identity and custody mint in
# one finalized batch. A relay response or transaction signature is not proof.
pub fn read_slash_receipt(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  expected_mint :: Pubkey,
  proof_hash :: Bytes,
  minimum_slot :: U64) -> ConfirmedSlashReceipt!String do
  case find_slash_receipt(pins, service_key, version, expected_mint, proof_hash, minimum_slot)? do
    None -> Err("slash_receipt_account_missing")
    Some(value) -> Ok(value)
  end
end

# A missing or system-owned empty prefunded PDA has not settled. Malformed,
# foreign-owned or disagreeing receipts must never become an absence result.
pub fn find_slash_receipt(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  expected_mint :: Pubkey,
  proof_hash :: Bytes,
  minimum_slot :: U64) -> Option<ConfirmedSlashReceipt>!String do
  let state = read_slash_receipt_state(pins,
    service_key,
    version,
    expected_mint,
    proof_hash,
    minimum_slot)?
  Ok(case state.receipt do
    None
    Some(value) -> Some(ConfirmedSlashReceipt { receipt: value, context_slot: state.context_slot })
  end)
end

# Preserve the authenticated context even for absence. A scheduler must never
# turn an exception or a context-free None into permission to repeat spending.
pub fn read_slash_receipt_state(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  expected_mint :: Pubkey,
  proof_hash :: Bytes,
  minimum_slot :: U64) -> SlashReceiptState!String do
  let addresses = anchor_addresses(pins.program, pins.log_name)?
  if Bytes.length(service_key) != 32
    || Bytes.length(expected_mint.bytes) != 32
    || (version != 1 && version != 2)
    || !Bytes.secure_equals(addresses.log_id, pins.log_id)
    || !pubkey_equal(addresses.ring, pins.ring) do
    return Err("invalid_anchor_pins")
  end
  let receipt_address = slash_receipt_address(pins.program, pins.log_id, proof_hash)?
  let economics_address = find_program_address(pins.program,
    [Bytes.from_utf8("economics"), pins.log_id])?.address
  let result = read_anchor_accounts(pins.endpoints,
    [addresses.log, economics_address, receipt_address],
    minimum_slot)?
  let log = decode_anchor_log(owned(List.get(result.accounts, 0), pins.program)?)?
  let economics = decode_anchor_economics(owned(List.get(result.accounts, 1), pins.program)?)?
  if log.name != pins.log_name
    || log.version != version
    || !Bytes.secure_equals(log.log_id, pins.log_id)
    || !Bytes.secure_equals(log.service_public_key, service_key)
    || !Bytes.secure_equals(log.ring_address, pins.ring.bytes)
    || !Bytes.secure_equals(economics.log_id, pins.log_id)
    || !Bytes.secure_equals(economics.mint, expected_mint.bytes) do
    return Err("slash_receipt_identity_mismatch")
  end
  let state = SlashReceiptState {
    address: receipt_address,
    proof_hash: proof_hash,
    receipt: None,
    context_slot: result.slot
  }
  case List.get(result.accounts, 2) do
    None -> return Ok(state)
    Some(account) -> if !account.executable
      && Bytes.length(account.data) == 0
      && Bytes.to_hex(account.owner.bytes) == String.repeat("00", 32) do
      return Ok(state)
    end
  end
  let receipt = decode_slash_receipt(owned(List.get(result.accounts, 2), pins.program)?)?
  if !log.service_slashed
    || economics.directory_status != 3
    || !Bytes.secure_equals(receipt.log_id, pins.log_id)
    || !Bytes.secure_equals(receipt.mint, expected_mint.bytes)
    || !Bytes.secure_equals(receipt.proof_hash, proof_hash) do
    return Err("slash_receipt_identity_mismatch")
  end
  Ok(%{state | receipt: Some(receipt)})
end

pub fn slash_receipt_state_report(value :: SlashReceiptState) -> String do
  let (status, receipt) = case value.receipt do
    None -> ("missing", "null")
    Some(receipt) -> ("settled",
      slash_receipt_report(ConfirmedSlashReceipt {
        receipt: receipt,
        context_slot: value.context_slot
      }))
  end
  """{"schema_version":1,"status":#{Json.encode_string(status)},"address":#{address(value.address.bytes)},"proof_hash":#{Json.encode_string(Bytes.to_hex(value.proof_hash))},"context_slot":#{units(value.context_slot)},"receipt":#{receipt}}"""
end
