##! Permanent receipt authentication has no oracle, registry or bond dependency.
from Read import (
  CollateralOperatorPins,
  validate_collateral_operator_pins,
  validate_collateral_operator_sources
)
from Accounts import operator_required, operator_owned, operator_absent, operator_snapshot_digest
from Solana.Read import (
  Pubkey,
  OptionalAccountSlicesAtSlot,
  pubkey_string,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_send,
  pubkey
)
from Transparency.TokenCollateralWrite import token_collateral_addresses, collateral_derived
from Transparency.AnchorLog import decode_anchor_log
from Transparency.TokenProofWrite import TokenPreparedProof, decode_token_prepared_proof
from Transparency.SlashReceipt import SlashReceipt, decode_slash_receipt
from Transparency.SlashReceiptRead import ConfirmedSlashReceipt, slash_receipt_report

pub type PermanentReceipt do
  MixedReceipt(TokenPreparedProof)
  LegacyReceipt(SlashReceipt)
end

pub struct RelayReceiptState do
  status :: String
  address :: Pubkey
  proof_hash :: Bytes
  context_slot :: U64
  digest :: Bytes
  value :: Option<PermanentReceipt>
end

pub fn receipt_keys(pins :: CollateralOperatorPins, proof_hash :: Bytes) -> List<Pubkey>!String do
  validate_collateral_operator_pins(pins)?
  if Bytes.length(proof_hash) != 32 do
    return Err("relay_receipt_hash")
  end
  let a = token_collateral_addresses(pins.context)?
  Ok([
    pins.context.judge,
    a.judge_data,
    a.log,
    collateral_derived(pins.context.judge, [Bytes.from_utf8("proof"), a.log_id, proof_hash])?
  ])
end

# Only the loader header is required; retained fixtures may carry shorter code
# prefixes than a fresh RPC slice. Full allocation/owner remain authenticated.
fn operator_owned_image(snapshot :: OptionalAccountSlicesAtSlot,
  program :: Pubkey,
  loader :: Pubkey,
  data_address :: Pubkey) -> U64!String do
  let image = operator_required(snapshot, 0, loader, U64.parse("36")?, 36, true)?.info.data
  if Bytes.to_hex(Bytes.slice(image, 0, 4)?) != "02000000"
    || Bytes.slice(image, 4, 32)? != data_address.bytes do
    return Err("relay_receipt_program")
  end
  let account = case List.get(snapshot.accounts, 1) do
    None -> return Err("relay_receipt_program_data")
    Some(value) -> value
  end
  let raw = account.info.data
  if account.info.owner != loader
    || account.info.executable
    || account.info.lamports == U64.parse("0")?
    || U64.compare(account.space, U64.parse("45")?) < 0
    || U64.compare(account.space, U64.parse("10485760")?) > 0
    || Bytes.length(raw) < 45
    || Bytes.length(raw) > 9216
    || U64.compare(U64.parse(Int.to_string(Bytes.length(raw)))?, account.space) > 0
    || Bytes.to_hex(Bytes.slice(raw, 0, 4)?) != "03000000"
    || Bytes.get(raw, 12)? > 1 do
    return Err("relay_receipt_program_data")
  end
  let slot = U64.parse(Bytes.read_uint_le(raw, 4, 8)?)?
  if U64.compare(slot, snapshot.slot) > 0 do
    return Err("relay_receipt_program_data")
  end
  Ok(slot)
end

pub fn decode_receipt_snapshot(pins :: CollateralOperatorPins,
  proof_hash :: Bytes,
  minimum :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> RelayReceiptState!String do
  let keys = receipt_keys(pins, proof_hash)?
  let a = token_collateral_addresses(pins.context)?
  if List.length(snapshot.accounts) != 4 || U64.compare(snapshot.slot, minimum) < 0 do
    return Err("relay_receipt_snapshot")
  end
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let image = operator_owned_image(snapshot, pins.context.judge, loader, a.judge_data)?
  if image != pins.judge_slot do
    return Err("relay_receipt_program_revision")
  end
  let log = decode_anchor_log(operator_owned(snapshot, 2, pins.context.judge, 352)?)?
  if log.name != pins.context.log_name
    || log.log_id != a.log_id
    || log.service_public_key != pins.service_key
    || log.version != pins.log_version
    || log.ring_address != a.ring.bytes do
    return Err("relay_receipt_log_identity")
  end
  let initial = RelayReceiptState {
    status: "missing",
    address: List.get(keys, 3),
    proof_hash: proof_hash,
    context_slot: snapshot.slot,
    digest: operator_snapshot_digest(keys, snapshot)?,
    value: None
  }
  if operator_absent(List.get(snapshot.accounts, 3)) do
    return Ok(initial)
  end
  let account = case List.get(snapshot.accounts, 3) do
    None -> return Err("relay_receipt_missing")
    Some(value) -> value
  end
  let raw = operator_owned(snapshot, 3, pins.context.judge, U64.to_int(account.space)?)?
  let magic = Bytes.to_hex(Bytes.slice(raw, 0, 4)?)
  let receipt = if magic == "4d505202" do
    let r = decode_token_prepared_proof(raw)?
    let bits = U64.to_int(r.verified_signature_mask)?
    if r.log_id != a.log_id
      || r.proof_hash != proof_hash
      || r.usdc_mint != pins.context.usdc_mint.bytes
      || r.morse_mint != a.morse_mint.bytes
      || bits > 17179869183
      || (r.anchored && bits % 4 != 1)
      || (!r.anchored && bits % 4 != 3) do
      return Err("relay_receipt_identity")
    end
    MixedReceipt(r)
  else if magic == "4d505201" do
    let r = decode_slash_receipt(raw)?
    if r.log_id != a.log_id
      || r.proof_hash != proof_hash
      || r.mint != pins.context.usdc_mint.bytes do
      return Err("relay_receipt_identity")
    end
    LegacyReceipt(r)
  else
    return Err("relay_receipt_version")
  end
  let status = case receipt do
    MixedReceipt(r) -> if r.settled do
      "settled"
    else
      "prepared"
    end
    LegacyReceipt(_) -> "settled"
  end
  Ok(%{initial | status: status, value: Some(receipt)})
end

pub fn receipt_origin(client :: Int,
  url :: String,
  pins :: CollateralOperatorPins,
  hash :: Bytes,
  minimum :: U64) -> RelayReceiptState!String do
  let request = get_multiple_accounts_slice_request(1,
    receipt_keys(pins, hash)?,
    "finalized",
    0,
    9216,
    Some(minimum))?
  decode_receipt_snapshot(pins,
    hash,
    minimum,
    optional_accounts_slice_from_response(rpc_send(client, url, request, 5000, 131072)?)?)
end

pub fn receipt_quorum(first :: RelayReceiptState!String,
  second :: RelayReceiptState!String,
  third :: RelayReceiptState!String) -> RelayReceiptState!String do
  for pair in [(first, second), (first, third), (second, third)] do
    case pair do
      (Ok(a), Ok(b)) -> if a.digest == b.digest do
        return Ok(a)
      end
      _ -> nil
    end
  end
  Err("relay_receipt_quorum")
end

pub fn read_receipt(client :: Int,
  sources :: List<String>,
  pins :: CollateralOperatorPins,
  hash :: Bytes,
  minimum :: U64) -> RelayReceiptState!String do
  validate_collateral_operator_sources(sources)?
  receipt_quorum(receipt_origin(client, List.get(sources, 0), pins, hash, minimum),
    receipt_origin(client, List.get(sources, 1), pins, hash, minimum),
    receipt_origin(client, List.get(sources, 2), pins, hash, minimum))
end

fn key(value :: Bytes) -> String do
  Json.encode_string(Bytes.to_base58(value))
end

fn hex(value :: Bytes) -> String do
  Json.encode_string(Bytes.to_hex(value))
end

fn units(value :: U64) -> String do
  Json.encode_string(U64.to_string(value))
end

pub fn permanent_receipt_report(state :: RelayReceiptState) -> String do
  let r = case state.value do
    None -> return "null"
    Some(value) -> value
  end
  case r do
    MixedReceipt(v) ->
      let rows = for row in v.rows do
        """{"identity":#{hex(row.identity)},"witness":#{key(row.witness)},"public_key":#{hex(row.public_key)},"asset":#{row.asset},"bonded_at":#{units(row.bonded_at)},"principal_units":#{units(row.principal)},"slashed_units":#{units(row.slashed)},"finder_units":#{units(row.finder)}}"""
      end
      """{"schema_version":2,"format":"MPR2","status":#{Json.encode_string(state.status)},"log_id":#{hex(v.log_id)},"proof_hash":#{hex(v.proof_hash)},"kind":#{v.kind},"anchored":#{v.anchored},"finder":#{key(v.finder)},"submitter":#{key(v.submitter)},"usdc_mint":#{key(v.usdc_mint)},"morse_mint":#{key(v.morse_mint)},"first_checkpoint":#{hex(v.first_hash)},"second_checkpoint":#{hex(v.second_hash)},"prepared_at":#{units(v.prepared_at)},"settled_at":#{units(v.settled_at)},"usdc_slashed_units":#{units(v.usdc_slashed)},"usdc_finder_units":#{units(v.usdc_finder)},"directory_usdc_units":#{units(v.directory_usdc)},"morse_slashed_units":#{units(v.morse_slashed)},"morse_finder_units":#{units(v.morse_finder)},"directory_morse_units":#{units(v.directory_morse)},"stage":#{key(v.stage)},"deadline_ms":#{units(v.deadline_ms)},"directory_bonded_at":#{units(v.directory_bonded_at)},"directory_asset":#{v.directory_asset},"verified_signature_mask":#{units(v.verified_signature_mask)},"context_slot":#{units(state.context_slot)},"witnesses":[#{String.join(rows,
        ",")}]}"""
    LegacyReceipt(v) -> slash_receipt_report(ConfirmedSlashReceipt {
      receipt: v,
      context_slot: state.context_slot
    })
  end
end

pub fn receipt_report(state :: RelayReceiptState) -> String do
  """{"schema_version":2,"status":#{Json.encode_string(state.status)},"address":#{Json.encode_string(pubkey_string(state.address))},"proof_hash":#{hex(state.proof_hash)},"context_slot":#{units(state.context_slot)},"digest":#{hex(state.digest)},"receipt":#{permanent_receipt_report(state)}}"""
end
