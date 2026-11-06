##! Permanent receipt authentication has no oracle, registry or bond dependency.
from Transparency.RpcTransport import (
  RpcTransport,
  RpcEndpoint,
  rpc_urls,
  rpc_fatal_error,
  require_rpc_current
)
from Transparency.AnchorRpc import read_anchor_rpc_response, validate_anchor_sources
from Transparency.AnchorChain import anchor_addresses
from Transparency.TokenChain import token_addresses
from Solana.Address import find_program_address
from Solana.Read import (
  Pubkey,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  pubkey
)
from Transparency.AnchorLog import decode_anchor_log
from Transparency.TokenProofWrite import TokenPreparedProof, decode_token_prepared_proof
from Transparency.SlashReceipt import SlashReceipt, decode_slash_receipt

pub struct PermanentReceiptPins do
  judge :: Pubkey
  token :: Pubkey
  log_name :: String
  usdc :: Pubkey
  judge_slot :: U64
  service_key :: Bytes
  log_version :: Int
end

pub type PermanentReceipt do
  MixedReceipt(TokenPreparedProof)
  LegacyReceipt(SlashReceipt)
end

pub struct PermanentReceiptState do
  status :: String
  address :: Pubkey
  proof_hash :: Bytes
  context_slot :: U64
  digest :: Bytes
  value :: Option<PermanentReceipt>
end

fn public_key(key :: Pubkey) -> Bool do
  Bytes.length(key.bytes) == 32 && Bytes.to_hex(key.bytes) != String.repeat("00", 32)
end

fn validate_pins(pins :: PermanentReceiptPins) -> Bool!String do
  if !public_key(pins.judge)
    || !public_key(pins.token)
    || !public_key(pins.usdc)
    || pins.judge == pins.token
    || Bytes.length(pins.service_key) != 32
    || Bytes.to_hex(pins.service_key) == String.repeat("00", 32)
    || (pins.log_version != 1 && pins.log_version != 2) do
    return Err("invalid_anchor_pins")
  end
  anchor_addresses(pins.judge, pins.log_name)?
  if token_addresses(pins.token)?.mint == pins.usdc do
    return Err("invalid_anchor_pins")
  end
  Ok(true)
end

fn operator_required(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  space :: U64,
  size :: Int,
  executable :: Bool) -> AccountSlice!String do
  let value = case List.get(snapshot.accounts, index) do
    None -> return Err("collateral_operator_account_missing")
    Some(value) -> value
  end
  if value.info.owner != owner
    || value.info.executable != executable
    || value.info.lamports == U64.parse("0")?
    || value.space != space
    || Bytes.length(value.info.data) != size do
    return Err("collateral_operator_account_mismatch")
  end
  Ok(value)
end

fn operator_owned(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  size :: Int) -> Bytes!String do
  Ok(operator_required(snapshot,
    index,
    owner,
    U64.parse(Int.to_string(size))?,
    size,
    false)?.info.data)
end

fn operator_absent(value :: Option<AccountSlice>) -> Bool do
  case value do
    None -> true
    Some(value) -> !value.info.executable
      && U64.to_string(value.space) == "0"
      && Bytes.length(value.info.data) == 0
      && Bytes.to_hex(value.info.owner.bytes) == String.repeat("00", 32)
  end
end

fn operator_snapshot_digest(keys :: List<Pubkey>,
  snapshot :: OptionalAccountSlicesAtSlot) -> Bytes!String do
  let parts = for index in 0..List.length(keys) do
    let body = case List.get(snapshot.accounts, index) do
      None -> Bytes.from_hex("00")?
      Some(value) ->
        let prefix = Bytes.concat(Bytes.concat(Bytes.concat(Bytes.from_hex(if value.info.executable do
                "0101"
              else
                "0100"
              end)?,
              value.info.owner.bytes)?,
            Bytes.write_uint_le(U64.to_string(value.space), 8)?)?,
          Bytes.write_uint_le(U64.to_string(value.info.lamports), 8)?)?
        Bytes.concat(Bytes.concat(prefix,
            Bytes.write_uint_le(U64.to_string(value.info.rent_epoch), 8)?)?,
          Crypto.sha256(value.info.data))?
    end
    Bytes.concat(List.get(keys, index).bytes, body)?
  end
  let bytes = List.reduce(parts,
    Ok(Bytes.from_utf8("morse-collateral-operator-snapshot-v1")),
    fn(result, part) do Bytes.concat(result?, part) end)?
  Ok(Crypto.sha256(Bytes.concat(Bytes.write_uint_le(U64.to_string(snapshot.slot), 8)?, bytes)?))
end

pub fn permanent_receipt_keys(pins :: PermanentReceiptPins,
  proof_hash :: Bytes) -> List<Pubkey>!String do
  validate_pins(pins)?
  if Bytes.length(proof_hash) != 32 do
    return Err("relay_receipt_hash")
  end
  let a = anchor_addresses(pins.judge, pins.log_name)?
  Ok([
    pins.judge,
    find_program_address(pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?,
      [pins.judge.bytes])?.address,
    a.log,
    find_program_address(pins.judge, [Bytes.from_utf8("proof"), a.log_id, proof_hash])?.address
  ])
end

# Only the loader header is required; retained fixtures may carry shorter code
# prefixes than a fresh RPC slice. Full allocation/owner remain authenticated.
fn operator_owned_image(snapshot :: OptionalAccountSlicesAtSlot,
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

pub fn decode_permanent_receipt_snapshot(pins :: PermanentReceiptPins,
  proof_hash :: Bytes,
  minimum :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> PermanentReceiptState!String do
  let keys = permanent_receipt_keys(pins, proof_hash)?
  let a = anchor_addresses(pins.judge, pins.log_name)?
  if List.length(snapshot.accounts) != 4 || U64.compare(snapshot.slot, minimum) < 0 do
    return Err("relay_receipt_snapshot")
  end
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let image = operator_owned_image(snapshot, loader, List.get(keys, 1))?
  if image != pins.judge_slot do
    return Err("relay_receipt_program_revision")
  end
  let log = decode_anchor_log(operator_owned(snapshot, 2, pins.judge, 352)?)?
  if log.name != pins.log_name
    || log.log_id != a.log_id
    || log.service_public_key != pins.service_key
    || log.version != pins.log_version
    || log.ring_address != a.ring.bytes do
    return Err("relay_receipt_log_identity")
  end
  let initial = PermanentReceiptState {
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
  let raw = operator_owned(snapshot, 3, pins.judge, U64.to_int(account.space)?)?
  let magic = Bytes.to_hex(Bytes.slice(raw, 0, 4)?)
  let receipt = if magic == "4d505202" do
    let r = decode_token_prepared_proof(raw)?
    let bits = U64.to_int(r.verified_signature_mask)?
    if r.log_id != a.log_id
      || r.proof_hash != proof_hash
      || r.usdc_mint != pins.usdc.bytes
      || r.morse_mint != token_addresses(pins.token)?.mint.bytes
      || bits > 17179869183
      || (r.anchored && bits % 4 != 1)
      || (!r.anchored && bits % 4 != 3) do
      return Err("relay_receipt_identity")
    end
    for row in r.rows do
      let witness = find_program_address(pins.judge,
        [Bytes.from_utf8("witness"), a.log_id, row.identity])?.address
      if row.witness != witness.bytes do
        return Err("relay_receipt_identity")
      end
    end
    MixedReceipt(r)
  else if magic == "4d505201" do
    let r = decode_slash_receipt(raw)?
    if r.log_id != a.log_id || r.proof_hash != proof_hash || r.mint != pins.usdc.bytes do
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

fn receipt_origin(rpc :: RpcTransport,
  endpoint :: RpcEndpoint,
  pins :: PermanentReceiptPins,
  hash :: Bytes,
  minimum :: U64) -> PermanentReceiptState!String do
  let request = get_multiple_accounts_slice_request(1,
    permanent_receipt_keys(pins, hash)?,
    "finalized",
    0,
    9216,
    Some(minimum))?
  decode_permanent_receipt_snapshot(pins,
    hash,
    minimum,
    optional_accounts_slice_from_response(read_anchor_rpc_response(rpc,
      endpoint,
      request,
      131072)?)?)
end

fn receipt_quorum(first :: PermanentReceiptState!String,
  second :: PermanentReceiptState!String,
  third :: PermanentReceiptState!String) -> PermanentReceiptState!String do
  for result in [first, second, third] do
    case result do
      Err(error) when rpc_fatal_error(error) -> return Err(error)
      _ -> nil
    end
  end
  for pair in [(first, second), (first, third), (second, third)] do
    case pair do
      (Ok(a), Ok(b)) -> if a.digest == b.digest do
        return Ok(a)
      end
      _ -> nil
    end
  end
  let valid = List.filter([first, second, third],
    fn(result) do
      case result do
        Ok(_) -> true
        Err(_) -> false
      end
    end)
  if List.length(valid) >= 2 do
    Err("anchor_rpc_disagree")
  else
    Err("anchor_rpc_unavailable")
  end
end

pub fn read_permanent_receipt(rpc :: RpcTransport,
  pins :: PermanentReceiptPins,
  hash :: Bytes,
  minimum :: U64) -> PermanentReceiptState!String do
  require_rpc_current(rpc.require_current)?
  validate_anchor_sources(rpc_urls(rpc))?
  let results = for endpoint in List.take(rpc.sources, 3) do
    let result = receipt_origin(rpc, endpoint, pins, hash, minimum)
    case result do
      Err(error) when rpc_fatal_error(error) -> return Err(error)
      _ -> result
    end
  end
  require_rpc_current(rpc.require_current)?
  let state = receipt_quorum(List.get(results, 0), List.get(results, 1), List.get(results, 2))?
  require_rpc_current(rpc.require_current)?
  Ok(state)
end
