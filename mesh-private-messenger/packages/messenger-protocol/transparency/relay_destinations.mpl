from Solana.Read import (
  Pubkey,
  AccountInfo,
  OptionalAccountsAtSlot,
  TokenAccount,
  Mint,
  pubkey,
  pubkey_equal,
  pubkey_string,
  token_account,
  mint
)
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.AnchorChain import (
  AnchorPins,
  AnchorAddresses,
  anchor_addresses,
  sample_anchor_sources
)
from Transparency.AnchorBatch import read_anchor_accounts
from Transparency.AnchorLog import AnchorLog, decode_anchor_log
from Transparency.AnchorBond import AnchorEconomics, decode_anchor_economics
from Transparency.Relay import validate_relay_submission
from Transparency.Fork import ForkProof, fork_hash

pub struct RelayDestinationState do
  address :: Pubkey
  owner :: Pubkey
  present :: Bool
end

pub struct RelayDestinationsState do
  proof_hash :: Bytes
  mint :: Pubkey
  finder :: RelayDestinationState
  locked :: RelayDestinationState
  context_slot :: U64
end

pub fn relay_destination_address(owner :: Pubkey, expected_mint :: Pubkey) -> Pubkey!String do
  Ok(find_program_address(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?,
    [
      owner.bytes,
      pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?.bytes,
      expected_mint.bytes
    ])?.address)
end

# Admission and restart recovery share exactly the same destination contract.
# Missing/prefunded means setup is still needed; malformed or unsafe state is
# an error. Recovery uses zero incoming units; admission additionally checks
# that the proposed payout cannot overflow either token destination.
pub fn check_relay_destination(value :: Option<AccountInfo>,
  owner :: Pubkey,
  expected_mint :: Pubkey,
  incoming :: U64,
  locked :: Bool) -> Bool!String do
  let account = case value do
    None -> return Ok(false)
    Some(value) -> value
  end
  if !account.executable
    && Bytes.length(account.data) == 0
    && Bytes.to_hex(account.owner.bytes) == String.repeat("00", 32) do
    return Ok(false)
  end
  if account.executable
    || Bytes.length(account.data) != 165
    || account.lamports == U64.parse("0")? do
    return Err("invalid_relay_destination")
  end
  let token = token_account(account)?
  if !pubkey_equal(token.owner, owner)
    || !pubkey_equal(token.mint, expected_mint)
    || token.state != 1 do
    return Err("invalid_relay_destination")
  end
  case token.native_reserve do
    Some(_) -> return Err("invalid_relay_destination")
    None -> nil
  end
  if locked do
    case token.delegate do
      Some(_) -> return Err("invalid_relay_destination")
      None -> nil
    end
    case token.close_authority do
      Some(_) -> return Err("invalid_relay_destination")
      None -> nil
    end
  end
  U64.add(token.amount, incoming)?
  Ok(true)
end

fn owned(value :: Option<AccountInfo>, owner :: Pubkey, size :: Int) -> AccountInfo!String do
  let account = case value do
    None -> return Err("relay_destination_context_missing")
    Some(value) -> value
  end
  if account.executable
    || !pubkey_equal(account.owner, owner)
    || Bytes.length(account.data) != size
    || account.lamports == U64.parse("0")? do
    return Err("invalid_relay_destination_context")
  end
  Ok(account)
end

pub fn read_relay_destinations(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  expected_mint :: Pubkey,
  submitter :: Pubkey,
  wire :: Bytes,
  minimum_slot :: U64) -> RelayDestinationsState!String do
  let proof = validate_relay_submission(service_key, version, wire)?
  if Bytes.length(expected_mint.bytes) != 32
    || Bytes.length(submitter.bytes) != 32
    || Bytes.to_hex(expected_mint.bytes) == String.repeat("00", 32)
    || Bytes.to_hex(submitter.bytes) == String.repeat("00", 32) do
    return Err("invalid_relay_pins")
  end
  let pins = sample_anchor_sources(pins)?
  let addresses = anchor_addresses(pins.program, pins.log_name)?
  if !Bytes.secure_equals(addresses.log_id, pins.log_id)
    || !pubkey_equal(addresses.ring, pins.ring) do
    return Err("invalid_anchor_pins")
  end
  let finder = if Bytes.to_hex(proof.finder) == String.repeat("00", 32) do
    submitter
  else
    Pubkey { bytes: proof.finder }
  end
  let locked = find_program_address(pins.program, [Bytes.from_utf8("locked"), pins.log_id])?.address
  let finder_address = relay_destination_address(finder, expected_mint)?
  let locked_address = relay_destination_address(locked, expected_mint)?
  if pubkey_equal(finder_address, locked_address) do
    return Err("relay_destination_alias")
  end
  let economics = find_program_address(pins.program,
    [Bytes.from_utf8("economics"), pins.log_id])?.address
  let snapshot = read_anchor_accounts(pins.rpc,
    [addresses.log, economics, expected_mint, finder_address, locked_address],
    minimum_slot)?
  let log = decode_anchor_log(owned(List.get(snapshot.accounts, 0), pins.program, 352)?.data)?
  let policy = decode_anchor_economics(owned(List.get(snapshot.accounts, 1),
    pins.program,
    192)?.data)?
  if log.name != pins.log_name
    || log.version != version
    || !Bytes.secure_equals(log.log_id, pins.log_id)
    || !Bytes.secure_equals(log.service_public_key, service_key)
    || !Bytes.secure_equals(log.ring_address, pins.ring.bytes)
    || !Bytes.secure_equals(policy.log_id, pins.log_id)
    || !Bytes.secure_equals(policy.mint, expected_mint.bytes) do
    return Err("relay_destination_identity_mismatch")
  end
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let currency = mint(owned(List.get(snapshot.accounts, 2), token, 82)?)?
  if !currency.initialized || currency.decimals != 6 do
    return Err("invalid_relay_destination_mint")
  end
  let zero = U64.parse("0")?
  Ok(RelayDestinationsState {
    proof_hash: fork_hash(proof)?,
    mint: expected_mint,
    finder: RelayDestinationState {
      address: finder_address,
      owner: finder,
      present: check_relay_destination(List.get(snapshot.accounts, 3),
        finder,
        expected_mint,
        zero,
        false)?
    },
    locked: RelayDestinationState {
      address: locked_address,
      owner: locked,
      present: check_relay_destination(List.get(snapshot.accounts, 4),
        locked,
        expected_mint,
        zero,
        true)?
    },
    context_slot: snapshot.slot
  })
end

fn destination_report(value :: RelayDestinationState) -> String do
  let status = if value.present do
    "ready"
  else
    "missing"
  end
  """{"address":#{Json.encode_string(pubkey_string(value.address))},"owner":#{Json.encode_string(pubkey_string(value.owner))},"status":#{Json.encode_string(status)}}"""
end

pub fn relay_destinations_report(value :: RelayDestinationsState) -> String do
  """{"schema_version":1,"proof_hash":#{Json.encode_string(Bytes.to_hex(value.proof_hash))},"mint":#{Json.encode_string(pubkey_string(value.mint))},"context_slot":"#{U64.to_string(value.context_slot)}","finder":#{destination_report(value.finder)},"locked":#{destination_report(value.locked)}}"""
end
