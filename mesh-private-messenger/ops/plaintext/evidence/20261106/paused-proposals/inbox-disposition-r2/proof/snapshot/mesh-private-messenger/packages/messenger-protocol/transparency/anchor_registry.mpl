from Transparency.RpcTransport import RpcEndpoint, RpcTransport, rpc_urls, rpc_fatal_error
from Solana.Read import (
  Pubkey,
  AccountInfo,
  KeyedAccountInfo,
  ProgramAccountsAtSlot,
  ProgramAccountFilter,
  RpcRequest,
  RpcResponse,
  pubkey_equal,
  data_size_filter,
  memcmp_filter,
  program_accounts_context_request,
  program_accounts_from_response
)
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.AnchorRpc import validate_anchor_sources, read_anchor_rpc_response
from Transparency.AnchorBond import bond_witness_identity
from Transparency.Merkle import WitnessKey

pub struct CollectibleWitnesses do
  keys :: List<WitnessKey>
  context_slot :: U64
end

fn zero(bytes :: Bytes) -> Bool do
  Bytes.to_hex(bytes) == String.repeat("00", Bytes.length(bytes))
end

fn key(pins :: AnchorPins, entry :: KeyedAccountInfo, status :: Int) -> WitnessKey!String do
  let bytes = entry.account.data
  if entry.account.executable
    || !pubkey_equal(entry.account.owner, pins.program)
    || entry.account.lamports == U64.parse("0")?
    || Bytes.length(bytes) != 320 do
    return Err("invalid_anchor_registry")
  end
  let length = Bytes.get(bytes, 4)?
  if Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d574901"
    || length < 1
    || length > 64
    || Bytes.get(bytes, 5)? != status
    || Bytes.get(bytes, 6)? > 1
    || Bytes.get(bytes, 7)? != 0
    || !zero(Bytes.slice(bytes, 8 + length, 64 - length)?)
    || zero(Bytes.slice(bytes, 104, 32)?)
    || zero(Bytes.slice(bytes, 136, 32)?)
    || !Bytes.secure_equals(Bytes.slice(bytes, 200, 32)?, pins.log_id)
    || zero(Bytes.slice(bytes, 232, 32)?)
    || !zero(Bytes.slice(bytes, 272, 48)?) do
    return Err("invalid_anchor_registry")
  end
  let unbond = U64.parse(Bytes.read_uint_le(bytes, 264, 8)?)?
  if (status == 1 && unbond != U64.parse("0")?)
    || (status == 2 && unbond == U64.parse("0")?)
    || U64.compare(unbond, U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_anchor_registry")
  end
  let value = WitnessKey {
    witness_id: Bytes.to_utf8(Bytes.slice(bytes, 8, length)?)?,
    public_key: Bytes.slice(bytes, 72, 32)?
  }
  let derived = find_program_address(pins.program,
    [
      Bytes.from_utf8("witness"),
      pins.log_id,
      bond_witness_identity(value.witness_id, value.public_key)?
    ])?.address
  if !pubkey_equal(entry.address, derived) do
    return Err("invalid_anchor_registry")
  end
  Ok(value)
end

fn read(endpoint :: RpcEndpoint,
  pins :: AnchorPins,
  status :: Int,
  minimum :: U64) -> ProgramAccountsAtSlot!String do
  let request = program_accounts_context_request(1,
    pins.program,
    [
      data_size_filter(320)?,
      memcmp_filter(0, Bytes.to_base58(Bytes.from_hex("4d574901")?))?,
      memcmp_filter(200, Bytes.to_base58(pins.log_id))?,
      memcmp_filter(5, Bytes.to_base58(Bytes.write_uint_le(Int.to_string(status), 1)?))?
    ],
    "finalized",
    Some(minimum))?
  let snapshot = program_accounts_from_response(read_anchor_rpc_response(pins.rpc, endpoint, request, 65536)?,
    64)?
  if U64.compare(snapshot.slot, minimum) < 0 do
    return Err("invalid_anchor_registry")
  end
  for entry in snapshot.accounts do
    key(pins, entry, status)?
  end
  Ok(snapshot)
end

fn same(first :: ProgramAccountsAtSlot, second :: ProgramAccountsAtSlot) -> Bool do
  if List.length(first.accounts) != List.length(second.accounts) do
    return false
  end
  for entry in first.accounts do
    let matches = List.filter(second.accounts,
      fn(other) do pubkey_equal(entry.address, other.address)
        && Bytes.secure_equals(entry.account.data, other.account.data) end)
    if List.length(matches) != 1 do
      return false
    end
  end
  true
end

fn agree(first :: ProgramAccountsAtSlot!String,
  second :: ProgramAccountsAtSlot!String) -> Option<ProgramAccountsAtSlot> do
  case (first, second) do
    (Ok(a), Ok(b)) -> if same(a, b) do
      Some(%{a |
        slot: if U64.compare(a.slot, b.slot) < 0 do
          a.slot
        else
          b.slot
        end
      })
    else
      None
    end
    _ -> None
  end
end

fn quorum(pins :: AnchorPins, status :: Int, minimum :: U64) -> ProgramAccountsAtSlot!String do
  let first = read(List.get(pins.rpc.sources, 0), pins, status, minimum)
  case first do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  let second = read(List.get(pins.rpc.sources, 1), pins, status, minimum)
  case second do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = read(List.get(pins.rpc.sources, 2), pins, status, minimum)
  case third do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agree(second, third) do
    Some(value) -> return Ok(value)
    None -> nil
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

# Registered records are permissionless and can be numerous. Query only the
# funded Active/Unbonding statuses, bounded at 64 each. Re-read both sets after
# discovery to detect status transitions/rotations; never truncate on overflow.
# This authenticates candidate keys, not vault balances or payout eligibility.
pub fn read_collectible_witnesses(pins :: AnchorPins,
  minimum :: U64) -> CollectibleWitnesses!String do
  let derived = anchor_addresses(pins.program, pins.log_name)?
  if !pubkey_equal(derived.ring, pins.ring) || !Bytes.secure_equals(derived.log_id, pins.log_id) do
    return Err("invalid_anchor_pins")
  end
  validate_anchor_sources(rpc_urls(pins.rpc))?
  let active = quorum(pins, 1, minimum)?
  let unbonding = quorum(pins, 2, active.slot)?
  let active_again = quorum(pins, 1, unbonding.slot)?
  let unbonding_again = quorum(pins, 2, active_again.slot)?
  if !same(active, active_again) || !same(unbonding, unbonding_again) do
    return Err("anchor_snapshot_changed")
  end
  for first in active.accounts do
    for second in unbonding.accounts do
      if pubkey_equal(first.address, second.address) do
        return Err("anchor_snapshot_changed")
      end
    end
  end
  let active_keys = for entry in active.accounts do
    key(pins, entry, 1)?
  end
  let unbonding_keys = for entry in unbonding.accounts do
    key(pins, entry, 2)?
  end
  Ok(CollectibleWitnesses {
    keys: active_keys ++ unbonding_keys,
    context_slot: unbonding_again.slot
  })
end
