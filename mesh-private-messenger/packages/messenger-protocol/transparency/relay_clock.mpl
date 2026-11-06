from Solana.Read import (
  Pubkey,
  AccountInfo,
  AccountAtSlot,
  SolanaClock,
  pubkey,
  clock_sysvar_address,
  clock_sysvar
)
from Transparency.AnchorRpc import validate_anchor_sources, read_anchor_account

pub struct RelayClock do
  earliest_seconds :: Int
  latest_seconds :: Int
  context_slot :: U64
end

fn read(endpoint :: String,
  first_ms :: U64,
  second_ms :: U64,
  bonded_at :: U64,
  minimum_slot :: U64) -> RelayClock!String do
  let account = read_anchor_account(endpoint,
    clock_sysvar_address()?,
    pubkey("Sysvar1111111111111111111111111111111111111")?,
    0,
    40,
    minimum_slot)?
  let clock = clock_sysvar(account.account)?
  if clock.slot != account.slot || clock.unix_timestamp < 0 do
    return Err("invalid_relay_clock")
  end
  let seconds = U64.parse(Int.to_string(clock.unix_timestamp))?
  let now = U64.multiply(seconds, U64.parse("1000")?)?
  if U64.compare(first_ms, now) > 0 || U64.compare(second_ms, now) > 0 do
    return Err("relay_proof_future")
  end
  let oldest = if U64.compare(first_ms, second_ms) < 0 do
    first_ms
  else
    second_ms
  end
  if U64.compare(U64.subtract(now, oldest)?, U64.parse("2419200000")?) > 0 do
    return Err("relay_proof_expired")
  end
  if U64.compare(bonded_at, seconds) > 0 do
    return Err("relay_bond_from_future")
  end
  Ok(RelayClock {
    earliest_seconds: clock.unix_timestamp,
    latest_seconds: clock.unix_timestamp,
    context_slot: account.slot
  })
end

fn agree(first :: RelayClock!String, second :: RelayClock!String) -> Option<RelayClock> do
  case (first, second) do
    (Ok(a), Ok(b)) -> Some(RelayClock {
      earliest_seconds: if a.earliest_seconds < b.earliest_seconds do
        a.earliest_seconds
      else
        b.earliest_seconds
      end,
      latest_seconds: if a.latest_seconds > b.latest_seconds do
        a.latest_seconds
      else
        b.latest_seconds
      end,
      context_slot: if U64.compare(a.context_slot, b.context_slot) < 0 do
        a.context_slot
      else
        b.context_slot
      end
    })
    _ -> None
  end
end

# Providers may be on different finalized banks. Require two independent
# admission decisions, each from a correctly owned Clock whose slot equals its
# RPC context; exact Clock bytes need not match. With at most one dishonest
# source, acceptance includes an honest bank's age and bonded-at checks. The
# judge rechecks its current Clock at execution: this is not a deadline lease.
pub fn check_relay_clock(endpoints :: List<String>,
  first_ms :: U64,
  second_ms :: U64,
  bonded_at :: U64,
  minimum_slot :: U64) -> RelayClock!String do
  validate_anchor_sources(endpoints)?
  let first = read(List.get(endpoints, 0), first_ms, second_ms, bonded_at, minimum_slot)
  let second = read(List.get(endpoints, 1), first_ms, second_ms, bonded_at, minimum_slot)
  case agree(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = read(List.get(endpoints, 2), first_ms, second_ms, bonded_at, minimum_slot)
  case agree(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agree(second, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  for error in ["relay_proof_future", "relay_proof_expired", "relay_bond_from_future"] do
    let matching = List.filter([first, second, third],
      fn(result) do
        case result do
          Err(value) -> value == error
          Ok(_) -> false
        end
      end)
    if List.length(matching) >= 2 do
      return Err(error)
    end
  end
  Err("relay_clock_unavailable")
end
