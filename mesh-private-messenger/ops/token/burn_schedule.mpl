from BurnJournal import TokenBurnJournalEntry
from Transparency.TokenBurn import TokenBurnWeek

# Policy only. The worker authenticates the finalized account bank and its block height.
# An expired packet is replaceable, never implicitly replaced or released by this decision.
pub fn token_burn_packet_disposition(entry :: TokenBurnJournalEntry,
  week :: TokenBurnWeek,
  now :: U64,
  height :: U64,
  slot :: U64,
  code_current :: Bool) -> String!String do
  if !code_current do
    return Ok("reconcile:code")
  end
  if U64.compare(slot, entry.context_slot) < 0 do
    return Ok("reconcile:stale")
  end
  if entry.kind != 10 || entry.epoch != week.epoch || entry.index < 0 || entry.index >= 24 do
    return Ok("reconcile:intent")
  end
  let row = List.get(week.rows, entry.index)
  if entry.not_before != row.execute_at || entry.deadline != row.window_end do
    return Ok("reconcile:intent")
  end
  if row.complete do
    return Ok("confirm:receipt")
  end
  if entry.status == 3 do
    return Ok("reconcile:state")
  end
  if U64.compare(now, entry.deadline) >= 0 do
    return Ok("missed:window")
  end
  if U64.compare(now, entry.not_before) < 0 do
    return Ok("waiting:window")
  end
  if entry.status == 0 do
    return Ok("sign:initial")
  end
  if U64.compare(height, entry.last_valid_block_height) > 0 do
    Ok("replace:expired")
  else
    Ok("submit:exact")
  end
end
