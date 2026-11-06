# Presentation of authenticated custody only. No instructions, signer or oracle authority.
from Transparency.TokenBurnRead import TokenBurnReadPins
from Transparency.TokenBurnCarryRead import TokenBurnCarryState, token_burn_carry_read_keys
from Transparency.TokenBurn import TokenBurnRow
from Solana.Read import pubkey_string

fn quoted(value :: String) -> String do
  Json.encode_string(value)
end

fn units(value :: U64) -> String do
  quoted(U64.to_string(value))
end

fn flag(value :: Bool) -> String do
  if value do
    "true"
  else
    "false"
  end
end

fn row_status(row :: TokenBurnRow, closed :: Bool, now :: U64) -> String do
  if row.complete do
    "executed"
  else if closed do
    "carried"
  else if U64.compare(now, row.window_end) >= 0 do
    "missed"
  else if U64.compare(now, row.execute_at) >= 0 do
    "delayed"
  else
    "scheduled"
  end
end

pub fn burn_snapshot_report(pins :: TokenBurnReadPins,
  epoch :: U64,
  state :: TokenBurnCarryState) -> String!String do
  let keys = token_burn_carry_read_keys(pins, epoch)?
  let header = """"epoch":#{units(epoch)},"availability":"available","context_slot":#{units(state.context_slot)},"source_time_unix":#{quoted(Int.to_string(state.timestamp))},"snapshot_digest":#{quoted(Bytes.to_hex(state.digest))},"code_current":#{flag(state.code_current)},"program":#{quoted(pubkey_string(pins.program))},"week_address":#{quoted(pubkey_string(List.get(keys,
    5)))},"usdc_mint":#{quoted(pubkey_string(pins.usdc))},"decimals":6,"remaining_units":#{units(state.remaining)},"week_donation_surplus_units":#{units(state.week_surplus)},"carry_donation_surplus_units":#{units(state.carry_surplus)},"quote":{"status":"unavailable","reason":"custody-only-reader","spot_usd_micros":null,"twap_usd_micros":null,"source_time_unix":null}"""
  let frame = case state.frame do
    None -> return Ok("""{#{header},"status":"unfunded","budget_units":null,"spent_units":null,"burned_units":null,"receipt":null,"rows":[]}""")
    Some(value) -> value
  end
  let now = U64.parse(Int.to_string(state.timestamp))?
  let statuses = for row in frame.week.rows do
    row_status(row, frame.closed, now)
  end
  let status = if frame.closed do
    "closed"
  else if frame.week.completion_mask == U64.parse("16777215")? do
    "executed"
  else if List.contains(statuses, "missed") do
    "missed"
  else if List.contains(statuses, "delayed") do
    "delayed"
  else
    "scheduled"
  end
  let rows = for index in 0..List.length(frame.week.rows) do
    let row = List.get(frame.week.rows, index)
    let execution = if row.complete do
      quoted(Bytes.to_hex(row.execution_hash))
    else
      "null"
    end
    """{"index":#{index},"status":#{quoted(List.get(statuses,
      index))},"input_usdc_units":#{units(row.amount)},"burned_morse_units":#{units(row.burned)},"execute_at_unix":#{units(row.execute_at)},"window_end_unix":#{units(row.window_end)},"execution_hash":#{execution}}"""
  end
  let receipt = case state.receipt do
    None -> "null"
    Some(value) -> """{"address":#{quoted(pubkey_string(List.get(keys,
      9)))},"budget_units":#{units(value.budget)},"spent_units":#{units(value.spent)},"burned_units":#{units(value.burned)},"carried_units":#{units(value.carried)},"closed_at_unix":#{units(value.closed_at)},"funding_hash":#{quoted(Bytes.to_hex(value.funding_hash))},"active_frame_hash":#{quoted(Bytes.to_hex(value.active_frame_hash))}}"""
  end
  Ok("""{#{header},"status":#{quoted(status)},"budget_units":#{units(frame.week.budget)},"cash_budget_units":#{units(frame.cash_budget)},"carry_budget_units":#{units(frame.carry_budget)},"spent_units":#{units(frame.week.spent)},"burned_units":#{units(frame.week.burned)},"receipt":#{receipt},"rows":[#{String.join(rows,
    ",")}] }""")
end

pub fn unavailable_burn_report(epoch :: U64, status :: String) -> String do
  """{"epoch":#{units(epoch)},"availability":#{quoted(status)},"reason":"no-agreeing-finalized-snapshot"}"""
end
