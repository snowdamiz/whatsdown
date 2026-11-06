from Client.BondsV2Pins import BondsV2Options, parse_bonds_v2_options
from Transparency.NetworkCollateralPins import CollateralSelection, collateral_bond_keys
from Transparency.NetworkCollateralAccounts import (
  CollateralContext,
  collateral_context,
  collateral_owned,
  collateral_digest
)
from Transparency.NetworkCollateralState import PublicBondRow, decode_public_bond_row
from Solana.Read import (
  OptionalAccountSlicesAtSlot,
  Pubkey,
  pubkey,
  pubkey_string,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_send
)

struct PublicBonds do
  context :: CollateralContext
  rows :: List<PublicBondRow>
  digest :: Bytes
end

fn principal(rows :: List<PublicBondRow>, asset :: Int) -> U64!String do
  List.reduce(rows,
    Ok(U64.parse("0")?),
    fn(total, row) do
      if row.bond.asset == asset do
        U64.add(total?, row.bond.principal)
      else
        total
      end
    end)
end

fn decode_bonds(options :: BondsV2Options,
  snapshot :: OptionalAccountSlicesAtSlot,
  now :: U64) -> PublicBonds!String do
  let selected = options.selection
  let keys = collateral_bond_keys(selected)?
  if List.length(snapshot.accounts) != List.length(keys) do
    return Err("bonds_v2_snapshot_length")
  end
  let context = collateral_context(selected.pins, snapshot, options.minimum)?
  if !context.code_current do
    return Err("bonds_v2_release_mismatch")
  end
  check_clock(context.timestamp, now, options.max_age)?
  let rows = for index in 0..(List.length(selected.witnesses) + 1) do
    let at = if index == 0 do
      14
    else
      19 + (index - 1) * 5
    end
    let raw = collateral_owned(snapshot, at, selected.pins.judge, 208)?
    if Bytes.to_hex(Bytes.slice(raw, 0, 4)?) != "4d424402" do
      return Err("bonds_v2_requires_MBD2")
    end
    decode_public_bond_row(selected, snapshot, context, keys, at, index - 1)?
  end
  let e = context.economics
  if U64.compare(principal(List.take(rows, 1), 0)?, e.directory_usdc) > 0
    || U64.compare(principal(List.take(rows, 1), 1)?, e.directory_morse) > 0
    || U64.compare(principal(List.drop(rows, 1), 0)?, e.witness_usdc) > 0
    || U64.compare(principal(List.drop(rows, 1), 1)?, e.witness_morse) > 0 do
    return Err("bonds_v2_selected_principal_mismatch")
  end
  Ok(PublicBonds {
    context: context,
    rows: rows,
    digest: collateral_digest(keys, snapshot, "morse-cli-bonds-v2-finalized-v1")?
  })
end

fn observe(client :: Int,
  endpoint :: String,
  options :: BondsV2Options,
  now :: U64) -> PublicBonds!String do
  let keys = collateral_bond_keys(options.selection)?
  if List.length(keys) > 100 do
    return Err("bonds_v2_account_capacity")
  end
  let request = get_multiple_accounts_slice_request(1,
    keys,
    "finalized",
    0,
    8416,
    Some(options.minimum))?
  decode_bonds(options,
    optional_accounts_slice_from_response(rpc_send(client, endpoint, request, 5000, 524288)?)?,
    now)
end

fn agree(a :: PublicBonds!String, b :: PublicBonds!String) -> Option<PublicBonds> do
  case (a, b) do
    (Ok(first), Ok(second)) -> if first.digest == second.digest do
      Some(first)
    else
      None
    end
    _ -> None
  end
end

fn refuse(results :: List<PublicBonds!String>) -> String do
  let valid = List.length(List.filter(results, fn(value) do Result.is_ok(value) end))
  if valid >= 2 do
    return "bonds_v2_rpc_disagreed"
  end
  for reason in [
    "bonds_v2_requires_MBD2",
    "bonds_v2_stale_clock",
    "bonds_v2_future_clock",
    "bonds_v2_release_mismatch"
  ] do
    let count = List.length(List.filter(results,
      fn(value) do
        case value do
          Err(error) -> error == reason
          Ok(_) -> false
        end
      end))
    if count >= 2 do
      return reason
    end
  end
  "bonds_v2_rpc_unavailable"
end

pub fn read_bonds_v2(options :: BondsV2Options, now :: U64) -> String!String do
  let client = Http.client()
  let results = for endpoint in options.sources do
    observe(client, endpoint, options, now)
  end
  Http.client_close(client)
  for pair in [
    agree(List.get(results, 0), List.get(results, 1)),
    agree(List.get(results, 0), List.get(results, 2)),
    agree(List.get(results, 1), List.get(results, 2))
  ] do
    case pair do
      Some(state) -> do
        let finished = host_clock()?
        if U64.compare(finished, now) < 0 do
          return Err("bonds_v2_host_clock_regressed")
        end
        check_clock(state.context.timestamp, finished, options.max_age)?
        return public_bonds_report(options.selection, state, options, finished)
      end
      None -> nil
    end
  end
  Err(refuse(results))
end

pub fn run_bonds_v2_command(args :: List<String>) -> Int!String do
  if List.length(args) != 6
    || List.get(args, 4) != "--v2-config"
    || List.get(args, 5) == ""
    || String.length(List.get(args, 5)) > 4096 do
    return Err("usage: morse bonds --log LOG_NAME --v2-config FILE")
  end
  let bytes = File.read_bytes(List.get(args, 5), 0, 32769)?
  if Bytes.length(bytes) > 32768 do
    return Err("bonds_v2_config_capacity")
  end
  let options = parse_bonds_v2_options(Bytes.to_utf8(bytes)?, List.get(args, 3))?
  println(read_bonds_v2(options, host_clock()?)?)
  Ok(0)
end

fn q(value :: String) -> String do
  Json.encode_string(value)
end

fn u(value :: U64) -> String do
  q(U64.to_string(value))
end

fn flag(value :: Bool) -> String do
  if value do
    "true"
  else
    "false"
  end
end

fn address(value :: Bytes) -> String!String do
  Ok(q(pubkey_string(pubkey(Bytes.to_base58(value))?)))
end

fn status(value :: Int) -> String do
  case value do
    1 -> "active"
    2 -> "unbonding"
    3 -> "slashed"
    _ -> "withdrawn"
  end
end

fn header(selection :: CollateralSelection,
  context :: CollateralContext,
  digest :: Bytes) -> String do
  let p = selection.pins
  """"schema_version":2,"availability":"available","selection_scope":"explicit-indexed-records-only","bank_scope":"this-section-only","context_slot":#{u(context.slot)},"source_time_unix":#{u(context.timestamp)},"snapshot_digest":#{q(Bytes.to_hex(digest))},"code_current":#{flag(context.code_current)},"judge":#{q(pubkey_string(p.judge))},"token":#{q(pubkey_string(p.token))},"rewards":#{q(pubkey_string(p.rewards))},"log_name":#{q(p.log_name)},"log_id":#{q(Bytes.to_hex(context.log.log_id))},"service_public_key":#{q(Bytes.to_hex(p.service_key))},"usdc_mint":#{q(pubkey_string(p.usdc))},"morse_mint":#{q(pubkey_string(p.morse))},"decimals":6"""
end

pub fn unavailable_collateral(status :: String) -> String do
  """{"schema_version":2,"availability":#{q(status)},"reason":"no-agreeing-finalized-selected-snapshot"}"""
end

pub fn public_bonds_report(selection :: CollateralSelection,
  state :: PublicBonds,
  options :: BondsV2Options,
  now :: U64) -> String!String do
  let rows = for row in state.rows do
    let b = row.bond
    let other = case row.opposite_balance do
      None -> """{"availability":"absent","balance_units":null}"""
      Some(value) -> """{"availability":"present","balance_units":#{u(value)}}"""
    end
    """{"kind":#{q(row.kind)},"witness_id":#{q(row.witness_id)},"public_key":#{q(Bytes.to_hex(row.public_key))},"address":#{q(pubkey_string(row.address))},"owner":#{address(b.owner)?},"asset":#{q(if b.asset == 0 do
      "USDC"
    else
      "MORSE"
    end)},"mint":#{address(b.mint)?},"vault":#{address(b.vault)?},"status":#{q(status(b.status))},"principal_units":#{u(b.principal)},"pending_recorded_units":#{u(row.pending_recorded)},"pending_liability_units":#{u(row.pending_liability)},"vault_balance_units":#{u(row.balance)},"donation_surplus_units":#{u(row.donation)},"opposite_asset_vault":#{other},"bonded_at_unix":#{u(b.bonded_at)},"unbond_at_unix":#{u(b.unbond_at)},"slashed_at_unix":#{u(b.slashed_at)},"underwater_since_unix":#{u(b.underwater_since)},"pending_target_usd_micros":#{u(row.pending_target_usd)}}"""
  end
  Ok("""{#{header(selection,
    state.context,
    state.digest)},"mode":"v2","bond_layout":"MBD2-only","scope":#{q(options.scope)},"checked_at_unix":#{u(now)},"max_age_seconds":#{u(options.max_age)},"provider_independence":"not-established","valuation":{"availability":"unavailable","reason":"no-oracle-authentication-or-USD-valuation"},"rows":[#{String.join(rows,
    ",")}] }""")
end

fn host_clock() -> U64!String do
  let now = DateTime.to_unix_secs(DateTime.utc_now())
  if now <= 0 do
    return Err("bonds_v2_host_clock")
  end
  U64.parse(Int.to_string(now))
end

fn check_clock(timestamp :: U64, now :: U64, maximum :: U64) -> Result<(), String> do
  if U64.compare(timestamp, now) > 0 do
    return Err("bonds_v2_future_clock")
  end
  if U64.compare(U64.subtract(now, timestamp)?, maximum) > 0 do
    return Err("bonds_v2_stale_clock")
  end
  Ok(nil)
end
