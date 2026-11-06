from BurnNetwork import TokenBurnBank, read_token_burn_worker_quorum, read_token_burn_expiry_quorum
from BurnSchedule import token_burn_packet_disposition
from BurnJournal import (
  TokenBurnJournalEntry,
  reserve_token_burn_chunk,
  reserve_token_burn_close,
  load_token_burn_entry,
  sign_and_commit_token_burn_entry,
  replace_token_burn_expired_packet,
  submit_token_burn_entry,
  confirm_token_burn_original_from_carry,
  confirm_token_burn_carry_entry,
  record_token_burn_missed_window,
  load_token_burn_missed_window
)
from Transparency.TokenBurnRead import TokenBurnReadPins, token_burn_rpc_sources
from Transparency.TokenBurnCarryRead import plan_token_burn_carry_close
from Transparency.TokenBurnWrite import token_burn_execute_instruction
from Solana.Read import Pubkey, Hash
from Solana.TransactionRead import signed_transaction

pub struct TokenBurnWorkerConfig do
  pins :: TokenBurnReadPins
  payer :: Pubkey
  epoch :: U64
  minimum_slot :: U64
  urls :: List<String>
  test_mode :: Bool
  replace_expired :: Bool
  # Exactly 24 bounded supported ExactIn routes, checked against the fresh row/price.
  # Once reserved the original route is immutable, including on replacement.
  routes :: List<Bytes>
end

pub struct TokenBurnWorkerResult do
  status :: String
  kind :: Int
  index :: Int
  epoch :: U64
  context_slot :: U64
  height :: U64
  bank_digest :: Bytes
  operation :: Bytes
  signature :: Bytes
end

fn worker_result(config :: TokenBurnWorkerConfig,
  bank :: TokenBurnBank,
  status :: String,
  kind :: Int,
  index :: Int,
  entry :: Option<TokenBurnJournalEntry>) -> TokenBurnWorkerResult do
  TokenBurnWorkerResult {
    status: status,
    kind: kind,
    index: index,
    epoch: config.epoch,
    context_slot: bank.custody.context_slot,
    height: bank.height,
    bank_digest: bank.digest,
    operation: case entry do
      None -> Bytes.empty()
      Some(value) -> value.id
    end,
    signature: case entry do
      None -> Bytes.empty()
      Some(value) -> value.signature
    end
  }
end

fn worker_load(path :: String,
  wrapping :: borrow StorageKey,
  config :: TokenBurnWorkerConfig,
  kind :: Int,
  index :: Int) -> Option<TokenBurnJournalEntry>!String do
  case load_token_burn_entry(path, wrapping, config.pins.program, kind, config.epoch, index) do
    Ok(value) -> Ok(Some(value))
    Err(error) -> if error == "token_burn_operation_missing" do
      Ok(None)
    else
      Err(error)
    end
  end
end

fn worker_fresh(config :: TokenBurnWorkerConfig, bank :: TokenBurnBank) -> Bool!String do
  if config.test_mode do
    return Ok(true)
  end
  let local = DateTime.to_unix_ms(DateTime.utc_now()) / 1000
  if bank.custody.timestamp > local + 30 || bank.custody.timestamp < local - 120 do
    Err("token_burn_worker_stale_clock")
  else
    Ok(true)
  end
end

fn worker_read(client :: Int,
  config :: TokenBurnWorkerConfig,
  minimum :: U64) -> TokenBurnBank!String do
  let bank = read_token_burn_worker_quorum(client,
    config.urls,
    config.test_mode,
    config.pins,
    config.epoch,
    minimum)?
  worker_fresh(config, bank)?
  Ok(bank)
end

fn worker_send(path :: String,
  wrapping :: borrow StorageKey,
  config :: TokenBurnWorkerConfig,
  bank :: TokenBurnBank,
  entry :: TokenBurnJournalEntry,
  client :: Int,
  provider :: Int) -> TokenBurnWorkerResult!String do
  # Refresh the entire authenticated bank immediately before the one bounded send.
  let minimum = if U64.compare(bank.custody.context_slot, entry.context_slot) > 0 do
    bank.custody.context_slot
  else
    entry.context_slot
  end
  let fresh = worker_read(client, config, minimum)?
  let frame = case fresh.custody.frame do
    None -> return Err("burn_bank_week_missing")
    Some(value) -> value
  end
  if !fresh.custody.code_current do
    return Ok(worker_result(config, fresh, "reconcile:code", entry.kind, entry.index, Some(entry)))
  end
  if entry.kind == 10 && List.get(frame.week.rows, entry.index).complete do
    let confirmed = confirm_token_burn_original_from_carry(path,
      wrapping,
      config.pins.program,
      10,
      config.epoch,
      entry.index,
      fresh.custody.profile,
      frame,
      fresh.custody.receipt,
      fresh.custody.context_slot)?
    return Ok(worker_result(config, fresh, "complete:chunk", 10, entry.index, Some(confirmed)))
  end
  if entry.kind == 13 && frame.closed do
    let confirmed = confirm_token_burn_carry_entry(path,
      wrapping,
      config.pins.program,
      13,
      config.epoch,
      fresh.custody.profile,
      frame,
      fresh.custody.receipt,
      fresh.custody.context_slot)?
    return Ok(worker_result(config, fresh, "complete:carry", 13, 0, Some(confirmed)))
  end
  if entry.kind == 10 do
    let market = case fresh.market do
      None -> return Ok(worker_result(config,
        fresh,
        "reconcile:window",
        10,
        entry.index,
        Some(entry)))
      Some(value) -> value
    end
    if !market.code_current || market.spot == None do
      return Ok(worker_result(config, fresh, "reconcile:market", 10, entry.index, Some(entry)))
    end
    let spot = case market.spot do
      None -> return Err("token_burn_reconcile_price")
      Some(value) -> value
    end
    let canonical = token_burn_execute_instruction(config.pins.program,
      entry.payer,
      fresh.custody.profile,
      frame.week,
      entry.index,
      Bytes.slice(entry.instruction.data, 2, 39)?,
      spot)
    if canonical != Ok(entry.instruction) do
      return Ok(worker_result(config,
        fresh,
        "reconcile:price-or-intent",
        10,
        entry.index,
        Some(entry)))
    end
    let disposition = token_burn_packet_disposition(entry,
      frame.week,
      U64.parse(Int.to_string(fresh.custody.timestamp))?,
      fresh.height,
      fresh.custody.context_slot,
      market.code_current)?
    if disposition != "submit:exact" do
      return Ok(worker_result(config, fresh, disposition, 10, entry.index, Some(entry)))
    end
  end
  if entry.status == 3 do
    return Ok(worker_result(config, fresh, "reconcile:state", entry.kind, entry.index, Some(entry)))
  end
  let now = U64.parse(Int.to_string(fresh.custody.timestamp))?
  let sent = submit_token_burn_entry(path,
    wrapping,
    config.pins.program,
    entry.kind,
    config.epoch,
    entry.index,
    client,
    List.get(config.urls, provider),
    now,
    fresh.height)
  case sent do
    Err(_) -> Ok(worker_result(config,
      fresh,
      "pending:unknown",
      entry.kind,
      entry.index,
      Some(entry)))
    Ok(value) -> Ok(worker_result(config,
      fresh,
      "pending:rpc-ack",
      entry.kind,
      entry.index,
      Some(value)))
  end
end

fn worker_expiry(client :: Int,
  config :: TokenBurnWorkerConfig,
  bank :: TokenBurnBank,
  entry :: TokenBurnJournalEntry) -> TokenBurnBank!String do
  let signed = signed_transaction(entry.packet, entry.signature)?
  let proof = read_token_burn_expiry_quorum(client,
    config.urls,
    config.test_mode,
    config.pins,
    config.epoch,
    bank.custody.context_slot,
    Hash { bytes: signed.recent_blockhash })?
  worker_fresh(config, proof)?
  Ok(proof)
end

# One tick visits at most 24 rows and signs at most one packet. It never funds a week.
# Exact packet retries are safe after an unknown reply. Replacement is separately opted in.
pub fn token_burn_worker_tick(path :: String,
  wrapping :: borrow StorageKey,
  config :: TokenBurnWorkerConfig,
  payer :: borrow SigningPrivateKey,
  client :: Int,
  provider :: Int) -> TokenBurnWorkerResult!String do
  token_burn_rpc_sources(config.urls, config.test_mode)?
  if List.length(config.routes) != 24 || provider < 0 || provider > 2 do
    return Err("invalid_token_burn_worker_config")
  end
  for route in config.routes do
    if Bytes.length(route) != 39 do
      return Err("invalid_token_burn_worker_route")
    end
  end
  let proof = Bytes.concat(Bytes.from_utf8("morse-token-burn-worker-payer-v1"),
    config.pins.program.bytes)?
  let signature = case Crypto.sign(payer, proof) do
    Err(_) -> return Err("token_burn_worker_signer")
    Ok(value) -> value
  end
  let valid = case Crypto.verify(SigningPublicKey { bytes: config.payer.bytes },
    proof,
    signature) do
    Err(_) -> false
    Ok(value) -> value
  end
  if !valid do
    return Err("token_burn_worker_signer")
  end
  let bank = worker_read(client, config, config.minimum_slot)?
  let frame = case bank.custody.frame do
    None -> return Err("burn_bank_week_missing")
    Some(value) -> value
  end
  let now = U64.parse(Int.to_string(bank.custody.timestamp))?
  if !bank.custody.code_current do
    return Ok(worker_result(config, bank, "reconcile:code", 0, 0, None))
  end
  # A late observed receipt belongs to its original permanent row even after the
  # scheduler advances to another window. Never leave an earlier exact packet unknown.
  for index in 0..24 do
    if List.get(frame.week.rows, index).complete do
      case worker_load(path, wrapping, config, 10, index)? do
        None -> nil
        Some(entry) -> if entry.status != 0 do
          confirm_token_burn_original_from_carry(path,
            wrapping,
            config.pins.program,
            10,
            config.epoch,
            index,
            bank.custody.profile,
            frame,
            bank.custody.receipt,
            bank.custody.context_slot)?
          nil
        else
          nil
        end
      end
    end
  end
  if frame.closed do
    case worker_load(path, wrapping, config, 13, 0)? do
      None -> return Ok(worker_result(config, bank, "complete:carry", 13, 0, None))
      Some(_) -> do
        let confirmed = confirm_token_burn_carry_entry(path,
          wrapping,
          config.pins.program,
          13,
          config.epoch,
          bank.custody.profile,
          frame,
          bank.custody.receipt,
          bank.custody.context_slot)?
        return Ok(worker_result(config, bank, "complete:carry", 13, 0, Some(confirmed)))
      end
    end
  end
  # Persist every newly observed missed row without changing its budget or windows.
  for index in 0..24 do
    let row = List.get(frame.week.rows, index)
    if !row.complete && U64.compare(now, row.window_end) >= 0 do
      record_token_burn_missed_window(path,
        wrapping,
        config.pins.program,
        config.epoch,
        index,
        bank)?
    end
  end
  let end_time = U64.multiply(U64.add(config.epoch, U64.parse("1")?)?, U64.parse("604800")?)?
  if U64.compare(now, end_time) >= 0 do
    let plan = plan_token_burn_carry_close(config.pins, config.payer, bank.custody)?
    if plan.status != "close" do
      return Ok(worker_result(config, bank, plan.status, 13, 0, None))
    end
    let entry = reserve_token_burn_close(path,
      wrapping,
      config.pins.program,
      config.payer,
      bank.custody.profile,
      config.epoch)?
    let committed = if entry.status == 0 do
      sign_and_commit_token_burn_entry(path,
        wrapping,
        config.pins.program,
        13,
        config.epoch,
        0,
        payer,
        payer,
        bank.tip.blockhash,
        bank.custody.context_slot,
        bank.tip.last_valid_block_height)?
    else if U64.compare(bank.height, entry.last_valid_block_height) > 0 do
      if !config.replace_expired do
        return Ok(worker_result(config, bank, "reconcile:expired-packet", 13, 0, Some(entry)))
      end
      replace_token_burn_expired_packet(path,
        wrapping,
        config.pins.program,
        13,
        config.epoch,
        0,
        entry.signature,
        worker_expiry(client, config, bank, entry)?,
        payer)?
    else
      entry
    end
    return worker_send(path, wrapping, config, bank, committed, client, provider)
  end
  let index = (bank.custody.timestamp % 604800) / 25200
  let row = List.get(frame.week.rows, index)
  if row.complete do
    case worker_load(path, wrapping, config, 10, index)? do
      None -> return Ok(worker_result(config, bank, "complete:chunk", 10, index, None))
      Some(_) -> do
        let confirmed = confirm_token_burn_original_from_carry(path,
          wrapping,
          config.pins.program,
          10,
          config.epoch,
          index,
          bank.custody.profile,
          frame,
          bank.custody.receipt,
          bank.custody.context_slot)?
        return Ok(worker_result(config, bank, "complete:chunk", 10, index, Some(confirmed)))
      end
    end
  end
  if U64.compare(now, row.execute_at) < 0 do
    return Ok(worker_result(config, bank, "waiting:window", 10, index, None))
  end
  if load_token_burn_missed_window(path,
    wrapping,
    config.pins.program,
    config.epoch,
    index)? != None do
    return Ok(worker_result(config, bank, "reconcile:missed", 10, index, None))
  end
  let market = case bank.market do
    None -> return Err("token_burn_reconcile_market")
    Some(value) -> value
  end
  if !market.code_current do
    return Ok(worker_result(config, bank, "reconcile:code", 10, index, None))
  end
  let spot = case market.spot do
    None -> return Ok(worker_result(config, bank, "reconcile:price", 10, index, None))
    Some(value) -> value
  end
  let entry = case worker_load(path, wrapping, config, 10, index)? do
    Some(value) -> value
    None -> reserve_token_burn_chunk(path,
      wrapping,
      config.pins.program,
      config.payer,
      bank.custody.profile,
      frame.week,
      index,
      List.get(config.routes, index),
      spot)?
  end
  let disposition = token_burn_packet_disposition(entry,
    frame.week,
    now,
    bank.height,
    bank.custody.context_slot,
    market.code_current)?
  let committed = if disposition == "sign:initial" do
    sign_and_commit_token_burn_entry(path,
      wrapping,
      config.pins.program,
      10,
      config.epoch,
      index,
      payer,
      payer,
      bank.tip.blockhash,
      bank.custody.context_slot,
      bank.tip.last_valid_block_height)?
  else if disposition == "replace:expired" do
    if !config.replace_expired do
      return Ok(worker_result(config, bank, "reconcile:expired-packet", 10, index, Some(entry)))
    end
    replace_token_burn_expired_packet(path,
      wrapping,
      config.pins.program,
      10,
      config.epoch,
      index,
      entry.signature,
      worker_expiry(client, config, bank, entry)?,
      payer)?
  else if disposition == "submit:exact" do
    entry
  else
    return Ok(worker_result(config, bank, disposition, 10, index, Some(entry)))
  end
  worker_send(path, wrapping, config, bank, committed, client, provider)
end

pub fn token_burn_worker_report(value :: TokenBurnWorkerResult) -> String do
  "{\"schema_version\":1,\"status\":"
    <> Json.encode_string(value.status)
    <> ",\"kind\":"
    <> Int.to_string(value.kind)
    <> ",\"index\":"
    <> Int.to_string(value.index)
    <> ",\"epoch\":\""
    <> U64.to_string(value.epoch)
    <> "\",\"context_slot\":\""
    <> U64.to_string(value.context_slot)
    <> "\",\"block_height\":\""
    <> U64.to_string(value.height)
    <> "\",\"bank_digest\":\""
    <> Bytes.to_hex(value.bank_digest)
    <> "\",\"operation\":\""
    <> Bytes.to_hex(value.operation)
    <> "\",\"signature\":\""
    <> Bytes.to_base58(value.signature)
    <> "\"}"
end
