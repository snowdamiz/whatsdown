from Mobile.ForkFiling import FilingPlan, prepare_filing, run_filing, start_filing, filing_view
from Mobile.ForkFilingState import FilingState, FilingObservation, load_filing
from Tests.ForkFilingSupport import filing_fixture
from Tests.GroupLifecycleWire import output_list
from Tests.GroupConsistencySupport import wide
from Tests.Support import database_path, repeated
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Transparency.Config import SecurityConfig
from Transparency.Fork import ForkProof, ForkTarget, encode_fork
from Transparency.Merkle import checkpoint_hash
from Transparency.SlashReceipt import SlashReceipt, SlashWitness, slash_receipt_address
from Transparency.SlashReceiptRead import SlashReceiptState, read_slash_receipt_state
from Transparency.AnchorChain import AnchorPins
from Transparency.RpcTransport import RpcTls, rpc_endpoint, rpc_transport, webpki_rpc_transport
from Solana.Read import Pubkey

fn await_file(path :: String, tries :: Int) -> Bool do
  if File.exists(path) do
    true
  else if tries == 0 do
    false
  else
    Timer.sleep(10)
    await_file(path, tries - 1)
  end
end

fn await_filing(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes,
  tries :: Int) -> FilingState!String do
  let state = load_filing(path, key, identity)?
  if Bytes.length(state.token) == 0 || tries == 0 do
    Ok(state)
  else
    Timer.sleep(10)
    await_filing(path, key, identity, tries - 1)
  end
end

fn actor_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("filing-actor")?
  ensure_schema(path)?
  let (proof, config) = filing_fixture()?
  let plan = plan_for(proof, config)?
  let held = start_filing(path,
    key,
    plan,
    wide(1000)?,
    fn() -> Ok(2) end,
    fn(_slot :: U64) do
      File.write(path <> ".entered", "yes")?
      if !await_file(path <> ".release", 1000) do
        return Err("test_reader_never_released")
      end
      chain_state(plan, false)
    end,
    fn() -> true end)?
  assert(Bytes.length(held.token) == 16)
  assert(await_file(path <> ".entered", 1000))
  # Reading local state remains possible while networking is waiting.
  assert(load_filing(path, key, plan.identity)?.checked_at == wide(0)?)
  File.write(path <> ".release", "yes")?
  let completed = await_filing(path, key, plan.identity, 1000)?
  assert(completed.accepted == 2 && completed.observation.context_slot == wide(80)?)
  File.delete(path <> ".entered")?
  File.delete(path <> ".release")?
  File.delete(path)?
  Ok(true)
end

test("filing actor returns while receipt I/O waits and commits its result independently") do
  case actor_proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn plan_for(proof :: ForkProof, config :: SecurityConfig) -> FilingPlan!String do
  case prepare_filing(config, webpki_rpc_transport(config.rpc_urls)?, encode_fork(proof)?)? do
    Some(plan) -> Ok(plan)
    None -> Err("missing filing plan")
  end
end

fn chain_state(plan :: FilingPlan, paid :: Bool) -> SlashReceiptState!String do
  let second = case plan.proof.second do
    SignedCheckpoint(value) -> checkpoint_hash(value)?
    AnchorReference(_) -> repeated(3, 32)?
  end
  let receipt = SlashReceipt {
    kind: plan.proof.kind,
    anchored: false,
    log_id: plan.pins.log_id,
    proof_hash: plan.proof_hash,
    finder: repeated(8, 32)?,
    submitter: repeated(9, 32)?,
    mint: plan.mint.bytes,
    first_checkpoint: checkpoint_hash(plan.proof.first)?,
    second_checkpoint: second,
    slashed_at: wide(5000)?,
    total_slashed: wide(1000)?,
    finder_amount: wide(100)?,
    directory_slashed: wide(1000)?,
    verified_signatures: wide(3)?,
    witnesses: []
  }
  Ok(SlashReceiptState {
    address: slash_receipt_address(plan.pins.program, plan.pins.log_id, plan.proof_hash)?,
    proof_hash: plan.proof_hash,
    context_slot: wide(80)?,
    receipt: if paid do
      Some(receipt)
    else
      None
    end
  })
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("filing-worker")?
  let calls = path <> ".calls"
  ensure_schema(path)?
  File.write(calls, "")?
  let (proof, config) = filing_fixture()?
  let plan = plan_for(proof, config)?
  let post = fn() do
    File.append(calls, "p")?
    Ok(2)
  end
  let down = run_filing(path,
    key,
    plan,
    wide(1000)?,
    post,
    fn(_slot :: U64) -> Err("anchor_rpc_unavailable") end,
    fn() -> true end)?
  assert(down.observation.status == "rpc_unavailable" && down.accepted == 2)
  assert(Bytes.length(down.observation.finder) == 0)
  let deferred = run_filing(path,
    key,
    plan,
    wide(1001)?,
    post,
    fn(_slot :: U64) -> Err("must not read") end,
    fn() -> true end)?
  assert(File.read(calls)? == "p" && deferred.tier == 1)
  let pending = run_filing(path,
    key,
    plan,
    wide(61000)?,
    post,
    fn(_slot :: U64) -> chain_state(plan, false) end,
    fn() -> true end)?
  assert(pending.observation.status == "pending" && pending.accepted == 2)
  assert(File.read(calls)? == "pp")
  let paid = run_filing(path,
    key,
    plan,
    wide(361000)?,
    post,
    fn(slot :: U64) do
      assert(slot == wide(80)?)
      chain_state(plan, true)
    end,
    fn() -> true end)?
  assert(paid.observation.status == "settled" && File.read(calls)? == "pp")
  let view = for field in output_list(filing_view(plan, paid)?)? do
    Bytes.to_utf8(field)?
  end
  assert(List.get(view, 0) == "paid_elsewhere")
  assert(List.get(view, 2) == Bytes.to_base58(proof.finder))
  assert(List.get(view, 3) == Bytes.to_base58(repeated(8, 32)?))
  assert(List.get(view, 4) == "100")
  # Endpoint rotation preserves the settled receipt and never re-posts the proof.
  let rotated = plan_for(proof, %{config | relay_urls: ["https://new-relay.example"]})?
  assert(Bytes.secure_equals(rotated.identity, plan.identity))
  let terminal = run_filing(path,
    key,
    rotated,
    wide(99999999)?,
    post,
    fn(_slot :: U64) -> Err("must not read") end,
    fn() -> true end)?
  assert(terminal.observation.status == "settled" && File.read(calls)? == "pp")
  # Native key rotation and malformed evidence fail before any filing attempt.
  case prepare_filing(%{config | service_public_key: repeated(3, 32)?},
    webpki_rpc_transport(config.rpc_urls)?,
    plan.wire) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case prepare_filing(config,
    webpki_rpc_transport(config.rpc_urls)?,
    Bytes.from_utf8("unverified")) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let disabled = %{config | relay_urls: [], slash_mint: "-"}
  assert(case prepare_filing(disabled, webpki_rpc_transport(disabled.rpc_urls)?, plan.wire)? do
    None -> true
    Some(_) -> false
  end)
  File.delete(calls)?
  File.delete(path)?
  Ok(true)
end

test("phone filing survives outages and restart, trusts only receipts, and reports a different paid finder") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn fence_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("filing-fence")?
  ensure_schema(path)?
  let (proof, config) = filing_fixture()?
  let plan = plan_for(proof, config)?
  let mode = path <> ".mode"
  File.write(mode, "current")?
  let post = fn() do
    File.write(mode <> ".posted", "bad")?
    Ok(3)
  end
  case run_filing(path,
    key,
    plan,
    wide(1000)?,
    post,
    fn(_slot :: U64) do
      File.write(mode, "changed")?
      chain_state(plan, false)
    end,
    fn() do File.read(mode).unwrap_or("changed") == "current" end) do
    Err(error) -> assert(error == "filing_config_changed")
    Ok(_) -> assert(false)
  end
  assert(!File.exists(mode <> ".posted"))
  File.write(mode, "current")?
  let state = run_filing(path,
    key,
    plan,
    wide(1001)?,
    post,
    fn(_slot :: U64) -> chain_state(plan, true) end,
    fn() -> true end)?
  assert(state.tier == 1 && state.checked_at == wide(0)?)
  # A mismatched receipt object cannot become a paid observation, even if the
  # transport reported success. Real receipt authentication stays in the reader.
  let invalid = run_filing(path,
    key,
    plan,
    wide(61000)?,
    fn() -> Ok(0) end,
    fn(_slot :: U64) do
      let value = chain_state(plan, true)?
      Ok(%{value | proof_hash: repeated(3, 32)?})
    end,
    fn() -> true end)?
  assert(invalid.observation.status == "rpc_unavailable")
  assert(Bytes.length(invalid.observation.finder) == 0)
  File.delete(mode)?
  File.delete(path)?
  Ok(true)
end

test("native pin changes fence pending submissions and mismatched receipt data never reports payment") do
  case fence_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn fatal_rpc_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let (proof, original) = filing_fixture()?
  let config = %{original |
    rpc_urls: [
      "https://127.0.0.1:19991/rpc",
      "https://127.0.0.1:19992/rpc",
      "https://127.0.0.1:19993/rpc"
    ]
  }
  # This reaches the production reader and public Http PEM validation. Invalid
  # roots fail before dispatch; every URL is also loopback-only.
  let rpc = rpc_transport(for url in config.rpc_urls do
      rpc_endpoint(url, OriginRoots(Http.url_origin(url)?, Bytes.from_utf8("bad PEM")))?
    end,
    fn() -> Ok(nil) end)?
  let plan = case prepare_filing(config, rpc, encode_fork(proof)?)? do
    None -> return Err("missing filing plan")
    Some(value) -> value
  end
  for error in ["rpc_tls_config_invalid", "rpc_context_changed:account_state_changed"] do
    let path = database_path("filing-fatal-rpc")?
    let posted = path <> ".posted"
    ensure_schema(path)?
    case run_filing(path,
      key,
      plan,
      wide(1000)?,
      fn() do
        File.write(posted, "bad")?
        Ok(3)
      end,
      fn(slot :: U64) do
        if error == "rpc_tls_config_invalid" do
          read_slash_receipt_state(plan.pins,
            config.service_public_key,
            config.log_version,
            plan.mint,
            plan.proof_hash,
            slot)
        else
          Err(error)
        end
      end,
      fn() -> true end) do
      Err(found) -> assert(found == error)
      Ok(_) -> return Err("fatal_rpc_error_became_outage")
    end
    assert(!File.exists(posted))
    let state = load_filing(path, key, plan.identity)?
    assert(state.checked_at == wide(0)? && state.accepted == 0)
    assert(Bytes.length(state.token) == 16)
    File.delete(path)?
  end
  Ok(true)
end

test("filing refuses fatal RPC authority errors before relay fallback or completion") do
  case fatal_rpc_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
