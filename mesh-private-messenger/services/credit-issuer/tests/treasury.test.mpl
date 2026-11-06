from Storage.TreasuryFunding import (
  reserve_treasury_funding,
  reconcile_treasury_funding,
  treasury_funding_instruction
)
from Payment.TreasuryRewards import TreasuryFundingProof
from Transparency.RewardsChain import (
  reward_pool_address,
  decode_reward_funding_receipt,
  reward_funding_address
)
from Transparency.RewardsWrite import RewardWriteContext
from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Runtime.TreasurySigning import sign_treasury_packet
from Storage.Treasury import load_treasury_movement
from Storage.TreasuryPacket import (
  reserve_treasury_message,
  commit_treasury_packet,
  block_treasury_history,
  retry_failed_treasury_movement,
  finalize_treasury_packet
)
from Solana.Read import Pubkey, Hash
from Solana.Nonce import NonceAccountState
from Solana.TransactionRead import (
  signed_transaction,
  FinalizedTransaction,
  FinalizedTransactionOutcome
)
from Credits.Issuance import CreditQuote, encode_credit_quote
from Payment.Verify import PaymentReceipt, payment_token_address
from Payment.Observation import CreditDepositObservation
from Storage.Treasury import (
  record_credit_deposit,
  reserve_treasury_movement,
  record_issued_credit_revenue,
  freeze_treasury_week
)

fn treasury_text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_fixture_row")
  end
end

fn treasury_bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

pub struct TreasuryTestSeed do
  quote :: CreditQuote
  observation :: CreditDepositObservation
end

# Storage policy fixture only: no fake data reaches RPC or payment acceptance.
# Real BR1 issuance and signed chain observations have separate integration gates.
fn treasury_fixture(conn :: borrow PgConn,
  owner :: Bytes,
  domain :: String) -> TreasuryTestSeed!String do
  let key_id = Crypto.sha256(Bytes.from_utf8("treasury-key" <> domain))
  let quote_id = Crypto.sha256(Bytes.from_utf8("treasury-quote" <> domain))
  let mint = treasury_bytes("44", 32)?
  let quote = CreditQuote {
    quote_id: quote_id,
    deposit_owner: owner,
    destination: payment_token_address(owner, mint)?,
    mint: mint,
    asset: 0,
    amount: U64.parse("5000000")?,
    purpose: 1,
    credits: 100,
    issued_at: U64.parse("1700000000")?,
    expires_at: U64.parse("1700000900")?,
    issuer_key_id: key_id,
    batch_hash: treasury_bytes("84", 32)?
  }
  Pg.execute_values(conn,
    "INSERT INTO issuer_keys(key_id,epoch,purpose,spki,sealed_private_key) VALUES($1,$4::numeric,1,$2,$3)",
    [
      Binary(key_id),
      Binary(Bytes.from_hex(String.repeat(Bytes.to_hex(key_id), 10)
        <> Bytes.to_hex(Bytes.slice(key_id, 0, 22)?))?),
      Binary(treasury_bytes("81", 68)?),
      Text(Bytes.read_uint_le(key_id, 0, 8)?)
    ])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_quotes(quote_id,quote,key_id,batch_hash,deposit_owner,sealed_deposit_key,price_observed_at) VALUES($1,$2,$3,$4,$5,$6,0)",
    [
      Binary(quote_id),
      Binary(encode_credit_quote(quote)?),
      Binary(key_id),
      Binary(quote.batch_hash),
      Binary(owner),
      Binary(treasury_bytes("81", 99)?)
    ])?
  Ok(TreasuryTestSeed {
    quote: quote,
    observation: CreditDepositObservation {
      quote_id: quote_id,
      asset: 0,
      mint: mint,
      deposit_owner: owner,
      destination: quote.destination,
      payment: PaymentReceipt {
        transaction_signature: Bytes.concat(quote_id, quote_id)?,
        payer: treasury_bytes("86", 32)?,
        slot: U64.parse("9007199254740993")?,
        block_time: U64.parse("1700000010")?,
        received_amount: U64.parse("4999999")?
      },
      wire_sha256: treasury_bytes("87", 32)?,
      disposition: 1
    }
  })
end

fn treasury_record_probe(conn :: borrow PgConn, seed :: TreasuryTestSeed) -> Bool!String do
  record_credit_deposit(conn, seed.observation)?
  record_credit_deposit(conn, seed.observation)?
  assert(Result.is_err(record_credit_deposit(conn,
    %{seed.observation |
      payment: %{seed.observation.payment | received_amount: U64.parse("4999998")?}
    })))
  assert(Result.is_err(record_credit_deposit(conn,
    %{seed.observation | wire_sha256: treasury_bytes("88", 32)?})))
  assert(Result.is_err(record_credit_deposit(conn, %{seed.observation | disposition: 0})))
  assert(Result.is_err(record_issued_credit_revenue(conn, seed.quote.quote_id)))
  assert(Result.is_err(reserve_treasury_movement(conn,
    seed.quote.quote_id,
    seed.observation.payment.transaction_signature,
    0,
    treasury_bytes("89", 32)?,
    treasury_bytes("90", 32)?,
    U64.parse("1700000020")?,
    U64.parse("5")?)))
  let rows = Pg.query_values(conn,
    "SELECT COUNT(*)::text AS count FROM issuer_credit_revenue WHERE quote_id=$1",
    [Binary(seed.quote.quote_id)])?
  assert(treasury_text(Map.get(List.head(rows), "count"))? == "0")
  Ok(true)
end

fn treasury_refund(pool :: PoolHandle, seed :: TreasuryTestSeed, offset :: Int) -> Bytes!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let value = reserve_treasury_movement(conn,
        seed.quote.quote_id,
        seed.observation.payment.transaction_signature,
        1,
        treasury_bytes("89", 32)?,
        treasury_bytes("90", 32)?,
        U64.parse(Int.to_string(1700000020 + offset))?,
        U64.parse("0")?)?
      assert(value.amount == U64.parse("4999999")?)
      assert(Bytes.secure_equals(value.destination_owner, seed.observation.payment.payer))
      assert(Bytes.secure_equals(value.destination,
        payment_token_address(seed.observation.payment.payer, seed.quote.mint)?))
      assert(Bytes.secure_equals(value.source, seed.quote.destination))
      assert(value.state == 0)
      Ok(value.movement_id)
    end)
end

fn treasury_allocation_proof(pool :: PoolHandle) -> Bool!String do
  let seed = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do treasury_fixture(conn,
      treasury_bytes("83", 32)?,
      "concurrent-refund") end)?
  Repo.transaction(pool, fn(conn :: borrow PgConn) do treasury_record_probe(conn, seed) end)?
  let results = Job.map([0, 1, 2, 3, 4, 5], fn(index) do treasury_refund(pool, seed, index) end)
  let ids = for result in results do
    result??
  end
  for id in ids do
    assert(Bytes.secure_equals(id, List.head(ids)))
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT COUNT(*)::text AS count FROM issuer_treasury_movements WHERE payment_signature=$1",
        [Binary(seed.observation.payment.transaction_signature)])?
      assert(treasury_text(Map.get(List.head(rows), "count"))? == "1")
      assert(Result.is_err(reserve_treasury_movement(conn,
        seed.quote.quote_id,
        seed.observation.payment.transaction_signature,
        1,
        treasury_bytes("89", 32)?,
        treasury_bytes("91", 32)?,
        U64.parse("1700001000")?,
        U64.parse("0")?)))
      Ok(true)
    end)
end

test("underpayment observation and six concurrent refund reservations preserve exact original payer and amount") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 6, 5000) do
    Ok(value) -> value
    Err(error) -> do
      println(error)
      assert(false)
      return
    end
  end
  let result = treasury_allocation_proof(pool)
  Pool.close(pool)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn treasury_test_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Ok(value)
    Err(_) -> Err("fixture signer failed")
  end
end

fn treasury_packet_proof(pool :: PoolHandle) -> Bool!String do
  let source = treasury_test_pair()?
  let fee = treasury_test_pair()?
  let authority = treasury_test_pair()?
  let source_public = source.public_key.bytes
  let seed = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do treasury_fixture(conn, source_public, "packet") end)?
  let config = TreasuryChainConfig {
    providers_hash: Bytes.from_hex(String.repeat("12", 32))?,
    cluster: treasury_bytes("91", 32)?,
    mint: seed.quote.mint,
    treasury_owner: treasury_bytes("92", 32)?,
    fee_payer: fee.public_key.bytes,
    nonce_authority: authority.public_key.bytes,
    nonce_address: treasury_bytes("93", 32)?,
    rewards_program: treasury_bytes("94", 32)?,
    rewards_pool: treasury_bytes("95", 32)?
  }
  let config_hash = treasury_config_hash(config)?
  let nonce = NonceAccountState {
    authority: Pubkey { bytes: config.nonce_authority },
    nonce: Hash { bytes: treasury_bytes("96", 32)? },
    lamports_per_signature: U64.parse("5000")?
  }
  let reserved = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      record_credit_deposit(conn, seed.observation)?
      let movement = reserve_treasury_movement(conn,
        seed.quote.quote_id,
        seed.observation.payment.transaction_signature,
        1,
        config.treasury_owner,
        config_hash,
        U64.parse("1700000020")?,
        U64.parse("0")?)?
      reserve_treasury_message(conn, movement.movement_id, config, nonce, U64.parse("1700000020")?)
    end)?
  let packet = sign_treasury_packet(reserved,
    config,
    nonce,
    source.private_key,
    fee.private_key,
    authority.private_key)?
  let signature = Bytes.slice(packet, 1, 64)?
  let commits = Job.map([0, 1, 2, 3],
    fn(_index) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        let movement = commit_treasury_packet(conn, reserved.movement_id, packet, signature)?
        assert(movement.state == 1 && Bytes.secure_equals(movement.packet, packet))
        Ok(true)
      end) end)
  for result in commits do
    assert(result??)
  end
  let signed = signed_transaction(packet, signature)?
  let balances = for _row in signed.accounts do
    U64.parse("1000000")?
  end
  let post_values = for index in 0..List.length(signed.accounts) do
    U64.parse(if index == 0 do
      "985000"
    else
      "1000000"
    end)?
  end
  let outcome = FinalizedTransactionOutcome {
    execution_error: Some("\"InsufficientFunds\""),
    transaction: FinalizedTransaction {
      signed: signed,
      slot: U64.parse("777")?,
      block_time: Some(1700000030),
      fee: U64.parse("15000")?,
      pre_balances: balances,
      post_balances: post_values,
      pre_token_balances: [],
      post_token_balances: [],
      inner_instruction_count: 0,
      inner_instructions: []
    }
  }
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      assert(Result.is_err(retry_failed_treasury_movement(conn, reserved.movement_id)))
      block_treasury_history(conn, reserved.movement_id, signature)?
      assert(load_treasury_movement(conn, reserved.movement_id)?.state == 4)
      assert(Result.is_err(retry_failed_treasury_movement(conn, reserved.movement_id)))
      let failed = finalize_treasury_packet(conn, reserved.movement_id, config, outcome)?
      assert(failed.state == 3)
      assert(finalize_treasury_packet(conn, reserved.movement_id, config, outcome)?.state == 3)
      let reset = retry_failed_treasury_movement(conn, reserved.movement_id)?
      assert(reset.state == 0 && Bytes.length(reset.packet) == 0)
      assert(Result.is_err(finalize_treasury_packet(conn, reserved.movement_id, config, outcome)))
      assert(Result.is_err(reserve_treasury_message(conn,
        reserved.movement_id,
        config,
        nonce,
        U64.parse("1700000040")?)))
      let attempts = Pg.query_values(conn,
        "SELECT COUNT(*)::text AS count FROM issuer_treasury_attempts WHERE movement_id=$1 AND state=3",
        [Binary(reserved.movement_id)])?
      assert(treasury_text(Map.get(List.head(attempts), "count"))? == "1")
      Ok(true)
    end)
end

test("durable packet commits converge across retries and unknown history never authorizes a replacement") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 6, 5000) do
    Ok(value) -> value
    Err(error) -> do
      println(error)
      assert(false)
      return
    end
  end
  let result = treasury_packet_proof(pool)
  Pool.close(pool)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

# These are SQL state-machine fixtures, not claims of chain execution. The
# production transition requires finalize_treasury_packet's authenticated proof.
fn treasury_week_event(conn :: borrow PgConn,
  domain :: String,
  asset :: Int,
  amount :: U64,
  swept :: Bool) -> Bytes!String do
  let original = treasury_fixture(conn, Crypto.sha256(Bytes.from_utf8("owner-" <> domain)), domain)?
  let quote = if asset == 0 do
    original.quote
  else
    %{original.quote |
      asset: 1,
      mint: treasury_bytes("00", 32)?,
      destination: original.quote.deposit_owner,
      amount: amount
    }
  end
  let observed = %{original.observation |
    asset: asset,
    mint: quote.mint,
    destination: quote.destination,
    payment: %{original.observation.payment | received_amount: amount},
    disposition: 0
  }
  Pg.execute_values(conn,
    "UPDATE issuer_quotes SET quote=$2 WHERE quote_id=$1",
    [Binary(quote.quote_id), Binary(encode_credit_quote(quote)?)])?
  record_credit_deposit(conn, observed)?
  Pg.execute_values(conn,
    "UPDATE issuer_quotes SET payment_signature=$2,payment_payer=$3,payment_slot=100,payment_time=1700000010,payment_amount=$4::numeric,issued_response=$5 WHERE quote_id=$1",
    [
      Binary(quote.quote_id),
      Binary(observed.payment.transaction_signature),
      Binary(observed.payment.payer),
      Text(U64.to_string(amount)),
      Binary(treasury_bytes("01", 25670)?)
    ])?
  record_issued_credit_revenue(conn, quote.quote_id)?
  let movement = reserve_treasury_movement(conn,
    quote.quote_id,
    observed.payment.transaction_signature,
    0,
    treasury_bytes("a2", 32)?,
    treasury_bytes("a1", 32)?,
    U64.parse("1700000020")?,
    U64.parse("0")?)?
  if swept do
    treasury_week_mark_swept(conn, movement.movement_id)?
  end
  Ok(movement.movement_id)
end

fn treasury_week_mark_swept(conn :: borrow PgConn, id :: Bytes) -> Result<(), String> do
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_movements SET state=2,nonce_address=$2,nonce_value=$2,message=$3,packet=$3,transaction_signature=payment_signature,finalized_slot=100,fee=5000 WHERE movement_id=$1",
    [Binary(id), Binary(treasury_bytes("a3", 32)?), Binary(treasury_bytes("01", 1)?)])?
  Ok(nil)
end

fn treasury_week_proof(pool :: PoolHandle) -> Bool!String do
  let week = U64.divide(U64.parse("1700000010")?, U64.parse("604800")?)?
  let now = U64.multiply(U64.add(week, U64.parse("1")?)?, U64.parse("604800")?)?
  let mint = treasury_bytes("44", 32)?
  let config_hash = treasury_bytes("a1", 32)?
  let late = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      treasury_week_event(conn, "weekly-first", 0, U64.parse("5000001")?, true)?
      let late = treasury_week_event(conn, "weekly-late", 0, U64.parse("5000001")?, false)?
      let foreign = treasury_week_event(conn,
        "weekly-foreign-config",
        0,
        U64.parse("5000001")?,
        true)?
      Pg.execute_values(conn,
        "UPDATE issuer_treasury_movements SET config_hash=$2 WHERE movement_id=$1",
        [Binary(foreign), Binary(treasury_bytes("af", 32)?)])?
      assert(Result.is_err(freeze_treasury_week(conn,
        week,
        0,
        mint,
        config_hash,
        U64.subtract(now, U64.parse("1")?)?)))
      let frozen = freeze_treasury_week(conn, week, 0, mint, config_hash, now)?
      assert(frozen.amount == U64.parse("5000001")? && frozen.witness == U64.parse("1000000")?)
      assert(frozen.operations == U64.parse("4000001")? && frozen.carry_after == 1)
      treasury_week_mark_swept(conn, late)?
      let replay = freeze_treasury_week(conn,
        week,
        0,
        mint,
        config_hash,
        U64.add(now, U64.parse("100")?)?)?
      assert(replay.batch_id == frozen.batch_id
        && Bytes.secure_equals(replay.membership_hash, frozen.membership_hash))
      assert(Result.is_err(freeze_treasury_week(conn,
        week,
        0,
        mint,
        treasury_bytes("a4", 32)?,
        now)))
      Ok(late)
    end)?
  let next = U64.add(week, U64.parse("1")?)?
  let next_time = U64.add(now, U64.parse("604800")?)?
  let races = Job.map([0, 1, 2, 3],
    fn(_index) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        let batch = freeze_treasury_week(conn, next, 0, mint, config_hash, next_time)?
        assert(batch.amount == U64.parse("5000001")?
          && batch.carry_before == 1
          && batch.carry_after == 2)
        Ok(batch.batch_id)
      end) end)
  let ids = for result in races do
    result??
  end
  for id in ids do
    assert(id == List.head(ids))
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      for index in 0..3 do
        treasury_week_event(conn,
          "weekly-dust-" <> Int.to_string(index),
          0,
          U64.parse("5000001")?,
          true)?
      end
      treasury_week_event(conn, "weekly-sol", 1, U64.parse("9007199254740993")?, true)?
      let third = U64.add(next, U64.parse("1")?)?
      let third_time = U64.add(next_time, U64.parse("604800")?)?
      let batch = freeze_treasury_week(conn, third, 0, mint, config_hash, third_time)?
      assert(batch.amount == U64.parse("15000003")?
        && batch.witness == U64.parse("3000001")?
        && batch.operations == U64.parse("12000002")?)
      assert(batch.carry_before == 2 && batch.carry_after == 0)
      let sol = freeze_treasury_week(conn,
        third,
        1,
        treasury_bytes("00", 32)?,
        config_hash,
        third_time)?
      assert(sol.amount == U64.parse("9007199254740993")?
        && sol.witness == U64.parse("1801439850948198")?)
      assert(sol.operations == U64.parse("7205759403792795")?
        && sol.carry_before == 0
        && sol.carry_after == 3)
      assert(Result.is_err(freeze_treasury_week(conn,
        week,
        1,
        treasury_bytes("00", 32)?,
        config_hash,
        third_time)))
      let counts = Pg.query_values(conn,
        "SELECT COUNT(*)::text AS count FROM issuer_treasury_weekly_events",
        [])?
      assert(treasury_text(Map.get(List.head(counts), "count"))? == "6")
      Ok(true)
    end)
end

test("weekly snapshots allocate swept revenue once, carry fifths and retain late SOL in original units") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 6, 5000) do
    Ok(value) -> value
    Err(error) -> do
      println(error)
      assert(false)
      return
    end
  end
  let result = treasury_week_proof(pool)
  Pool.close(pool)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn treasury_funding_proof(pool :: PoolHandle) -> Bool!String do
  let program = Pubkey { bytes: treasury_bytes("94", 32)? }
  let config = TreasuryChainConfig {
    providers_hash: treasury_bytes("12", 32)?,
    cluster: treasury_bytes("91", 32)?,
    mint: treasury_bytes("44", 32)?,
    treasury_owner: treasury_bytes("a2", 32)?,
    fee_payer: treasury_bytes("b1", 32)?,
    nonce_authority: treasury_bytes("b2", 32)?,
    nonce_address: treasury_bytes("b3", 32)?,
    rewards_program: program.bytes,
    rewards_pool: reward_pool_address(program)?.bytes
  }
  let week = U64.add(U64.divide(U64.parse("1700000010")?, U64.parse("604800")?)?, U64.parse("4")?)?
  let now = U64.multiply(U64.add(week, U64.parse("1")?)?, U64.parse("604800")?)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do # Independent funding fixture starts a new accounting lane; production
      # configuration changes require explicit migration, never inherited carry.
      Pg.execute_values(conn, "DELETE FROM issuer_treasury_weekly_events", [])?
      Pg.execute_values(conn, "DELETE FROM issuer_treasury_weekly", [])?
      let movement = treasury_week_event(conn, "funding-handoff", 0, U64.parse("5000001")?, true)?
      Pg.execute_values(conn,
        "UPDATE issuer_treasury_movements SET config_hash=$2 WHERE movement_id=$1",
        [Binary(movement), Binary(treasury_config_hash(config)?)])?
      let batch = freeze_treasury_week(conn,
        week,
        0,
        config.mint,
        treasury_config_hash(config)?,
        now)?
      let epoch = U64.add(week, U64.parse("2")?)?
      let first = case reserve_treasury_funding(conn, batch.batch_id, config, epoch)? do
        Some(value) -> value
        None -> return Err("missing funding")
      end
      assert(first.amount == batch.witness && first.state == 0)
      let retained = reconcile_treasury_funding(conn,
        first.intent_id,
        TreasuryFundingProof { current_epoch: epoch, receipt_bytes: Bytes.empty(), receipt: None })?
      assert(retained.state == 0)
      let later = U64.add(epoch, U64.parse("1")?)?
      assert(Result.is_err(reserve_treasury_funding(conn, batch.batch_id, config, later)))
      let expired = reconcile_treasury_funding(conn,
        first.intent_id,
        TreasuryFundingProof { current_epoch: later, receipt_bytes: Bytes.empty(), receipt: None })?
      assert(expired.state == 2)
      let child = case reserve_treasury_funding(conn, batch.batch_id, config, later)? do
        Some(value) -> value
        None -> return Err("missing child funding")
      end
      assert(child.epoch == later
        && child.amount == first.amount
        && !Bytes.secure_equals(child.intent_id, first.intent_id))
      let context = RewardWriteContext {
        program: program,
        judge: Pubkey { bytes: treasury_bytes("b4", 32)? },
        log_name: "morse-main",
        mint: Pubkey { bytes: config.mint }
      }
      let instruction = treasury_funding_instruction(child,
        context,
        Pubkey { bytes: config.fee_payer })?
      assert(Bytes.get(instruction.data, 0)? == 12 && Bytes.get(instruction.data, 1)? == 0)
      assert(Bytes.read_uint_le(instruction.data, 2, 8)? == U64.to_string(child.amount))
      assert(Bytes.secure_equals(Bytes.slice(instruction.data, 10, 32)?, child.intent_id))
      assert(Bytes.secure_equals(List.get(instruction.accounts, 8).pubkey.bytes,
        reward_funding_address(program,
          Pubkey { bytes: config.treasury_owner },
          child.intent_id)?.bytes))
      assert(Result.is_err(treasury_funding_instruction(expired,
        context,
        Pubkey { bytes: config.fee_payer })))
      let funded_at = U64.add(U64.multiply(later, U64.parse("604800")?)?, U64.parse("10")?)?
      let raw = Bytes.from_hex("4d524601"
        <> Bytes.to_hex(child.pool)
        <> Bytes.to_hex(child.funder)
        <> Bytes.to_hex(child.intent_id)
        <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(child.epoch), 8)?)
        <> "00000000"
        <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(child.amount), 8)?)
        <> Bytes.to_hex(child.source)
        <> Bytes.to_hex(child.mint)
        <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(funded_at), 8)?))?
      let receipt = decode_reward_funding_receipt(raw)?
      let proof = TreasuryFundingProof {
        current_epoch: later,
        receipt_bytes: raw,
        receipt: Some(receipt)
      }
      let wrong_kind = Bytes.from_hex(Bytes.to_hex(Bytes.slice(raw, 0, 108)?)
        <> "01"
        <> Bytes.to_hex(Bytes.slice(raw, 109, 83)?))?
      assert(Result.is_err(reconcile_treasury_funding(conn,
        child.intent_id,
        %{proof | receipt_bytes: wrong_kind})))
      assert(Result.is_err(reconcile_treasury_funding(conn,
        child.intent_id,
        %{proof | receipt_bytes: treasury_bytes("01", 192)?})))
      let funded = reconcile_treasury_funding(conn, child.intent_id, proof)?
      assert(funded.state == 1)
      assert(reconcile_treasury_funding(conn, child.intent_id, proof)?.state == 1)
      let replay = case reserve_treasury_funding(conn,
        batch.batch_id,
        config,
        U64.add(later, U64.parse("3")?)?)? do
        Some(value) -> value
        None -> return Err("missing replay")
      end
      assert(Bytes.secure_equals(replay.intent_id, child.intent_id) && replay.state == 1)
      assert(Result.is_err(reconcile_treasury_funding(conn,
        child.intent_id,
        %{proof | receipt: None, receipt_bytes: Bytes.empty()})))
      Ok(true)
    end)
end

test("weekly witness funding hands off only idempotent revenue intents and permanent matching receipts") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 6, 5000) do
    Ok(value) -> value
    Err(error) -> do
      println(error)
      assert(false)
      return
    end
  end
  let result = treasury_funding_proof(pool)
  Pool.close(pool)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
