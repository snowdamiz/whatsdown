from Credits.QuoteAuth import decode_signed_credit_quote, verify_credit_quote
from Credits.Issuance import (
  CreditQuoteRequest,
  CreditQuote,
  CreditIssueRequest,
  encode_credit_quote,
  encode_credit_quote_request,
  encode_credit_issue_request,
  encode_credit_issue_response,
  credit_batch_hash
)
from Credits.Issuer import CreditIssuerKey, issuer_key_id, encode_issuer_key
from Credits.Policy import issuer_epoch
from Credits.Token import blind_credit, finalize_credit, verify_credit_token
from Payment.Verify import PaymentReceipt, payment_token_address
from Storage.Issuance import (
  insert_issuer_key,
  insert_quote,
  issue_paid_on_connection,
  load_quote,
  admit_issuer_key
)
from Storage.Quotes import create_quote_on_connection, quote_amount
from Api.Purchases import IssuerPolicy, quote_response, issue_response
from Storage.Keys import ensure_current_key
from Transparency.Merkle import (
  WitnessKey,
  leaf_hash_for,
  merkle_root_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_tree_checkpoint_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence
from Credits.Lightning import LightningQuoteRequest
from Payment.LightningBackend import LndConfig
from Storage.Lightning import (
  reserve_lightning_quote,
  reserve_lightning_quote_with_revenue_policy,
  load_lightning_record,
  restore_lightning_preimage
)

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

pub struct LedgerSeed do
  service_key :: Bytes
  key :: CreditIssuerKey
end

fn ledger(conn :: borrow PgConn) -> LedgerSeed!String do
  let wrapping = case StorageKey.platform() do
    Ok(value) -> value
    Err(_) -> return Err("fixture storage failed")
  end
  let private = case Crypto.blind_rsa_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture key failed")
  end
  let public = case Crypto.blind_rsa_public(private) do
    Ok(value) -> value
    Err(_) -> return Err("fixture public failed")
  end
  let now = wide(1703000000)?
  let service_pair = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture service failed")
  end
  let witness = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture witness failed")
  end
  let quote_pair = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture quote signer failed")
  end
  let service_key = service_pair.public_key.bytes
  let key = CreditIssuerKey {
    epoch: issuer_epoch(now)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: quote_pair.public_key.bytes
  }
  insert_issuer_key(conn, key, private, quote_pair.private_key, wrapping, service_key)?
  insert_issuer_key(conn, key, private, quote_pair.private_key, wrapping, service_key)?
  assert(Result.is_err(insert_issuer_key(conn,
    %{key | quote_public_key: witness.public_key.bytes},
    private,
    witness.private_key,
    wrapping,
    service_key)))
  let entry = encode_issuer_key(key)?
  let tree = [leaf_hash_for(2, entry)?]
  let checkpoint = sign_tree_checkpoint_for(2,
    service_pair.private_key,
    service_key,
    wide(1)?,
    wide(1)?,
    merkle_root_for(2, tree)?,
    bytes("00", 32)?,
    wide(1703000000000)?)?
  let evidence = TransparencyEvidence {
    entry_bytes: entry,
    inclusion: compact_inclusion_proof_for(2, tree, 0)?,
    consistency: compact_consistency_proof_for(2, [], tree)?,
    checkpoint: checkpoint,
    witnesses: [sign_witness("outside", witness.private_key, checkpoint)?]
  }
  admit_issuer_key(conn,
    evidence,
    service_pair.public_key,
    [WitnessKey { witness_id: "outside", public_key: witness.public_key.bytes }],
    1,
    now,
    1)?
  Ok(LedgerSeed { service_key: service_key, key: key })
end

fn key() -> StorageKey!String do
  case StorageKey.platform() do
    Ok(value)
    Err(_) -> Err("fixture_key_failed")
  end
end

fn refused(value :: Result<HashPreimage, String>) -> Bool do
  case value do
    Err(_) -> true
    Ok(secret) -> do
      Secret.destroy(secret)
      false
    end
  end
end

fn proof(pool :: PoolHandle) -> Bool!String do
  let seed = Repo.transaction(pool, fn(conn :: borrow PgConn) do ledger(conn) end)?
  let request = LightningQuoteRequest {
    credits: 100,
    network: 2,
    purpose: 1,
    issuer_key_id: issuer_key_id(seed.key)?,
    batch_hash: bytes("ac", 32)?
  }
  let config = LndConfig {
    origin: "http://127.0.0.1:19877",
    macaroon: String.repeat("ab", 32),
    network: 2,
    purpose: 1,
    payee: Bytes.from_hex("03659ee9278803e3667d20d2d081dffc7d6bd6145e4e1bca9fb4a941bfd932dbc2")?
  }
  let results = Job.map([0, 1, 2, 3, 4, 5],
    fn(_index) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        let wrapping = key()?
        reserve_lightning_quote_with_revenue_policy(conn,
          request,
          config,
          U64.parse("100000000000")?,
          wide(1703000000)?,
          wide(1703000000)?,
          wrapping,
          seed.service_key,
          2)
      end) end)
  let values = for item in results do
    item??
  end
  let first = List.head(values)
  for item in values do
    assert(Bytes.secure_equals(item.quote_id, first.quote_id))
    assert(Bytes.secure_equals(item.payment_hash, first.payment_hash))
    assert(item.amount_msat == wide(5000000)?)
    assert(item.state == 0 && item.policy_version == 2)
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let wrapping = key()?
      let restored = reserve_lightning_quote(conn,
        request,
        config,
        wide(0)?,
        wide(0)?,
        wide(1800000000)?,
        wrapping,
        seed.service_key)?
      assert(Bytes.secure_equals(restored.quote_id, first.quote_id) && restored.policy_version == 2)
      assert(refused(restore_lightning_preimage(conn,
        first.quote_id,
        config,
        wrapping,
        seed.service_key)))
      assert(Result.is_err(reserve_lightning_quote(conn,
        %{request | credits: 500},
        config,
        wide(1)?,
        wide(1703000000)?,
        wide(1703000000)?,
        wrapping,
        seed.service_key)))
      assert(Result.is_err(reserve_lightning_quote(conn,
        request,
        %{config | origin: "http://127.0.0.1:19878"},
        wide(1)?,
        wide(1703000000)?,
        wide(1703000000)?,
        wrapping,
        seed.service_key)))
      let sol = CreditQuoteRequest {
        credits: 100,
        asset: 0,
        purpose: 1,
        issuer_key_id: request.issuer_key_id,
        batch_hash: request.batch_hash
      }
      assert(Result.is_err(create_quote_on_connection(conn,
        sol,
        bytes("44", 32)?,
        wide(0)?,
        wide(1703000000)?,
        wide(1703000000)?,
        wrapping,
        seed.service_key)))
      let other = %{sol | batch_hash: bytes("ad", 32)?}
      create_quote_on_connection(conn,
        other,
        bytes("44", 32)?,
        wide(0)?,
        wide(1703000000)?,
        wide(1703000000)?,
        wrapping,
        seed.service_key)?
      assert(Result.is_err(reserve_lightning_quote(conn,
        %{request | batch_hash: other.batch_hash},
        config,
        wide(1)?,
        wide(1703000000)?,
        wide(1703000000)?,
        wrapping,
        seed.service_key)))
      let stored = load_lightning_record(conn, first.quote_id, config)?
      assert(Bytes.secure_equals(stored.payment_hash, first.payment_hash))
      let rows = Pg.query_values(conn,
        "SELECT sealed_preimage FROM issuer_lightning_quotes WHERE quote_id=$1",
        [Binary(first.quote_id)])?
      assert(case Map.get(List.head(rows), "sealed_preimage") do
        Binary(value) -> Bytes.length(value) == 99
        _ -> false
      end)
      Ok(true)
    end)?
  let rolled = %{request | batch_hash: bytes("ae", 32)?}
  let attempted :: Bool!String = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let wrapping = key()?
      reserve_lightning_quote(conn,
        rolled,
        config,
        U64.parse("100000000000")?,
        wide(1703000000)?,
        wide(1703000000)?,
        wrapping,
        seed.service_key)?
      Err("forced_rollback_before_invoice_creation")
    end)
  assert(Result.is_err(attempted))
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT quote_id FROM issuer_lightning_quotes WHERE key_id=$1 AND batch_hash=$2",
        [Binary(request.issuer_key_id), Binary(rolled.batch_hash)])?
      assert(List.length(rows) == 0)
      Ok(true)
    end)
end

test("six Lightning reservations retain one sealed payment hash and fence premature disclosure, rail changes and rollback") do
  Test.install_in_memory_secure_store()
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 6, 5000) do
    Ok(value) -> value
    Err(error) -> do
      println(error)
      assert(false)
      return
    end
  end
  let result = proof(pool)
  Pool.close(pool)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
