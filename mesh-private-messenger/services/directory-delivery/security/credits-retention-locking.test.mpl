from Storage.WitnessRegistry import bootstrap_witness_registry
from Credits.Action import credit_action_id
from Credits.ActionWire import CreditActionSubmission
from Credits.Retention import (
  sign_credit_retention_request,
  encode_credit_retention_request,
  credit_retention_action
)
from Credits.Issuer import CreditIssuerKey, encode_issuer_key
from Credits.Policy import issuer_epoch
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Credits.Wire import CreditFrame
from Storage.Credits import redeem_credits_on_connection
from Storage.CreditOperation import lock_credit_operation
from Storage.CreditRetention import apply_credit_retention
from Storage.CreditIssuers import announce_credit_issuer, admit_credit_issuer
from Tests.MailboxSupport import register_test_mailbox, mailbox_test_now
from Transparency.Merkle import (
  leaf_hash_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence

fn bytes(hex :: String) -> Bytes!String do
  Bytes.from_hex(String.repeat(hex, 32))
end

fn pair(name :: String) -> SigningKeyPair!String do
  let seed = case Env.get_secret_hex(name) do
    Err(_) -> return Err("missing proof signer")
    Ok(value) -> value
  end
  case Crypto.signing_from_secret(seed) do
    Err(_) -> Err("invalid proof signer")
    Ok(value)
  end
end

fn number(rows :: List<Map<String, DbValue>>) -> Int!String do
  let text = case Map.get(List.head(rows), "value") do
    Text(value) -> value
    _ -> return Err("invalid proof row")
  end
  case String.to_int(text) do
    None -> Err("invalid proof number")
    Some(value) -> Ok(value)
  end
end

fn wait_for_waiter(conn :: borrow PgConn, tries :: Int) -> Result<(), String> do
  let count = number(Pg.query_values(conn,
    "SELECT count(*)::text AS value FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND l.locktype='advisory' AND NOT l.granted AND l.pid<>pg_backend_pid()",
    [])?)?
  if count > 0 do
    Ok(nil)
  else if tries == 0 do
    Err("retention did not contend for operation lock")
  else
    Timer.sleep(10)
    wait_for_waiter(conn, tries - 1)
  end
end

fn wait_for_owner(pool :: PoolHandle, tries :: Int) -> Result<(), String> do
  let rows = Pool.query(pool,
    "SELECT count(*)::text AS value FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.datname=current_database() AND l.locktype='advisory' AND l.granted",
    [])?
  if Map.get(List.head(rows), "value") != "0" do
    Ok(nil)
  else if tries == 0 do
    Err("redeem did not own operation lock")
  else
    Timer.sleep(10)
    wait_for_owner(pool, tries - 1)
  end
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL", "")
  if !String.contains(url, "/credits_retention_lock_test?") do
    return Err("requires disposable retention lock harness")
  end
  let pool = Pool.open(url, 2, 2, 5000)?
  bootstrap_witness_registry(pool)?
  let secret = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(secret) do
    Err(_) -> return Err("RSA public failed")
    Ok(value) -> value
  end
  let core = pair("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX")?
  let first = pair("CREDIT_FIXTURE_WITNESS_A_SEED")?
  let second = pair("CREDIT_FIXTURE_WITNESS_B_SEED")?
  let now_ms = mailbox_test_now()?
  let now = U64.divide(now_ms, U64.parse("1000")?)?
  let key = CreditIssuerKey {
    epoch: issuer_epoch(now)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: core.public_key.bytes
  }
  let leaf = encode_issuer_key(key)?
  let announced = announce_credit_issuer(pool, leaf)?
  let tree = [leaf_hash_for(2, leaf)?]
  admit_credit_issuer(pool,
    TransparencyEvidence {
      entry_bytes: leaf,
      inclusion: compact_inclusion_proof_for(2, tree, 0)?,
      consistency: compact_consistency_proof_for(2, [], tree)?,
      checkpoint: announced.checkpoint,
      witnesses: [
        sign_witness("witness-a", first.private_key, announced.checkpoint)?,
        sign_witness("witness-b", second.private_key, announced.checkpoint)?
      ]
    })?
  let token = bytes("17")?
  let owner = register_test_mailbox(pool, "retention-lock-owner", token)?
  let request = sign_credit_retention_request(owner.signing_private_key,
    Crypto.sha256(token),
    bytes("22")?,
    32,
    U64.add(now, U64.parse("600")?)?,
    now_ms)?
  let body = encode_credit_retention_request(request)?
  let tokens = for _index in 0..10 do
    let pending = blind_credit(key, core.public_key.bytes, now)?
    let signed = sign_credit_request(secret, key, pending.request)?
    finalize_credit(key, pending, signed)?
  end
  let submission = CreditActionSubmission {
    action: credit_retention_action(request)?,
    request_body: body,
    frame: CreditFrame { binding: Crypto.sha256(body), tokens: tokens }
  }
  # T1 deliberately owns the same operation lock before T2 starts. Both old
  # and fixed retention implementations wait on that lock; only the old one
  # holds the mailbox UPDATE lock while waiting, creating a guaranteed cycle.
  let results = Job.map([0, 1],
    fn(index) do
      if index == 0 do
        Repo.transaction(pool,
          fn(conn :: borrow PgConn) do
            lock_credit_operation(conn, credit_action_id(submission.action)?)?
            wait_for_waiter(conn, 200)?
            redeem_credits_on_connection(conn,
              submission.action,
              submission.request_body,
              submission.frame)?
            Ok(true)
          end)
      else
        wait_for_owner(pool, 200)?
        apply_credit_retention(pool, submission)?
        Ok(true)
      end
    end)
  for result in results do
    case result do
      Ok(Ok(true)) -> nil
      Ok(Ok(false)) -> return Err("retention/redeem returned false")
      Ok(Err(error)) -> return Err("retention/redeem lock-order failure: #{error}")
      Err(error) -> return Err("retention/redeem job failure: #{error}")
    end
  end
  let rows = Pool.query(pool,
    "SELECT (SELECT count(*) FROM credit_holds)::text||':'||(SELECT count(*) FROM credit_spent)::text||':'||(SELECT count(*) FROM credit_action_effects)::text AS value",
    [])?
  assert(Map.get(List.head(rows), "value") == "1:10:1")
  Pool.close(pool)
  println("CREDITS_RETENTION_LOCK_ORDER: both transactions committed; one hold, ten spends, one effect")
  Ok(true)
end

test("retention and bare redemption take operation before mailbox locks") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
