import File
from Mobile.CreditNonce import issued_credit_intent_nonce, require_fresh_credit_intent_nonce
from Mobile.Codec import mobile_read_u64
from Mobile.CreditWallet import prune_credit_history
from Storage.Credits import CreditWalletIdentity, load_credit_wallet
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("credit_intent_nonce")?
  let who = CreditWalletIdentity {
    account_id: repeated(41, 32)?,
    device_id: repeated(42, 16)?,
    service_key: repeated(43, 32)?,
    purpose: 1
  }
  let now = U64.parse("1700000000000")?
  let nonce = issued_credit_intent_nonce(now)?
  assert(Bytes.length(nonce) == 32 && mobile_read_u64(Bytes.slice(nonce, 0, 8)?)? == now)
  assert(Result.is_ok(require_fresh_credit_intent_nonce(path, wrapping, who, 1, nonce, now)))
  assert(Result.is_ok(require_fresh_credit_intent_nonce(path,
    wrapping,
    who,
    3,
    nonce,
    U64.add(now, U64.parse("900000")?)?)))
  assert(Result.is_err(require_fresh_credit_intent_nonce(path,
    wrapping,
    who,
    1,
    nonce,
    U64.add(now, U64.parse("900001")?)?)))
  assert(Result.is_err(require_fresh_credit_intent_nonce(path,
    wrapping,
    who,
    1,
    nonce,
    U64.subtract(now, U64.parse("1")?)?)))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == U64.parse("0")?)
  prune_credit_history(path,
    wrapping,
    who,
    U64.divide(U64.add(now, U64.parse("900001")?)?, U64.parse("1000")?)?)?
  # The durable floor is second-resolution, so move one full second past it.
  prune_credit_history(path,
    wrapping,
    who,
    U64.divide(U64.add(now, U64.parse("901000")?)?, U64.parse("1000")?)?)?
  assert(Result.is_err(require_fresh_credit_intent_nonce(path, wrapping, who, 1, nonce, now)))
  assert(Result.is_ok(require_fresh_credit_intent_nonce(path,
    wrapping,
    %{who | purpose: 0},
    1,
    nonce,
    now)))
  File.delete(path)?
  Ok(true)
end

test("native preview nonces expire without clock rollback or cross-purpose reopening") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
