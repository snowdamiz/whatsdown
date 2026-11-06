from Mobile.ForkFilingState import (
  FilingClaim,
  FilingState,
  FilingObservation,
  claim_filing,
  finish_filing,
  load_filing,
  filing_pending
)
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key
from Storage.Records import store_updated_session
from Tests.Support import database_path, repeated

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn required(value :: Option<FilingClaim>) -> FilingClaim!String do
  case value do
    Some(claim) -> Ok(claim)
    None -> Err("missing filing claim")
  end
end

fn attempt(path :: String, now :: U64) -> Option<FilingClaim>!String do
  let key = platform_key()?
  claim_filing(path, key, repeated(1, 32)?, repeated(2, 32)?, 3, now)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("filing-state")?
  ensure_schema(path)?
  let scope = repeated(1, 32)?
  let first = required(attempt(path, wide("1000")?)?)?
  assert(attempt(path, wide("60999")?)? == None)
  # A crashed request consumes its first minute; retry receives a different token.
  let retry = required(attempt(path, wide("61000")?)?)?
  assert(!Bytes.secure_equals(first.token, retry.token))
  case finish_filing(path, key, first, wide("61001")?, 3, filing_pending(wide("80")?)?) do
    Err(error) -> assert(error == "filing_claim_superseded")
    Ok(_) -> assert(false)
  end
  finish_filing(path, key, retry, wide("61001")?, 2, filing_pending(wide("80")?)?)?
  let state = load_filing(path, key, scope)?
  assert(state.accepted == 2 && state.targets == 3 && state.tier == 2)
  assert(state.observation.context_slot == wide("80")?)
  assert(state.next_attempt == wide("361000")?)
  # Endpoint rotation cannot reset the rate limit or authenticated context floor.
  assert(claim_filing(path, key, scope, repeated(3, 32)?, 2, wide("61002")?)? == None)
  let next = required(claim_filing(path, key, scope, repeated(2, 32)?, 3, wide("361000")?)?)?
  # A wake that crashes before completion cannot erase the last acknowledgment.
  assert(load_filing(path, key, scope)?.accepted == 2)
  assert(next.minimum_slot == wide("80")?)
  case finish_filing(path, key, next, wide("361001")?, 1, filing_pending(wide("79")?)?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let paid = FilingObservation {
    status: "settled",
    context_slot: wide("90")?,
    finder: repeated(7, 32)?,
    units: wide("18446744073709551615")?
  }
  finish_filing(path, key, next, wide("361002")?, 1, paid)?
  assert(claim_filing(path, key, scope, repeated(4, 32)?, 8, wide("99999999")?)? == None)
  let terminal = load_filing(path, key, scope)?
  assert(terminal.observation.units == wide("18446744073709551615")?)
  assert(Bytes.secure_equals(terminal.observation.finder, repeated(7, 32)?))
  assert(!Bytes.secure_equals(load_blob(path, "fork-filing/v1")?, repeated(7, 32)?))
  # A new judge/proof identity starts separately; stale completions cannot cross it.
  let other = required(claim_filing(path,
    key,
    repeated(9, 32)?,
    repeated(4, 32)?,
    0,
    wide("99999999")?)?)?
  case finish_filing(path, key, next, wide("99999999")?, 1, paid) do
    Err(error) -> assert(error == "filing_claim_superseded")
    Ok(_) -> assert(false)
  end
  case finish_filing(path, key, other, wide("1")?, 0, filing_pending(wide("0")?)?) do
    Err(error) -> assert(error == "invalid_filing_clock")
    Ok(_) -> assert(false)
  end
  File.delete(path)?
  Ok(true)
end

test("encrypted filing state preserves retry budgets, receipt finality and stale-completion fences") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn race_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("filing-race")?
  ensure_schema(path)?
  let results = Job.map([0, 1, 2, 3, 4, 5, 6, 7], fn(_) do attempt(path, wide("1000")?) end)
  let claims = for result in results do
    result??
  end
  assert(List.length(List.filter(claims, fn(value) do value != None end)) == 1)
  let before = load_blob(path, "fork-filing/v1")?
  case claim_filing(path,
    key,
    repeated(9, 32)?,
    repeated(2, 32)?,
    3,
    wide("18446744073709551615")?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(before, load_blob(path, "fork-filing/v1")?))
  store_updated_session(path, "fork-filing/v1", Bytes.from_utf8("corrupt"))?
  case attempt(path, wide("1000000")?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  File.delete(path)?
  Ok(true)
end

test("simultaneous filing wakes claim once and corruption or overflow cannot reset the budget") do
  case race_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
