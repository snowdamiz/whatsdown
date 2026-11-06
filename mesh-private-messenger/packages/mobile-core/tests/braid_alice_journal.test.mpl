from Tests.BraidAliceJournalFixture import (
  first_send_and_recovery,
  account_source_races,
  competing_prepares,
  lost_reply_fresh_actor,
  authenticated_storage_refusals,
  commit_failure_boundaries,
  actual_authentication_boundaries
)

test("C1 Alice first real header commit and exact recovery") do
  first_send_and_recovery()?
  Ok(nil)
end

test("C1 Alice original account session history cursor and outbox sources fence races") do
  account_source_races()?
  Ok(nil)
end

test("C1 Alice two prepared header actors commit one exact generation") do
  competing_prepares()?
  Ok(nil)
end

test("C1 Alice committed lost reply recovers exact ciphertext in a fresh actor") do
  lost_reply_fresh_actor()?
  Ok(nil)
end

test("C1 Alice authenticated metadata typed key and pending component refusals never fall back") do
  authenticated_storage_refusals()?
  Ok(nil)
end

test("C1 Alice precommit full outbox and replacement failures publish no partial generation") do
  commit_failure_boundaries()?
  Ok(nil)
end

test("C1 Alice real HE valid internal MAC failure preserves responder terminal behavior") do
  actual_authentication_boundaries()?
  println("C1_ALICE_HEADER_COORDINATOR_COMPLETE")
  Ok(nil)
end
