##! Draft UNRUN. Actual HE and local encrypted SQLite only; no native gate.
from Tests.BraidJournalFixture import (
  actual_he_boundary,
  exact_pending_output,
  terminal_lifecycle,
  guarded_sources,
  competing_prepared_sends,
  unknown_reply_actor_restart,
  replacement_cannot_be_terminated
)

test("C1 ignores unauthenticated malformed wrong-scope and wrong-epoch carriers without a durable receive") do
  actual_he_boundary()?
  Ok(nil)
end

test("C1 accepted HE header and later explicit pending send have separate atomic outcomes") do
  exact_pending_output()?
  Ok(nil)
end

test("C1 internal MAC fatal commits accepted HE and terminal state only once") do
  terminal_lifecycle()?
  Ok(nil)
end

test("C1 prepared send refuses every captured source mutation and precommit abort leaves no partial rows") do
  guarded_sources()?
  Ok(nil)
end

test("C1 two actually prepared send racers have one CAS winner") do
  competing_prepared_sends()?
  Ok(nil)
end

test("C1 committed unknown reply recovers exact pending ciphertext in a fresh actor") do
  unknown_reply_actor_restart()?
  Ok(nil)
end

test("C1 stale terminal preparation cannot erase or terminate a replacement account") do
  replacement_cannot_be_terminated()?
  println("C1_BRAID_MOBILE_ACCEPTANCE_COMPLETE")
  Ok(nil)
end
