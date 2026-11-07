from Tests.HeaderRoutingFixture import capacity_and_progress, expiry_and_churn, malformed

test("full unauthenticated cursor queue preserves admitted progress across cold reopen and does not impose4096 read ceiling") do
  assert(Result.unwrap_or(capacity_and_progress(), false))
end

test("deterministic idle and absolute cursor leases reclaim capacity; packet and profile/index churn cannot renew original lease") do
  assert(Result.unwrap_or(expiry_and_churn(), false))
end

test("strict cursor codec rejects duplicate IDs, trailing bytes, invalid offsets and future service ticks; writer admission never changes legacy readability") do
  assert(Result.unwrap_or(malformed(), false))
end
