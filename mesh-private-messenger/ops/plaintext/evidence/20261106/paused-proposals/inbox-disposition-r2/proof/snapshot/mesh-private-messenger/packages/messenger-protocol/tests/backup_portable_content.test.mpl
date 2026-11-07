from Tests.BackupPortableContentFixture import (
  portable_content_legacy_proof,
  portable_content_creation_proof,
  portable_content_policy_proof,
  portable_content_minimum_proof
)
from Tests.BackupPortableContentFixture import (
  portable_content_independent_proof,
  portable_content_authenticated_refusal_proof,
  portable_content_maximum_proof
)

test("generic portable reader preserves exact independent v1 and v2 text literals") do
  assert(portable_content_legacy_proof())
end

test("typed MCA1 creation binds actual owner ID time and file bytes without widening old reader") do
  assert(portable_content_creation_proof())
end

test("portable MCA1 authenticates allow omissions and refuses omitted slots under strict policy") do
  assert(portable_content_policy_proof())
end

test("portable reader retains293 text minimum and accepts319 MCA1 minimum") do
  assert(portable_content_minimum_proof())
end

test("portable MCA1 opens independent authenticated literals and preserves text-only API refusal") do
  assert(portable_content_independent_proof())
end

test("portable MCA1 refuses fully reauthenticated identity hash policy counter and schema faults") do
  assert(portable_content_authenticated_refusal_proof())
end

test("portable MCA1 seals restores exact16MiB and both chunk boundaries while refusing one extra") do
  assert(portable_content_maximum_proof())
end
