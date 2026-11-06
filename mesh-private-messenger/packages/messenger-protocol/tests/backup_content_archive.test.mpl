from Tests.BackupContentArchiveFixture import (
  content_archive_literal_proof,
  content_archive_policy_proof,
  content_archive_association_proof,
  content_archive_metadata_proof,
  content_archive_count_proof,
  content_archive_maximum_proof,
  content_archive_legacy_proof
)

fn content_fixture_observe(value :: Bool) -> Bool do
  declassify(value,
    "TEST ONLY authored synthetic content-archive literal equality and finite refusal predicates; no real history attachment metadata bytes keys or arbitrary errors are disclosed")
end

test("content archive matches independent nested literal and legacy empty-ID association") do
  assert(content_fixture_observe(Result.unwrap_or(content_archive_literal_proof(), false)))
end

test("content archive validates distinct message and per-file omission policy counts") do
  assert(content_fixture_observe(Result.unwrap_or(content_archive_policy_proof(), false)))
end

test("content archive refuses missing duplicate orphan and noncanonical ordinal slots") do
  assert(content_fixture_observe(Result.unwrap_or(content_archive_association_proof(), false)))
end

test("content archive binds complete file bytes and bounded metadata without path authority") do
  assert(content_fixture_observe(Result.unwrap_or(content_archive_metadata_proof(), false)))
end

test("content archive accepts4096parts and ten per-message while refusing one extra") do
  assert(content_fixture_observe(Result.unwrap_or(content_archive_count_proof(), false)))
end

test("content archive accepts exact16MiB independent hash and refuses one extra byte") do
  assert(content_fixture_observe(Result.unwrap_or(content_archive_maximum_proof(), false)))
end

test("content archive new syntax does not alias unchanged legacy text syntax") do
  assert(content_fixture_observe(Result.unwrap_or(content_archive_legacy_proof(), false)))
end
