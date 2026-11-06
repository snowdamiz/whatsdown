from Tests.BackupArchiveContentViewFixture import (
  content_view_overview_proof,
  content_view_literal_proof,
  content_view_chunk_proof,
  content_view_budget_proof,
  content_view_refusal_proof
)

test("MCA1 overview keeps authenticated message and per-file omission counters distinct") do
  assert(content_view_overview_proof())
end

test("MCA1 page matches independent slot token and sparse legacy ordinal association") do
  assert(content_view_literal_proof())
end

test("MCA1 selected chunks preserve64KiB boundaries and reject stale or aliased selectors") do
  assert(content_view_chunk_proof())
end

test("MCA1 pages budget full UTF8 slot framing and advance at maximum record sizes") do
  assert(content_view_budget_proof())
end

test("MCA1 views retain finished cursors and reject malformed legacy and invalid page requests") do
  assert(content_view_refusal_proof())
end
