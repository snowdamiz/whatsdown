from Mobile.BackupArchive import (
  d4_publication_prepare_proof,
  d4_publication_commit_proof,
  d4_publication_clock_pair_proof
)
from Tests.BackupContentPublicationFixture import publication_fixture, publication_authored_content
from Tests.BackupArchiveFixture import d4_core_cleanup
from Backups.ContentArchive import BackupAttachmentPolicy

fn publication_prepare_case() -> Plaintext<Bool>!String do
  let fixture = publication_fixture()?
  let raw = case publication_authored_content(fixture, RequireArchiveAttachments) do
    Err(error) -> Err(error)
    Ok(authored) -> d4_publication_prepare_proof(fixture.path,
      fixture.public_profile, authored, [fixture.source_label])
  end
  let cleanup = d4_core_cleanup(fixture)
  cleanup?
  raw
end

# Pure closed outcome over the COMPLETE Result. No case or private condition
# surrounds the sole test-only declassification at the public test entry.
fn publication_prepare_outcome(raw :: Result<Plaintext<Bool>, String>) -> Plaintext<Int> do
  case raw do
    Err(_) -> 0
    Ok(value) -> if value do
      2
    else
      1
    end
  end
end

test("pending content preparation binds authored MCA1 bundle and original descriptor to genuine held custody") do
  let raw = publication_prepare_case()
  let protected = publication_prepare_outcome(raw)
  let outcome = declassify(protected,
    "TEST ONLY closed synthetic pending preparation setup refusal semantic false or success; no real code keys identifiers metadata content or raw errors are released")
  assert(outcome != 0)
  assert(outcome == 2)
end

fn publication_commit_case() -> Plaintext<Bool>!String do
  let fixture = publication_fixture()?
  let raw = case publication_authored_content(fixture, RequireArchiveAttachments) do
    Err(error) -> Err(error)
    Ok(authored) -> d4_publication_commit_proof(fixture.path,
      fixture.public_profile, authored, [fixture.source_label])
  end
  let cleanup = d4_core_cleanup(fixture)
  cleanup?
  raw
end

fn publication_commit_outcome(raw :: Result<Plaintext<Bool>, String>) -> Plaintext<Int> do
  case raw do
    Err(_) -> 0
    Ok(value) -> if value do
      2
    else
      1
    end
  end
end

test("pending content writer publishes an authenticated pair that fresh custody resumes byte exactly") do
  let raw = publication_commit_case()
  let protected = publication_commit_outcome(raw)
  let outcome = declassify(protected,
    "TEST ONLY closed synthetic pending publication setup refusal semantic false or exact pair and ciphertext resume success; no real code keys identifiers metadata content or raw errors are released")
  assert(outcome != 0)
  assert(outcome == 2)
end

fn publication_clock_case() -> Plaintext<Bool>!String do
  let captured = U64.parse("1000")?
  let fresh = U64.parse("10000")?
  let expires = Some(U64.parse("6000")?)
  let held = U64.parse("5000")?
  let earlier = U64.parse("4000")?
  let rolled = U64.parse("4500")?
  let later = U64.parse("5500")?
  let expired = U64.parse("6000")?
  let values = [
    d4_publication_clock_pair_proof(captured, fresh, expires, held, earlier, rolled, false),
    d4_publication_clock_pair_proof(captured, fresh, expires, held, held, held, true),
    d4_publication_clock_pair_proof(captured, fresh, expires, held, held, later, true),
    d4_publication_clock_pair_proof(captured, fresh, expires, held, later, held, false),
    d4_publication_clock_pair_proof(captured, fresh, expires, held, later, expired, false),
    d4_publication_clock_pair_proof(captured, fresh, expires, held, expired, expired, false),
    d4_publication_clock_pair_proof(captured, fresh, None, held, earlier, rolled, false),
    d4_publication_clock_pair_proof(captured, fresh, None, held, fresh, fresh, true),
    d4_publication_clock_pair_proof(captured, fresh, None, held, fresh, U64.parse("10001")?, false),
    d4_publication_clock_pair_proof(captured, fresh, None, held, U64.parse("999")?, captured, false)
  ]
  Ok(List.all(values, fn(value) -> value end))
end

test("pending content writer policy retains capture watermark strict expiry and precommit monotonicity") do
  let raw = publication_clock_case()
  let protected = publication_commit_outcome(raw)
  let outcome = declassify(protected,
    "TEST ONLY closed synthetic publication time policy setup refusal false or exact authored clock boundary predicates; no real clocks expiry metadata keys codes or content are released")
  assert(outcome != 0)
  assert(outcome == 2)
end
