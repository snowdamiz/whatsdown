# Canonical membership IDs only; database foreign keys retain their original
# positive BIGINT IDs. Solana batches keep the legacy low half. Lightning
# batches occupy the high half, so equal IDs from the two sequences never alias.
pub fn credit_burn_source_id(source :: Int, batch_id :: U64) -> U64!String do
  if (source != 0 && source != 1)
    || batch_id == U64.parse("0")?
    || U64.compare(batch_id, U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_credit_burn_source")
  end
  if source == 0 do
    Ok(batch_id)
  else
    U64.add(U64.parse("9223372036854775808")?, batch_id)
  end
end

pub struct CreditBurnSource do
  source :: Int
  batch_id :: U64
  week :: U64
end deriving(Eq)

fn identity_order(a :: CreditBurnSource, b :: CreditBurnSource) -> Int do
  if a.source != b.source do
    a.source - b.source
  else
    U64.compare(a.batch_id, b.batch_id)
  end
end

fn age_order(a :: CreditBurnSource, b :: CreditBurnSource) -> Int do
  let weeks = U64.compare(a.week, b.week)
  if weeks == 0 do
    identity_order(a, b)
  else
    weeks
  end
end

# Each source query supplies at most 64 locked rows. Select by original week
# first so the low-half namespace cannot continually crowd out older BTC
# outputs, then restore the canonical order used by the existing handoff hash.
pub fn select_credit_burn_sources(candidates :: List<CreditBurnSource>) -> List<CreditBurnSource>!String do
  if List.length(candidates) > 128 do
    return Err("credit_burn_candidates_unbounded")
  end
  let valid = for candidate in candidates do
    credit_burn_source_id(candidate.source, candidate.batch_id)?
    candidate
  end
  let ordered = List.sort(valid, identity_order)
  for index in 1..List.length(ordered) do
    if identity_order(List.get(ordered, index - 1), List.get(ordered, index)) == 0 do
      return Err("duplicate_credit_burn_source")
    end
  end
  Ok(List.sort(List.take(List.sort(ordered, age_order), 64), identity_order))
end
