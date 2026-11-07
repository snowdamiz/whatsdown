from Tests.SpqrStoreFixture import (
  literal_store_contexts,
  real_store_roundtrip,
  store_binding_refusals
)

test("C1 SPQR store literal role24/25 contexts include complete bounded metadata") do
  assert(case literal_store_contexts() do
    Ok(_) -> true
    Err(_) -> false
  end)
end

test("C1 real output-consumed SPQR restores both maps and agrees with independent peer") do
  assert(case real_store_roundtrip() do
    Ok(_) -> true
    Err(_) -> false
  end)
end

test("C1 SPQR store refuses substituted components and reseals both maps for new descriptor") do
  assert(case store_binding_refusals() do
    Ok(_) -> true
    Err(_) -> false
  end)
  println("C1_SPQR_STORE_EXECUTED")
end
