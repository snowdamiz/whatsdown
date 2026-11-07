##! Test-first complete-carrier controls, executed only with an explicit lane.
##! Host complete-carrier kernel only, not authenticated transport/chunking.
from Tests.BraidBilateralFixture import (
  two_epochs_and_unique_outputs,
  vector_refusal_and_exact_retry,
  ciphertext_shape_and_authenticated_terminal,
  typed_key_and_continuation_recovery,
  stored_identity_and_component_refusals,
  recovery_no_resampling_and_epoch_limits
)

test("C1 bilateral E1 and role-reversed E2 agree with one affine output each") do
  assert(case two_epochs_and_unique_outputs() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 complete-vector validation refuses before Ct2 and preserves exact retry") do
  assert(case vector_refusal_and_exact_retry() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 complete-ciphertext shape refusal differs from admitted internal MAC fatal") do
  assert(case ciphertext_shape_and_authenticated_terminal() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 bilateral typed epoch key and continuation restore through later agreement") do
  assert(case typed_key_and_continuation_recovery() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 bilateral storage binds role substate scope epoch and exact public components") do
  assert(case stored_identity_and_component_refusals() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 bilateral pending recovery never samples or emits again and epoch cannot wrap") do
  assert(case recovery_no_resampling_and_epoch_limits() do
    Ok(true) -> true
    _ -> false
  end)
  println("C1_BILATERAL_COMPLETE_KERNEL_EXECUTED")
end
