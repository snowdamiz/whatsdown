from Mobile.ForkFilingPins import native_filing_pin_frame, require_filing_pin_frame

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  assert(Test.set_push_token(Bytes.from_utf8("unrelated-resource"), Bytes.from_utf8("present")))
  # The Test host reports an unknown selector as a platform input error.
  # Production's distinct NotFound callback is covered by the native fixture.
  assert(Result.is_err(native_filing_pin_frame()))
  let absent = Bytes.empty()
  assert(Result.is_err(require_filing_pin_frame(absent)))
  let selector = Bytes.from_utf8("messenger/network-counter/v1")
  assert(Test.set_push_token(selector, Bytes.empty()))
  assert(Result.is_err(native_filing_pin_frame()))
  assert(Result.is_err(require_filing_pin_frame(absent)))
  let captured = Bytes.from_utf8("captured native pins")
  assert(Test.set_push_token(selector, captured))
  assert(native_filing_pin_frame()? == captured)
  require_filing_pin_frame(captured)?
  assert(Test.set_push_token(selector, Bytes.from_utf8("replacement native pins")))
  assert(Result.is_err(require_filing_pin_frame(captured)))
  Ok(true)
end

test("native filing rejects failed or empty pin resources and retires a replaced capture") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
