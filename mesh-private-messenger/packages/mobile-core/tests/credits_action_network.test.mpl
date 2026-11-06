from Mobile.Credits import native_credit_action_continue, apply_credit_action_response
from Mobile.CreditState import pack_credit_parts
from Credits.ActionWire import CreditActionReceipt, encode_credit_action_receipt
from Tests.Support import repeated

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let id = repeated(41, 32)?
  # A response to another pending operation must be refused before touching
  # that operation's journal, even when the wire is otherwise well formed.
  let response = encode_credit_action_receipt(CreditActionReceipt {
    operation_id: repeated(42, 32)?,
    action_sha256: repeated(43, 32)?,
    frame_sha256: repeated(44, 32)?,
    effect_id: repeated(45, 32)?,
    applied_at: U64.parse("1")?,
    result: repeated(1, 1)?,
    signature: repeated(46, 64)?
  })?
  case apply_credit_action_response("/nonexistent/credit-network.db", id, response) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "credit_response_operation_mismatch")
  end
  for fields in [
    [Bytes.from_utf8("/nonexistent/credit-network.db"), id, repeated(3, 1)?],
    [Bytes.from_utf8("/nonexistent/credit-network.db"), id, Bytes.empty()],
    [Bytes.from_utf8("/nonexistent/credit-network.db"), repeated(41, 31)?, repeated(0, 1)?],
    [Bytes.from_utf8("/nonexistent/credit-network.db"), id, repeated(0, 1)?, Bytes.empty()]
  ] do
    assert(Result.is_err(native_credit_action_continue(pack_credit_parts(fields)?)))
  end
  Ok(true)
end

test("native credit action transport binds the response to its requested journal operation") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
