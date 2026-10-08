from Tests.Support import (
  fixture_checkpoint,
  fixture_leaves,
  fixture_now,
  fixture_signer,
  stub_file,
  stub_reset
)
from Transparency.Merkle import TransparencyCheckpoint
from Transparency.Wire import encode_checkpoint
from Witness.State import (
  witness_clear_halt,
  witness_halt,
  witness_halted,
  witness_state_read,
  witness_state_write
)

fn holds(path :: String, expected :: TransparencyCheckpoint) -> Bool!String do
  case witness_state_read(path)? do
    None -> Ok(false)
    Some(value) -> Ok(Bytes.secure_equals(encode_checkpoint(value)?, encode_checkpoint(expected)?))
  end
end

fn compare_and_swap_proof() -> Bool!String do
  stub_reset("state-cas")
  let path = stub_file("state-cas", "state")
  let log = fixture_signer(91)?
  let leaves = fixture_leaves("cas", 3)?
  let now = fixture_now()
  let first = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    1,
    List.take(leaves, 1),
    None,
    now)?
  let second = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    2,
    List.take(leaves, 2),
    Some(first),
    now + 1)?
  let third = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    3,
    leaves,
    Some(second),
    now + 2)?
  assert(witness_state_read(path)? == None)
  witness_state_write(path, None, first)?
  assert(holds(path, first)?)
  # A second instance that still thinks the state is empty cannot overwrite it.
  assert(witness_state_write(path,
    None,
    third) == Err("witness state changed underneath this instance"))
  witness_state_write(path, Some(first), second)?
  # An instance that read the first checkpoint before the second was committed
  # loses the race and must not sign.
  assert(witness_state_write(path,
    Some(first),
    third) == Err("witness state changed underneath this instance"))
  assert(holds(path, second)?)
  witness_state_write(path, Some(second), third)?
  Ok(holds(path, third)?)
end

test("a file state is replaced only over the checkpoint this instance read") do
  case compare_and_swap_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("a halt marker sits beside the state until it is cleared") do
  stub_reset("state-halt")
  let path = stub_file("state-halt", "state")
  assert(witness_halted(path) == Ok(None))
  assert(witness_halt(path, "stale state") == Ok(nil))
  assert(witness_halted(path) == Ok(Some("stale state")))
  assert(witness_clear_halt(path) == Ok(nil))
  assert(witness_halted(path) == Ok(None))
end
