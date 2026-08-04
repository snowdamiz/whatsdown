import File
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleMessages import exercise_group_message_boundary, exercise_linked_greeting
from Tests.GroupLifecycleRemove import exercise_group_removal
from Tests.GroupLifecycleSupport import group_account_fixture

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture() ?
  let group_id = create_group_with_bob(accounts) ?
  assert(exercise_linked_greeting(accounts, group_id) ?)
  assert(exercise_group_message_boundary(accounts, group_id) ?)
  assert(exercise_group_removal(accounts, group_id) ?)
  File.delete(accounts.alice_path) ?
  File.delete(accounts.linked_path) ?
  File.delete(accounts.bob_path) ?
  Ok(true)
end

test("mobile groups persist MLS state and fan out canonical suite-3 delivery") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
