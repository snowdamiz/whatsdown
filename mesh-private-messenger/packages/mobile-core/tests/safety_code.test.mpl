import File
from Mobile.History import decode_conversation_summary
from Mobile.Types import ConversationSummary
from MobileCore import (
  create_account_export,
  list_conversations_export,
  receive_initial_export,
  safety_code_check_export,
  safety_code_export,
  safety_number_export,
  start_conversation_export
)
from Tests.GroupLifecycleWire import acknowledge, group_vectors
from Tests.Support import database_path

fn ensure(value :: Bool, error :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(error)
  end
end

fn text(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

fn check(path :: String, peer :: Bytes, code :: Bytes) -> String!String do
  let outcome = safety_code_check_export(group_vectors([text(path), peer, code])?)?
  case Bytes.to_utf8(outcome) do
    Err(_) -> Err("check outcome is not text")
    Ok(value)
  end
end

fn verified(path :: String) -> Bool!String do
  Ok(decode_conversation_summary(list_conversations_export(text(path))?)?.verified)
end

fn proof() -> Bool!String do
  let alice_path = database_path("safety-code-alice")?
  let bob_path = database_path("safety-code-bob")?
  let alice_profile = create_account_export(group_vectors([text(alice_path), text("alice")])?)?
  let bob_profile = create_account_export(group_vectors([text(bob_path), text("bob")])?)?
  let initial = start_conversation_export(group_vectors([
    text(alice_path),
    bob_profile,
    text("hello bob")
  ])?)?
  acknowledge(alice_path, [initial], 0)?
  receive_initial_export(group_vectors([text(bob_path), initial])?)?
  let alice_code = safety_code_export(group_vectors([text(alice_path), bob_profile])?)?
  let bob_code = safety_code_export(group_vectors([text(bob_path), alice_profile])?)?
  let safety = safety_number_export(group_vectors([text(alice_path), bob_profile])?)?
  let code_text = case Bytes.to_utf8(alice_code) do
    Err(_) -> Err("code is not text")
    Ok(value)
  end?
  let safety_text = case Bytes.to_utf8(safety) do
    Err(_) -> Err("safety number is not text")
    Ok(value)
  end?
  ensure(String.starts_with(code_text, "morse-verify:1:")
      && String.ends_with(code_text, safety_text),
    "the code does not carry the safety number")?
  ensure(check(bob_path, alice_profile, text("not a code"))? == "invalid",
    "garbage passed as a code")?
  # Bob's own code, scanned on his own phone, is for the other side.
  ensure(check(bob_path, alice_profile, bob_code)? == "wrong_contact",
    "a code for another chat matched")?
  ensure(!verified(bob_path)?, "a failed scan verified the chat")?
  ensure(check(bob_path, alice_profile, alice_code)? == "verified", "alice's code did not verify")?
  ensure(verified(bob_path)?, "a matching scan did not mark the chat verified")?
  # The same code with another number: the chat is no longer marked verified.
  let altered_tail = if String.ends_with(code_text, "0") do
    "1"
  else
    "0"
  end
  let altered = String.slice(code_text, 0, String.length(code_text) - 1) <> altered_tail
  ensure(check(bob_path, alice_profile, text(altered))? == "mismatch", "a changed number matched")?
  ensure(!verified(bob_path)?, "a mismatched scan left the chat verified")?
  File.delete(alice_path)?
  File.delete(bob_path)?
  Ok(true)
end

test("a scanned safety code verifies only the matching chat and number") do
  assert(Test.install_in_memory_secure_store())
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
