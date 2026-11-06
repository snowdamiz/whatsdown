from Mobile.PushNetwork import native_push_intent, native_push_complete_with_endpoint
from Mobile.Push import push_intent, complete_push_action_with_config
from Mobile.Requests import parse_push_intent_request, parse_push_action_completion
from MobileCore import create_account_export, erase_account_export
from Mobile.Codec import mobile_join, mobile_vector, mobile_byte
from Tests.Support import database_path
from Tests.PushNetworkSupport import fields, intent, complete, config

actor provider(port :: Int) do
  HTTP.router()
    |> HTTP.on_post("/provider",
      fn(_) -> HTTP.response(200,
        "{\"data\":{\"expoPushToken\":\"ExpoPushToken[native-boundary]\"}}") end)
    |> HTTP.serve(port)
end

fn opaque_actions() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  config(20570)?
  let path = database_path("push_opaque")?
  create_account_export(fields([Bytes.from_utf8(path), Bytes.from_utf8("alice")])?)?
  let action = native_push_intent(intent(path, 1)?)?
  assert(Bytes.length(action) == 50 && Bytes.get(action, 0)? == 2)
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

fn false_network_ack() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  config(20571)?
  let _server = spawn(provider, 20571)
  Timer.sleep(100)
  let endpoint = "http://127.0.0.1:20571/provider"
  let path = database_path("push_false_ack")?
  create_account_export(fields([Bytes.from_utf8(path), Bytes.from_utf8("alice")])?)?
  let permission = push_intent(parse_push_intent_request(intent(path, 1)?)?)?
  let prime = complete_push_action_with_config(parse_push_action_completion(complete(path,
      permission,
      0)?)?,
    endpoint)?
  complete_push_action_with_config(parse_push_action_completion(complete(path, prime, 0)?)?,
    endpoint)?
  let bind = native_push_intent(intent(path, 0)?)?
  assert(Bytes.get(bind, 4)? == 3)
  assert(Result.is_err(native_push_complete_with_endpoint(complete(path, bind, 0)?, endpoint)))
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

test("push actions expose only bounded opaque tickets") do
  case opaque_actions() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("a JS success report cannot acknowledge a network push action") do
  case false_network_ack() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn replacement_ticket() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  config(20570)?
  let path = database_path("push_ticket_identity")?
  create_account_export(fields([Bytes.from_utf8(path), Bytes.from_utf8("alice")])?)?
  let first = native_push_intent(intent(path, 1)?)?
  erase_account_export(Bytes.from_utf8(path))?
  create_account_export(fields([Bytes.from_utf8(path), Bytes.from_utf8("bob")])?)?
  let second = native_push_intent(intent(path, 1)?)?
  assert(!Bytes.secure_equals(first, second))
  assert(Result.is_err(native_push_complete_with_endpoint(complete(path, first, 0)?,
    "http://127.0.0.1:20570/provider")))
  assert(Bytes.secure_equals(native_push_intent(intent(path, 0)?)?, second))
  let next = native_push_complete_with_endpoint(complete(path, second, 0)?,
    "http://127.0.0.1:20570/provider")?
  assert(Bytes.get(next, 4)? == 2)
  assert(Result.is_err(native_push_complete_with_endpoint(complete(path, second, 0)?,
    "http://127.0.0.1:20570/provider")))
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

test("push tickets cannot cross account replacement or be completed twice") do
  case replacement_ticket() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
