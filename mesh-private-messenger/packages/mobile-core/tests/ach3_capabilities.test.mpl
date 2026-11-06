import File
from MobileCore import create_account_export, create_link_request_export
from Mobile.Codec import mobile_join, mobile_vector
from Protocol.DirectoryWire import decode_device_link_request
from Protocol.Capabilities import supports_ach3
from Transport.Packet import decode_client_profile
from Tests.Support import database_path

fn fresh_account_capabilities() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("ach3-new-account")?
  let request = mobile_join([
      mobile_vector(Bytes.from_utf8(path))?,
      mobile_vector(Bytes.from_utf8("alice"))?
    ],
    0,
    Bytes.empty())?
  let profile = decode_client_profile(create_account_export(request)?)?
  assert(supports_ach3(profile.credential.capabilities))
  assert(U64.compare(profile.credential.capabilities, U64.parse("3")?) == 0)
  File.delete(path)?
  Ok(true)
end

fn fresh_link_capabilities() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("ach3-new-link")?
  let encoded = create_link_request_export(Bytes.from_utf8(path))?
  let pending = case decode_device_link_request(encoded) do
    Err(_) -> return Err("link request failed")
    Ok(value) -> value
  end
  assert(supports_ach3(pending.capabilities))
  assert(U64.compare(pending.capabilities, U64.parse("3")?) == 0)
  assert(Bytes.secure_equals(create_link_request_export(Bytes.from_utf8(path))?, encoded))
  File.delete(path)?
  Ok(true)
end

test("new account credentials advertise authenticated baseline and ACH3 support") do
  case fresh_account_capabilities() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("new link requests advertise ACH3 explicitly and retries preserve the exact request") do
  case fresh_link_capabilities() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
