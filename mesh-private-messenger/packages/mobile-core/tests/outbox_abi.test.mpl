from Mobile.OutboxNetwork import native_outbox_drain
from MobileCore import create_account_export, erase_account_export
from Mobile.Codec import mobile_vector, mobile_join
from Mobile.CreditState import pack_credit_parts
from Tests.Support import database_path, install_security_config

fn frame(path :: Bytes, mode :: Bytes) -> Bytes!String do
  mobile_join([mobile_vector(path)?, mobile_vector(mode)?], 0, Bytes.empty())
end

fn invalid() -> Result<(), String> do
  let path = Bytes.from_utf8("/native/morse.db")
  let valid = frame(path, Bytes.from_hex("00")?)?
  let invalid = [
    Bytes.empty(),
    path,
    frame(Bytes.empty(), Bytes.from_hex("00")?)?,
    frame(Bytes.from_utf8("/native/\0morse.db"), Bytes.from_hex("00")?)?,
    frame(Bytes.from_hex("ff")?, Bytes.from_hex("00")?)?,
    frame(path, Bytes.empty())?,
    frame(path, Bytes.from_hex("0000")?)?,
    frame(path, Bytes.from_hex("02")?)?,
    Bytes.concat(valid, Bytes.from_hex("00")?)?,
    frame(Bytes.from_utf8(String.repeat("x", 4097)), Bytes.from_hex("00")?)?,
    pack_credit_parts([path, Bytes.from_hex("00")?])?
  ]
  for input in invalid do
    case native_outbox_drain(input) do
      Ok(_) -> assert(false)
      Err(error) -> assert(error != "secure_storage_unavailable"
        && error != "network_configuration_required")
    end
  end
  Ok(nil)
end

test("outbox ABI rejects malformed, trailing, counted and invalid mode inputs before native custody or HTTP") do
  case invalid() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn empty_queue() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("outbox_abi")?
  create_account_export(mobile_join([
      mobile_vector(Bytes.from_utf8(path))?,
      mobile_vector(Bytes.from_utf8("alice"))?
    ],
    0,
    Bytes.empty())?)?
  let signing = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture key")
  end
  let witness_a = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture key")
  end
  let witness_b = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture key")
  end
  let delivery = case Crypto.x25519_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture key")
  end
  assert(install_security_config(signing.public_key.bytes,
    witness_a.public_key.bytes,
    witness_b.public_key.bytes,
    delivery.public_key.bytes,
    8))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("2\n1\nhttp://127.0.0.1:20799\nhttp://127.0.0.1:20899\nhttp://127.0.0.1:20999\nws://127.0.0.1:20999/v1/mailbox/stream\n8")))
  let output = native_outbox_drain(frame(Bytes.from_utf8(path), Bytes.from_hex("00")?)?)?
  assert(Bytes.to_hex(output) == "0000000600000004014f4258000000010000000002000000000002000000000004000000000000000400000000")
  erase_account_export(Bytes.from_utf8(path))?
  File.delete(path)?
  Ok(nil)
end

test("empty outbox emits the exact typed six-field golden frame without any HTTP") do
  case empty_queue() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
