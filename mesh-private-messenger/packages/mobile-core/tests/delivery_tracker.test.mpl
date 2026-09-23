import File
from Mobile.Delivery import DeliveryRecord, delivery_state, load_delivery, resolved_delivery, tracked_delivery
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Storage.Records import put_blobs
from Tests.Support import database_path, repeated

fn store(path :: String, writes ::(List<String>, List<Bytes>)) -> Result<(), String> do
  let (labels, blobs) = writes
  let database = case Sqlite.open(path) do
    Err(_) -> Err("database_open_failed")
    Ok(value)
  end?
  let result = put_blobs(database, labels, blobs, 0)
  Sqlite.close(database)
  result
end

fn state(path :: String, message :: Bytes) -> Int!String do
  let key = platform_key()?
  Ok(delivery_state(load_delivery(path, key)?, message))
end

fn settle(path :: String, envelope :: Bytes, accepted :: Bool) -> Result<(), String> do
  let key = platform_key()?
  store(path, resolved_delivery(path, key, envelope, accepted)?)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("delivery-tracker")?
  ensure_schema(path)?
  let key = platform_key()?
  let first = repeated(1, 16)?
  let second = repeated(2, 16)?
  let group = repeated(3, 32)?
  # A message waits while its envelopes do.
  store(path, tracked_delivery(path, key, first, [repeated(11, 16)?, repeated(12, 16)?])?)?
  assert(state(path, first)? == 1)
  assert(state(path, second)? == 0)
  # One device is gone, the other accepts: the message arrived, in either order.
  settle(path, repeated(11, 16)?, false)?
  assert(state(path, first)? == 1)
  settle(path, repeated(12, 16)?, true)?
  assert(state(path, first)? == 0)
  store(path, tracked_delivery(path, key, second, [repeated(21, 16)?, repeated(22, 16)?])?)?
  settle(path, repeated(21, 16)?, true)?
  # Reached one device while the other still waits: not pending any more.
  assert(state(path, second)? == 0)
  settle(path, repeated(22, 16)?, false)?
  assert(state(path, second)? == 0)
  # Delivered messages leave nothing behind.
  assert(List.length(load_delivery(path, key)?) == 0)
  # Refused everywhere: failed, and it stays failed.
  store(path, tracked_delivery(path, key, group, [repeated(31, 16)?, repeated(32, 16)?])?)?
  settle(path, repeated(31, 16)?, false)?
  assert(state(path, group)? == 1)
  settle(path, repeated(32, 16)?, false)?
  assert(state(path, group)? == 2)
  # An envelope nobody tracked, and a message with nothing addressed outward,
  # change nothing.
  settle(path, repeated(99, 16)?, false)?
  let (labels, _blobs) = tracked_delivery(path, key, first, List.new())?
  assert(List.length(labels) == 0)
  assert(List.length(load_delivery(path, key)?) == 1)
  File.delete(path)?
  Ok(true)
end

test("a message is pending, sent or failed by what happened to its envelopes") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
