from Mobile.NetworkCounterPins import decode_network_counter_pins
from Mobile.NetworkCounter import (
  read_network_counter,
  network_counter_output,
  refresh_network_counter
)
from Mobile.NetworkCounterState import network_counter_keys
from Transparency.Config import decode_security_config

fn proof(input :: String) -> Bytes!String do
  let data = Json.parse(input)?
  let security = decode_security_config(Bytes.from_utf8(Json.as_string(Json.object_get(data,
    "security")?)?))?
  let pins = decode_network_counter_pins(Bytes.from_utf8(Json.as_string(Json.object_get(data,
      "pins")?)?),
    security)?
  let checked = U64.parse(Json.as_string(Json.object_get(data, "checked_at")?)?)?
  if Json.get(input, "action") == "refresh" do
    let path = Json.as_string(Json.object_get(data, "database")?)?
    let key = case StorageKey.file(Json.as_string(Json.object_get(data, "key_directory")?)?) do
      Err(_) -> return Err("fixture_storage_key")
      Ok(value) -> value
    end
    let result = refresh_network_counter(path, pins, key, checked)
    Secret.destroy(key)
    result
  else
    let value = read_network_counter(pins, pins.minimum_slot, checked)?
    network_counter_output(pins, value, checked)
  end
end

fn run() -> String!String do
  let args = Env.args()
  Bytes.to_utf8(proof(File.read(List.get(args, 1))?)?)
end

fn main() do
  case run() do
    Err(error) -> do
      IO.eprintln(error)
      Process.exit(1)
    end
    Ok(value) -> println(value)
  end
end
