from Monitor.Config import MonitorConfig, monitor_configuration, monitor_configuration_for
from Monitor.Policy import MonitorPolicy
from Transparency.Config import WitnessPin, decode_security_config, encode_security_config

fn frame() -> Bytes do
  Bytes.from_utf8(String.join([
      "4",
      String.repeat("11", 32),
      String.repeat("22", 32),
      "8",
      "2",
      "2",
      "a #{String.repeat("01", 32)} Morse",
      "b #{String.repeat("02", 32)} Outside",
      "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb",
      "3",
      "https://one.example",
      "https://two.example",
      "https://three.example",
      "-",
      "2",
      "2",
      "2",
      "a #{String.repeat("01", 32)} Morse",
      "b #{String.repeat("02", 32)} Outside",
      String.repeat("1", 32),
      "morse-main"
    ],
    "\n"))
end

fn proof() -> Bool!String do
  let config = decode_security_config(frame())?
  let first = monitor_configuration("morse-main",
    "https://directory.example/",
    "/tmp/monitor.sqlite",
    [frame()])?
  assert(first.origin == "https://directory.example" && List.length(first.policies) == 1)
  let relay_frame = encode_security_config(%{config | version: 5, wire_version: 5})?
  let with_relays = monitor_configuration("morse-main",
    "https://directory.example",
    "/tmp/monitor.sqlite",
    [relay_frame, frame()])?
  assert(Bytes.secure_equals(first.identity, with_relays.identity))
  assert(List.length(with_relays.policies) == 2)
  let rotated_rpc = %{config |
    rpc_urls: ["https://four.example", "https://five.example", "https://six.example"]
  }
  let same = monitor_configuration("morse-main",
    "https://directory.example",
    "/tmp/monitor.sqlite",
    [encode_security_config(rotated_rpc)?])?
  assert(Bytes.secure_equals(first.identity, same.identity))
  let legacy_pins = %{config |
    legacy_witnesses: [
      %{List.get(config.legacy_witnesses, 0) |
        public_key: Bytes.from_hex(String.repeat("03", 32))?
      },
      %{List.get(config.legacy_witnesses, 1) | public_key: Bytes.from_hex(String.repeat("04", 32))?}
    ]
  }
  let legacy_frame = encode_security_config(legacy_pins)?
  let legacy = monitor_configuration_for("morse-main",
    "https://directory.example",
    "/tmp/legacy.sqlite",
    [legacy_frame],
    1)?
  assert(legacy.log_version == 1 && legacy.primary.log_version == 2)
  assert(Bytes.secure_equals(encode_security_config(legacy.primary)?, legacy_frame))
  assert(Bytes.to_hex(List.head(List.head(legacy.policies).witnesses).public_key) == String.repeat("03",
      32))
  assert(!Bytes.secure_equals(first.identity, legacy.identity))
  for name in ["morse-canary", ""] do
    case monitor_configuration(name,
      "https://directory.example",
      "/tmp/monitor.sqlite",
      [frame()]) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  for origin in [
    "http://directory.example",
    "https://directory.example/path",
    "https://user:password@directory.example"
  ] do
    case monitor_configuration("morse-main", origin, "/tmp/monitor.sqlite", [frame()]) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  let foreign = %{config | service_public_key: Bytes.from_hex(String.repeat("44", 32))?}
  case monitor_configuration("morse-main",
    "https://directory.example",
    "/tmp/monitor.sqlite",
    [frame(), encode_security_config(foreign)?]) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("monitor pins a single log identity across supported policies and RPC rotation") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
