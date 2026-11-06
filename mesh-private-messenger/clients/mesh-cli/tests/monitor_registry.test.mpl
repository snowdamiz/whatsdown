from Monitor.Registry import registry_key_changes
from Monitor.Policy import MonitorPolicy
from Transparency.Config import WitnessPin

fn registry(key :: String) -> String do
  "{\"witnesses\":[{\"witness_id\":\"a\",\"public_key\":\""
    <> String.repeat(key, 32)
    <> "\",\"status\":\"pinned\"}]}"
end

fn proof() -> Bool!String do
  let old = MonitorPolicy {
    threshold: 1,
    witnesses: [
      WitnessPin {
        witness_id: "a",
        public_key: Bytes.from_hex(String.repeat("11", 32))?,
        operator_label: "operator"
      }
    ]
  }
  let next = %{old |
    witnesses: [%{List.head(old.witnesses) | public_key: Bytes.from_hex(String.repeat("22", 32))?}]
  }
  assert(List.length(registry_key_changes("", registry("11"), [old])?) == 0)
  assert(registry_key_changes(registry("11"), registry("22"), [old])? == ["a"])
  assert(registry_key_changes("", registry("22"), [old])? == ["a"])
  assert(List.length(registry_key_changes(registry("11"), registry("22"), [old, next])?) == 0)
  assert(registry_key_changes(registry("11"), "{\"witnesses\":[]}", [old])? == ["a"])
  for invalid in ["{}", "{\"witnesses\":[{}]}", registry("XX")] do
    case registry_key_changes("", invalid, [old]) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  Ok(true)
end

test("monitor registry changes require an explicit supported key rotation") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
