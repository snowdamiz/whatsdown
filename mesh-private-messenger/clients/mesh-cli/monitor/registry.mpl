from Monitor.Policy import MonitorPolicy
from Transparency.Config import valid_witness_id, witness_set_id
from Transparency.Merkle import WitnessKey

fn keys(document :: String) -> List<WitnessKey>!String do
  if String.length(document) > 524288 do
    return Err("monitor_registry_too_large")
  end
  let values = Json.object_get(Json.parse(document)?, "witnesses")?
  let count = Json.array_length(values)?
  if count > 1024 do
    return Err("monitor_registry_too_large")
  end
  let parsed = for index in 0..count do
    let item = Json.array_get(values, index)?
    let id = Json.as_string(Json.object_get(item, "witness_id")?)?
    let encoded = Json.as_string(Json.object_get(item, "public_key")?)?
    let status = Json.as_string(Json.object_get(item, "status")?)?
    let key = Bytes.from_hex(encoded)?
    if !valid_witness_id(id)
      || Bytes.length(key) != 32
      || Bytes.to_hex(key) != encoded
      || (status != "shadow" && status != "pinned" && status != "retired") do
      return Err("invalid_monitor_registry")
    end
    WitnessKey { witness_id: id, public_key: key }
  end
  for index in 0..count do
    let key = List.get(parsed, index)
    for previous in 0..index do
      let other = List.get(parsed, previous)
      if key.witness_id == other.witness_id
        || Bytes.secure_equals(key.public_key, other.public_key) do
        return Err("invalid_monitor_registry")
      end
    end
  end
  Ok(parsed)
end

# The public registry announces no trusted key by itself. A rotation is
# accepted only when an explicitly installed monitor policy contains it.
pub fn registry_key_changes(previous :: String,
  current :: String,
  policies :: List<MonitorPolicy>) -> List<String>!String do
  if List.length(policies) < 1 || List.length(policies) > 16 do
    return Err("invalid_monitor_policies")
  end
  for policy in policies do
    witness_set_id(policy.witnesses, policy.threshold)?
  end
  let before = if previous == "" do
    []
  else
    keys(previous)?
  end
  let observed = keys(current)?
  let pins = List.flat_map(policies, fn(policy) do policy.witnesses end)
  let changed = for key in observed when !List.any(pins,
    fn(pin) do pin.witness_id == key.witness_id
      && Bytes.secure_equals(pin.public_key, key.public_key) end)
    && (List.any(pins, fn(pin) do pin.witness_id == key.witness_id end)
      || List.any(before,
        fn(old) do old.witness_id == key.witness_id
          && !Bytes.secure_equals(old.public_key, key.public_key) end)) do
    key.witness_id
  end
  let missing = for old in before when !List.any(observed,
    fn(key) do key.witness_id == old.witness_id end) do
    old.witness_id
  end
  Ok(changed ++ missing)
end
