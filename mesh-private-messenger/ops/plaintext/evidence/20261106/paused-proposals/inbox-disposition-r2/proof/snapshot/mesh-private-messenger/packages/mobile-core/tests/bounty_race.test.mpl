from Mobile.Bounty import bounty_state, set_bounty_enabled, commit_bounty_address, disclosable_fork
from Mobile.TransparencySafety import retain_fork, retained_fork
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated, append
from Tests.ForkFilingSupport import filing_fixture
from Transparency.Config import encode_security_config
from Transparency.Fork import decode_fork, encode_fork

fn await_file(path :: String, attempts :: Int) -> Bool do
  if File.exists(path) do
    case File.read(path) do
      Ok(value) -> if String.length(value) > 0 do
        return true
      end
      Err(_) -> nil
    end
  end
  if attempts == 0 do
    false
  else
    Timer.sleep(5)
    await_file(path, attempts - 1)
  end
end

fn contend(path :: String, index :: Int, wire :: Bytes, choosing :: Bool) -> Result<(), String> do
  let name = path
    <> ".#{if choosing do
      "choose"
    else
      "retain"
    end}.#{index}"
  let key = platform_key()?
  File.write(name <> ".ready", "ready")?
  if !await_file(path <> ".go", 1000) do
    return Err("race_start_timeout")
  end
  if choosing do
    let sdk = append(Bytes.write_uint_le(Int.to_string(index), 8)?, repeated(index + 71, 32)?)?
    commit_bounty_address(path, key, wire, sdk)?
    Ok(nil)
  else
    retain_fork(path, key, decode_fork(wire)?)
  end
end

actor contender(path :: String, index :: Int, wire :: Bytes, choosing :: Bool) do
  let name = path
    <> ".#{if choosing do
      "choose"
    else
      "retain"
    end}.#{index}"
  let result = contend(path, index, wire, choosing)
  let message = case result do
    Ok(_) -> "ok"
    Err(error) -> error
  end
  File.write(name <> ".done", message)
  nil
end

fn barrier(path :: String, choosing :: Bool) -> List<String>!String do
  let names = for index in 0..8 do
    path
      <> ".#{if choosing do
        "choose"
      else
        "retain"
      end}.#{index}"
  end
  for name in names do
    if !await_file(name <> ".ready", 1000) do
      return Err("race_worker_timeout")
    end
  end
  File.write(path <> ".go", "go")?
  let results = for name in names do
    if !await_file(name <> ".done", 1000) do
      return Err("race_finish_timeout")
    end
    let value = File.read(name <> ".done")?
    File.delete(name <> ".ready")?
    File.delete(name <> ".done")?
    value
  end
  File.delete(path <> ".go")?
  Ok(results)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let (sample, config) = filing_fixture()?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(config)?))
  let first = %{sample | finder: repeated(0, 32)?}
  let second = %{first |
    first: case first.second do
      SignedCheckpoint(value) -> value
      _ -> first.first
    end,
    second: SignedCheckpoint(first.first)
  }
  let candidates = [encode_fork(first)?, encode_fork(second)?]
  let path = database_path("bounty-race")?
  ensure_schema(path)?
  let key = platform_key()?
  set_bounty_enabled(path, key, true)?
  for index in 0..8 do
    let _worker = spawn(contender, path, index, List.get(candidates, index % 2), false)
    nil
  end
  let retained = barrier(path, false)?
  assert(List.all(retained, fn(value) do value == "ok" end))
  let wire = retained_fork(path, key)?
  assert(List.any(candidates, fn(candidate) do Bytes.secure_equals(candidate, wire) end))
  let pending = bounty_state(path, key)?
  assert(pending.status == 1 && Bytes.secure_equals(pending.proof_identity, Crypto.sha256(wire)))
  for index in 0..8 do
    let _worker = spawn(contender, path, index, pending.proof_identity, true)
    nil
  end
  let choices = barrier(path, true)?
  assert(List.length(List.filter(choices, fn(value) do value == "ok" end)) == 1)
  assert(List.all(choices,
    fn(value) do value == "ok"
      || value == "local_state_changed"
      || value == "bounty_selection_frozen" end))
  let chosen = bounty_state(path, key)?
  assert(chosen.status == 3)
  assert(Bytes.secure_equals(chosen.finder, repeated(U64.to_int(chosen.index)? + 71, 32)?))
  assert(Bytes.secure_equals(decode_fork(disclosable_fork(path, key)?)?.finder, chosen.finder))
  File.delete(path)?
  Ok(true)
end

test("eight independent native writers retain one proof and one immutable finder") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
