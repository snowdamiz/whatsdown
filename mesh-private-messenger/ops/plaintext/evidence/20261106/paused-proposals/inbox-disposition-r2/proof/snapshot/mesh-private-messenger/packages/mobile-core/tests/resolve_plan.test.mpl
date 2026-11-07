from MobileCore import resolve_plan_export, install_group_checkpoint_for_test
from Mobile.Platform import native_security_config
from Mobile.Codec import current_time
from Privacy.Edge import decode_stamped_request, verify_request_stamp
from Tests.GroupLifecycleWire import output_list
from Tests.Support import append, database_path, install_security_config, vector, repeated
from Transparency.Config import encode_security_config
from Transparency.Merkle import sign_tree_checkpoint_for
from Transparency.Wire import encode_checkpoint, decode_transparency_lookup

fn check_plan(frame :: Bytes, paths :: List<String>, sizes :: List<Int>) -> Result<(), String> do
  let plans = output_list(frame)?
  assert(List.length(plans) == List.length(paths))
  for index in 0..List.length(plans) do
    let parts = output_list(List.get(plans, index))?
    assert(List.length(parts) == 2)
    assert(Bytes.to_utf8(List.get(parts, 0))? == List.get(paths, index))
    let (stamp, payload) = decode_stamped_request(List.get(parts, 1), 76)?
    let lookup = decode_transparency_lookup(payload)?
    assert(lookup.username == "alice" && lookup.previous_tree_size == List.get(sizes, index))
    assert(verify_request_stamp("mesh-msg/v1/work/resolve",
      payload,
      stamp,
      current_time()?,
      U64.parse("300000")?,
      8)?)
  end
  Ok(nil)
end

fn proof(config_version :: Int) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("fixture signer failed")
    Ok(value) -> value
  end
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> return Err("fixture delivery failed")
    Ok(value) -> value
  end
  assert(install_security_config(signer.public_key.bytes,
    repeated(10, 32)?,
    repeated(11, 32)?,
    delivery.public_key.bytes,
    8))
  let path = database_path("resolve-plan")?
  let input = append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?
  check_plan(resolve_plan_export(input)?, ["/v1/devices/resolve"], [0])?
  let legacy_config = native_security_config()?
  let migration = %{legacy_config |
    version: config_version,
    log_version: 2,
    legacy_witnesses: legacy_config.witnesses,
    legacy_threshold: legacy_config.threshold
  }
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(migration)?))
  check_plan(resolve_plan_export(input)?, ["/v2/devices/resolve", "/v1/devices/resolve"], [0, 0])?
  let old = sign_tree_checkpoint_for(1,
    signer.private_key,
    signer.public_key.bytes,
    U64.parse("8")?,
    U64.parse("17")?,
    Crypto.sha256(Bytes.from_utf8("old root")),
    repeated(0, 32)?,
    current_time()?)?
  install_group_checkpoint_for_test(path, encode_checkpoint(old)?)?
  check_plan(resolve_plan_export(input)?, ["/v2/devices/resolve", "/v1/devices/resolve"], [0, 17])?
  let current = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    U64.parse("1")?,
    U64.parse("2")?,
    Crypto.sha256(Bytes.from_utf8("RFC root")),
    repeated(0, 32)?,
    current_time()?)?
  install_group_checkpoint_for_test(path, encode_checkpoint(current)?)?
  check_plan(resolve_plan_export(input)?, ["/v2/devices/resolve"], [2])?
  # Installing an older native frame cannot make a cached RFC tree disappear.
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(legacy_config)?))
  case resolve_plan_export(input) do
    Err(error) -> assert(error == "unsupported_transparency_log")
    Ok(_) -> assert(false)
  end
  File.delete(path)?
  Ok(true)
end

test("Mesh resolution plans carry paid requests for the permitted logs and preserve the RFC transition") do
  case proof(3) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("native v4 retains the RFC migration and downgrade protections") do
  case proof(4) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("native v5 relay pins retain RFC resolution and downgrade protections") do
  case proof(5) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
