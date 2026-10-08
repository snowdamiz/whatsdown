import File
from MobileCore import (
  inspect_device_set_export,
  install_transparency_set_for_test,
  network_status_export,
  verify_transparency_export
)
from Protocol.V1 import DeviceSet
from Security.Config import SecurityWitness
from Tests.GroupConsistencySupport import (
  ConsistencyAccount,
  account_fixture,
  decode_account,
  encode_set,
  request,
  signing_pair,
  wide
)
from Tests.Support import (
  append,
  evidence_v2,
  install_security_config,
  install_witness_config,
  read_u32,
  repeated
)
from Transparency.Merkle import TransparencyCheckpoint, leaf_hash, sign_checkpoint, sign_witness
from Transparency.Wire import encode_checkpoint
from Mobile.Codec import current_time

fn delivery_key() -> Bytes!String do
  case Crypto.x25519_generate() do
    Err(_) -> Err("test delivery key generation failed")
    Ok(value) -> Ok(value.public_key.bytes)
  end
end

fn witness(id :: String, key :: Bytes, label :: String) -> SecurityWitness do
  SecurityWitness { witness_id: id, public_key: key, label: label }
end

fn verify(account :: ConsistencyAccount, evidence :: Bytes) -> Bytes!String do
  verify_transparency_export(request([
    Bytes.from_utf8(account.path),
    Bytes.from_utf8(account.username),
    evidence
  ])?)
end

fn accepted(result :: Result<Bytes, String>) -> Bool do
  case result do
    Ok(_) -> true
    Err(error) -> do
      println(error)
      false
    end
  end
end

fn refused(result :: Result<Bytes, String>, expected :: String) -> Bool do
  case result do
    Ok(_) -> false
    Err(error) -> error == expected
  end
end

fn signed(signer :: borrow SigningPrivateKey,
  signer_public_key :: Bytes,
  sequence :: Int,
  leaves :: List<Bytes>,
  timestamp :: U64) -> TransparencyCheckpoint!String do
  sign_checkpoint(signer, signer_public_key, wide(sequence)?, leaves, repeated(0, 32)?, timestamp)
end

# A 3 of 5 set: two attestations are not enough, however they are dressed up;
# three are.

fn threshold_proof() -> Bool!String do
  let account = account_fixture("witness-threshold", "tessa")?
  let leaves = [leaf_hash(account.device_set)?]
  let log_key = signing_pair()?
  let one = signing_pair()?
  let two = signing_pair()?
  let three = signing_pair()?
  let four = signing_pair()?
  let five = signing_pair()?
  let stranger = signing_pair()?
  assert(install_witness_config(log_key.public_key.bytes,
    delivery_key()?,
    [
      witness("w-1", one.public_key.bytes, "Morse"),
      witness("w-2", two.public_key.bytes, "Morse"),
      witness("w-3", three.public_key.bytes, "Acme Labs"),
      witness("w-4", four.public_key.bytes, "Open Relay Co"),
      witness("w-5", five.public_key.bytes, "Witness Guild")
    ])?)
  let checkpoint = signed(log_key.private_key,
    log_key.public_key.bytes,
    1,
    leaves,
    current_time()?)?
  let a = sign_witness("w-1", one.private_key, checkpoint)?
  let b = sign_witness("w-2", two.private_key, checkpoint)?
  let evidence = fn attestations -> evidence_v2(account.device_set,
    leaves,
    0,
    0,
    checkpoint,
    attestations) end
  assert(refused(verify(account, evidence([a, b])?), "transparency_verification_failed"))
  # A repeated witness counts once; an unpinned ID or a pinned ID signed with
  # another key counts not at all.
  assert(refused(verify(account, evidence([a, b, a, b])?), "transparency_verification_failed"))
  assert(refused(verify(account,
      evidence([a, b, sign_witness("w-9", stranger.private_key, checkpoint)?])?),
    "transparency_verification_failed"))
  assert(refused(verify(account,
      evidence([a, b, sign_witness("w-3", four.private_key, checkpoint)?])?),
    "transparency_verification_failed"))
  let c = sign_witness("w-3", three.private_key, checkpoint)?
  assert(Bytes.secure_equals(verify(account, evidence([a, c, b])?)?, account.device_set))
  File.delete(account.path)?
  Ok(true)
end

struct StatusWitness do
  id :: String
  label :: String
  morse :: Int
end

struct Status do
  profile :: String
  threshold :: Int
  count :: Int
  morse :: Int
  set_id :: Bytes
  witnesses :: List<StatusWitness>
  sections :: Int
end

fn text_at(input :: Bytes, offset :: Int) -> (String, Int)!String do
  let length = read_u32(Bytes.slice(input, offset, 4)?)?
  let text = case Bytes.to_utf8(Bytes.slice(input, offset + 4, length)?) do
    Err(_) -> Err("status text is not UTF-8")
    Ok(value)
  end?
  Ok((text, offset + 4 + length))
end

fn byte_at(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.get(input, offset) do
    Err(_) -> Err("status is too short")
    Ok(value)
  end
end

fn status_witnesses(input :: Bytes,
  offset :: Int,
  count :: Int,
  output :: List<StatusWitness>) -> (List<StatusWitness>, Int)!String do
  if List.length(output) >= count do
    Ok((output, offset))
  else
    let (id, after_id) = text_at(input, offset)?
    let (label, after_label) = text_at(input, after_id)?
    status_witnesses(input,
      after_label + 1,
      count,
      List.append(output,
        StatusWitness { id: id, label: label, morse: byte_at(input, after_label)? }))
  end
end

fn status(path :: String) -> Status!String do
  let input = network_status_export(Bytes.from_utf8(path))?
  assert(Bytes.secure_equals(Bytes.slice(input, 1, 3)?, Bytes.from_utf8("NST")))
  let (profile, offset) = text_at(input, 4)?
  let count = byte_at(input, offset + 1)?
  let (witnesses, rest_offset) = status_witnesses(input, offset + 35, count, List.new())?
  Ok(Status {
    profile: profile,
    threshold: byte_at(input, offset)?,
    count: count,
    morse: byte_at(input, offset + 2)?,
    set_id: Bytes.slice(input, offset + 3, 32)?,
    witnesses: witnesses,
    sections: byte_at(input, rest_offset)?
  })
end

fn status_refused(path :: String) -> Bool do
  case network_status_export(Bytes.from_utf8(path)) do
    Ok(_) -> false
    Err(error) -> error == "invalid_messenger_configuration"
  end
end

fn replace_line(frame :: String, index :: Int, value :: String) -> Bytes do
  let lines = String.split(frame, "\n")
  let updated = for position in 0..List.length(lines) do
    if position == index do
      value
    else
      List.get(lines, position)
    end
  end
  Bytes.from_utf8(String.join(updated, "\n"))
end

fn config_proof() -> Bool!String do
  let account = account_fixture("witness-config", "cora")?
  let log_key = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  # Version 1 reads as witness-a and witness-b, both Morse, 2 of 2.
  assert(install_security_config(log_key.public_key.bytes,
    a.public_key.bytes,
    b.public_key.bytes,
    delivery_key()?,
    8))
  let v1 = status(account.path)?
  assert(v1.profile == "bootstrap" && v1.threshold == 2 && v1.count == 2 && v1.morse == 2)
  assert(List.get(v1.witnesses, 0).id == "witness-a" && List.get(v1.witnesses, 1).id == "witness-b")
  assert(List.all(v1.witnesses, fn value -> value.label == "Morse" && value.morse == 1 end))
  assert(v1.sections == 0)
  let expected = Crypto.sha256(Bytes.from_utf8("morse-witness-set-v1"
    <> "2\n2\nwitness-a "
    <> Bytes.to_hex(a.public_key.bytes)
    <> " Morse\nwitness-b "
    <> Bytes.to_hex(b.public_key.bytes)
    <> " Morse"))
  assert(Bytes.secure_equals(v1.set_id, expected))
  # Open: one of five is Morse's, k = 3.
  let keys = for index in 0..5 do
    signing_pair()?.public_key.bytes
  end
  let open_set = [
    witness("a-1", List.get(keys, 0), "Morse"),
    witness("b-2", List.get(keys, 1), "Acme Labs"),
    witness("c-3", List.get(keys, 2), "Witness Guild"),
    witness("d-4", List.get(keys, 3), "Open Relay Co"),
    witness("e-5", List.get(keys, 4), "Kestrel")
  ]
  let delivery = delivery_key()?
  assert(install_witness_config(log_key.public_key.bytes, delivery, open_set)?)
  let opened = status(account.path)?
  assert(opened.profile == "open"
    && opened.threshold == 3
    && opened.count == 5
    && opened.morse == 1)
  assert(List.get(opened.witnesses, 1).label == "Acme Labs"
    && List.get(opened.witnesses, 1).morse == 0)
  # A k that is not the strict majority is refused.
  let frame = "2\n"
    <> Bytes.to_hex(log_key.public_key.bytes)
    <> "\n"
    <> Bytes.to_hex(delivery)
    <> "\n8\n3\n5\na-1 "
    <> Bytes.to_hex(List.get(keys, 0))
    <> " Morse\nb-2 "
    <> Bytes.to_hex(List.get(keys, 1))
    <> " Acme Labs\nc-3 "
    <> Bytes.to_hex(List.get(keys, 2))
    <> " Witness Guild\nd-4 "
    <> Bytes.to_hex(List.get(keys, 3))
    <> " Open Relay Co\ne-5 "
    <> Bytes.to_hex(List.get(keys, 4))
    <> " Kestrel\n-\n0\n0\n-\n-\n1"
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), Bytes.from_utf8(frame)))
  assert(status(account.path)?.threshold == 3)
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), replace_line(frame, 4, "2")))
  assert(status_refused(account.path))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), replace_line(frame, 4, "5")))
  assert(status_refused(account.path))
  File.delete(account.path)?
  Ok(true)
end

# Moving to another pinned set drops what was verified under the old one, but
# the checkpoint this device last verified still anchors the log: evidence must
# extend it, whichever set signs.

fn rotation_proof() -> Bool!String do
  let account = account_fixture("witness-rotation", "rhea")?
  let leaf = leaf_hash(account.device_set)?
  let filler = repeated(7, 32)?
  let log_key = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  let x = signing_pair()?
  let y = signing_pair()?
  let z = signing_pair()?
  let delivery = delivery_key()?
  assert(install_security_config(log_key.public_key.bytes,
    a.public_key.bytes,
    b.public_key.bytes,
    delivery,
    8))
  let first = signed(log_key.private_key, log_key.public_key.bytes, 1, [leaf], current_time()?)?
  verify(account,
    evidence_v2(account.device_set,
      [leaf],
      0,
      0,
      first,
      [
        sign_witness("witness-a", a.private_key, first)?,
        sign_witness("witness-b", b.private_key, first)?
      ])?)?
  let inspect = request([Bytes.from_utf8(account.path), account.device_set])?
  inspect_device_set_export(inspect)?
  assert(install_witness_config(log_key.public_key.bytes,
    delivery,
    [
      witness("x-1", x.public_key.bytes, "Morse"),
      witness("y-2", y.public_key.bytes, "Morse"),
      witness("z-3", z.public_key.bytes, "Acme Labs")
    ])?)
  case inspect_device_set_export(inspect) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "device_set_transparency_unverified")
  end
  let grown = [leaf, filler]
  let second = signed(log_key.private_key, log_key.public_key.bytes, 2, grown, current_time()?)?
  let new_set = [
    sign_witness("x-1", x.private_key, second)?,
    sign_witness("z-3", z.private_key, second)?
  ]
  # The old set's signatures do not count under the new one.
  assert(refused(verify(account,
      evidence_v2(account.device_set,
        grown,
        0,
        1,
        second,
        [
          sign_witness("witness-a", a.private_key, second)?,
          sign_witness("witness-b", b.private_key, second)?
        ])?),
    "transparency_verification_failed"))
  # A new set cannot restart the log: evidence must be consistent with the
  # checkpoint verified under the old set.
  assert(refused(verify(account, evidence_v2(account.device_set, grown, 0, 0, second, new_set)?),
    "transparency_verification_failed"))
  let other = [repeated(9, 32)?, filler]
  let forked = signed(log_key.private_key, log_key.public_key.bytes, 2, other, current_time()?)?
  assert(refused(verify(account,
      evidence_v2(account.device_set,
        other,
        0,
        1,
        forked,
        [
          sign_witness("x-1", x.private_key, forked)?,
          sign_witness("y-2", y.private_key, forked)?
        ])?),
    "transparency_verification_failed"))
  assert(Bytes.secure_equals(verify(account,
      evidence_v2(account.device_set, grown, 0, 1, second, new_set)?)?,
    account.device_set))
  inspect_device_set_export(inspect)?
  File.delete(account.path)?
  Ok(true)
end

fn day_ms() -> Int do
  86_400_000
end

fn ago(days :: Int) -> U64!String do
  let now = U64.to_int(current_time()?)?
  wide(now - days * day_ms())
end

# This device last saw its own account at sequence s, `days` ago; the
# directory now shows s + `steps`.

fn returning(label :: String, days :: Int, steps :: Int) -> Result<Bytes, String>!String do
  let account = account_fixture(label, label)?
  let identity = decode_account(account.entry.account_identity)?
  let log_key = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  assert(install_security_config(log_key.public_key.bytes,
    a.public_key.bytes,
    b.public_key.bytes,
    delivery_key()?,
    8))
  let seen = signed(log_key.private_key,
    log_key.public_key.bytes,
    1,
    [leaf_hash(account.device_set)?],
    ago(days)?)?
  assert(install_transparency_set_for_test(account.path,
    encode_checkpoint(seen)?,
    account.device_set)?)
  let moved = encode_set(DeviceSet {
    version: 1,
    username: account.username,
    account_identity: account.entry.account_identity,
    sequence: U64.add(identity.directory_sequence, wide(steps)?)?,
    devices: [account.entry],
    revoked_device_ids: List.new()
  })?
  let leaves = [leaf_hash(account.device_set)?, leaf_hash(moved)?]
  let now = signed(log_key.private_key, log_key.public_key.bytes, 2, leaves, current_time()?)?
  let evidence = evidence_v2(moved,
    leaves,
    1,
    0,
    now,
    [
      sign_witness("witness-a", a.private_key, now)?,
      sign_witness("witness-b", b.private_key, now)?
    ])?
  let result = verify(account, evidence)
  # Either way the new set is what this device holds now.
  inspect_device_set_export(request([Bytes.from_utf8(account.path), moved])?)?
  File.delete(account.path)?
  Ok(result)
end

fn away_proof() -> Bool!String do
  assert(refused(returning("awaya", 91, 2)?, "account_changed_while_away"))
  # One step is a transition this device sees itself; a recent look means the
  # directory still holds everything in between.
  assert(accepted(returning("awayb", 91, 1)?))
  assert(accepted(returning("awayc", 30, 2)?))
  Ok(true)
end

fn run(name :: String, value :: Result<Bool, String>) -> Bool do
  case value do
    Err(error) -> do
      println(name <> ": " <> error)
      false
    end
    Ok(result) -> result
  end
end

test("verification needs k of the pinned set and ignores repeats and strangers") do
  assert(Test.install_in_memory_secure_store())
  assert(run("threshold", threshold_proof()))
end

test("config v2 status: v1 reads as 2 of 2, profiles, and only a strict majority k") do
  assert(Test.install_in_memory_secure_store())
  assert(run("config", config_proof()))
end

test("a set rotation re-verifies cached device sets and keeps the log's continuity") do
  assert(Test.install_in_memory_secure_store())
  assert(run("rotation", rotation_proof()))
end

test("this device's own account moving through pruned transitions is reported") do
  assert(Test.install_in_memory_secure_store())
  assert(run("away", away_proof()))
end
