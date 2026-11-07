from Groups.GroupPayload import GroupPayload, encode_group_payload, decode_group_payload

fn fixture_only(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "synthetic public group payload fixture comparisons only; no application disclosure")
end

fn check_fixture(value :: Plaintext<Bool>) -> Bool!String do
  if value do
    Ok(true)
  else
    Err("fixture comparison failed")
  end
end

fn bytes(count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat("41", count))
end

fn proof() -> Bool!String do
  let application = GroupPayload {
    kind: 1,
    body: bytes(65237)?,
    hint: bytes(40)?,
    recipient_account: Bytes.empty(),
    recipient_device: Bytes.empty()
  }
  let wire = encode_group_payload(application)?
  check_fixture(Bytes.length(wire) == 65290)?
  let decoded = decode_group_payload(wire)?
  check_fixture(decoded.kind == 1 && Bytes.secure_equals(decoded.body, application.body))?
  check_fixture(Bytes.secure_equals(decoded.hint, application.hint))?
  check_fixture(Bytes.secure_equals(encode_group_payload(decoded)?, wire))?
  for invalid in [
    %{application | body: bytes(65238)?},
    %{application | hint: bytes(39)?},
    %{application | recipient_account: bytes(32)?},
    %{application | kind: 2}
  ] do
    check_fixture(Result.is_err(encode_group_payload(invalid)))?
  end
  let control = GroupPayload {
    kind: 5,
    body: bytes(2987)?,
    hint: Bytes.empty(),
    recipient_account: bytes(32)?,
    recipient_device: bytes(16)?
  }
  let control_wire = encode_group_payload(control)?
  let opened = decode_group_payload(control_wire)?
  check_fixture(opened.kind == 5 && Bytes.length(control_wire) == 3044)?
  check_fixture(Bytes.secure_equals(opened.recipient_account, control.recipient_account))?
  check_fixture(Bytes.secure_equals(opened.recipient_device, control.recipient_device))?
  for invalid in [
    %{control | body: bytes(2988)?},
    %{control | hint: bytes(40)?},
    %{control | recipient_device: Bytes.empty()}
  ] do
    check_fixture(Result.is_err(encode_group_payload(invalid)))?
  end
  for invalid in [Bytes.concat(wire, bytes(1)?)?, Bytes.slice(control_wire, 0, 56)?] do
    check_fixture(Result.is_err(decode_group_payload(invalid)))?
  end
  Ok(true)
end

test("group gossip payloads separate application text from addressed bounded controls") do
  assert(fixture_only(Result.unwrap_or(proof(), false)))
end
