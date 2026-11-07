from Groups.GroupPayload import GroupPayload, encode_group_payload, decode_group_payload

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
  assert(Bytes.length(wire) == 65290)
  let decoded = decode_group_payload(wire)?
  assert(decoded.kind == 1 && Bytes.secure_equals(decoded.body, application.body))
  assert(Bytes.secure_equals(decoded.hint, application.hint))
  assert(Bytes.secure_equals(encode_group_payload(decoded)?, wire))
  for invalid in [
    %{application | body: bytes(65238)?},
    %{application | hint: bytes(39)?},
    %{application | recipient_account: bytes(32)?},
    %{application | kind: 2}
  ] do
    case encode_group_payload(invalid) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
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
  assert(opened.kind == 5 && Bytes.length(control_wire) == 3044)
  assert(Bytes.secure_equals(opened.recipient_account, control.recipient_account))
  assert(Bytes.secure_equals(opened.recipient_device, control.recipient_device))
  for invalid in [
    %{control | body: bytes(2988)?},
    %{control | hint: bytes(40)?},
    %{control | recipient_device: Bytes.empty()}
  ] do
    case encode_group_payload(invalid) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  for invalid in [Bytes.concat(wire, bytes(1)?)?, Bytes.slice(control_wire, 0, 56)?] do
    case decode_group_payload(invalid) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  Ok(true)
end

test("group gossip payloads separate application text from addressed bounded controls") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
