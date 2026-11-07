from Groups.GroupMessages import encode_group_message, decode_group_message
from Groups.Mls import GroupMessage

fn bytes(count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat("41", count))
end

fn frame(version :: Int) -> GroupMessage!String do
  Ok(GroupMessage {
    version: version,
    suite: 3,
    group_id: bytes(32)?,
    epoch: U64.parse("1")?,
    tree_hash: bytes(32)?,
    sender_leaf: 1,
    generation: 0,
    nonce: bytes(12)?,
    ciphertext: bytes(16)?,
    signature: Signature { bytes: bytes(64)? }
  })
end

# Structural framing only; cryptographic authentication is tested separately.
fn proof() -> Bool!String do
  let value = frame(6)?
  case encode_group_message(value) do
    Err(_) -> assert(false)
    Ok(wire) -> case decode_group_message(wire) do
      Err(_) -> assert(false)
      Ok(opened) -> do
        assert(opened.version == 6)
        assert(Bytes.secure_equals(opened.ciphertext, value.ciphertext))
        case encode_group_message(opened) do
          Err(_) -> assert(false)
          Ok(encoded) -> assert(Bytes.secure_equals(encoded, wire))
        end
      end
    end
  end
  for version in [0, 7] do
    case frame(version) do
      Err(_) -> assert(false)
      Ok(invalid) -> case encode_group_message(invalid) do
        Err(_) -> nil
        Ok(_) -> assert(false)
      end
    end
  end
  Ok(true)
end

test("mandatory GMS6 timed framing is canonical while unknown versions refuse") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
