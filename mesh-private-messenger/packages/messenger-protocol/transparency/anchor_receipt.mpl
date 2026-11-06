##! Bounded public transaction hints. A receipt is not a chain proof: consumers
##! authenticate the configured judge, log and ring independently.

pub struct AnchorReceipt do
  log_version :: Int
  sequence :: U64
  tree_size :: U64
  checkpoint_hash :: Bytes
  ring_index :: Int
  transaction_signature :: Bytes
  slot :: U64
end

fn valid(value :: AnchorReceipt) -> Result<(), String> do
  if (value.log_version != 1 && value.log_version != 2)
    || U64.compare(value.sequence, U64.parse("0")?) == 0
    || U64.compare(value.tree_size, U64.parse("0")?) == 0
    || U64.compare(value.tree_size, U64.parse("4294967295")?) > 0
    || Bytes.length(value.checkpoint_hash) != 32
    || value.ring_index < 0
    || value.ring_index >= 4096
    || Bytes.length(value.transaction_signature) != 64 do
    Err("invalid_anchor_receipt")
  else
    Ok(nil)
  end
end

fn narrow(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("invalid_anchor_receipt")
    Ok(bytes)
  end
end

fn wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid_anchor_receipt")
    Ok(bytes)
  end
end

fn cat(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    return Ok(output)
  end
  let next = case Bytes.concat(output, List.get(parts, index)) do
    Err(_) -> return Err("invalid_anchor_receipt")
    Ok(bytes) -> bytes
  end
  cat(parts, index + 1, next)
end

pub fn encode_anchor_receipt(value :: AnchorReceipt) -> Bytes!String do
  valid(value)?
  cat([
      Bytes.from_hex("014b5441")?,
      narrow(value.log_version)?,
      wide(value.sequence)?,
      wide(value.tree_size)?,
      value.checkpoint_hash,
      narrow(value.ring_index)?,
      value.transaction_signature,
      wide(value.slot)?
    ],
    0,
    Bytes.empty())
end

fn read_narrow(bytes :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_be(bytes, offset) do
    Err(_) -> Err("invalid_anchor_receipt")
    Ok(value)
  end
end

fn read_wide(bytes :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(bytes, offset) do
    Err(_) -> Err("invalid_anchor_receipt")
    Ok(value)
  end
end

pub fn decode_anchor_receipt(bytes :: Bytes) -> AnchorReceipt!String do
  if Bytes.length(bytes) != 128 || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "014b5441" do
    return Err("invalid_anchor_receipt")
  end
  let value = AnchorReceipt {
    log_version: read_narrow(bytes, 4)?,
    sequence: read_wide(bytes, 6)?,
    tree_size: read_wide(bytes, 14)?,
    checkpoint_hash: Bytes.slice(bytes, 22, 32)?,
    ring_index: read_narrow(bytes, 54)?,
    transaction_signature: Bytes.slice(bytes, 56, 64)?,
    slot: read_wide(bytes, 120)?
  }
  valid(value)?
  Ok(value)
end

pub fn anchor_receipt_json(value :: AnchorReceipt) -> String!String do
  valid(value)?
  Ok("{\"log_version\":"
    <> Int.to_string(value.log_version)
    <> ",\"checkpoint_sequence\":"
    <> Json.encode_string(U64.to_string(value.sequence))
    <> ",\"tree_size\":"
    <> Json.encode_string(U64.to_string(value.tree_size))
    <> ",\"checkpoint_hash\":"
    <> Json.encode_string(Bytes.to_hex(value.checkpoint_hash))
    <> ",\"ring_index\":"
    <> Int.to_string(value.ring_index)
    <> ",\"tx_signature\":"
    <> Json.encode_string(Bytes.to_base58(value.transaction_signature))
    <> ",\"slot\":"
    <> Json.encode_string(U64.to_string(value.slot))
    <> "}")
end
