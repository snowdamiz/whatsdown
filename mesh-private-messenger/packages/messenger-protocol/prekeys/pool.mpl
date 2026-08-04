from Binary.Reader import BinaryReader, finish, read_fixed, read_u8, reader

pub struct OneTimePrekeyPublic do
  id :: U64
  public_key :: Bytes
end

pub struct PrekeyPublishRequest do
  account_id :: Bytes
  device_id :: Bytes
  prekeys :: List < OneTimePrekeyPublic >
  signature :: Bytes
end

pub struct PrekeyClaimRequest do
  account_id :: Bytes
  device_id :: Bytes
  base_bundle_hash :: Bytes
end

pub struct PrekeyPublishResponse do
  account_id :: Bytes
  device_id :: Bytes
  active_ids :: List < U64 >
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadWide do
  state :: BinaryReader
  value :: U64
end

struct ReadPrekeys do
  state :: BinaryReader
  value :: List < OneTimePrekeyPublic >
end

struct ReadIds do
  state :: BinaryReader
  value :: List < U64 >
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("prekey pool allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("invalid prekey pool integer")
    Ok( output) -> Ok(output)
  end
end

fn write_u64(value :: U64) -> Bytes ! String do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err("invalid prekey pool integer")
    Ok( output) -> Ok(output)
  end
end

fn start(input :: Bytes, maximum :: Int) -> BinaryReader ! String do
  if Bytes.length(input) > maximum do
    Err("prekey pool wire oversized")
  else
    case reader(input, maximum) do
      Err( _) -> Err("invalid prekey pool wire")
      Ok( output) -> Ok(output)
    end
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes ! String do
  case read_fixed(state, length) do
    Err( _) -> Err("invalid prekey pool wire")
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err("invalid prekey pool wire")
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt ! String do
  case read_u8(state) do
    Err( _) -> Err("invalid prekey pool wire")
    Ok( ( next, value)) -> Ok(ReadInt {
      state : next,
      value : value
    })
    Ok( _) -> Err("invalid prekey pool wire")
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide ! String do
  let value = take_fixed(state, 8) ?
  case Bytes.read_u64_be(value.value, 0) do
    Err( _) -> Err("invalid prekey pool integer")
    Ok( output) -> Ok(ReadWide {
      state : value.state,
      value : output
    })
  end
end

fn done(state :: BinaryReader) -> Result <(), String > do
  case finish(state) do
    Err( _) -> Err("invalid prekey pool wire")
    Ok( _) -> Ok(nil)
  end
end

fn valid_id(value :: U64) -> Bool ! String do
  let zero = U64.parse("0") ?
  let maximum = U64.parse("9223372036854775807") ?
  Ok(U64.compare(value, zero) > 0 && U64.compare(value, maximum) <= 0)
end

fn valid_prekeys(values :: List < OneTimePrekeyPublic >, index :: Int, previous :: U64) -> Bool ! String do
  if index >= List.length(values) do
    Ok(true)
  else
    let value = List.get(values, index)
    if !(valid_id(value.id) ?) || Bytes.length(value.public_key) != 32 || U64.compare(value.id,
    previous) <= 0 do
      Ok(false)
    else
      valid_prekeys(values, index + 1, value.id)
    end
  end
end

fn valid_ids(values :: List < U64 >, index :: Int, previous :: U64) -> Bool ! String do
  if index >= List.length(values) do
    Ok(true)
  else
    let value = List.get(values, index)
    if !(valid_id(value) ?) || U64.compare(value, previous) <= 0 do
      Ok(false)
    else
      valid_ids(values, index + 1, value)
    end
  end
end

fn encode_prekeys(values :: List < OneTimePrekeyPublic >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    encode_prekeys(values,
    index + 1,
    join([output, write_u64(value.id) ?, value.public_key], 0, Bytes.empty()) ?)
  end
end

fn decode_prekeys(state :: BinaryReader,
remaining :: Int,
previous :: U64,
output :: List < OneTimePrekeyPublic >) -> ReadPrekeys ! String do
  if remaining <= 0 do
    Ok(ReadPrekeys {
      state : state,
      value : output
    })
  else
    let id = take_u64(state) ?
    let public_key = take_fixed(id.state, 32) ?
    if !(valid_id(id.value) ?) || U64.compare(id.value, previous) <= 0 do
      Err("invalid prekey publication order")
    else
      decode_prekeys(public_key.state,
      remaining - 1,
      id.value,
      List.append(output,
      OneTimePrekeyPublic {
        id : id.value,
        public_key : public_key.value
      }))
    end
  end
end

fn encode_ids(values :: List < U64 >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_ids(values, index + 1, append(output, write_u64(List.get(values, index)) ?) ?)
  end
end

fn decode_ids(state :: BinaryReader, remaining :: Int, previous :: U64, output :: List < U64 >) -> ReadIds ! String do
  if remaining <= 0 do
    Ok(ReadIds {
      state : state,
      value : output
    })
  else
    let id = take_u64(state) ?
    if !(valid_id(id.value) ?) || U64.compare(id.value, previous) <= 0 do
      Err("invalid active prekey order")
    else
      decode_ids(id.state, remaining - 1, id.value, List.append(output, id.value))
    end
  end
end

fn publish_content(value :: PrekeyPublishRequest) -> Bytes ! String do
  let count = List.length(value.prekeys)
  if Bytes.length(value.account_id) != 32 || Bytes.length(value.device_id) != 16 || count > 64 || !(valid_prekeys(value.prekeys,
  0,
  U64.parse("0") ?) ?) do
    Err("invalid prekey publication")
  else
    let prefix = join([byte(1) ?, Bytes.from_utf8("OTB"), value.account_id, value.device_id, byte(count) ?],
    0,
    Bytes.empty()) ?
    encode_prekeys(value.prekeys, 0, prefix)
  end
end

fn claim_content(value :: PrekeyClaimRequest) -> Bytes ! String do
  if Bytes.length(value.account_id) != 32 || Bytes.length(value.device_id) != 16 || Bytes.length(value.base_bundle_hash) != 32 do
    Err("invalid prekey claim")
  else
    join([byte(1) ?, Bytes.from_utf8("OTQ"), value.account_id, value.device_id, value.base_bundle_hash],
    0,
    Bytes.empty())
  end
end

pub fn prekey_publish_signing_bytes(value :: PrekeyPublishRequest) -> Bytes ! String do
  append(Bytes.from_utf8("mesh-msg/v1/one-time-prekey-batch"), publish_content(value) ?)
end

pub fn encode_prekey_publish(value :: PrekeyPublishRequest) -> Bytes ! String do
  if Bytes.length(value.signature) != 64 do
    Err("invalid prekey publication signature")
  else
    append(publish_content(value) ?, value.signature)
  end
end

pub fn decode_prekey_publish(input :: Bytes) -> PrekeyPublishRequest ! String do
  let version = take_u8(start(input, 2677) ?) ?
  let magic = take_fixed(version.state, 3) ?
  let account_id = take_fixed(magic.state, 32) ?
  let device_id = take_fixed(account_id.state, 16) ?
  let count = take_u8(device_id.state) ?
  if count.value > 64 do
    Err("invalid prekey publication count")
  else
    let prekeys = decode_prekeys(count.state, count.value, U64.parse("0") ?, List.new()) ?
    let signature = take_fixed(prekeys.state, 64) ?
    done(signature.state) ?
    if version.value != 1 || !Bytes.secure_equals(magic.value, Bytes.from_utf8("OTB")) do
      Err("invalid prekey publication wire")
    else
      let value = PrekeyPublishRequest {
        account_id : account_id.value,
        device_id : device_id.value,
        prekeys : prekeys.value,
        signature : signature.value
      }
      let _ = publish_content(value) ?
      Ok(value)
    end
  end
end

pub fn encode_prekey_claim(value :: PrekeyClaimRequest) -> Bytes ! String do
  claim_content(value)
end

pub fn decode_prekey_claim(input :: Bytes) -> PrekeyClaimRequest ! String do
  let version = take_u8(start(input, 84) ?) ?
  let magic = take_fixed(version.state, 3) ?
  let account_id = take_fixed(magic.state, 32) ?
  let device_id = take_fixed(account_id.state, 16) ?
  let base_bundle_hash = take_fixed(device_id.state, 32) ?
  done(base_bundle_hash.state) ?
  if version.value != 1 || !Bytes.secure_equals(magic.value, Bytes.from_utf8("OTQ")) do
    Err("invalid prekey claim wire")
  else
    let value = PrekeyClaimRequest {
      account_id : account_id.value,
      device_id : device_id.value,
      base_bundle_hash : base_bundle_hash.value
    }
    let _ = claim_content(value) ?
    Ok(value)
  end
end

pub fn encode_prekey_publish_response(value :: PrekeyPublishResponse) -> Bytes ! String do
  let count = List.length(value.active_ids)
  if Bytes.length(value.account_id) != 32 || Bytes.length(value.device_id) != 16 || count > 64 || !(valid_ids(value.active_ids,
  0,
  U64.parse("0") ?) ?) do
    Err("invalid prekey publication response")
  else
    let prefix = join([byte(1) ?, Bytes.from_utf8("OTA"), value.account_id, value.device_id, byte(count) ?],
    0,
    Bytes.empty()) ?
    encode_ids(value.active_ids, 0, prefix)
  end
end

pub fn decode_prekey_publish_response(input :: Bytes) -> PrekeyPublishResponse ! String do
  let version = take_u8(start(input, 565) ?) ?
  let magic = take_fixed(version.state, 3) ?
  let account_id = take_fixed(magic.state, 32) ?
  let device_id = take_fixed(account_id.state, 16) ?
  let count = take_u8(device_id.state) ?
  if count.value > 64 do
    Err("invalid active prekey count")
  else
    let active_ids = decode_ids(count.state, count.value, U64.parse("0") ?, List.new()) ?
    done(active_ids.state) ?
    if version.value != 1 || !Bytes.secure_equals(magic.value, Bytes.from_utf8("OTA")) do
      Err("invalid prekey publication response wire")
    else
      let value = PrekeyPublishResponse {
        account_id : account_id.value,
        device_id : device_id.value,
        active_ids : active_ids.value
      }
      let _ = encode_prekey_publish_response(value) ?
      Ok(value)
    end
  end
end
