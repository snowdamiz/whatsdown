from Binary.Reader import BinaryReader, finish, read_fixed, read_u8, read_vector, reader
from Push.Token import valid_sealed_provider_token

pub struct PushBindRequest do
  mailbox_token_hash :: Bytes
  wake_token_hash :: Bytes
  revision :: U64
  provider :: Int
  provider_token_ciphertext :: Bytes
  signature :: Bytes
end

pub struct PushUnbindRequest do
  mailbox_token_hash :: Bytes
  revision :: U64
  signature :: Bytes
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

fn append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("push binding allocation failed")
    Ok(output) -> Ok(output)
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
    Err(_) -> Err("invalid push binding byte")
    Ok(output) -> Ok(output)
  end
end

fn write_u64(value :: U64) -> Bytes ! String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid push binding revision")
    Ok(output) -> Ok(output)
  end
end

fn vector(value :: Bytes) -> Bytes ! String do
  let length = U64.parse(Int.to_string(Bytes.length(value))) ?
  let prefix = case Bytes.write_u32_be(length) do
    Err(_) -> Err("invalid push binding length")
    Ok(output) -> Ok(output)
  end ?
  join([prefix, value], 0, Bytes.empty())
end

fn start(input :: Bytes, maximum :: Int) -> BinaryReader ! String do
  if Bytes.length(input) > maximum do
    Err("push binding wire oversized")
  else
    case reader(input, maximum) do
      Err(_) -> Err("invalid push binding wire")
      Ok(output) -> Ok(output)
    end
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes ! String do
  case read_fixed(state, length) do
    Err(_) -> Err("invalid push binding wire")
    Ok((next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt ! String do
  case read_u8(state) do
    Err(_) -> Err("invalid push binding wire")
    Ok((next, value)) -> Ok(ReadInt {
      state : next,
      value : value
    })
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide ! String do
  let value = take_fixed(state, 8) ?
  case Bytes.read_u64_be(value.value, 0) do
    Err(_) -> Err("invalid push binding revision")
    Ok(revision) -> Ok(ReadWide {
      state : value.state,
      value : revision
    })
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes ! String do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid push binding wire")
    Ok((next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
  end
end

fn done(state :: BinaryReader) -> Result <(), String > do
  case finish(state) do
    Err(_) -> Err("invalid push binding wire")
    Ok(_) -> Ok(nil)
  end
end

fn valid_revision(revision :: U64) -> Bool ! String do
  let zero = U64.parse("0") ?
  let maximum = U64.parse("9223372036854775807") ?
  Ok(U64.compare(revision, zero) > 0 && U64.compare(revision, maximum) <= 0)
end

fn bind_content(value :: PushBindRequest) -> Bytes ! String do
  let ciphertext_length = Bytes.length(value.provider_token_ciphertext)
  if Bytes.length(value.mailbox_token_hash) != 32 || Bytes.length(value.wake_token_hash) != 32 || Bytes.secure_equals(value.mailbox_token_hash,
  value.wake_token_hash) || !(valid_revision(value.revision) ?) || value.provider != 1 || ciphertext_length > 580 || !valid_sealed_provider_token(value.provider_token_ciphertext) do
    Err("invalid push binding")
  else
    join([byte(1) ?, Bytes.from_utf8("PSB"), value.mailbox_token_hash, value.wake_token_hash, write_u64(value.revision) ?, byte(value.provider) ?, vector(value.provider_token_ciphertext) ?],
    0,
    Bytes.empty())
  end
end

fn unbind_content(value :: PushUnbindRequest) -> Bytes ! String do
  if Bytes.length(value.mailbox_token_hash) != 32 || !(valid_revision(value.revision) ?) do
    Err("invalid push unbind")
  else
    join([byte(1) ?, Bytes.from_utf8("PSU"), value.mailbox_token_hash, write_u64(value.revision) ?],
    0,
    Bytes.empty())
  end
end

pub fn push_bind_signing_bytes(value :: PushBindRequest) -> Bytes ! String do
  append(Bytes.from_utf8("mesh-msg/v1/push-bind"), bind_content(value) ?)
end

pub fn push_unbind_signing_bytes(value :: PushUnbindRequest) -> Bytes ! String do
  append(Bytes.from_utf8("mesh-msg/v1/push-unbind"), unbind_content(value) ?)
end

pub fn encode_push_bind(value :: PushBindRequest) -> Bytes ! String do
  if Bytes.length(value.signature) != 64 do
    Err("invalid push bind signature")
  else
    append(bind_content(value) ?, value.signature)
  end
end

pub fn decode_push_bind(input :: Bytes) -> PushBindRequest ! String do
  let version = take_u8(start(input, 725) ?) ?
  let magic = take_fixed(version.state, 3) ?
  let mailbox_token_hash = take_fixed(magic.state, 32) ?
  let wake_token_hash = take_fixed(mailbox_token_hash.state, 32) ?
  let revision = take_u64(wake_token_hash.state) ?
  let provider = take_u8(revision.state) ?
  let ciphertext = take_vector(provider.state, 580) ?
  let signature = take_fixed(ciphertext.state, 64) ?
  done(signature.state) ?
  if version.value != 1 || !Bytes.secure_equals(magic.value, Bytes.from_utf8("PSB")) do
    Err("invalid push bind wire")
  else
    let value = PushBindRequest {
      mailbox_token_hash : mailbox_token_hash.value,
      wake_token_hash : wake_token_hash.value,
      revision : revision.value,
      provider : provider.value,
      provider_token_ciphertext : ciphertext.value,
      signature : signature.value
    }
    let _ = bind_content(value) ?
    Ok(value)
  end
end

pub fn encode_push_unbind(value :: PushUnbindRequest) -> Bytes ! String do
  if Bytes.length(value.signature) != 64 do
    Err("invalid push unbind signature")
  else
    append(unbind_content(value) ?, value.signature)
  end
end

pub fn decode_push_unbind(input :: Bytes) -> PushUnbindRequest ! String do
  let version = take_u8(start(input, 108) ?) ?
  let magic = take_fixed(version.state, 3) ?
  let mailbox_token_hash = take_fixed(magic.state, 32) ?
  let revision = take_u64(mailbox_token_hash.state) ?
  let signature = take_fixed(revision.state, 64) ?
  done(signature.state) ?
  if version.value != 1 || !Bytes.secure_equals(magic.value, Bytes.from_utf8("PSU")) do
    Err("invalid push unbind wire")
  else
    let value = PushUnbindRequest {
      mailbox_token_hash : mailbox_token_hash.value,
      revision : revision.value,
      signature : signature.value
    }
    let _ = unbind_content(value) ?
    Ok(value)
  end
end
