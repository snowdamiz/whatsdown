##! Inactive CBF1 fragment syntax. Parsing is not authentication or admission.
from Protocol.V1 import ProtocolError
from Protocol.WirePrimitives import (
  protocol_byte,
  protocol_is_zero,
  protocol_join,
  protocol_open,
  protocol_require_end,
  protocol_take_fixed,
  protocol_take_u16,
  protocol_take_u64,
  protocol_take_u8,
  protocol_valid_magic,
  protocol_write_u16,
  protocol_write_u64
)

pub type BraidFragmentKind do
  NoBraidFragment
  BraidHeaderFragment
  BraidVectorFragment
  BraidVectorAckFragment
  BraidAckFragment
  BraidFirstFragment
  BraidSecondFragment
end deriving(Eq, Debug)

pub struct BraidFragment do
  kind :: BraidFragmentKind
  configuration :: Bytes
  session :: Bytes
  epoch :: U64
  index :: Int
  word :: Bytes
end

fn kind_tag(kind :: BraidFragmentKind) -> Int do
  case kind do
    NoBraidFragment -> 0
    BraidHeaderFragment -> 1
    BraidVectorFragment -> 2
    BraidVectorAckFragment -> 3
    BraidAckFragment -> 4
    BraidFirstFragment -> 5
    BraidSecondFragment -> 6
  end
end

fn parse_kind(tag :: Int) -> BraidFragmentKind!ProtocolError do
  case tag do
    0 -> Ok(NoBraidFragment)
    1 -> Ok(BraidHeaderFragment)
    2 -> Ok(BraidVectorFragment)
    3 -> Ok(BraidVectorAckFragment)
    4 -> Ok(BraidAckFragment)
    5 -> Ok(BraidFirstFragment)
    6 -> Ok(BraidSecondFragment)
    _ -> Err(MalformedEncoding)
  end
end

pub fn braid_fragment_source_length(kind :: BraidFragmentKind) -> Int do
  case kind do
    NoBraidFragment -> 0
    BraidHeaderFragment -> 96
    BraidVectorFragment -> 1152
    BraidVectorAckFragment -> 1152
    BraidAckFragment -> 0
    BraidFirstFragment -> 960
    BraidSecondFragment -> 160
  end
end

fn valid_scope(configuration :: Bytes, session :: Bytes) -> Result<(), ProtocolError> do
  if Bytes.length(configuration) == 32 && Bytes.length(session) == 32 do
    Ok(nil)
  else
    Err(InvalidFieldLength)
  end
end

## Parameters are derived from the kind. A control has no data/index field.
pub fn encode_braid_fragment(value :: BraidFragment) -> Bytes!ProtocolError do
  valid_scope(value.configuration, value.session)?
  if protocol_is_zero(value.epoch) do
    return Err(InvalidPolicy)
  end
  let length = braid_fragment_source_length(value.kind)
  if length == 0 do
    if value.index != 0 || Bytes.length(value.word) != 0 do
      return Err(MalformedEncoding)
    end
  else if value.index < 0 || value.index > 65535 || Bytes.length(value.word) != 64 do
    return Err(MalformedEncoding)
  end
  let header = protocol_join([
      Bytes.from_utf8("CBF1"),
      protocol_byte(1)?,
      protocol_byte(kind_tag(value.kind))?,
      value.configuration,
      value.session,
      protocol_write_u64(value.epoch)?
    ],
    0,
    Bytes.empty())?
  if length == 0 do
    Ok(header)
  else
    protocol_join([
        header,
        protocol_write_u16(length)?,
        protocol_write_u16(64)?,
        protocol_write_u16(value.index)?,
        value.word
      ],
      0,
      Bytes.empty())
  end
end

## The expected scope comes from the caller's captured authenticated session.
## This only parses public syntax; the coordinator still authenticates the
## envelope and applies its epoch/phase policy before committing anything.
pub fn decode_braid_fragment(input :: Bytes,
  configuration :: Bytes,
  session :: Bytes) -> BraidFragment!ProtocolError do
  valid_scope(configuration, session)?
  let size = Bytes.length(input)
  if size != 78 && size != 148 do
    return Err(MalformedEncoding)
  end
  let magic = protocol_take_fixed(protocol_open(input, 148)?, 4)?
  protocol_valid_magic(magic.value, "CBF1")?
  let profile = protocol_take_u8(magic.state)?
  if profile.value != 1 do
    return Err(UnsupportedVersion)
  end
  let tag = protocol_take_u8(profile.state)?
  let kind = parse_kind(tag.value)?
  let length = braid_fragment_source_length(kind)
  if size != (if length == 0 do
      78
    else
      148
    end) do
    return Err(MalformedEncoding)
  end
  let config = protocol_take_fixed(tag.state, 32)?
  let session_id = protocol_take_fixed(config.state, 32)?
  if !Bytes.secure_equals(config.value, configuration)
    || !Bytes.secure_equals(session_id.value, session) do
    return Err(InvalidPolicy)
  end
  let epoch = protocol_take_u64(session_id.state)?
  if protocol_is_zero(epoch.value) do
    return Err(InvalidPolicy)
  end
  if length == 0 do
    protocol_require_end(epoch.state)?
    Ok(BraidFragment {
      kind: kind,
      configuration: configuration,
      session: session,
      epoch: epoch.value,
      index: 0,
      word: Bytes.empty()
    })
  else
    let original_length = protocol_take_u16(epoch.state)?
    let width = protocol_take_u16(original_length.state)?
    if original_length.value != length || width.value != 64 do
      return Err(MalformedEncoding)
    end
    let index = protocol_take_u16(width.state)?
    let word = protocol_take_fixed(index.state, 64)?
    protocol_require_end(word.state)?
    Ok(BraidFragment {
      kind: kind,
      configuration: configuration,
      session: session,
      epoch: epoch.value,
      index: index.value,
      word: word.value
    })
  end
end
