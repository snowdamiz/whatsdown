from Binary.Reader import BinaryReader, finish, read_fixed, read_u16_be, read_u8, read_vector, reader

pub type ProtocolError do
  UnsupportedVersion

  UnsupportedSuite

  InvalidFieldLength

  InvalidPaddingBucket

  InvalidExpiration

  PostQuantumNotSupported

  OversizedInput

  MalformedEncoding
end deriving(Eq, Debug)

pub struct OuterEnvelope do
  version :: Int
  envelope_id :: Bytes
  mailbox_token :: Bytes
  suite :: Int
  expiration :: U64
  padding_bucket :: Int
  ciphertext :: Bytes
end

pub struct DeviceCredential do
  version :: Int
  suite :: Int
  account_id :: Bytes
  device_id :: Bytes
  signing_public_key :: Bytes
  dh_public_key :: Bytes
  post_quantum_public_key :: Bytes
  capabilities :: U64
  created_at :: U64
  expires_at :: U64
  directory_sequence :: U64
  signature :: Bytes
end

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadWide do
  state :: BinaryReader
  value :: U64
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

fn append(output :: Bytes, value :: Bytes) -> Bytes ! ProtocolError do
  case Bytes.concat(output, value) do
    Err( _) -> Err(OversizedInput)
    Ok( bytes) -> Ok(bytes)
  end
end

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! ProtocolError do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn byte(value :: Int) -> Bytes ! ProtocolError do
  case Bytes.from_list([value]) do
    Err( _) -> Err(MalformedEncoding)
    Ok( bytes) -> Ok(bytes)
  end
end

fn write_u16(value :: Int) -> Bytes ! ProtocolError do
  case Bytes.write_u16_be(value) do
    Err( _) -> Err(MalformedEncoding)
    Ok( bytes) -> Ok(bytes)
  end
end

fn write_u32(value :: U64) -> Bytes ! ProtocolError do
  case Bytes.write_u32_be(value) do
    Err( _) -> Err(MalformedEncoding)
    Ok( bytes) -> Ok(bytes)
  end
end

fn write_length(value :: Int) -> Bytes ! ProtocolError do
  case value
    |> Int.to_string()
    |> U64.parse() do
    Err( _) -> Err(MalformedEncoding)
    Ok( parsed) -> write_u32(parsed)
  end
end

fn write_u64(value :: U64) -> Bytes ! ProtocolError do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err(MalformedEncoding)
    Ok( bytes) -> Ok(bytes)
  end
end

fn vector(value :: Bytes) -> Bytes ! ProtocolError do
  join([write_length(Bytes.length(value)) ?, value], 0, Bytes.empty())
end

fn open(input :: Bytes, maximum :: Int) -> BinaryReader ! ProtocolError do
  if Bytes.length(input) > maximum do
    Err(OversizedInput)
  else
    case reader(input, maximum) do
      Err( _) -> Err(MalformedEncoding)
      Ok( state) -> Ok(state)
    end
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt ! ProtocolError do
  case read_u8(state) do
    Err( _) -> Err(MalformedEncoding)
    Ok( ( next, value)) -> Ok(ReadInt {
      state : next,
      value : value
    })
    Ok( _) -> Err(MalformedEncoding)
  end
end

fn take_u16(state :: BinaryReader) -> ReadInt ! ProtocolError do
  case read_u16_be(state) do
    Err( _) -> Err(MalformedEncoding)
    Ok( ( next, value)) -> Ok(ReadInt {
      state : next,
      value : value
    })
    Ok( _) -> Err(MalformedEncoding)
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes ! ProtocolError do
  case read_fixed(state, length) do
    Err( _) -> Err(MalformedEncoding)
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err(MalformedEncoding)
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes ! ProtocolError do
  case read_vector(state, maximum) do
    Err( _) -> Err(MalformedEncoding)
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err(MalformedEncoding)
  end
end

fn take_u32(state :: BinaryReader) -> ReadWide ! ProtocolError do
  let bytes = take_fixed(state, 4) ?
  case Bytes.read_u32_be(bytes.value, 0) do
    Err( _) -> Err(MalformedEncoding)
    Ok( value) -> Ok(ReadWide {
      state : bytes.state,
      value : value
    })
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide ! ProtocolError do
  let bytes = take_fixed(state, 8) ?
  case Bytes.read_u64_be(bytes.value, 0) do
    Err( _) -> Err(MalformedEncoding)
    Ok( value) -> Ok(ReadWide {
      state : bytes.state,
      value : value
    })
  end
end

fn as_int(value :: U64) -> Int ! ProtocolError do
  case U64.to_int(value) do
    Err( _) -> Err(MalformedEncoding)
    Ok( result) -> Ok(result)
  end
end

fn require_end(state :: BinaryReader) -> Result <(), ProtocolError > do
  case finish(state) do
    Err( _) -> Err(MalformedEncoding)
    Ok( _) -> Ok(nil)
  end
end

fn supported_bucket(value :: Int) -> Bool do
  value == 256 || value == 512 || value == 1024 || value == 2048 || value == 4096 || value == 8192 || value == 16384 || value == 32768 || value == 65536
end

fn validate_outer(value :: OuterEnvelope) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if value.suite != 1 do
      Err(UnsupportedSuite)
    else
      if Bytes.length(value.envelope_id) != 16 || Bytes.length(value.mailbox_token) != 32 do
        Err(InvalidFieldLength)
      else
        if !supported_bucket(value.padding_bucket) || Bytes.length(value.ciphertext) > value.padding_bucket do
          Err(InvalidPaddingBucket)
        else
          Ok(nil)
        end
      end
    end
  end
end

pub fn encode_outer_envelope(value :: OuterEnvelope) -> Bytes ! ProtocolError do
  validate_outer(value) ?
  join([byte(value.version) ?, Bytes.from_utf8("MSG"), value.envelope_id, value.mailbox_token, write_u16(value.suite) ?, write_u64(value.expiration) ?, write_length(value.padding_bucket) ?, vector(value.ciphertext) ?],
  0,
  Bytes.empty())
end

pub fn decode_outer_envelope(input :: Bytes) -> OuterEnvelope ! ProtocolError do
  let version = take_u8(open(input, 65606) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("MSG")) do
      Err(MalformedEncoding)
    else
      let envelope_id = take_fixed(magic.state, 16) ?
      let mailbox_token = take_fixed(envelope_id.state, 32) ?
      let suite = take_u16(mailbox_token.state) ?
      let expiration = take_u64(suite.state) ?
      let padding = take_u32(expiration.state) ?
      let padding_bucket = as_int(padding.value) ?
      let ciphertext = take_vector(padding.state, 65536) ?
      require_end(ciphertext.state) ?
      let value = OuterEnvelope {
        version : version.value,
        envelope_id : envelope_id.value,
        mailbox_token : mailbox_token.value,
        suite : suite.value,
        expiration : expiration.value,
        padding_bucket : padding_bucket,
        ciphertext : ciphertext.value
      }
      validate_outer(value) ?
      Ok(value)
    end
  end
end

fn validate_credential(value :: DeviceCredential) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if value.suite != 1 do
      Err(UnsupportedSuite)
    else
      if Bytes.length(value.account_id) != 32 || Bytes.length(value.device_id) != 16 || Bytes.length(value.signing_public_key) != 32 || Bytes.length(value.dh_public_key) != 32 || Bytes.length(value.signature) != 64 do
        Err(InvalidFieldLength)
      else
        if Bytes.length(value.post_quantum_public_key) != 0 do
          Err(PostQuantumNotSupported)
        else
          if U64.compare(value.expires_at, value.created_at) < 0 do
            Err(InvalidExpiration)
          else
            Ok(nil)
          end
        end
      end
    end
  end
end

pub fn encode_device_credential(value :: DeviceCredential) -> Bytes ! ProtocolError do
  validate_credential(value) ?
  join([byte(value.version) ?, write_u16(value.suite) ?, value.account_id, value.device_id, value.signing_public_key, value.dh_public_key, vector(value.post_quantum_public_key) ?, write_u32(value.capabilities) ?, write_u64(value.created_at) ?, write_u64(value.expires_at) ?, write_u64(value.directory_sequence) ?, value.signature],
  0,
  Bytes.empty())
end

pub fn decode_device_credential(input :: Bytes) -> DeviceCredential ! ProtocolError do
  let version = take_u8(open(input, 4307) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let suite = take_u16(version.state) ?
    let account_id = take_fixed(suite.state, 32) ?
    let device_id = take_fixed(account_id.state, 16) ?
    let signing_public_key = take_fixed(device_id.state, 32) ?
    let dh_public_key = take_fixed(signing_public_key.state, 32) ?
    let post_quantum_public_key = take_vector(dh_public_key.state, 4096) ?
    let capabilities = take_u32(post_quantum_public_key.state) ?
    let created_at = take_u64(capabilities.state) ?
    let expires_at = take_u64(created_at.state) ?
    let directory_sequence = take_u64(expires_at.state) ?
    let signature = take_fixed(directory_sequence.state, 64) ?
    require_end(signature.state) ?
    let value = DeviceCredential {
      version : version.value,
      suite : suite.value,
      account_id : account_id.value,
      device_id : device_id.value,
      signing_public_key : signing_public_key.value,
      dh_public_key : dh_public_key.value,
      post_quantum_public_key : post_quantum_public_key.value,
      capabilities : capabilities.value,
      created_at : created_at.value,
      expires_at : expires_at.value,
      directory_sequence : directory_sequence.value,
      signature : signature.value
    }
    validate_credential(value) ?
    Ok(value)
  end
end
