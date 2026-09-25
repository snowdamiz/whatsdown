from Transport.Padding import pad_message, unpad_message
from Identity.Device import is_retryable_verification_crypto_error
from Binary.Reader import BinaryReader, finish, read_fixed, read_u8, read_vector, reader
from Protocol.DirectoryWire import decode_directory_entry, encode_directory_entry
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle
from Protocol.V1 import AccountIdentity, DeviceCredential, DirectoryEntry, PrekeyBundle

pub type TransportPacket do
  InitialPacket(account_identity :: Bytes, message :: Bytes)
  RatchetPacket(message :: Bytes)
end deriving(Eq, Debug)

pub struct ClientProfile do
  encoded :: Bytes
  username :: String
  account_id :: Bytes
  device_id :: Bytes
  entry :: DirectoryEntry
  account :: AccountIdentity
  bundle :: PrekeyBundle
  credential :: DeviceCredential
end

pub struct InitialPlaintext do
  profile :: Bytes
  inner :: Bytes
end

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

fn append(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("transport packet too large")
    Ok(value)
  end
end

fn join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index))?)
  end
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid transport packet")
    Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes!String do
  let length = case U64.parse(Int.to_string(Bytes.length(value))) do
    Err(_) -> Err("invalid transport packet length")
    Ok(parsed)
  end?
  let encoded = case Bytes.write_u32_be(length) do
    Err(_) -> Err("invalid transport packet length")
    Ok(output)
  end?
  append(encoded, value)
end

fn client_append(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("byte_concatenation_failed")
    Ok(value)
  end
end

fn client_write_u32(value :: Int) -> Bytes!String do
  let wide = case U64.parse(Int.to_string(value)) do
    Err(_) -> Err("invalid_wide_integer")
    Ok(parsed)
  end?
  case Bytes.write_u32_be(wide) do
    Err(_) -> Err("integer_encoding_failed")
    Ok(encoded)
  end
end

fn client_vector(value :: Bytes) -> Bytes!String do
  client_append(client_write_u32(Bytes.length(value))?, value)
end

fn client_join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    client_join(parts, index + 1, client_append(output, List.get(parts, index))?)
  end
end

pub fn encode_packet(value :: TransportPacket) -> Bytes!String do
  let encoded = case value do
    InitialPacket(account_identity, message) -> if Bytes.length(account_identity) == 0 || Bytes.length(account_identity) > 16582 || Bytes.length(message) == 0 || Bytes.length(message) > 48800 do
      Err("invalid initial transport packet")
    else
      join([byte(1)?, Bytes.from_utf8("M8P"), byte(1)?, vector(account_identity)?, vector(message)?],
        0,
        Bytes.empty())
    end
    RatchetPacket(message) -> if Bytes.length(message) == 0 || Bytes.length(message) > 65523 do
      Err("invalid ratchet transport packet")
    else
      join([byte(1)?, Bytes.from_utf8("M8P"), byte(2)?, vector(Bytes.empty())?, vector(message)?],
        0,
        Bytes.empty())
    end
  end?
  if Bytes.length(encoded) > 65536 do
    Err("transport packet too large")
  else
    Ok(encoded)
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt!String do
  case read_u8(state) do
    Err(_) -> Err("invalid transport packet")
    Ok((next, value)) -> Ok(ReadInt { state: next, value: value })
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes!String do
  case read_fixed(state, length) do
    Err(_) -> Err("invalid transport packet")
    Ok((next, value)) -> Ok(ReadBytes { state: next, value: value })
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes!String do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid transport packet")
    Ok((next, value)) -> Ok(ReadBytes { state: next, value: value })
  end
end

pub fn decode_packet(input :: Bytes) -> TransportPacket!String do
  let state = case reader(input, 65536) do
    Err(_) -> Err("invalid transport packet")
    Ok(value)
  end?
  let version = take_u8(state)?
  let magic = take_fixed(version.state, 3)?
  let kind = take_u8(magic.state)?
  let account = take_vector(kind.state, 16582)?
  let message = take_vector(account.state, 65523)?
  case finish(message.state) do
    Err(_) -> Err("invalid transport packet")
    Ok(_) -> Ok(nil)
  end?
  if version.value != 1 || !Bytes.secure_equals(magic.value, Bytes.from_utf8("M8P")) || Bytes.length(message.value) == 0 do
    Err("invalid transport packet")
  else if kind.value == 1 && Bytes.length(account.value) > 0 && Bytes.length(message.value) <= 48800 do
    Ok(InitialPacket(account.value, message.value))
  else if kind.value == 2 && Bytes.length(account.value) == 0 do
    Ok(RatchetPacket(message.value))
  else
    Err("invalid transport packet")
  end
end

pub fn is_sealed_initial_packet(input :: Bytes) -> Bool do
  if Bytes.length(input) < 52 || Bytes.length(input) > 65536 do
    false
  else
    case Bytes.slice(input, 0, 4) do
      Err(_) -> false
      Ok(header) -> Bytes.to_hex(header) == "01534950"
    end
  end
end

pub fn seal_initial_packet(account_identity :: Bytes,
  message :: Bytes,
  recipient :: X25519PublicKey) -> Bytes!String do
  let plaintext = pad_message(encode_packet(InitialPacket(account_identity, message))?, 52)?
  if Bytes.length(plaintext) > 65484 do
    Err("initial transport packet too large")
  else
    let info = Bytes.from_utf8("mesh-msg/v1/recipient-initial")
    let sealed = case Crypto.hpke_seal(recipient, info, recipient.bytes, plaintext) do
      Err(_) -> Err("initial packet encryption failed")
      Ok(value)
    end?
    join([byte(1)?, Bytes.from_utf8("SIP"), sealed], 0, Bytes.empty())
  end
end

pub fn open_initial_packet(input :: Bytes, recipient :: borrow X25519PrivateKey) -> TransportPacket!String do
  if !is_sealed_initial_packet(input) do
    Err("invalid sealed initial packet")
  else
    let public_key = case Crypto.x25519_public(recipient) do
      Err(_) -> Err("initial_crypto_failed")
      Ok(value)
    end?
    let plaintext = case Crypto.hpke_open(recipient,
      Bytes.from_utf8("mesh-msg/v1/recipient-initial"),
      public_key.bytes,
      Bytes.slice(input, 4, Bytes.length(input) - 4)?) do
      Err(error) -> if is_retryable_verification_crypto_error(error) do
        Err("initial_crypto_failed")
      else
        Err("initial packet authentication failed")
      end
      Ok(value)
    end?
    case decode_packet(unpad_message(plaintext, 52)?) do
      Ok(InitialPacket(account, message))
      _ -> Err("invalid sealed initial packet")
    end
  end
end

fn profile_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes!String do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid_profile")
    Ok((next, value)) -> Ok(ReadBytes { state: next, value: value })
  end
end

fn profile_utf8(value :: Bytes) -> String!String do
  case Bytes.to_utf8(value) do
    Err(_) -> Err("invalid_profile")
    Ok(text)
  end
end

fn profile_directory_bytes(value :: DirectoryEntry) -> Bytes!String do
  case encode_directory_entry(value) do
    Err(_) -> Err("directory_encoding_failed")
    Ok(encoded)
  end
end

pub fn encode_client_profile(value :: DirectoryEntry, account_id :: Bytes, device_id :: Bytes) -> Bytes!String do
  client_join([
      client_vector(Bytes.from_utf8(value.username))?,
      client_vector(account_id)?,
      client_vector(device_id)?,
      client_vector(profile_directory_bytes(value)?)?
    ],
    0,
    Bytes.empty())
end

pub fn decode_client_profile(encoded :: Bytes) -> ClientProfile!String do
  case reader(encoded, 36134) do
    Err(_) -> Err("invalid_profile")
    Ok(state) -> do
      let username_bytes = profile_vector(state, 64)?
      let account_id = profile_vector(username_bytes.state, 32)?
      let device_id = profile_vector(account_id.state, 16)?
      let entry_bytes = profile_vector(device_id.state, 36006)?
      case finish(entry_bytes.state) do
        Err(_) -> Err("invalid_profile")
        Ok(_) -> do
          let username = profile_utf8(username_bytes.value)?
          let entry = case decode_directory_entry(entry_bytes.value) do
            Err(_) -> Err("invalid_profile")
            Ok(value)
          end?
          let account = case decode_account_identity(entry.account_identity) do
            Err(_) -> Err("invalid_profile")
            Ok(value)
          end?
          let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
            Err(_) -> Err("invalid_profile")
            Ok(value)
          end?
          let credential = case decode_device_credential(bundle.device_credential) do
            Err(_) -> Err("invalid_profile")
            Ok(value)
          end?
          let mismatch = entry.username != username || !Bytes.secure_equals(account_id.value,
            account.account_id) || !Bytes.secure_equals(device_id.value, credential.device_id) || !Bytes.secure_equals(account.account_id,
            credential.account_id)
          if mismatch do
            Err("invalid_profile")
          else
            Ok(ClientProfile {
              encoded: encoded,
              username: username,
              account_id: account_id.value,
              device_id: device_id.value,
              entry: entry,
              account: account,
              bundle: bundle,
              credential: credential
            })
          end
        end
      end
    end
  end
end

fn plaintext_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes!String do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid_initial_plaintext")
    Ok((next, value)) -> Ok(ReadBytes { state: next, value: value })
  end
end

pub fn encode_initial_plaintext(profile :: Bytes, inner :: Bytes) -> Bytes!String do
  client_join([client_vector(profile)?, client_vector(inner)?], 0, Bytes.empty())
end

pub fn decode_initial_plaintext(input :: Bytes) -> InitialPlaintext!String do
  case reader(input, 65536) do
    Err(_) -> Err("invalid_initial_plaintext")
    Ok(state) -> do
      let profile = plaintext_vector(state, 36134)?
      let inner = plaintext_vector(profile.state, 49144)?
      case finish(inner.state) do
        Err(_) -> Err("invalid_initial_plaintext")
        Ok(_) -> Ok(InitialPlaintext { profile: profile.value, inner: inner.value })
      end
    end
  end
end

pub fn session_aad(session_id :: Bytes) -> Bytes!String do
  Ok(Crypto.sha256(client_append(Bytes.from_utf8("mesh-msg/mobile/ratchet-aad/v1"), session_id)?))
end

## A direct conversation is named after its two accounts, so every device of
## either account, on any client, arrives at the same name with nothing to
## coordinate, and a receiver checks the name instead of trusting it.

pub fn direct_conversation_id(first_account_id :: Bytes, second_account_id :: Bytes) -> Bytes!String do
  let (lower, higher) = if account_before(first_account_id, second_account_id, 0)? do
    (first_account_id, second_account_id)
  else
    (second_account_id, first_account_id)
  end
  let named = join([Bytes.from_utf8("mesh-msg/mobile/conversation/v2"), lower, higher],
    0,
    Bytes.empty())?
  case Bytes.slice(Crypto.sha256(named), 0, 16) do
    Err(_) -> Err("conversation_id_failed")
    Ok(value)
  end
end

fn account_before(left :: Bytes, right :: Bytes, index :: Int) -> Bool!String do
  if Bytes.length(left) != Bytes.length(right) do
    Err("invalid_account_id")
  else if index >= Bytes.length(left) do
    Ok(false)
  else
    let left_byte = Bytes.get(left, index)?
    let right_byte = Bytes.get(right, index)?
    if left_byte == right_byte do
      account_before(left, right, index + 1)
    else
      Ok(left_byte < right_byte)
    end
  end
end
