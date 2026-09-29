##! Renewal of a device's credential, signed prekey and ML-KEM prekey.
##!
##! A device's credential, signed prekey and ML-KEM prekey sit inside the
##! logged device set, so each renewal is a logged transition. The device that
##! holds the account key renews itself in one. A linked device cannot sign a
##! credential: it publishes a request in its own bundle (the keys it wants
##! next, signed with its device key), and the account key answers with a
##! credential for exactly those keys.

from Identity.Device import DeviceKeys
from Prekeys.Bundle import (
  PostQuantumPrekeySecrets,
  PrekeyError,
  SignedPrekeySecrets,
  generate_signed_prekey,
  signed_prekey_signature_valid
)
from Protocol.IdentityWire import decode_device_credential, encode_device_credential
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import DeviceCredential, PrekeyBundle, ProtocolError, ProtocolExtension
from Protocol.WirePrimitives import (
  protocol_byte,
  protocol_is_zero,
  protocol_join,
  protocol_open,
  protocol_require_end,
  protocol_take_fixed,
  protocol_take_u64,
  protocol_take_u8,
  protocol_valid_magic,
  protocol_write_u64
)

pub struct RenewalRequest do
  version :: Int
  account_id :: Bytes
  device_id :: Bytes
  signed_prekey_id :: U64
  signed_prekey :: Bytes
  expires_at :: U64
  signed_prekey_signature :: Bytes
  post_quantum_prekey :: Bytes
  signature :: Bytes
end

## What the directory does with a registration for a device it already holds:
## take it as the next logged transition, answer that it is already registered
## (the directory holds it or something newer), or refuse it.

pub type BundleTransition do
  TransitionAccepted
  TransitionReplayed
  TransitionRefused
end

fn renewal_zeroes(length :: Int) -> Bytes!ProtocolError do
  case Bytes.repeat(0, length) do
    Err(_) -> Err(InvalidFieldLength)
    Ok(value)
  end
end

pub fn encode_renewal_request(value :: RenewalRequest) -> Bytes!ProtocolError do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else if Bytes.length(value.account_id) != 32
    || Bytes.length(value.device_id) != 16
    || Bytes.length(value.signed_prekey) != 32
    || Bytes.length(value.signed_prekey_signature) != 64
    || Bytes.length(value.post_quantum_prekey) != 1184
    || Bytes.length(value.signature) != 64 do
    Err(InvalidFieldLength)
  else if protocol_is_zero(value.signed_prekey_id) do
    Err(InvalidFieldLength)
  else
    protocol_join([
        protocol_byte(value.version)?,
        Bytes.from_utf8("RNW"),
        value.account_id,
        value.device_id,
        protocol_write_u64(value.signed_prekey_id)?,
        value.signed_prekey,
        protocol_write_u64(value.expires_at)?,
        value.signed_prekey_signature,
        value.post_quantum_prekey,
        value.signature
      ],
      0,
      Bytes.empty())
  end
end

pub fn decode_renewal_request(input :: Bytes) -> RenewalRequest!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 1412)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "RNW")?
    let account_id = protocol_take_fixed(magic.state, 32)?
    let device_id = protocol_take_fixed(account_id.state, 16)?
    let signed_prekey_id = protocol_take_u64(device_id.state)?
    let signed_prekey = protocol_take_fixed(signed_prekey_id.state, 32)?
    let expires_at = protocol_take_u64(signed_prekey.state)?
    let signed_prekey_signature = protocol_take_fixed(expires_at.state, 64)?
    let post_quantum_prekey = protocol_take_fixed(signed_prekey_signature.state, 1184)?
    let signature = protocol_take_fixed(post_quantum_prekey.state, 64)?
    protocol_require_end(signature.state)?
    let value = RenewalRequest {
      version: version.value,
      account_id: account_id.value,
      device_id: device_id.value,
      signed_prekey_id: signed_prekey_id.value,
      signed_prekey: signed_prekey.value,
      expires_at: expires_at.value,
      signed_prekey_signature: signed_prekey_signature.value,
      post_quantum_prekey: post_quantum_prekey.value,
      signature: signature.value
    }
    encode_renewal_request(value)?
    Ok(value)
  end
end

fn request_signing_bytes(value :: RenewalRequest) -> Bytes!ProtocolError do
  protocol_join([
      Bytes.from_utf8("mesh-msg/v1/device-renewal-request"),
      encode_renewal_request(%{value | signature: renewal_zeroes(64)?})?
    ],
    0,
    Bytes.empty())
end

## The next signed prekey, signed for the hybrid suite whatever this device's
## credential says now: the credential that answers a request is hybrid, so a
## classical device comes out of its renewal hybrid.

pub fn generate_renewal_signed_prekey(device :: borrow DeviceKeys,
  credential :: DeviceCredential,
  id :: U64,
  expires_at :: U64) -> SignedPrekeySecrets!PrekeyError do
  generate_signed_prekey(device, %{credential | version: 1, suite: 2}, id, expires_at)
end

pub fn issue_renewal_request(device :: borrow DeviceKeys,
  credential :: DeviceCredential,
  next_signed :: borrow SignedPrekeySecrets,
  next_post_quantum :: borrow PostQuantumPrekeySecrets) -> RenewalRequest!PrekeyError do
  let unsigned = RenewalRequest {
    version: 1,
    account_id: credential.account_id,
    device_id: credential.device_id,
    signed_prekey_id: next_signed.id,
    signed_prekey: next_signed.public_key.bytes,
    expires_at: next_signed.expires_at,
    signed_prekey_signature: next_signed.signature.bytes,
    post_quantum_prekey: next_post_quantum.public_key.bytes,
    signature: case renewal_zeroes(64) do
      Err(error) -> Err(ProtocolFailure(error))
      Ok(value)
    end?
  }
  let signing_bytes = case request_signing_bytes(unsigned) do
    Err(error) -> Err(ProtocolFailure(error))
    Ok(value)
  end?
  case Crypto.sign(device.signing_private_key, signing_bytes) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(signature) -> Ok(%{unsigned | signature: signature.bytes})
  end
end

## A request made by the device this credential names, with its device key,
## for a signed prekey that device signed for the hybrid suite.

pub fn verify_renewal_request(credential :: DeviceCredential, request :: RenewalRequest) -> Bool do
  let names_device = request.version == 1
    && Bytes.secure_equals(request.account_id, credential.account_id)
    && Bytes.secure_equals(request.device_id, credential.device_id)
  if !names_device || Bytes.length(credential.signing_public_key) != 32 do
    false
  else
    let prekey_signed = signed_prekey_signature_valid(%{credential | version: 1, suite: 2},
      request.signed_prekey_id,
      request.signed_prekey,
      request.expires_at,
      request.signed_prekey_signature)
    let request_signed = case request_signing_bytes(request) do
      Err(_) -> false
      Ok(signing_bytes) -> case Crypto.verify(SigningPublicKey {
          bytes: credential.signing_public_key
        },
        signing_bytes,
        Signature { bytes: request.signature }) do
        Err(_) -> false
        Ok(valid) -> valid
      end
    end
    prekey_signed && request_signed
  end
end

# The request travels as bundle extensions 1 and 2: one extension holds at
# most 1,024 bytes and a request is 1,412. No other extension uses them.

fn renewal_extension_id(id :: Int) -> Bool do
  id == 1 || id == 2
end

fn find_extension(values :: List<ProtocolExtension>, id :: Int, index :: Int) -> Option<Bytes> do
  if index >= List.length(values) do
    None
  else
    let extension = List.get(values, index)
    if extension.id == id do
      Some(extension.value)
    else
      find_extension(values, id, index + 1)
    end
  end
end

fn other_extensions(values :: List<ProtocolExtension>,
  index :: Int,
  output :: List<ProtocolExtension>) -> List<ProtocolExtension> do
  if index >= List.length(values) do
    output
  else
    let extension = List.get(values, index)
    if renewal_extension_id(extension.id) do
      other_extensions(values, index + 1, output)
    else
      other_extensions(values, index + 1, List.append(output, extension))
    end
  end
end

fn prekey_protocol(value :: Result<Bytes, ProtocolError>) -> Bytes!PrekeyError do
  case value do
    Err(error) -> Err(ProtocolFailure(error))
    Ok(output)
  end
end

fn joined_request(first :: Bytes, second :: Bytes) -> Option<RenewalRequest>!PrekeyError do
  case Bytes.concat(first, second) do
    Err(_) -> Err(InvalidBundle)
    Ok(wire) -> case decode_renewal_request(wire) do
      Err(error) -> Err(ProtocolFailure(error))
      Ok(value) -> Ok(Some(value))
    end
  end
end

## The renewal request a bundle carries, if any. Half a request is malformed.

pub fn bundle_renewal_request(bundle :: PrekeyBundle) -> Option<RenewalRequest>!PrekeyError do
  case find_extension(bundle.extensions, 1, 0) do
    None -> case find_extension(bundle.extensions, 2, 0) do
      None -> Ok(None)
      Some(_) -> Err(InvalidBundle)
    end
    Some(first) -> case find_extension(bundle.extensions, 2, 0) do
      None -> Err(InvalidBundle)
      Some(second) -> joined_request(first, second)
    end
  end
end

fn without_renewal_request(bundle :: PrekeyBundle) -> PrekeyBundle do
  %{bundle | extensions: other_extensions(bundle.extensions, 0, List.new())}
end

pub fn bundle_with_renewal_request(bundle :: PrekeyBundle,
  request :: RenewalRequest) -> PrekeyBundle!PrekeyError do
  let wire = prekey_protocol(encode_renewal_request(request))?
  let first = case Bytes.slice(wire, 0, 1024) do
    Err(_) -> Err(InvalidBundle)
    Ok(value)
  end?
  let second = case Bytes.slice(wire, 1024, Bytes.length(wire) - 1024) do
    Err(_) -> Err(InvalidBundle)
    Ok(value)
  end?
  let parts = [
    ProtocolExtension { id: 1, mandatory: false, value: first },
    ProtocolExtension { id: 2, mandatory: false, value: second }
  ]
  let output = %{bundle |
    extensions: List.concat(parts, other_extensions(bundle.extensions, 0, List.new()))
  }
  prekey_protocol(encode_prekey_bundle(output))?
  Ok(output)
end

## The bundle that answers a request: the new credential, the requested signed
## prekey and ML-KEM prekey, no one-time prekey and no request.

pub fn renewed_prekey_bundle(credential :: DeviceCredential,
  request :: RenewalRequest) -> PrekeyBundle!PrekeyError do
  let answers = credential.suite == 2
    && Bytes.secure_equals(credential.account_id, request.account_id)
    && Bytes.secure_equals(credential.device_id, request.device_id)
    && Bytes.secure_equals(credential.post_quantum_public_key, request.post_quantum_prekey)
  if !answers do
    Err(InvalidBundle)
  else
    let zero = case U64.parse("0") do
      Err(_) -> Err(InvalidBundle)
      Ok(value)
    end?
    let bundle = PrekeyBundle {
      version: 1,
      suite: 2,
      device_credential: prekey_protocol(encode_device_credential(credential))?,
      identity_dh_public_key: credential.dh_public_key,
      signing_public_key: credential.signing_public_key,
      signed_prekey_id: request.signed_prekey_id,
      signed_prekey: request.signed_prekey,
      signed_prekey_signature: request.signed_prekey_signature,
      one_time_prekey_id: zero,
      one_time_prekey: Bytes.empty(),
      post_quantum_prekey: request.post_quantum_prekey,
      supported_suites: [2, 1],
      expires_at: request.expires_at,
      extensions: List.new()
    }
    prekey_protocol(encode_prekey_bundle(bundle))?
    Ok(bundle)
  end
end

fn bundle_wire(bundle :: PrekeyBundle) -> Option<Bytes> do
  case encode_prekey_bundle(bundle) do
    Err(_) -> None
    Ok(value) -> Some(value)
  end
end

fn same_wire(left :: PrekeyBundle, right :: PrekeyBundle) -> Bool do
  case bundle_wire(left) do
    None -> false
    Some(first) -> case bundle_wire(right) do
      None -> false
      Some(second) -> Bytes.secure_equals(first, second)
    end
  end
end

fn carries_request(bundle :: PrekeyBundle) -> Bool do
  case bundle_renewal_request(bundle) do
    Ok(None) -> false
    _ -> true
  end
end

# A new credential from the account key. It must take exactly the next
# sequence and never step back from the hybrid suite. It either moves a
# classical device to the hybrid suite with its signed prekey unchanged (the
# original upgrade), or brings a newer signed prekey. One older than the
# credential held is a replay of an entry already superseded.

fn credential_transition(stored :: PrekeyBundle,
  stored_credential :: DeviceCredential,
  proposed :: PrekeyBundle,
  proposed_credential :: DeviceCredential,
  next_sequence :: U64) -> BundleTransition do
  if U64.compare(proposed_credential.directory_sequence,
    stored_credential.directory_sequence) < 0 do
    TransitionReplayed
  else if U64.compare(proposed_credential.directory_sequence, next_sequence) != 0
    || proposed_credential.suite < stored_credential.suite
    || carries_request(proposed) do
    TransitionRefused
  else
    let same_signed_prekey = U64.compare(stored.signed_prekey_id, proposed.signed_prekey_id) == 0
      && Bytes.secure_equals(stored.signed_prekey, proposed.signed_prekey)
      && U64.compare(stored.expires_at, proposed.expires_at) == 0
    let upgrade = stored_credential.suite == 1
      && proposed_credential.suite == 2
      && same_signed_prekey
    let renewal = proposed_credential.suite == 2
      && U64.compare(proposed.signed_prekey_id, stored.signed_prekey_id) > 0
    if upgrade || renewal do
      TransitionAccepted
    else
      TransitionRefused
    end
  end
end

fn newer_request(stored :: PrekeyBundle, asked :: RenewalRequest) -> BundleTransition do
  case bundle_renewal_request(stored) do
    Ok(Some(previous)) -> do
      let order = U64.compare(asked.signed_prekey_id, previous.signed_prekey_id)
      if order > 0 do
        TransitionAccepted
      else if order < 0 do
        TransitionReplayed
      else
        TransitionRefused
      end
    end
    _ -> TransitionAccepted
  end
end

# The same credential: the device publishes a request, or a newer one. Its
# bundle is otherwise unchanged, and the request is signed by the device and
# asks for a signed prekey newer than the one it has.

fn request_transition(stored :: PrekeyBundle,
  stored_credential :: DeviceCredential,
  proposed :: PrekeyBundle) -> BundleTransition do
  if !same_wire(without_renewal_request(stored), without_renewal_request(proposed)) do
    TransitionRefused
  else
    case bundle_renewal_request(proposed) do
      Err(_) -> TransitionRefused
      Ok(None) -> if carries_request(stored) do
        TransitionReplayed
      else
        TransitionRefused
      end
      Ok(Some(asked)) -> if !verify_renewal_request(stored_credential, asked)
        || U64.compare(asked.signed_prekey_id, stored.signed_prekey_id) <= 0 do
        TransitionRefused
      else
        newer_request(stored, asked)
      end
    end
  end
end

fn classified_transition(stored :: PrekeyBundle,
  stored_credential :: DeviceCredential,
  proposed :: PrekeyBundle,
  proposed_credential :: DeviceCredential,
  next_sequence :: U64) -> BundleTransition do
  let same_device = Bytes.secure_equals(stored_credential.account_id,
    proposed_credential.account_id)
    && Bytes.secure_equals(stored_credential.device_id, proposed_credential.device_id)
    && Bytes.secure_equals(stored_credential.signing_public_key,
      proposed_credential.signing_public_key)
    && Bytes.secure_equals(stored_credential.dh_public_key, proposed_credential.dh_public_key)
  if !same_device do
    TransitionRefused
  else if same_wire(stored, proposed) do
    TransitionReplayed
  else if Bytes.secure_equals(stored.device_credential, proposed.device_credential) do
    request_transition(stored, stored_credential, proposed)
  else
    credential_transition(stored, stored_credential, proposed, proposed_credential, next_sequence)
  end
end

## How a registration for a device the directory holds changes its logged
## bundle. Both bundles come without a one-time prekey; the proposed one has
## already been verified against the account.

pub fn classify_bundle_transition(stored :: PrekeyBundle,
  proposed :: PrekeyBundle,
  next_sequence :: U64) -> BundleTransition do
  case decode_device_credential(stored.device_credential) do
    Err(_) -> TransitionRefused
    Ok(stored_credential) -> case decode_device_credential(proposed.device_credential) do
      Err(_) -> TransitionRefused
      Ok(proposed_credential) -> classified_transition(stored,
        stored_credential,
        proposed,
        proposed_credential,
        next_sequence)
    end
  end
end
