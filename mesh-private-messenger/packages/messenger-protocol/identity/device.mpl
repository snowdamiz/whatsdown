from Protocol.DirectoryWire import (
  encode_account_deletion,
  encode_device_departure,
  encode_device_link_authorization,
  encode_device_link_request,
  encode_device_revocation
)
from Protocol.IdentityWire import (
  decode_account_identity,
  decode_device_credential,
  encode_account_identity,
  encode_device_credential
)
from Protocol.V1 import (
  AccountDeletion,
  AccountIdentity,
  DeviceCredential,
  DeviceDeparture,
  DeviceLinkAuthorization,
  DeviceLinkRequest,
  DeviceRevocation,
  ProtocolError
)

pub type IdentityError do
  CryptoFailure(error :: CryptoError)
  ProtocolFailure(error :: ProtocolError)
  InvalidCredential
end

pub fn is_retryable_verification_crypto_error(error :: CryptoError) -> Bool do
  case error do
    EntropyUnavailable -> true
    SecretDestroyed -> true
    ResourceLimitExceeded -> true
    UnsupportedOperation -> true
    InternalFailure -> true
    _ -> false
  end
end

pub fn is_retryable_identity_verification_error(error :: IdentityError) -> Bool do
  case error do
    CryptoFailure(crypto_error) -> is_retryable_verification_crypto_error(crypto_error)
    _ -> false
  end
end

pub struct VerificationPolicy do
  current_time :: U64
  minimum_directory_sequence :: U64
end

pub resource struct AccountKeys do
  account_id :: Bytes
  private_key :: SigningPrivateKey
  public_key :: SigningPublicKey
end

pub resource struct DeviceKeys do
  device_id :: Bytes
  signing_private_key :: SigningPrivateKey
  signing_public_key :: SigningPublicKey
  identity_private_key :: X25519PrivateKey
  identity_public_key :: X25519PublicKey
end

fn random_public(length :: Int) -> Bytes!IdentityError do
  case Crypto.random_bytes(length) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn signing_pair() -> SigningKeyPair!IdentityError do
  case Crypto.signing_generate() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn identity_pair() -> X25519KeyPair!IdentityError do
  case Crypto.x25519_generate() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn empty_signature() -> Bytes!IdentityError do
  case Bytes.repeat(0, 64) do
    Err(_) -> Err(InvalidCredential)
    Ok(value)
  end
end

pub fn generate_account(created_at :: U64, directory_sequence :: U64) -> Result<(AccountKeys, AccountIdentity), IdentityError> do
  let account_id = random_public(32)?
  let pair = signing_pair()?
  let public_key = pair.public_key
  let private_key = pair.private_key
  Ok((AccountKeys {
      account_id: account_id,
      private_key: private_key,
      public_key: public_key
    },
    AccountIdentity {
      version: 1,
      account_id: account_id,
      authorization_public_key: public_key.bytes,
      created_at: created_at,
      directory_sequence: directory_sequence,
      extensions: List.new()
    }))
end

pub fn generate_device() -> DeviceKeys!IdentityError do
  let device_id = random_public(16)?
  let signing = signing_pair()?
  let signing_public_key = signing.public_key
  let signing_private_key = signing.private_key
  let identity = identity_pair()?
  let identity_public_key = identity.public_key
  let identity_private_key = identity.private_key
  Ok(DeviceKeys {
    device_id: device_id,
    signing_private_key: signing_private_key,
    signing_public_key: signing_public_key,
    identity_private_key: identity_private_key,
    identity_public_key: identity_public_key
  })
end

pub fn credential_signing_bytes(value :: DeviceCredential) -> Bytes!IdentityError do
  let unsigned = DeviceCredential {
    version: value.version,
    suite: value.suite,
    account_id: value.account_id,
    device_id: value.device_id,
    signing_public_key: value.signing_public_key,
    dh_public_key: value.dh_public_key,
    post_quantum_public_key: value.post_quantum_public_key,
    capabilities: value.capabilities,
    created_at: value.created_at,
    expires_at: value.expires_at,
    directory_sequence: value.directory_sequence,
    signature: empty_signature()?
  }
  case encode_device_credential(unsigned) do
    Err(error) -> Err(ProtocolFailure(error))
    Ok(encoded) -> case Bytes.concat(Bytes.from_utf8("mesh-msg/v1/device-credential"), encoded) do
      Err(_) -> Err(InvalidCredential)
      Ok(signing_bytes)
    end
  end
end

pub fn issue_device_credential(account :: borrow AccountKeys,
  device :: borrow DeviceKeys,
  capabilities :: U64,
  created_at :: U64,
  expires_at :: U64,
  directory_sequence :: U64) -> DeviceCredential!IdentityError do
  issue_credential(account,
    device.device_id,
    device.signing_public_key.bytes,
    device.identity_public_key.bytes,
    Bytes.empty(),
    1,
    capabilities,
    created_at,
    expires_at,
    directory_sequence)
end

pub fn issue_hybrid_device_credential(account :: borrow AccountKeys,
  device :: borrow DeviceKeys,
  post_quantum_public_key :: MlKemPublicKey,
  capabilities :: U64,
  created_at :: U64,
  expires_at :: U64,
  directory_sequence :: U64) -> DeviceCredential!IdentityError do
  issue_credential(account,
    device.device_id,
    device.signing_public_key.bytes,
    device.identity_public_key.bytes,
    post_quantum_public_key.bytes,
    2,
    capabilities,
    created_at,
    expires_at,
    directory_sequence)
end

pub fn issue_public_device_credential(account :: borrow AccountKeys,
  device_id :: Bytes,
  signing_public_key :: Bytes,
  dh_public_key :: Bytes,
  capabilities :: U64,
  created_at :: U64,
  expires_at :: U64,
  directory_sequence :: U64) -> DeviceCredential!IdentityError do
  issue_credential(account,
    device_id,
    signing_public_key,
    dh_public_key,
    Bytes.empty(),
    1,
    capabilities,
    created_at,
    expires_at,
    directory_sequence)
end

fn issue_credential(account :: borrow AccountKeys,
  device_id :: Bytes,
  signing_public_key :: Bytes,
  dh_public_key :: Bytes,
  post_quantum_public_key :: Bytes,
  suite :: Int,
  capabilities :: U64,
  created_at :: U64,
  expires_at :: U64,
  directory_sequence :: U64) -> DeviceCredential!IdentityError do
  let expected_post_quantum_length = if suite == 2 do
    1184
  else
    0
  end
  if Bytes.length(device_id) != 16 || Bytes.length(signing_public_key) != 32 || Bytes.length(dh_public_key) != 32 || Bytes.length(post_quantum_public_key) != expected_post_quantum_length do
    Err(InvalidCredential)
  else
    let unsigned = DeviceCredential {
      version: 1,
      suite: suite,
      account_id: account.account_id,
      device_id: device_id,
      signing_public_key: signing_public_key,
      dh_public_key: dh_public_key,
      post_quantum_public_key: post_quantum_public_key,
      capabilities: capabilities,
      created_at: created_at,
      expires_at: expires_at,
      directory_sequence: directory_sequence,
      signature: empty_signature()?
    }
    let signing_bytes = credential_signing_bytes(unsigned)?
    case Crypto.sign(account.private_key, signing_bytes) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(signature) -> Ok(DeviceCredential {
        version: unsigned.version,
        suite: unsigned.suite,
        account_id: unsigned.account_id,
        device_id: unsigned.device_id,
        signing_public_key: unsigned.signing_public_key,
        dh_public_key: unsigned.dh_public_key,
        post_quantum_public_key: unsigned.post_quantum_public_key,
        capabilities: unsigned.capabilities,
        created_at: unsigned.created_at,
        expires_at: unsigned.expires_at,
        directory_sequence: unsigned.directory_sequence,
        signature: signature.bytes
      })
    end
  end
end

pub fn verify_device_credential(account :: AccountIdentity,
  credential :: DeviceCredential,
  current_time :: U64,
  minimum_directory_sequence :: U64) -> Bool!IdentityError do
  if !Bytes.secure_equals(account.account_id, credential.account_id) do
    Err(InvalidCredential)
  else
    let invalid_time = U64.compare(account.created_at, current_time) > 0 || U64.compare(credential.created_at,
      current_time) > 0 || U64.compare(credential.expires_at, current_time) < 0
    let rollback = U64.compare(account.directory_sequence, minimum_directory_sequence) < 0 || U64.compare(credential.directory_sequence,
      minimum_directory_sequence) < 0
    if invalid_time || rollback do
      Err(InvalidCredential)
    else
      let signing_bytes = credential_signing_bytes(credential)?
      case Crypto.verify(SigningPublicKey { bytes: account.authorization_public_key },
        signing_bytes,
        Signature { bytes: credential.signature }) do
        Err(error) -> Err(CryptoFailure(error))
        Ok(valid)
      end
    end
  end
end

fn protocol_bytes(value :: Result<Bytes, ProtocolError>) -> Bytes!IdentityError do
  case value do
    Err(error) -> Err(ProtocolFailure(error))
    Ok(encoded)
  end
end

fn protocol_account(value :: Result<AccountIdentity, ProtocolError>) -> AccountIdentity!IdentityError do
  case value do
    Err(error) -> Err(ProtocolFailure(error))
    Ok(decoded)
  end
end

fn protocol_credential(value :: Result<DeviceCredential, ProtocolError>) -> DeviceCredential!IdentityError do
  case value do
    Err(error) -> Err(ProtocolFailure(error))
    Ok(decoded)
  end
end

fn identity_append(left :: Bytes, right :: Bytes) -> Bytes!IdentityError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(InvalidCredential)
    Ok(value)
  end
end

fn link_authorization_signing_bytes(value :: DeviceLinkAuthorization) -> Bytes!IdentityError do
  let unsigned = DeviceLinkAuthorization {
    version: value.version,
    request_hash: value.request_hash,
    username: value.username,
    account_identity: value.account_identity,
    device_credential: value.device_credential,
    authorization_signature: empty_signature()?
  }
  identity_append(Bytes.from_utf8("mesh-msg/v1/device-link-authorization"),
    protocol_bytes(encode_device_link_authorization(unsigned))?)
end

pub fn authorize_device_link(account :: borrow AccountKeys,
  identity :: AccountIdentity,
  request :: DeviceLinkRequest,
  username :: String,
  credential_expires_at :: U64,
  directory_sequence :: U64) -> DeviceLinkAuthorization!IdentityError do
  if !Bytes.secure_equals(account.account_id, identity.account_id) || !Bytes.secure_equals(account.public_key.bytes,
    identity.authorization_public_key) do
    Err(InvalidCredential)
  else
    let request_wire = protocol_bytes(encode_device_link_request(request))?
    let credential = issue_credential(account,
      request.device_id,
      request.signing_public_key,
      request.dh_public_key,
      request.post_quantum_public_key,
      request.suite,
      request.capabilities,
      request.created_at,
      credential_expires_at,
      directory_sequence)?
    let unsigned = DeviceLinkAuthorization {
      version: 1,
      request_hash: Crypto.sha256(request_wire),
      username: username,
      account_identity: protocol_bytes(encode_account_identity(identity))?,
      device_credential: protocol_bytes(encode_device_credential(credential))?,
      authorization_signature: empty_signature()?
    }
    let signing_bytes = link_authorization_signing_bytes(unsigned)?
    case Crypto.sign(account.private_key, signing_bytes) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(signature) -> Ok(DeviceLinkAuthorization {
        version: unsigned.version,
        request_hash: unsigned.request_hash,
        username: unsigned.username,
        account_identity: unsigned.account_identity,
        device_credential: unsigned.device_credential,
        authorization_signature: signature.bytes
      })
    end
  end
end

pub fn verify_device_link_authorization(request :: DeviceLinkRequest,
  authorization :: DeviceLinkAuthorization,
  current_time :: U64,
  minimum_directory_sequence :: U64) -> Bool!IdentityError do
  let request_wire = protocol_bytes(encode_device_link_request(request))?
  let account = protocol_account(decode_account_identity(authorization.account_identity))?
  let credential = protocol_credential(decode_device_credential(authorization.device_credential))?
  let credential_valid = verify_device_credential(account,
    credential,
    current_time,
    minimum_directory_sequence)?
  let request_current = U64.compare(request.created_at, current_time) <= 0 && U64.compare(request.expires_at,
    current_time) >= 0
  let request_matches = Bytes.secure_equals(authorization.request_hash, Crypto.sha256(request_wire)) && Bytes.secure_equals(request.device_id,
    credential.device_id) && Bytes.secure_equals(request.signing_public_key,
    credential.signing_public_key) && Bytes.secure_equals(request.dh_public_key,
    credential.dh_public_key) && request.suite == credential.suite && Bytes.secure_equals(request.post_quantum_public_key,
    credential.post_quantum_public_key) && U64.compare(request.capabilities,
    credential.capabilities) == 0
  if !credential_valid || !request_current || !request_matches do
    Ok(false)
  else
    let signing_bytes = link_authorization_signing_bytes(authorization)?
    case Crypto.verify(SigningPublicKey { bytes: account.authorization_public_key },
      signing_bytes,
      Signature { bytes: authorization.authorization_signature }) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(valid)
    end
  end
end

fn revocation_signing_bytes(value :: DeviceRevocation) -> Bytes!IdentityError do
  let unsigned = DeviceRevocation {
    version: value.version,
    account_id: value.account_id,
    device_id: value.device_id,
    sequence: value.sequence,
    signature: empty_signature()?
  }
  identity_append(Bytes.from_utf8("mesh-msg/v1/device-revocation"),
    protocol_bytes(encode_device_revocation(unsigned))?)
end

pub fn issue_device_revocation(account :: borrow AccountKeys, device_id :: Bytes, sequence :: U64) -> DeviceRevocation!IdentityError do
  if Bytes.length(device_id) != 16 do
    Err(InvalidCredential)
  else
    let unsigned = DeviceRevocation {
      version: 1,
      account_id: account.account_id,
      device_id: device_id,
      sequence: sequence,
      signature: empty_signature()?
    }
    case Crypto.sign(account.private_key, revocation_signing_bytes(unsigned)?) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(signature) -> Ok(DeviceRevocation {
        version: unsigned.version,
        account_id: unsigned.account_id,
        device_id: unsigned.device_id,
        sequence: unsigned.sequence,
        signature: signature.bytes
      })
    end
  end
end

pub fn verify_device_revocation(account :: AccountIdentity, value :: DeviceRevocation) -> Bool!IdentityError do
  if !Bytes.secure_equals(account.account_id, value.account_id) do
    Ok(false)
  else
    case Crypto.verify(SigningPublicKey { bytes: account.authorization_public_key },
      revocation_signing_bytes(value)?,
      Signature { bytes: value.signature }) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(valid)
    end
  end
end

fn deletion_signing_bytes(value :: AccountDeletion) -> Bytes!IdentityError do
  identity_append(Bytes.from_utf8("mesh-msg/v1/account-deletion"),
    protocol_bytes(encode_account_deletion(%{value | signature: empty_signature()?}))?)
end

## Deletes the whole account: every device, the username, and all it left on
## the directory. The time is signed so a verifier can refuse a stale statement.

pub fn issue_account_deletion(account :: borrow AccountKeys, issued_at :: U64) -> AccountDeletion!IdentityError do
  let unsigned = AccountDeletion {
    version: 1,
    account_id: account.account_id,
    issued_at: issued_at,
    signature: empty_signature()?
  }
  case Crypto.sign(account.private_key, deletion_signing_bytes(unsigned)?) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(signature) -> Ok(%{unsigned | signature: signature.bytes})
  end
end

pub fn verify_account_deletion(account :: AccountIdentity, value :: AccountDeletion) -> Bool!IdentityError do
  if !Bytes.secure_equals(account.account_id, value.account_id) do
    Ok(false)
  else
    case Crypto.verify(SigningPublicKey { bytes: account.authorization_public_key },
      deletion_signing_bytes(value)?,
      Signature { bytes: value.signature }) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(valid)
    end
  end
end

fn departure_signing_bytes(value :: DeviceDeparture) -> Bytes!IdentityError do
  identity_append(Bytes.from_utf8("mesh-msg/v1/device-departure"),
    protocol_bytes(encode_device_departure(%{value | signature: empty_signature()?}))?)
end

## Takes one device out of its account, signed by that device alone: it can
## only ever remove itself. Linked devices hold no account key, so this is how
## one leaves instead of lingering as a device that no one can reach.

pub fn issue_device_departure(device :: borrow DeviceKeys, account_id :: Bytes, issued_at :: U64) -> DeviceDeparture!IdentityError do
  let unsigned = DeviceDeparture {
    version: 1,
    account_id: account_id,
    device_id: device.device_id,
    issued_at: issued_at,
    signature: empty_signature()?
  }
  case Crypto.sign(device.signing_private_key, departure_signing_bytes(unsigned)?) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(signature) -> Ok(%{unsigned | signature: signature.bytes})
  end
end

pub fn verify_device_departure(signing_public_key :: Bytes, value :: DeviceDeparture) -> Bool!IdentityError do
  case Crypto.verify(SigningPublicKey { bytes: signing_public_key },
    departure_signing_bytes(value)?,
    Signature { bytes: value.signature }) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(valid)
  end
end
