from Protocol.V1 import AccountIdentity, DeviceCredential, ProtocolError, encode_device_credential

pub type IdentityError do
  CryptoFailure( error :: CryptoError)

  ProtocolFailure( error :: ProtocolError)

  InvalidCredential
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

fn random_public(length :: Int) -> Bytes ! IdentityError do
  case Crypto.random_bytes(length) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

fn signing_pair() -> SigningKeyPair ! IdentityError do
  case Crypto.signing_generate() do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

fn identity_pair() -> X25519KeyPair ! IdentityError do
  case Crypto.x25519_generate() do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

fn empty_signature() -> Bytes ! IdentityError do
  case Bytes.repeat(0, 64) do
    Err( _) -> Err(InvalidCredential)
    Ok( value) -> Ok(value)
  end
end

pub fn generate_account(created_at :: U64, directory_sequence :: U64) -> Result <( AccountKeys, AccountIdentity), IdentityError > do
  let account_id = random_public(32) ?
  let pair = signing_pair() ?
  let public_key = pair.public_key
  let private_key = pair.private_key
  Ok((AccountKeys {
    account_id : account_id,
    private_key : private_key,
    public_key : public_key
  },
  AccountIdentity {
    version : 1,
    account_id : account_id,
    authorization_public_key : public_key.bytes,
    created_at : created_at,
    directory_sequence : directory_sequence,
    extensions : List.new()
  }))
end

pub fn generate_device() -> DeviceKeys ! IdentityError do
  let device_id = random_public(16) ?
  let signing = signing_pair() ?
  let signing_public_key = signing.public_key
  let signing_private_key = signing.private_key
  let identity = identity_pair() ?
  let identity_public_key = identity.public_key
  let identity_private_key = identity.private_key
  Ok(DeviceKeys {
    device_id : device_id,
    signing_private_key : signing_private_key,
    signing_public_key : signing_public_key,
    identity_private_key : identity_private_key,
    identity_public_key : identity_public_key
  })
end

pub fn credential_signing_bytes(value :: DeviceCredential) -> Bytes ! IdentityError do
  let unsigned = DeviceCredential {
    version : value.version,
    suite : value.suite,
    account_id : value.account_id,
    device_id : value.device_id,
    signing_public_key : value.signing_public_key,
    dh_public_key : value.dh_public_key,
    post_quantum_public_key : value.post_quantum_public_key,
    capabilities : value.capabilities,
    created_at : value.created_at,
    expires_at : value.expires_at,
    directory_sequence : value.directory_sequence,
    signature : empty_signature() ?
  }
  case encode_device_credential(unsigned) do
    Err( error) -> Err(ProtocolFailure(error))
    Ok( encoded) -> case Bytes.concat(Bytes.from_utf8("mesh-msg/v1/device-credential"), encoded) do
      Err( _) -> Err(InvalidCredential)
      Ok( signing_bytes) -> Ok(signing_bytes)
    end
  end
end

pub fn issue_device_credential(account :: borrow AccountKeys,
device :: borrow DeviceKeys,
capabilities :: U64,
created_at :: U64,
expires_at :: U64,
directory_sequence :: U64) -> DeviceCredential ! IdentityError do
  let unsigned = DeviceCredential {
    version : 1,
    suite : 1,
    account_id : account.account_id,
    device_id : device.device_id,
    signing_public_key : device.signing_public_key.bytes,
    dh_public_key : device.identity_public_key.bytes,
    post_quantum_public_key : Bytes.empty(),
    capabilities : capabilities,
    created_at : created_at,
    expires_at : expires_at,
    directory_sequence : directory_sequence,
    signature : empty_signature() ?
  }
  let signing_bytes = credential_signing_bytes(unsigned) ?
  case Crypto.sign(account.private_key, signing_bytes) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( signature) -> Ok(DeviceCredential {
      version : unsigned.version,
      suite : unsigned.suite,
      account_id : unsigned.account_id,
      device_id : unsigned.device_id,
      signing_public_key : unsigned.signing_public_key,
      dh_public_key : unsigned.dh_public_key,
      post_quantum_public_key : unsigned.post_quantum_public_key,
      capabilities : unsigned.capabilities,
      created_at : unsigned.created_at,
      expires_at : unsigned.expires_at,
      directory_sequence : unsigned.directory_sequence,
      signature : signature.bytes
    })
  end
end

pub fn verify_device_credential(account :: AccountIdentity,
credential :: DeviceCredential,
current_time :: U64,
minimum_directory_sequence :: U64) -> Bool ! IdentityError do
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
      let signing_bytes = credential_signing_bytes(credential) ?
      case Crypto.verify(SigningPublicKey { bytes : account.authorization_public_key },
      signing_bytes,
      Signature { bytes : credential.signature }) do
        Err( error) -> Err(CryptoFailure(error))
        Ok( valid) -> Ok(valid)
      end
    end
  end
end
