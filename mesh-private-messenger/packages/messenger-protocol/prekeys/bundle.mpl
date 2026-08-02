from Identity.Device import DeviceKeys, IdentityError, verify_device_credential
from Protocol.V1 import AccountIdentity, DeviceCredential, PrekeyBundle, ProtocolError, decode_device_credential, encode_device_credential, encode_prekey_bundle, negotiate_profile_a

pub type PrekeyError do
  CryptoFailure( error :: CryptoError)

  IdentityFailure( error :: IdentityError)

  ProtocolFailure( error :: ProtocolError)

  InvalidBundle
end

pub resource struct SignedPrekeySecrets do
  id :: U64
  private_key :: X25519PrivateKey
  public_key :: X25519PublicKey
  signature :: Signature
  expires_at :: U64
end

pub resource struct OneTimePrekeySecrets do
  id :: U64
  private_key :: X25519PrivateKey
  public_key :: X25519PublicKey
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! PrekeyError do
  case Bytes.concat(left, right) do
    Err( _) -> Err(InvalidBundle)
    Ok( value) -> Ok(value)
  end
end

fn write_u16(value :: Int) -> Bytes ! PrekeyError do
  case Bytes.write_u16_be(value) do
    Err( _) -> Err(InvalidBundle)
    Ok( bytes) -> Ok(bytes)
  end
end

fn write_u64(value :: U64) -> Bytes ! PrekeyError do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err(InvalidBundle)
    Ok( bytes) -> Ok(bytes)
  end
end

fn signed_prekey_statement(credential :: DeviceCredential,
id :: U64,
public_key :: X25519PublicKey,
expires_at :: U64) -> Bytes ! PrekeyError do
  let output = append(Bytes.from_utf8("mesh-msg/v1/signed-prekey"), write_u16(credential.version) ?) ?
  let output = append(output, write_u16(credential.suite) ?) ?
  let output = append(output, credential.account_id) ?
  let output = append(output, credential.device_id) ?
  let output = append(output, write_u64(id) ?) ?
  let output = append(output, public_key.bytes) ?
  append(output, write_u64(expires_at) ?)
end

pub fn generate_signed_prekey(device :: borrow DeviceKeys,
credential :: DeviceCredential,
id :: U64,
expires_at :: U64) -> SignedPrekeySecrets ! PrekeyError do
  case Crypto.x25519_generate() do
    Err( error) -> Err(CryptoFailure(error))
    Ok( pair) -> do
      let public_key = pair.public_key
      let private_key = pair.private_key
      let statement = signed_prekey_statement(credential, id, public_key, expires_at) ?
      case Crypto.sign(device.signing_private_key, statement) do
        Err( error) -> Err(CryptoFailure(error))
        Ok( signature) -> Ok(SignedPrekeySecrets {
          id : id,
          private_key : private_key,
          public_key : public_key,
          signature : signature,
          expires_at : expires_at
        })
      end
    end
  end
end

pub fn generate_one_time_prekey(id :: U64) -> OneTimePrekeySecrets ! PrekeyError do
  case Crypto.x25519_generate() do
    Err( error) -> Err(CryptoFailure(error))
    Ok( pair) -> do
      let public_key = pair.public_key
      let private_key = pair.private_key
      Ok(OneTimePrekeySecrets {
        id : id,
        private_key : private_key,
        public_key : public_key
      })
    end
  end
end

pub fn build_prekey_bundle(credential :: DeviceCredential,
signed_prekey :: borrow SignedPrekeySecrets,
one_time_prekey :: borrow OneTimePrekeySecrets) -> PrekeyBundle ! PrekeyError do
  let credential_bytes = case encode_device_credential(credential) do
    Err( error) -> Err(ProtocolFailure(error))
    Ok( value) -> Ok(value)
  end ?
  let bundle = PrekeyBundle {
    version : 1,
    suite : 1,
    device_credential : credential_bytes,
    identity_dh_public_key : credential.dh_public_key,
    signing_public_key : credential.signing_public_key,
    signed_prekey_id : signed_prekey.id,
    signed_prekey : signed_prekey.public_key.bytes,
    signed_prekey_signature : signed_prekey.signature.bytes,
    one_time_prekey_id : one_time_prekey.id,
    one_time_prekey : one_time_prekey.public_key.bytes,
    supported_suites : [1],
    expires_at : signed_prekey.expires_at,
    extensions : List.new()
  }
  case encode_prekey_bundle(bundle) do
    Err( error) -> Err(ProtocolFailure(error))
    Ok( _) -> Ok(bundle)
  end
end

pub fn verify_prekey_bundle(account :: AccountIdentity,
bundle :: PrekeyBundle,
strongest_authenticated_suite :: Int,
current_time :: U64,
minimum_directory_sequence :: U64) -> Bool ! PrekeyError do
  if U64.compare(bundle.expires_at, current_time) < 0 do
    Err(InvalidBundle)
  else
    let credential = case decode_device_credential(bundle.device_credential) do
      Err( error) -> Err(ProtocolFailure(error))
      Ok( value) -> Ok(value)
    end ?
    let credential_valid = case verify_device_credential(account,
    credential,
    current_time,
    minimum_directory_sequence) do
      Err( error) -> Err(IdentityFailure(error))
      Ok( value) -> Ok(value)
    end ?
    let identity_key_mismatch = !Bytes.secure_equals(credential.dh_public_key,
    bundle.identity_dh_public_key)
    let signing_key_mismatch = !Bytes.secure_equals(credential.signing_public_key,
    bundle.signing_public_key)
    if !credential_valid || identity_key_mismatch || signing_key_mismatch do
      Err(InvalidBundle)
    else
      let _ = case negotiate_profile_a([1], bundle.supported_suites, strongest_authenticated_suite) do
        Err( error) -> Err(ProtocolFailure(error))
        Ok( value) -> Ok(value)
      end ?
      let statement = signed_prekey_statement(credential,
      bundle.signed_prekey_id,
      X25519PublicKey { bytes : bundle.signed_prekey },
      bundle.expires_at) ?
      case Crypto.verify(SigningPublicKey { bytes : bundle.signing_public_key },
      statement,
      Signature { bytes : bundle.signed_prekey_signature }) do
        Err( error) -> Err(CryptoFailure(error))
        Ok( valid) -> Ok(valid)
      end
    end
  end
end
