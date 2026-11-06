##! Inactive complete-carrier Alice kernel. Published Braid revision1 KDFs;
##! structural unchunked transition reference only, no transport/wire authority.
from Session.BraidResponder import (
  BraidError,
  BraidScope,
  BraidAwaitHeader,
  initialize_responder,
  braid_join,
  braid_epoch_bytes,
  braid_valid_scope
)

pub resource struct BraidEpochOutput do
  epoch :: U64
  key :: SecretBytes
end

pub resource struct BraidAliceIdle do
  scope :: BraidScope
  epoch :: U64
  secrets :: SecretMap
end

pub resource struct BraidAliceHeaderSent do
  scope :: BraidScope
  epoch :: U64
  header :: MlKemHeader64
  vector :: MlKemPublicVector1152
  private_key :: MlKemPrivateKey
  secrets :: SecretMap
end

pub resource struct BraidAliceEkSent do
  scope :: BraidScope
  epoch :: U64
  header :: MlKemHeader64
  vector :: MlKemPublicVector1152
  private_key :: MlKemPrivateKey
  secrets :: SecretMap
end

pub resource struct BraidAliceCt1Received do
  scope :: BraidScope
  epoch :: U64
  header :: MlKemHeader64
  vector :: MlKemPublicVector1152
  first :: MlKemCiphertext1_960
  private_key :: MlKemPrivateKey
  secrets :: SecretMap
end

pub type BraidAliceCt1Admission do
  BraidAliceCt1Accepted(state :: BraidAliceCt1Received)
  BraidAliceCt1Ignored(state :: BraidAliceEkSent, error :: BraidError)
end

pub type BraidAliceCt2Admission do
  BraidAliceCt2Accepted(state :: BraidAwaitHeader, output :: BraidEpochOutput)
  BraidAliceCt2Ignored(state :: BraidAliceCt1Received, error :: BraidError)
  BraidAliceCt2Fatal(error :: BraidError)
end

pub fn bilateral_next_epoch(epoch :: U64) -> U64!BraidError do
  let one = case U64.parse("1") do
    Ok(v) -> v
    Err(_) -> return Err(BraidInvalidState)
  end
  case U64.add(epoch, one) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

pub fn bilateral_zero_salt() -> Bytes!BraidError do
  case Bytes.repeat(0, 32) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

pub fn bilateral_info(scope :: BraidScope, label :: String, epoch :: U64) -> Bytes!BraidError do
  braid_join([scope.protocol_info, Bytes.from_utf8(label), braid_epoch_bytes(epoch)?])
end

fn authenticator(wide :: consume SecretBytes) -> SecretMap!BraidError do
  let (root, mac) = Secret.split_at(wide, 32)?
  let slots = SecretMap.new(3)?
  SecretMap.insert(slots, Bytes.from_utf8("root"), root)?
  SecretMap.insert(slots, Bytes.from_utf8("mac"), mac)?
  Ok(slots)
end

pub fn bilateral_mac(secrets :: borrow SecretMap,
  scope :: BraidScope,
  epoch :: U64,
  label :: String,
  message :: Bytes) -> Bytes!BraidError do
  let mac = SecretMap.copy(secrets, Bytes.from_utf8("mac"))?
  let tag = Crypto.hmac_sha256_tag(mac,
    braid_join([bilateral_info(scope, label, epoch)?, message])?)?
  Secret.destroy(mac)
  Ok(tag)
end

## Independent initializer only. This does not choose or export an HE root.
pub fn initialize_initiator(scope :: BraidScope,
  shared :: borrow SecretBytes) -> BraidAliceIdle!BraidError do
  let initial = initialize_responder(scope, shared)?
  Ok(BraidAliceIdle { scope: initial.scope, epoch: initial.epoch, secrets: initial.secrets })
end

pub fn send_header(state :: consume BraidAliceIdle) -> (BraidAliceHeaderSent, Bytes)!BraidError do
  if !braid_valid_scope(state.scope, state.epoch) do
    return Err(BraidInvalidState)
  end
  let _next = bilateral_next_epoch(state.epoch)?
  let generated = Crypto.mlkem_generate()?
  let (header, vector) = Crypto.mlkem_public_parts(generated.private_key)?
  let tag = bilateral_mac(state.secrets, state.scope, state.epoch, ":ekheader", header.bytes)?
  let complete = braid_join([header.bytes, tag])?
  Ok((BraidAliceHeaderSent {
      scope: state.scope,
      epoch: state.epoch,
      header: header,
      vector: vector,
      private_key: generated.private_key,
      secrets: state.secrets
    },
    complete))
end

## This logical action proves no remote receipt. A future chunked adapter owns
## the authenticated event that makes sending this vector appropriate.
pub fn send_vector(state :: consume BraidAliceHeaderSent) -> (BraidAliceEkSent, MlKemPublicVector1152)!BraidError do
  if !braid_valid_scope(state.scope, state.epoch) do
    return Err(BraidInvalidState)
  end
  Crypto.mlkem_validate_public_parts(state.header, state.vector)?
  let BraidAliceHeaderSent { scope, epoch, header, vector, private_key, secrets } = state
  Ok((BraidAliceEkSent {
      scope: scope,
      epoch: epoch,
      header: header,
      vector: vector,
      private_key: private_key,
      secrets: secrets
    },
    vector))
end

pub fn receive_ct1(state :: consume BraidAliceEkSent,
  epoch :: U64,
  first :: MlKemCiphertext1_960) -> BraidAliceCt1Admission do
  if !braid_valid_scope(state.scope, state.epoch) do
    return BraidAliceCt1Ignored(state, BraidInvalidState)
  end
  if U64.compare(epoch, state.epoch) != 0 do
    return BraidAliceCt1Ignored(state, BraidWrongEpoch)
  end
  if Bytes.length(first.bytes) != 960 do
    return BraidAliceCt1Ignored(state, BraidInvalidHeader)
  end
  let BraidAliceEkSent { scope, epoch, header, vector, private_key, secrets } = state
  BraidAliceCt1Accepted(BraidAliceCt1Received {
    scope: scope,
    epoch: epoch,
    header: header,
    vector: vector,
    first: first,
    private_key: private_key,
    secrets: secrets
  })
end

fn prepare_completion(state :: borrow BraidAliceCt1Received,
  second :: MlKemCiphertext2_128) -> (SecretMap, SecretBytes)!BraidError do
  let shared = Crypto.mlkem_decapsulate_parts(state.private_key, state.first, second)?
  let output = Crypto.hkdf_sha256(shared,
    bilateral_zero_salt()?,
    bilateral_info(state.scope, ":SCKA Key", state.epoch)?,
    32)?
  Secret.destroy(shared)
  let root = SecretMap.copy(state.secrets, Bytes.from_utf8("root"))?
  let wide = Crypto.hkdf_sha256_secret_salt(output,
    root,
    bilateral_info(state.scope, ":Authenticator Update", state.epoch)?,
    64)?
  Secret.destroy(root)
  Ok((authenticator(wide)?, output))
end

## The complete frame must already be admitted by the actual HE coordinator.
## A fatal result alone authorizes no storage mutation, reset or renegotiation.
pub fn receive_ct2(state :: consume BraidAliceCt1Received,
  epoch :: U64,
  complete :: Bytes) -> BraidAliceCt2Admission do
  if !braid_valid_scope(state.scope, state.epoch) do
    return BraidAliceCt2Ignored(state, BraidInvalidState)
  end
  if U64.compare(epoch, state.epoch) != 0 do
    return BraidAliceCt2Ignored(state, BraidWrongEpoch)
  end
  if Bytes.length(complete) != 160 do
    return BraidAliceCt2Ignored(state, BraidInvalidHeader)
  end
  let next = case bilateral_next_epoch(state.epoch) do
    Ok(v) -> v
    Err(error) -> return BraidAliceCt2Ignored(state, error)
  end
  let second = case Bytes.slice(complete, 0, 128) do
    Ok(v) -> MlKemCiphertext2_128 { bytes: v }
    Err(_) -> return BraidAliceCt2Ignored(state, BraidInvalidHeader)
  end
  let supplied = case Bytes.slice(complete, 128, 32) do
    Ok(v) -> v
    Err(_) -> return BraidAliceCt2Ignored(state, BraidInvalidHeader)
  end
  let (auth, output) = case prepare_completion(state, second) do
    Ok(v) -> v
    Err(error) -> return BraidAliceCt2Ignored(state, error)
  end
  let ciphertext = case braid_join([state.first.bytes, second.bytes]) do
    Ok(v) -> v
    Err(error) -> do
      Secret.destroy(auth)
      Secret.destroy(output)
      return BraidAliceCt2Ignored(state, error)
    end
  end
  let expected = case bilateral_mac(auth, state.scope, state.epoch, ":ciphertext", ciphertext) do
    Ok(v) -> v
    Err(error) -> do
      Secret.destroy(auth)
      Secret.destroy(output)
      return BraidAliceCt2Ignored(state, error)
    end
  end
  let BraidAliceCt1Received { scope, epoch, header, vector, first, private_key, secrets } = state
  Secret.destroy(private_key)
  Secret.destroy(secrets)
  if !Bytes.secure_equals(expected, supplied) do
    Secret.destroy(auth)
    Secret.destroy(output)
    return BraidAliceCt2Fatal(BraidAuthenticationRejected)
  end
  BraidAliceCt2Accepted(BraidAwaitHeader { scope: scope, epoch: next, secrets: auth },
    BraidEpochOutput { epoch: epoch, key: output })
end
