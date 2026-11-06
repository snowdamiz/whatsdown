##! Inactive remaining Bob actions for the complete-carrier kernel. No Ack API.
from Session.BraidResponder import (
  BraidError,
  BraidScope,
  BraidHeaderReady,
  BraidCt1Ready,
  prepare_ct1,
  braid_join,
  braid_valid_scope
)
from Session.BraidInitiator import (
  BraidEpochOutput,
  BraidAliceIdle,
  bilateral_next_epoch,
  bilateral_mac
)

pub resource struct BraidBobCt1Sent do
  scope :: BraidScope
  epoch :: U64
  header :: MlKemHeader64
  first :: MlKemCiphertext1_960
  continuation :: MlKemEncapsulationState
  secrets :: SecretMap
end

pub resource struct BraidBobEkReceived do
  scope :: BraidScope
  epoch :: U64
  header :: MlKemHeader64
  vector :: MlKemPublicVector1152
  first :: MlKemCiphertext1_960
  continuation :: MlKemEncapsulationState
  secrets :: SecretMap
end

pub resource struct BraidBobCt2Sent do
  scope :: BraidScope
  epoch :: U64
  header :: MlKemHeader64
  vector :: MlKemPublicVector1152
  first :: MlKemCiphertext1_960
  wire :: Bytes
  secrets :: SecretMap
end

pub type BraidVectorAdmission do
  BraidVectorAccepted(state :: BraidBobEkReceived)
  BraidVectorIgnored(state :: BraidBobCt1Sent, error :: BraidError)
end

pub type BraidCt2Emission do
  BraidCt2Emitted(state :: BraidBobCt2Sent, wire :: Bytes)
  BraidCt2Refused(state :: BraidBobEkReceived, error :: BraidError)
end

pub type BraidNextEpochAdmission do
  BraidNextEpochAccepted(state :: BraidAliceIdle)
  BraidNextEpochIgnored(state :: BraidBobCt2Sent, error :: BraidError)
end

## Consumes the accepted-header owner. The old borrowed helper is only a
## tentative internal step: extract the output, erase its map slot, and return
## root/mac state plus exactly one opaque output owner. No durable CAS claim.
pub fn send_ct1(state :: consume BraidHeaderReady) -> (BraidBobCt1Sent, BraidEpochOutput)!BraidError do
  let _next = bilateral_next_epoch(state.epoch)?
  let prepared = prepare_ct1(state)?
  let output = SecretMap.copy(prepared.secrets, Bytes.from_utf8("output"))?
  SecretMap.delete(prepared.secrets, Bytes.from_utf8("output"))?
  if SecretMap.contains(prepared.secrets, Bytes.from_utf8("output")) do
    return Err(BraidInvalidState)
  end
  Secret.destroy(state.secrets)
  let BraidCt1Ready { scope, epoch, header, first, secrets, continuation } = prepared
  Ok((BraidBobCt1Sent {
      scope: scope,
      epoch: epoch,
      header: MlKemHeader64 { bytes: header },
      first: first,
      continuation: continuation,
      secrets: secrets
    },
    BraidEpochOutput { epoch: epoch, key: output }))
end

## The continuation is not touched during public validation. Refusal returns
## the exact affine state; accepting the vector does not compute Ct2.
pub fn receive_vector(state :: consume BraidBobCt1Sent,
  epoch :: U64,
  vector :: MlKemPublicVector1152) -> BraidVectorAdmission do
  if !braid_valid_scope(state.scope, state.epoch) do
    return BraidVectorIgnored(state, BraidInvalidState)
  end
  if U64.compare(epoch, state.epoch) != 0 do
    return BraidVectorIgnored(state, BraidWrongEpoch)
  end
  case Crypto.mlkem_validate_public_parts(state.header, vector) do
    Err(error) -> return BraidVectorIgnored(state, BraidCryptoFailure(error))
    Ok(_) -> nil
  end
  let BraidBobCt1Sent { scope, epoch, header, first, continuation, secrets } = state
  BraidVectorAccepted(BraidBobEkReceived {
    scope: scope,
    epoch: epoch,
    header: header,
    vector: vector,
    first: first,
    continuation: continuation,
    secrets: secrets
  })
end

pub fn send_ct2(state :: consume BraidBobEkReceived) -> BraidCt2Emission do
  if !braid_valid_scope(state.scope, state.epoch) do
    return BraidCt2Refused(state, BraidInvalidState)
  end
  let second = case Crypto.mlkem_encapsulate2(state.continuation, state.vector) do
    Ok(v) -> v
    Err(error) -> return BraidCt2Refused(state, BraidCryptoFailure(error))
  end
  let complete = case braid_join([state.first.bytes, second.bytes]) do
    Ok(v) -> v
    Err(error) -> return BraidCt2Refused(state, error)
  end
  let tag = case bilateral_mac(state.secrets, state.scope, state.epoch, ":ciphertext", complete) do
    Ok(v) -> v
    Err(error) -> return BraidCt2Refused(state, error)
  end
  let wire = case braid_join([second.bytes, tag]) do
    Ok(v) -> v
    Err(error) -> return BraidCt2Refused(state, error)
  end
  let BraidBobEkReceived { scope, epoch, header, vector, first, continuation, secrets } = state
  Secret.destroy(continuation)
  BraidCt2Emitted(BraidBobCt2Sent {
      scope: scope,
      epoch: epoch,
      header: header,
      vector: vector,
      first: first,
      wire: wire,
      secrets: secrets
    },
    wire)
end

## Exact pending output only: no new KEM, output key, state advance or mutation.
pub fn recover_ct2(state :: borrow BraidBobCt2Sent) -> Bytes!BraidError do
  if !braid_valid_scope(state.scope, state.epoch) || Bytes.length(state.wire) != 160 do
    return Err(BraidInvalidState)
  end
  Ok(state.wire)
end

## Pure successor check only. The caller must separately admit authenticated
## epoch evidence; invoking this function is not transport authentication.
pub fn receive_next_epoch(state :: consume BraidBobCt2Sent,
  epoch :: U64) -> BraidNextEpochAdmission do
  let next = case bilateral_next_epoch(state.epoch) do
    Ok(v) -> v
    Err(error) -> return BraidNextEpochIgnored(state, error)
  end
  if !braid_valid_scope(state.scope, state.epoch) || U64.compare(epoch, next) != 0 do
    return BraidNextEpochIgnored(state, BraidWrongEpoch)
  end
  BraidNextEpochAccepted(BraidAliceIdle { scope: state.scope, epoch: next, secrets: state.secrets })
end
