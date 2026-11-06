##! CLI fixture roles use explicit local release policy, never peer policy.
from Identity.Device import DeviceKeys, VerificationPolicy
from Prekeys.Bundle import OneTimePrekeySecrets, PostQuantumPrekeySecrets, SignedPrekeySecrets
from Protocol.V1 import AccountIdentity, DeviceCredential, InitialMessage, PrekeyBundle
from Session.State import RatchetState
from Session.Handshake import (
  SessionError,
  initiate_at_minimum_suite,
  receive_initial_at_minimum_suite
)

pub fn initiate_cli(minimum :: Int,
  initiator :: borrow DeviceKeys,
  credential :: DeviceCredential,
  responder :: AccountIdentity,
  bundle :: PrekeyBundle,
  policy :: VerificationPolicy,
  strongest_suite :: Int,
  plaintext :: Bytes) -> Result<(RatchetState, InitialMessage), SessionError> do
  initiate_at_minimum_suite(initiator,
    credential,
    responder,
    bundle,
    policy,
    strongest_suite,
    minimum,
    plaintext)
end

pub fn receive_initial_cli(minimum :: Int,
  responder :: borrow DeviceKeys,
  account :: AccountIdentity,
  bundle :: PrekeyBundle,
  signed :: borrow SignedPrekeySecrets,
  one_time :: consume OneTimePrekeySecrets,
  post_quantum :: borrow PostQuantumPrekeySecrets,
  initiator :: AccountIdentity,
  own_policy :: VerificationPolicy,
  peer_policy :: VerificationPolicy,
  strongest_suite :: Int,
  message :: Bytes) -> Result<(RatchetState, Bytes), SessionError> do
  receive_initial_at_minimum_suite(responder,
    account,
    bundle,
    signed,
    one_time,
    post_quantum,
    initiator,
    own_policy,
    peer_policy,
    strongest_suite,
    minimum,
    message)
end
