from Tests.GroupConsistencyCrypto import checkpoint
from Tests.GroupConsistencySupport import ConsistencyAccount, evidence_bytes, verify_for
from Transparency.Merkle import TransparencyCheckpoint

pub fn advance_both(alice :: ConsistencyAccount,
  bob :: ConsistencyAccount,
  leaves :: List<Bytes>,
  previous :: TransparencyCheckpoint,
  sequence :: Int,
  remaining :: Int,
  service_private :: borrow SigningPrivateKey,
  service_public_key :: Bytes,
  witness_a_private :: borrow SigningPrivateKey,
  witness_a_public_key :: Bytes,
  witness_b_private :: borrow SigningPrivateKey,
  witness_b_public_key :: Bytes) -> TransparencyCheckpoint!String do
  if remaining <= 0 do
    Ok(previous)
  else
    let next = checkpoint(service_private, service_public_key, sequence, leaves, previous, true)?
    let alice_evidence = evidence_bytes(alice.device_set,
      leaves,
      0,
      leaves,
      next,
      witness_a_private,
      witness_b_private)?
    let bob_evidence = evidence_bytes(bob.device_set,
      leaves,
      1,
      leaves,
      next,
      witness_a_private,
      witness_b_private)?
    verify_for(alice,
      alice.username,
      alice_evidence,
      service_public_key,
      witness_a_public_key,
      witness_b_public_key)?
    verify_for(bob,
      bob.username,
      bob_evidence,
      service_public_key,
      witness_a_public_key,
      witness_b_public_key)?
    advance_both(alice,
      bob,
      leaves,
      next,
      sequence + 1,
      remaining - 1,
      service_private,
      service_public_key,
      witness_a_private,
      witness_a_public_key,
      witness_b_private,
      witness_b_public_key)
  end
end
