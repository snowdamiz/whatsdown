from Storage.Blobs import blob_record_hash
import File
from Mobile.Account import create_signup_draft_account
from Mobile.Types import MobileAccountRequest, MobileTransparencyRequest
from Mobile.Profile import load_profile, directory_bytes
from Mobile.Codec import current_time
from Mobile.SignupDraft import (
  signup_draft_state,
  select_free_signup_draft,
  complete_free_signup_draft
)
from Mobile.Transparency import verify_transparency_response
from Storage.Credits import CreditWalletIdentity, load_credit_wallet
from Storage.Keys import platform_key
from Storage.Blobs import load_blob
from Transport.Packet import decode_client_profile
from Protocol.DirectoryWire import encode_device_set
from Protocol.V1 import DeviceSet, DirectoryEntry
from Protocol.IdentityWire import decode_account_identity
from Transparency.Merkle import (
  TransparencyCheckpoint,
  checkpoint_hash,
  consistency_proof,
  inclusion_proof,
  leaf_hash,
  sign_checkpoint,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence, encode_transparency_evidence
from Tests.Support import database_path, install_security_config, repeated

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test key failed")
    Ok(value)
  end
end

fn device_wire(entry :: DirectoryEntry) -> Bytes!String do
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> return Err("test account identity failed")
    Ok(value) -> value
  end
  case encode_device_set(DeviceSet {
    version: 1,
    username: entry.username,
    account_identity: entry.account_identity,
    sequence: account.directory_sequence,
    devices: [entry],
    revoked_device_ids: []
  }) do
    Err(_) -> Err("test device set failed")
    Ok(value)
  end
end

fn evidence(entry :: Bytes,
  leaves :: List<Bytes>,
  previous :: List<Bytes>,
  index :: Int,
  checkpoint :: TransparencyCheckpoint,
  a :: borrow SigningPrivateKey,
  b :: borrow SigningPrivateKey) -> Bytes!String do
  encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: entry,
    inclusion: inclusion_proof(leaves, index)?,
    consistency: consistency_proof(previous, leaves)?,
    checkpoint: checkpoint,
    witnesses: [
      sign_witness("witness-a", a, checkpoint)?,
      sign_witness("witness-b", b, checkpoint)?
    ]
  })
end

fn verify(path :: String, entry :: DirectoryEntry, proof :: Bytes) -> Bytes!String do
  verify_transparency_response(MobileTransparencyRequest {
    database_path: path,
    username: entry.username,
    evidence: proof,
    directory_url: ""
  })
end

fn marker_failure(path :: String, enabled :: Bool) -> Result<(), String> do
  let database = Sqlite.open(path)?
  if enabled do
    let hash = blob_record_hash(database, "signup-draft/v1")?
    Sqlite.execute(database,
      "CREATE TRIGGER fail_free_completion BEFORE UPDATE ON encrypted_blobs WHEN NEW.record_hash = '"
        <> hash
        <> "' BEGIN SELECT RAISE(ABORT, 'test free completion failure'); END",
      [])?
  else
    Sqlite.execute(database, "DROP TRIGGER fail_free_completion", [])?
  end
  Sqlite.close(database)
  Ok(nil)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let core = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  let attacker = signing_pair()?
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> return Err("delivery key failed")
    Ok(value) -> value
  end
  assert(install_security_config(core.public_key.bytes,
    a.public_key.bytes,
    b.public_key.bytes,
    delivery.public_key.bytes,
    1))
  let path = database_path("draft_free_complete")?
  let encoded = create_signup_draft_account(MobileAccountRequest {
    database_path: Bytes.from_utf8(path),
    username: Bytes.from_utf8("free-owner")
  })?
  let profile = decode_client_profile(encoded)?
  let who = CreditWalletIdentity {
    account_id: profile.account_id,
    device_id: profile.device_id,
    service_key: core.public_key.bytes,
    purpose: 1
  }
  assert(Result.is_err(complete_free_signup_draft(path, wrapping, who)))
  select_free_signup_draft(path, wrapping, who)?
  assert(Result.is_err(complete_free_signup_draft(path, wrapping, who)))
  assert(signup_draft_state(path)? == 2)
  let correct = device_wire(profile.entry)?
  let leaves = [leaf_hash(correct)?]
  let forged = sign_checkpoint(attacker.private_key,
    attacker.public_key.bytes,
    U64.parse("1")?,
    leaves,
    repeated(0, 32)?,
    current_time()?)?
  assert(Result.is_err(verify(path,
    profile.entry,
    evidence(correct, leaves, [], 0, forged, a.private_key, b.private_key)?)))
  assert(Result.is_err(complete_free_signup_draft(path, wrapping, who)))
  let stale = sign_checkpoint(core.private_key,
    core.public_key.bytes,
    U64.parse("1")?,
    leaves,
    repeated(0, 32)?,
    U64.parse("1000")?)?
  assert(Result.is_err(verify(path,
    profile.entry,
    evidence(correct, leaves, [], 0, stale, a.private_key, b.private_key)?)))
  assert(Result.is_err(complete_free_signup_draft(path, wrapping, who)))
  # Same account, device and username is insufficient: the exact current
  # mailbox/prekey entry must be included in the authenticated live set.
  let wrong_entry = %{profile.entry | mailbox_token: repeated(91, 32)?}
  let wrong = device_wire(wrong_entry)?
  let old_leaves = [leaf_hash(wrong)?]
  let first = sign_checkpoint(core.private_key,
    core.public_key.bytes,
    U64.parse("1")?,
    old_leaves,
    repeated(0, 32)?,
    current_time()?)?
  verify(path,
    profile.entry,
    evidence(wrong, old_leaves, [], 0, first, a.private_key, b.private_key)?)?
  assert(Result.is_err(complete_free_signup_draft(path, wrapping, who)))
  assert(signup_draft_state(path)? == 2)
  let all_leaves = old_leaves ++ leaves
  let second = sign_checkpoint(core.private_key,
    core.public_key.bytes,
    U64.parse("2")?,
    all_leaves,
    checkpoint_hash(first)?,
    current_time()?)?
  verify(path,
    profile.entry,
    evidence(correct, all_leaves, old_leaves, 1, second, a.private_key, b.private_key)?)?
  let before = load_credit_wallet(path, wrapping, who)?.wallet.revision
  let profile_blob = load_blob(path, "profile/v1")?
  let marker_blob = load_blob(path, "signup-draft/v1")?
  marker_failure(path, true)?
  assert(Result.is_err(complete_free_signup_draft(path, wrapping, who)))
  assert(signup_draft_state(path)? == 2
    && load_credit_wallet(path, wrapping, who)?.wallet.revision == before)
  assert(Bytes.secure_equals(profile_blob, load_blob(path, "profile/v1")?)
    && Bytes.secure_equals(marker_blob, load_blob(path, "signup-draft/v1")?))
  marker_failure(path, false)?
  assert(Bytes.secure_equals(complete_free_signup_draft(path, wrapping, who)?, load_profile(path)?))
  assert(signup_draft_state(path)? == 3)
  assert(Bytes.secure_equals(complete_free_signup_draft(path, wrapping, who)?, load_profile(path)?))
  File.delete(path)?
  Ok(true)
end

test("free signup completes only for the exact authenticated current own directory entry") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
