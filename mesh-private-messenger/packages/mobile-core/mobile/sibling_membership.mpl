##! Read-only checks over captured trust sources. Returned profiles confer no authority.
from Storage.AccountGuard import AccountBasis
from Storage.Keys import open_local, local_context
from Mobile.DeviceSet import verified_device_set
from Mobile.Platform import decode_native_security_config
from Mobile.SessionPolicy import NativeSessionPolicy, require_current_session_policy
from Mobile.Codec import current_time
from Mobile.Transparency import (
  BackupCapturedTransparencyInputs,
  backup_transparency_proof_label,
  verify_backup_captured_transparency,
  transparency_device_set_label,
  canonical_transparency_checkpoint
)
from Transport.Packet import ClientProfile

pub fn sibling_source_labels(account :: Bytes) -> List<String> do
  [
    transparency_device_set_label(account),
    "transparency-checkpoint/v1",
    "transparency-view/v1",
    "transparency-view-chunk/v1/0",
    "transparency-view-chunk/v1/1",
    "transparency-view-chunk/v1/2",
    "transparency-witnesses/v2"
  ]
end

pub fn sibling_captured_blob(bases :: List<AccountBasis>, label :: String) -> Bytes!String do
  for basis in bases do
    for index in 0..List.length(basis.labels) do
      if List.get(basis.labels, index) == label do
        return Ok(List.get(basis.records, index))
      end
    end
  end
  Err("sibling_source_not_captured")
end

fn captured_plaintext(bases :: List<AccountBasis>,
  key :: borrow StorageKey,
  label :: String) -> Bytes!String do
  let blob = sibling_captured_blob(bases, label)?
  if Bytes.length(blob) == 0 do
    return Err("sibling_source_missing")
  end
  open_local(blob, key, local_context(label)?)
end

pub fn sibling_proof_label(bases :: List<AccountBasis>,
  key :: borrow StorageKey,
  account :: Bytes) -> String!String do
  backup_transparency_proof_label(captured_plaintext(bases,
      key,
      transparency_device_set_label(account))?,
    captured_plaintext(bases, key, "transparency-checkpoint/v1")?)
end

pub fn sibling_captured_member(bases :: List<AccountBasis>,
  key :: borrow StorageKey,
  local :: ClientProfile,
  device :: Bytes,
  policy :: NativeSessionPolicy,
  now :: U64) -> Result<(ClientProfile, U64), String> do
  let shared = captured_plaintext(bases, key, "transparency-checkpoint/v1")?
  let proof_label = sibling_proof_label(bases, key, local.account_id)?
  let verified = verify_backup_captured_transparency(BackupCapturedTransparencyInputs {
      device_set_cache: captured_plaintext(bases,
        key,
        transparency_device_set_label(local.account_id))?,
      shared_checkpoint: shared,
      view_manifest: captured_plaintext(bases, key, "transparency-view/v1")?,
      view_chunks: for index in 0..3 do
        captured_plaintext(bases, key, "transparency-view-chunk/v1/#{Int.to_string(index)}")?
      end,
      witnesses: if canonical_transparency_checkpoint(shared)?.version == 1 do
        Bytes.empty()
      else
        captured_plaintext(bases, key, "transparency-witnesses/v2")?
      end,
      proof_label: proof_label,
      proof: if proof_label == "" do
        Bytes.empty()
      else
        captured_plaintext(bases, key, proof_label)?
      end
    },
    decode_native_security_config(policy.frame)?,
    now)?
  let members = verified_device_set(verified.verified.device_set)?
  if !Bytes.secure_equals(members.account.account_id, local.account_id)
    || !Bytes.secure_equals(members.account.authorization_public_key,
      local.account.authorization_public_key)
    || Bytes.secure_equals(device, local.device_id) do
    return Err("sibling_membership_invalid")
  end
  let local_matches = List.any(members.profiles,
    fn(member) -> Bytes.secure_equals(member.device_id, local.device_id)
      && Bytes.secure_equals(member.credential.signing_public_key,
        local.credential.signing_public_key)
      && Bytes.secure_equals(member.credential.dh_public_key, local.credential.dh_public_key) end)
  if !local_matches do
    return Err("sibling_membership_invalid")
  end
  for member in members.profiles do
    if Bytes.secure_equals(member.device_id, device) do
      let deadline = List.reduce([
          local.credential.expires_at,
          local.bundle.expires_at,
          member.credential.expires_at,
          member.bundle.expires_at
        ],
        verified.fresh_through,
        fn(before, value) do
          if U64.compare(value, before) < 0 do
            value
          else
            before
          end
        end)
      return Ok((member, deadline))
    end
  end
  Err("sibling_membership_invalid")
end

# The operation captures these ordinary inputs itself; final writers recheck them.
pub fn require_sibling_observation(observation :: Option<(NativeSessionPolicy, U64)>) -> Unit!String do
  case observation do
    None -> Ok(nil)
    Some((policy, deadline)) -> do
      require_current_session_policy(policy)?
      if U64.compare(current_time()?, deadline) > 0 do
        Err("sibling_membership_stale")
      else
        Ok(nil)
      end
    end
  end
end
