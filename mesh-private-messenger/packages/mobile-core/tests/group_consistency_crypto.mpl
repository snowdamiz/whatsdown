from Mobile.Codec import current_time
from MobileCore import group_add_export
from Tests.GroupConsistencySupport import ConsistencyAccount, evidence_bytes, request, verify_for, wide
from Tests.Support import append, repeated
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash, sign_checkpoint

pub fn tamper_last(input :: Bytes) -> Bytes ! String do
  let length = Bytes.length(input)
  case Bytes.get(input, length - 1) do
    Err( _) -> Err("test byte read failed")
    Ok( last) -> do
      let replacement = if last == 0 do
        1
      else
        0
      end
      case Bytes.slice(input, 0, length - 1) do
        Err( _) -> Err("test byte slice failed")
        Ok( prefix) -> case Bytes.from_list([replacement]) do
          Err( _) -> Err("test byte allocation failed")
          Ok( suffix) -> append(prefix, suffix)
        end
      end
    end
  end
end

pub fn checkpoint(service_private :: borrow SigningPrivateKey,
service_public_key :: Bytes,
sequence :: Int,
leaves :: List < Bytes >,
previous :: TransparencyCheckpoint,
has_previous :: Bool) -> TransparencyCheckpoint ! String do
  let previous_hash = if has_previous do
    checkpoint_hash(previous) ?
  else
    repeated(0, 32) ?
  end
  sign_checkpoint(service_private,
  service_public_key,
  wide(sequence) ?,
  leaves,
  previous_hash,
  current_time() ?)
end

pub fn expect_group_key_rejection(path :: String,
group_id :: Bytes,
device_set :: Bytes,
key_package :: Bytes) -> Bool ! String do
  case group_add_export(request([Bytes.from_utf8(path), group_id, device_set, key_package]) ?) do
    Ok( _) -> Ok(false)
    Err( error) -> Ok(error == "invalid_group_key_package")
  end
end
