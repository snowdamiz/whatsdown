from Storage.AccountGuard import AccountBasis, commit_account_changes
from Storage.Keys import context, seal_local, open_local
from Mobile.Codec import mobile_byte, mobile_write_u64, mobile_read_u64
from Transport.Packet import ClientProfile
from Protocol.DirectoryWire import decode_directory_entry, encode_directory_entry

pub struct RenewalPublication do
  devices_hash :: Bytes
  sequence :: U64
  entries :: List<Bytes>
end

fn label(index :: Int) -> String do
  "device-publication/v1/#{index}"
end

pub fn renewal_publication_labels() -> List<String> do
  ["device-publication/v1"]
    ++ for index in 0..8 do
      label(index)
    end
end

fn snapshot_record(before :: AccountBasis, label :: String, index :: Int) -> Bytes!String do
  if index >= List.length(before.labels) do
    return Err("invalid_renewal_publication")
  end
  if List.get(before.labels, index) == label do
    Ok(List.get(before.records, index))
  else
    snapshot_record(before, label, index + 1)
  end
end

fn queue_context(local :: ClientProfile, label :: String) -> Bytes!String do
  context(local.account_id, local.device_id, label, 14)
end

fn canonical_entry(input :: Bytes, local :: ClientProfile) -> Result<(), String> do
  if Bytes.length(input) == 0 || Bytes.length(input) > 36006 do
    return Err("invalid_renewal_publication")
  end
  let value = case decode_directory_entry(input) do
    Err(_) -> return Err("invalid_renewal_publication")
    Ok(value) -> value
  end
  let encoded = case encode_directory_entry(value) do
    Err(_) -> return Err("invalid_renewal_publication")
    Ok(value) -> value
  end
  if value.username != local.username
    || !Bytes.secure_equals(value.account_identity, local.entry.account_identity)
    || !Bytes.secure_equals(input, encoded) do
    return Err("invalid_renewal_publication")
  end
  Ok(nil)
end

pub fn load_renewal_publication(before :: AccountBasis,
  local :: ClientProfile,
  key :: borrow StorageKey) -> Option<RenewalPublication>!String do
  let previous = snapshot_record(before, "device-publication/v1", 0)?
  if Bytes.length(previous) == 0 do
    return Ok(None)
  end
  let head = open_local(previous, key, queue_context(local, "device-publication/v1")?)?
  if Bytes.length(head) != 45 || Bytes.to_hex(Bytes.slice(head, 0, 4)?) != "01445051" do
    return Err("invalid_renewal_publication")
  end
  let count = Bytes.get(head, 44)?
  if count < 1 || count > 8 do
    return Err("invalid_renewal_publication")
  end
  let entries = for index in 0..count do
    let name = label(index)
    let wire = open_local(snapshot_record(before, name, 0)?, key, queue_context(local, name)?)?
    canonical_entry(wire, local)?
    wire
  end
  Ok(Some(RenewalPublication {
    devices_hash: Bytes.slice(head, 4, 32)?,
    sequence: mobile_read_u64(Bytes.slice(head, 36, 8)?)?,
    entries: entries
  }))
end

fn patch_records(before :: AccountBasis,
  labels :: List<String>,
  blobs :: List<Bytes>,
  removed :: List<String>,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes> do
  if index >= List.length(before.labels) do
    return output
  end
  let name = List.get(before.labels, index)
  let matching = List.filter(for i in 0..List.length(labels) do
      i
    end,
    fn(i) -> List.get(labels, i) == name end)
  let value = if List.length(matching) == 1 do
    List.get(blobs, List.head(matching))
  else if List.contains(removed, name) do
    Bytes.empty()
  else
    List.get(before.records, index)
  end
  patch_records(before, labels, blobs, removed, index + 1, List.append(output, value))
end

fn expected_basis(before :: AccountBasis,
  labels :: List<String>,
  blobs :: List<Bytes>,
  removed :: List<String>) -> AccountBasis do
  %{before | records: patch_records(before, labels, blobs, removed, 0, [])}
end

## Each canonical entry is below the 64KiB sealing bound. The head and at most
## eight separately sealed entries commit together before any publication HTTP.
pub fn save_renewal_publication(path :: String,
  before :: AccountBasis,
  local :: ClientProfile,
  key :: borrow StorageKey,
  devices :: Bytes,
  sequence :: U64,
  entries :: List<Bytes>) -> AccountBasis!String do
  if List.length(entries) < 1 || List.length(entries) > 8 do
    return Err("invalid_renewal_publication")
  end
  let head = Bytes.concat(Bytes.concat(Bytes.from_hex("01445051")?, Crypto.sha256(devices))?,
    Bytes.concat(mobile_write_u64(sequence)?, mobile_byte(List.length(entries))?)?)?
  let names = ["device-publication/v1"]
    ++ for index in 0..List.length(entries) do
      label(index)
    end
  let body = for index in 0..List.length(entries) do
    let wire = List.get(entries, index)
    canonical_entry(wire, local)?
    seal_local(wire, key, queue_context(local, label(index))?)?
  end
  let blobs = [seal_local(head, key, queue_context(local, "device-publication/v1")?)?] ++ body
  let removed = for index in List.length(entries)..8 do
    label(index)
  end
  commit_account_changes(path, before, names, blobs, removed)?
  Ok(expected_basis(before, names, blobs, removed))
end

pub fn clear_renewal_publication(path :: String, before :: AccountBasis) -> Result<(), String> do
  commit_account_changes(path, before, [], [], renewal_publication_labels())
end
