from Mobile.Codec import mobile_finish, mobile_reader, mobile_utf8, take_vector_error
from Mobile.Journal import journal_label, validate_journal_value
from Mobile.AccountState import load_bound_account
from Storage.AccountGuard import (
  AccountBasis,
  load_account_basis,
  account_basis_current,
  commit_account_changes
)
from Storage.JournalBlobs import open_journal_blob, seal_journal_blob
from Storage.Keys import platform_key

pub struct JournalRequest do
  database_path :: String
  expected_profile :: Bytes
  key :: Bytes
  data :: Bytes
end

pub struct JournalWritePlan do
  database_path :: String
  before :: AccountBasis
  label :: String
  blob :: Bytes
  remove :: Bool
end

fn parse_journal(input :: Bytes, writing :: Bool) -> JournalRequest!String do
  let state = mobile_reader(input,
    if writing do
      302646
    else
      40498
    end,
    "invalid_journal_request")?
  let path = take_vector_error(state, 4096, "invalid_journal_request")?
  let profile = take_vector_error(path.state, 36134, "invalid_journal_request")?
  let key = take_vector_error(profile.state, 256, "invalid_journal_request")?
  let data = if writing do
    let value = take_vector_error(key.state, 262144, "invalid_journal_request")?
    mobile_finish(value.state, "invalid_journal_request")?
    if Bytes.length(value.value) == 0 do
      return Err("invalid_journal_request")
    end
    value.value
  else
    mobile_finish(key.state, "invalid_journal_request")?
    Bytes.empty()
  end
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if Bytes.length(path.value) == 0
    || String.contains(database_path, "\0")
    || Bytes.length(profile.value) == 0
    || Bytes.length(key.value) == 0 do
    return Err("invalid_journal_request")
  end
  Ok(JournalRequest {
    database_path: database_path,
    expected_profile: profile.value,
    key: key.value,
    data: data
  })
end

fn journal_basis(request :: JournalRequest, label :: String) -> AccountBasis!String do
  let account = load_bound_account(request.database_path, request.expected_profile, false)?
  let before = load_account_basis(request.database_path, [label])?
  if !Bytes.secure_equals(before.profile, account.before.profile) do
    return Err("account_state_changed")
  end
  Ok(before)
end

## Capture both account custody and the prior record before any encryption.
## Commit compares them under one SQLite write lock, including deletion plans.
pub fn prepare_journal_write(input :: Bytes) -> JournalWritePlan!String do
  let request = parse_journal(input, true)?
  let label = journal_label(request.key)?
  validate_journal_value(label, request.data)?
  let before = journal_basis(request, label)?
  let remove = Bytes.secure_equals(request.data, Bytes.from_hex("00")?)
  let blob = if remove do
    Bytes.empty()
  else
    let wrapping = platform_key()?
    seal_journal_blob(request.data, wrapping, label)?
  end
  Ok(JournalWritePlan {
    database_path: request.database_path,
    before: before,
    label: label,
    blob: blob,
    remove: remove
  })
end

pub fn commit_journal_write(plan :: JournalWritePlan) -> Bytes!String do
  if plan.remove do
    commit_account_changes(plan.database_path, plan.before, [], [], [plan.label])?
  else
    commit_account_changes(plan.database_path, plan.before, [plan.label], [plan.blob], [])?
  end
  Ok(Bytes.empty())
end

pub fn native_journal_load(input :: Bytes) -> Bytes!String do
  let request = parse_journal(input, false)?
  let label = journal_label(request.key)?
  let before = journal_basis(request, label)?
  let blob = List.head(before.records)
  let value = if Bytes.length(blob) == 0 do
    Bytes.empty()
  else
    let wrapping = platform_key()?
    open_journal_blob(blob, wrapping, label)?
  end
  if !account_basis_current(request.database_path, before) do
    return Err("account_state_changed")
  end
  Ok(value)
end

pub fn native_journal_save(input :: Bytes) -> Bytes!String do
  commit_journal_write(prepare_journal_write(input)?)
end
