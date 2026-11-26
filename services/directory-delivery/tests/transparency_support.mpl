##! Test fixture for the transparency log: synthetic accounts and device sets
##! appended straight to the log, the Morse witnesses' test keys, and resets
##! that also clear the witness-network tables.

from Api.Binary import submit_witness_request
from Protocol.DirectoryWire import encode_device_set
from Protocol.V1 import DeviceSet, DirectoryEntry
from Storage.Transparency import append_entry_on_connection
from Transparency.Merkle import TransparencyCheckpoint, sign_witness
from Transparency.Wire import encode_witnesses

pub fn transparency_test_bytes(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

pub fn transparency_test_reset(pool :: PoolHandle) -> Result<(), String> do
  Pool.execute(pool,
    "TRUNCATE messenger_deleted_accounts, messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, transparency_device_records, transparency_anchors, transparency_pruning_runs, transparency_witness_registry, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
    [])?
  Ok(nil)
end

## An account row the log's lookups can resolve, without devices.

pub fn transparency_test_account(pool :: PoolHandle,
  username :: String,
  account_id :: Bytes) -> Result<(), String> do
  Pool.execute_values(pool,
    "INSERT INTO messenger_accounts (username, account_id, account_identity) VALUES ($1, $2, $3)",
    [Text(username), Binary(account_id), Binary(transparency_test_bytes(7, 64))])?
  Ok(nil)
end

fn device(username :: String, seed :: Int) -> DirectoryEntry do
  DirectoryEntry {
    version: 1,
    username: username,
    account_identity: transparency_test_bytes(7, 64),
    prekey_bundle: transparency_test_bytes(seed, 900),
    mailbox_token: transparency_test_bytes(seed, 32)
  }
end

## A device set of synthetic devices, one per seed, with revoked device IDs.

pub fn transparency_test_set(username :: String,
  sequence :: Int,
  seeds :: List<Int>,
  revoked :: List<Int>) -> Bytes!String do
  let value = DeviceSet {
    version: 1,
    username: username,
    account_identity: transparency_test_bytes(7, 64),
    sequence: U64.parse(Int.to_string(sequence))?,
    devices: List.map(seeds, fn seed -> device(username, seed) end),
    revoked_device_ids: List.map(revoked, fn seed -> transparency_test_bytes(seed, 16) end)
  }
  case encode_device_set(value) do
    Err(_) -> Err("test device set failed")
    Ok(encoded)
  end
end

pub fn transparency_test_append(pool :: PoolHandle,
  account_id :: Bytes,
  entry :: Bytes) -> Int!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> append_entry_on_connection(conn, account_id, entry) end)
end

pub fn transparency_test_scalar(pool :: PoolHandle, sql :: String) -> String!String do
  let rows = Pool.query_values(pool, sql, [])?
  case rows do
    [row] -> case Map.get(row, "value") do
      Text(value) -> Ok(value)
      _ -> Err("expected a text value")
    end
    _ -> Err("expected one row")
  end
end

pub fn transparency_test_witness_key(name :: String) -> SigningKeyPair!String do
  let seed = if name == "witness-a" do
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  else
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
  end
  case Crypto.signing_from_seed(Bytes.from_hex(seed)?) do
    Err(_) -> Err("witness key failed")
    Ok(value)
  end
end

## Has a test witness sign the checkpoint and submits its statement (KTW v1);
## returns the HTTP status the directory answered.

pub fn transparency_test_attest(pool :: PoolHandle,
  name :: String,
  checkpoint :: TransparencyCheckpoint) -> Int!String do
  let key = transparency_test_witness_key(name)?
  let statement = sign_witness(name, key.private_key, checkpoint)?
  Ok(submit_witness_request(pool, encode_witnesses([statement])?).status)
end
