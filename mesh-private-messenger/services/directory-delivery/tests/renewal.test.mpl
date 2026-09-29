from Api.Binary import register_device_request
from Identity.Device import AccountKeys, DeviceKeys, generate_account, generate_device, issue_hybrid_device_credential
from Prekeys.Bundle import PostQuantumPrekeySecrets, SignedPrekeySecrets, build_hybrid_prekey_bundle, generate_one_time_prekey, generate_post_quantum_prekey, generate_signed_prekey, normalize_prekey_bundle
from Prekeys.Renewal import RenewalRequest, bundle_with_renewal_request, generate_renewal_signed_prekey, issue_renewal_request, renewed_prekey_bundle
from Protocol.DirectoryWire import encode_directory_entry
from Protocol.IdentityWire import encode_account_identity
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import AccountIdentity, DeviceCredential, DirectoryEntry, PrekeyBundle
from Storage.Devices import resolve_devices

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn now() -> U64!String do
  wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn year() -> U64!String do
  wide("31536000000")
end

fn filled(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid test row")
  end
end

fn scalar(pool :: PoolHandle, sql :: String) -> String!String do
  let rows = Pool.query_values(pool, sql, [])?
  if List.length(rows) == 1 do
    text(Map.get(List.head(rows), "value"))
  else
    Err("expected one row")
  end
end

# The account's sequence and the number of logged transitions.
fn logged(pool :: PoolHandle) -> String!String do
  scalar(pool,
    "SELECT concat((SELECT sequence FROM messenger_accounts WHERE username = 'alice'), ':', (SELECT count(*) FROM transparency_entries)) AS value")
end

fn prekeys(pool :: PoolHandle) -> String!String do
  scalar(pool, "SELECT count(*)::text AS value FROM messenger_one_time_prekeys")
end

fn reset(pool :: PoolHandle) -> Result<(), String> do
  Pool.execute(pool,
    "TRUNCATE messenger_deleted_accounts, messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
    [])?
  Ok(nil)
end

fn account(created_at :: U64) -> Result<(AccountKeys, AccountIdentity), String> do
  case generate_account(created_at, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(value)
  end
end

fn device() -> DeviceKeys!String do
  case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value)
  end
end

fn post_quantum() -> PostQuantumPrekeySecrets!String do
  case generate_post_quantum_prekey() do
    Err(_) -> Err("post-quantum prekey generation failed")
    Ok(value)
  end
end

fn credential(account_keys :: borrow AccountKeys,
  device_keys :: borrow DeviceKeys,
  keys :: borrow PostQuantumPrekeySecrets,
  created_at :: U64,
  expires_at :: U64,
  sequence :: U64) -> DeviceCredential!String do
  case issue_hybrid_device_credential(account_keys,
    device_keys,
    keys.public_key,
    wide("1")?,
    created_at,
    expires_at,
    sequence) do
    Err(_) -> Err("credential generation failed")
    Ok(value)
  end
end

# A device's first bundle, with the one-time prekey a registration carries.
fn first_bundle(device_keys :: borrow DeviceKeys,
  value :: DeviceCredential,
  keys :: borrow PostQuantumPrekeySecrets,
  expires_at :: U64) -> PrekeyBundle!String do
  let signed = case generate_signed_prekey(device_keys, value, wide("1")?, expires_at) do
    Err(_) -> Err("signed prekey generation failed")
    Ok(output)
  end?
  let one_time = case generate_one_time_prekey(wide("2")?) do
    Err(_) -> Err("one-time prekey generation failed")
    Ok(output)
  end?
  case build_hybrid_prekey_bundle(value, signed, one_time, keys) do
    Err(_) -> Err("bundle generation failed")
    Ok(output)
  end
end

fn base(bundle :: PrekeyBundle) -> PrekeyBundle!String do
  case normalize_prekey_bundle(bundle) do
    Err(_) -> Err("bundle normalization failed")
    Ok(output)
  end
end

fn next_signed(device_keys :: borrow DeviceKeys,
  value :: DeviceCredential,
  id :: String,
  expires_at :: U64) -> SignedPrekeySecrets!String do
  case generate_renewal_signed_prekey(device_keys, value, wide(id)?, expires_at) do
    Err(_) -> Err("renewal signed prekey generation failed")
    Ok(output)
  end
end

fn ask(device_keys :: borrow DeviceKeys,
  value :: DeviceCredential,
  signed :: borrow SignedPrekeySecrets,
  keys :: borrow PostQuantumPrekeySecrets) -> RenewalRequest!String do
  case issue_renewal_request(device_keys, value, signed, keys) do
    Err(_) -> Err("renewal request failed")
    Ok(output)
  end
end

fn asking(bundle :: PrekeyBundle, request :: RenewalRequest) -> PrekeyBundle!String do
  case bundle_with_renewal_request(bundle, request) do
    Err(_) -> Err("request bundle failed")
    Ok(output)
  end
end

fn answered(value :: DeviceCredential, request :: RenewalRequest) -> PrekeyBundle!String do
  case renewed_prekey_bundle(value, request) do
    Err(_) -> Err("renewed bundle failed")
    Ok(output)
  end
end

fn bundle_wire(bundle :: PrekeyBundle) -> Bytes!String do
  case encode_prekey_bundle(bundle) do
    Err(_) -> Err("bundle encoding failed")
    Ok(output)
  end
end

fn entry(identity :: AccountIdentity, bundle :: PrekeyBundle, mailbox_token :: Bytes) -> Bytes!String do
  let account_wire = case encode_account_identity(identity) do
    Err(_) -> Err("account encoding failed")
    Ok(output)
  end?
  case encode_directory_entry(DirectoryEntry {
    version: 1,
    username: "alice",
    account_identity: account_wire,
    prekey_bundle: bundle_wire(bundle)?,
    mailbox_token: mailbox_token
  }) do
    Err(_) -> Err("entry encoding failed")
    Ok(output)
  end
end

fn status(pool :: PoolHandle, identity :: AccountIdentity, bundle :: PrekeyBundle, mailbox_token :: Bytes) -> Int!String do
  Ok(register_device_request(pool, entry(identity, bundle, mailbox_token)?).status)
end

fn stored_bundle(pool :: PoolHandle, mailbox_token :: Bytes) -> Bytes!String do
  case resolve_devices(pool, "alice")? do
    None -> Err("device set missing")
    Some(set) -> stored_in(set.devices, mailbox_token, 0)
  end
end

fn stored_in(devices :: List<DirectoryEntry>, mailbox_token :: Bytes, index :: Int) -> Bytes!String do
  if index >= List.length(devices) do
    Err("device missing")
  else
    let candidate = List.get(devices, index)
    if Bytes.secure_equals(candidate.mailbox_token, mailbox_token) do
      Ok(candidate.prekey_bundle)
    else
      stored_in(devices, mailbox_token, index + 1)
    end
  end
end

fn renewal_proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
    "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000)?
  reset(pool)?
  let t = now()?
  let later = U64.add(t, year()?)?
  # Created three years ago, so that a credential can have come and gone.
  let (account_keys, identity) = account(U64.subtract(t, U64.add(year()?, U64.add(year()?, year()?)?)?)?)?
  let primary = device()?
  let linked = device()?
  let primary_mailbox = filled(81, 32)
  let linked_mailbox = filled(82, 32)
  let primary_keys = post_quantum()?
  let primary_credential = credential(account_keys, primary, primary_keys, t, later, wide("1")?)?
  let primary_first = first_bundle(primary, primary_credential, primary_keys, later)?
  assert(status(pool, identity, primary_first, primary_mailbox)? == 201)
  let linked_keys = post_quantum()?
  let linked_credential = credential(account_keys, linked, linked_keys, t, later, wide("2")?)?
  let linked_first = first_bundle(linked, linked_credential, linked_keys, later)?
  assert(status(pool, identity, linked_first, linked_mailbox)? == 201)
  assert(logged(pool)? == "2:2")
  assert(prekeys(pool)? == "2")
  # The linked device publishes what it wants next, under its current
  # credential: a transition of its own.
  let renewal_expiry = U64.add(later, wide("86400000")?)?
  let linked_next_keys = post_quantum()?
  let linked_next_signed = next_signed(linked, linked_credential, "2", renewal_expiry)?
  let request = ask(linked, linked_credential, linked_next_signed, linked_next_keys)?
  let requesting = asking(base(linked_first)?, request)?
  assert(status(pool, identity, requesting, linked_mailbox)? == 201)
  assert(logged(pool)? == "3:3")
  # The same again, or the entry from before it, is already registered.
  assert(status(pool, identity, requesting, linked_mailbox)? == 200)
  assert(status(pool, identity, linked_first, linked_mailbox)? == 200)
  assert(logged(pool)? == "3:3")
  # A request the device did not sign is refused.
  let forged = ask(primary, linked_credential, linked_next_signed, linked_next_keys)?
  assert(status(pool, identity, asking(base(linked_first)?, forged)?, linked_mailbox)? == 409)
  # The account key answers with a credential for exactly the requested keys,
  # at the next sequence and no other.
  let late = credential(account_keys, linked, linked_next_keys, t, renewal_expiry, wide("5")?)?
  assert(status(pool, identity, answered(late, request)?, linked_mailbox)? == 409)
  let answer = credential(account_keys, linked, linked_next_keys, t, renewal_expiry, wide("4")?)?
  let renewed = answered(answer, request)?
  assert(status(pool, identity, renewed, linked_mailbox)? == 201)
  assert(logged(pool)? == "4:4")
  assert(Bytes.secure_equals(stored_bundle(pool, linked_mailbox)?, bundle_wire(renewed)?))
  # Every earlier entry of the device is now a replay.
  assert(status(pool, identity, requesting, linked_mailbox)? == 200)
  assert(status(pool, identity, linked_first, linked_mailbox)? == 200)
  assert(logged(pool)? == "4:4")
  assert(Bytes.secure_equals(stored_bundle(pool, linked_mailbox)?, bundle_wire(renewed)?))
  # The device holding the account key renews itself in one transition.
  let primary_next_keys = post_quantum()?
  let primary_next_signed = next_signed(primary, primary_credential, "2", renewal_expiry)?
  let own = ask(primary, primary_credential, primary_next_signed, primary_next_keys)?
  let primary_renewed = answered(credential(account_keys,
      primary,
      primary_next_keys,
      t,
      renewal_expiry,
      wide("5")?)?,
    own)?
  assert(status(pool, identity, primary_renewed, primary_mailbox)? == 201)
  assert(status(pool, identity, primary_first, primary_mailbox)? == 200)
  assert(logged(pool)? == "5:5")
  # Renewals leave the one-time prekeys alone.
  assert(prekeys(pool)? == "2")
  # A device that stayed away past its expiry still answers its old entry as
  # registered, and may still ask; it cannot join the account expired.
  let away = device()?
  let away_mailbox = filled(83, 32)
  let away_keys = post_quantum()?
  let away_credential = credential(account_keys, away, away_keys, t, later, wide("6")?)?
  let away_first = first_bundle(away, away_credential, away_keys, later)?
  assert(status(pool, identity, away_first, away_mailbox)? == 201)
  let past = U64.subtract(t, year()?)?
  let long_ago = U64.subtract(past, year()?)?
  let lapsed_credential = credential(account_keys, away, away_keys, long_ago, past, wide("6")?)?
  let lapsed = base(first_bundle(away, lapsed_credential, away_keys, past)?)?
  Pool.execute_values(pool,
    "UPDATE messenger_devices SET prekey_bundle = $1 WHERE mailbox_token = $2",
    [Binary(bundle_wire(lapsed)?), Binary(away_mailbox)])?
  assert(status(pool, identity, lapsed, away_mailbox)? == 200)
  let stranger = device()?
  let stranger_keys = post_quantum()?
  let stranger_credential = credential(account_keys, stranger, stranger_keys, long_ago, past, wide("7")?)?
  assert(status(pool,
    identity,
    first_bundle(stranger, stranger_credential, stranger_keys, past)?,
    filled(84, 32))? == 400)
  assert(logged(pool)? == "6:6")
  let away_next_keys = post_quantum()?
  let away_next_signed = next_signed(away, lapsed_credential, "2", renewal_expiry)?
  let away_request = ask(away, lapsed_credential, away_next_signed, away_next_keys)?
  assert(status(pool, identity, asking(lapsed, away_request)?, away_mailbox)? == 201)
  let back = answered(credential(account_keys, away, away_next_keys, t, renewal_expiry, wide("8")?)?,
    away_request)?
  assert(status(pool, identity, back, away_mailbox)? == 201)
  assert(logged(pool)? == "8:8")
  reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("devices renew through logged transitions, and replays of earlier entries change nothing") do
  case renewal_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
