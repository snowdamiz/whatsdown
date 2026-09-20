from Api.Binary import checkpoint_request, consistency_request, fetch_request, inclusion_request, register_device_request, resolve_devices_request, revoke_device_request, submit_request, submit_witness_request, validate_transparency_config, witnesses_request
from Identity.Device import AccountKeys, DeviceKeys, credential_signing_bytes, generate_account, generate_device, issue_device_credential, issue_device_revocation, issue_hybrid_device_credential
from Prekeys.Bundle import build_hybrid_prekey_bundle, build_prekey_bundle, generate_one_time_prekey, generate_post_quantum_prekey, generate_signed_prekey, reauthorize_signed_prekey
from Protocol.DirectoryWire import (
  decode_device_set,
  encode_device_revocation,
  encode_device_set,
  encode_directory_entry
)
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.IdentityWire import decode_device_credential, encode_account_identity, encode_device_credential
from Tests.MailboxSupport import signed_fetch
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DirectoryEntry,
  OuterEnvelope,
  PrekeyBundle,
  ProtocolError,
  ProtocolExtension
)
from Storage.Devices import resolve_devices
from Storage.Transparency import latest_checkpoint, append_entry_on_connection, create_checkpoint, entry_count, consistency_from, evidence_for_username, inclusion_for_account
from Transparency.Merkle import checkpoint_hash, sign_checkpoint, WitnessKey, leaf_hash, sign_witness, verify_checkpoint, verify_consistency, verify_inclusion, verify_witnesses
from Transparency.Wire import TransparencyEvidence, TransparencyLookup, TransparencyTreeQuery, decode_checkpoint, decode_consistency_proof, decode_inclusion_proof, decode_transparency_evidence, decode_witnesses, encode_transparency_evidence, encode_transparency_lookup, encode_transparency_tree_query, encode_witnesses

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err( _) -> Bytes.empty()
    Ok( output) -> output
  end
end

fn wide(value :: String) -> U64 ! String do
  U64.parse(value)
end

fn now() -> U64 ! String do
  wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn account(created_at :: U64) -> Result <( AccountKeys, AccountIdentity), String > do
  case generate_account(created_at, wide("1") ?) do
    Err( _) -> Err("account generation failed")
    Ok( value) -> Ok(value)
  end
end

fn device() -> DeviceKeys ! String do
  case generate_device() do
    Err( _) -> Err("device generation failed")
    Ok( value) -> Ok(value)
  end
end

fn credential(account_keys :: borrow AccountKeys,
device_keys :: borrow DeviceKeys,
created_at :: U64,
expires_at :: U64,
sequence :: U64) -> DeviceCredential ! String do
  case issue_device_credential(account_keys,
  device_keys,
  wide("1") ?,
  created_at,
  expires_at,
  sequence) do
    Err( _) -> Err("credential generation failed")
    Ok( value) -> Ok(value)
  end
end

fn protocol(value :: Result < Bytes, ProtocolError >) -> Bytes ! String do
  case value do
    Err( _) -> Err("protocol encoding failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn text(value :: DbValue) -> String ! String do
  case value do
    Text( output) -> Ok(output)
    _ -> Err("invalid test row")
  end
end

fn scalar(pool :: PoolHandle, sql :: String) -> String ! String do
  let rows = Pool.query_values(pool, sql, []) ?
  if List.length(rows) == 1 do
    text(Map.get(List.head(rows), "value"))
  else
    Err("expected one row")
  end
end

fn maximal_extensions(index :: Int, output :: List < ProtocolExtension >) -> List < ProtocolExtension > do
  if index >= 16 do
    output
  else
    maximal_extensions(index + 1,
    List.append(output,
    ProtocolExtension {
      id : index + 1,
      mandatory : false,
      value : repeated(index, 1024)
    }))
  end
end

fn entry(identity :: AccountIdentity,
device_keys :: borrow DeviceKeys,
device_credential :: DeviceCredential,
mailbox_token :: Bytes,
expires_at :: U64) -> DirectoryEntry ! String do
  let signed = case generate_signed_prekey(device_keys, device_credential, wide("1") ?, expires_at) do
    Err( _) -> Err("signed prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let one_time = case generate_one_time_prekey(wide("2") ?) do
    Err( _) -> Err("one-time prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let bundle = case build_prekey_bundle(device_credential, signed, one_time) do
    Err( _) -> Err("bundle generation failed")
    Ok( value) -> Ok(value)
  end ?
  Ok(DirectoryEntry {
    version : 1,
    username : "alice",
    account_identity : protocol(encode_account_identity(identity)) ?,
    prekey_bundle : protocol(encode_prekey_bundle(bundle)) ?,
    mailbox_token : mailbox_token
  })
end

fn maximal_hybrid_entry(identity :: AccountIdentity,
account_keys :: borrow AccountKeys,
device_keys :: borrow DeviceKeys,
mailbox_token :: Bytes,
created_at :: U64,
expires_at :: U64,
sequence :: U64) -> DirectoryEntry ! String do
  let post_quantum = case generate_post_quantum_prekey() do
    Err( _) -> Err("post-quantum prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let device_credential = case issue_hybrid_device_credential(account_keys,
  device_keys,
  post_quantum.public_key,
  wide("3") ?,
  created_at,
  expires_at,
  sequence) do
    Err( _) -> Err("hybrid credential generation failed")
    Ok( value) -> Ok(value)
  end ?
  let signed = case generate_signed_prekey(device_keys, device_credential, wide("1") ?, expires_at) do
    Err( _) -> Err("signed prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let one_time = case generate_one_time_prekey(wide("2") ?) do
    Err( _) -> Err("one-time prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let base = case build_hybrid_prekey_bundle(device_credential, signed, one_time, post_quantum) do
    Err( _) -> Err("hybrid bundle generation failed")
    Ok( value) -> Ok(value)
  end ?
  let bundle = PrekeyBundle {
    version : base.version,
    suite : base.suite,
    device_credential : base.device_credential,
    identity_dh_public_key : base.identity_dh_public_key,
    signing_public_key : base.signing_public_key,
    signed_prekey_id : base.signed_prekey_id,
    signed_prekey : base.signed_prekey,
    signed_prekey_signature : base.signed_prekey_signature,
    one_time_prekey_id : base.one_time_prekey_id,
    one_time_prekey : base.one_time_prekey,
    post_quantum_prekey : base.post_quantum_prekey,
    supported_suites : base.supported_suites,
    expires_at : base.expires_at,
    extensions : maximal_extensions(0, List.new())
  }
  let encoded = protocol(encode_prekey_bundle(bundle)) ?
  assert(Bytes.length(encoded) == 19312)
  Ok(DirectoryEntry {
    version : 1,
    username : "alice",
    account_identity : protocol(encode_account_identity(identity)) ?,
    prekey_bundle : encoded,
    mailbox_token : mailbox_token
  })
end

struct RotationEntries do
  classical :: DirectoryEntry
  replayed_sequence :: DirectoryEntry
  first_hybrid :: DirectoryEntry
  second_hybrid :: DirectoryEntry
  swapped_signed_prekey :: DirectoryEntry
  downgrade :: DirectoryEntry
end

fn bundled_entry(identity :: AccountIdentity, bundle :: PrekeyBundle, mailbox_token :: Bytes) -> DirectoryEntry ! String do
  Ok(DirectoryEntry {
    version : 1,
    username : "alice",
    account_identity : protocol(encode_account_identity(identity)) ?,
    prekey_bundle : protocol(encode_prekey_bundle(bundle)) ?,
    mailbox_token : mailbox_token
  })
end

fn rotation_entries(identity :: AccountIdentity,
account_keys :: borrow AccountKeys,
primary :: borrow DeviceKeys,
mailbox_token :: Bytes,
created_at :: U64,
expires_at :: U64) -> RotationEntries ! String do
  let classical_credential = credential(account_keys, primary, created_at, expires_at, wide("1") ?) ?
  let signed = case generate_signed_prekey(primary, classical_credential, wide("1") ?, expires_at) do
    Err( _) -> Err("signed prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let one_time = case generate_one_time_prekey(wide("2") ?) do
    Err( _) -> Err("one-time prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let classical_bundle = case build_prekey_bundle(classical_credential, signed, one_time) do
    Err( _) -> Err("classical bundle generation failed")
    Ok( value) -> Ok(value)
  end ?
  let replay_post_quantum = case generate_post_quantum_prekey() do
    Err( _) -> Err("post-quantum prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let replay_credential = case issue_hybrid_device_credential(account_keys,
  primary,
  replay_post_quantum.public_key,
  wide("3") ?,
  created_at,
  expires_at,
  wide("1") ?) do
    Err( _) -> Err("hybrid credential generation failed")
    Ok( value) -> Ok(value)
  end ?
  let signed = case reauthorize_signed_prekey(primary, replay_credential, signed) do
    Err( _) -> Err("signed prekey reauthorization failed")
    Ok( value) -> Ok(value)
  end ?
  let replay_bundle = case build_hybrid_prekey_bundle(replay_credential,
  signed,
  one_time,
  replay_post_quantum) do
    Err( _) -> Err("hybrid bundle generation failed")
    Ok( value) -> Ok(value)
  end ?
  let first_post_quantum = case generate_post_quantum_prekey() do
    Err( _) -> Err("post-quantum prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let first_credential = case issue_hybrid_device_credential(account_keys,
  primary,
  first_post_quantum.public_key,
  wide("3") ?,
  created_at,
  expires_at,
  wide("2") ?) do
    Err( _) -> Err("hybrid credential generation failed")
    Ok( value) -> Ok(value)
  end ?
  let signed = case reauthorize_signed_prekey(primary, first_credential, signed) do
    Err( _) -> Err("signed prekey reauthorization failed")
    Ok( value) -> Ok(value)
  end ?
  let first_bundle = case build_hybrid_prekey_bundle(first_credential,
  signed,
  one_time,
  first_post_quantum) do
    Err( _) -> Err("hybrid bundle generation failed")
    Ok( value) -> Ok(value)
  end ?
  let second_post_quantum = case generate_post_quantum_prekey() do
    Err( _) -> Err("post-quantum prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let second_credential = case issue_hybrid_device_credential(account_keys,
  primary,
  second_post_quantum.public_key,
  wide("3") ?,
  created_at,
  expires_at,
  wide("2") ?) do
    Err( _) -> Err("hybrid credential generation failed")
    Ok( value) -> Ok(value)
  end ?
  let signed = case reauthorize_signed_prekey(primary, second_credential, signed) do
    Err( _) -> Err("signed prekey reauthorization failed")
    Ok( value) -> Ok(value)
  end ?
  let second_bundle = case build_hybrid_prekey_bundle(second_credential,
  signed,
  one_time,
  second_post_quantum) do
    Err( _) -> Err("hybrid bundle generation failed")
    Ok( value) -> Ok(value)
  end ?
  let swapped_signed = case generate_signed_prekey(primary,
  first_credential,
  wide("1") ?,
  expires_at) do
    Err( _) -> Err("swapped signed prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let swapped_bundle = case build_hybrid_prekey_bundle(first_credential,
  swapped_signed,
  one_time,
  first_post_quantum) do
    Err( _) -> Err("swapped bundle generation failed")
    Ok( value) -> Ok(value)
  end ?
  let downgrade_credential = credential(account_keys, primary, created_at, expires_at, wide("3") ?) ?
  let signed = case reauthorize_signed_prekey(primary, downgrade_credential, signed) do
    Err( _) -> Err("signed prekey reauthorization failed")
    Ok( value) -> Ok(value)
  end ?
  let downgrade_bundle = case build_prekey_bundle(downgrade_credential, signed, one_time) do
    Err( _) -> Err("downgrade bundle generation failed")
    Ok( value) -> Ok(value)
  end ?
  Ok(RotationEntries {
    classical : bundled_entry(identity, classical_bundle, mailbox_token) ?,
    replayed_sequence : bundled_entry(identity, replay_bundle, mailbox_token) ?,
    first_hybrid : bundled_entry(identity, first_bundle, mailbox_token) ?,
    second_hybrid : bundled_entry(identity, second_bundle, mailbox_token) ?,
    swapped_signed_prekey : bundled_entry(identity, swapped_bundle, mailbox_token) ?,
    downgrade : bundled_entry(identity, downgrade_bundle, mailbox_token) ?
  })
end

fn substituted_hybrid_entry(identity :: AccountIdentity,
account_keys :: borrow AccountKeys,
device_id :: Bytes,
substitute :: borrow DeviceKeys,
mailbox_token :: Bytes,
created_at :: U64,
expires_at :: U64,
sequence :: U64) -> DirectoryEntry ! String do
  let post_quantum = case generate_post_quantum_prekey() do
    Err( _) -> Err("post-quantum prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let unsigned = DeviceCredential {
    version : 1,
    suite : 2,
    account_id : identity.account_id,
    device_id : device_id,
    signing_public_key : substitute.signing_public_key.bytes,
    dh_public_key : substitute.identity_public_key.bytes,
    post_quantum_public_key : post_quantum.public_key.bytes,
    capabilities : wide("3") ?,
    created_at : created_at,
    expires_at : expires_at,
    directory_sequence : sequence,
    signature : repeated(0, 64)
  }
  let signing_bytes = case credential_signing_bytes(unsigned) do
    Err( _) -> Err("credential signing bytes failed")
    Ok( value) -> Ok(value)
  end ?
  let signature = case Crypto.sign(account_keys.private_key, signing_bytes) do
    Err( _) -> Err("credential signing failed")
    Ok( value) -> Ok(value)
  end ?
  let credential = % { unsigned | signature : signature.bytes }
  let signed = case generate_signed_prekey(substitute, credential, wide("1") ?, expires_at) do
    Err( _) -> Err("signed prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let one_time = case generate_one_time_prekey(wide("3") ?) do
    Err( _) -> Err("one-time prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let bundle = case build_hybrid_prekey_bundle(credential, signed, one_time, post_quantum) do
    Err( _) -> Err("hybrid bundle generation failed")
    Ok( value) -> Ok(value)
  end ?
  Ok(DirectoryEntry {
    version : 1,
    username : "alice",
    account_identity : protocol(encode_account_identity(identity)) ?,
    prekey_bundle : protocol(encode_prekey_bundle(bundle)) ?,
    mailbox_token : mailbox_token
  })
end

fn proof() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000) ?
  let _ = validate_transparency_config() ?
  let _ = Pool.execute(pool,
  "TRUNCATE messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
  []) ?
  let transparency_seed = repeated(91, 32)
  let created_at = now() ?
  let expires_at = U64.add(created_at, wide("31536000000") ?) ?
  let ( account_keys, identity) = account(created_at) ?
  let first_device = device() ?
  let second_device = device() ?
  let first = entry(identity,
  first_device,
  credential(account_keys, first_device, created_at, expires_at, wide("1") ?) ?,
  repeated(31, 32),
  expires_at) ?
  let second = maximal_hybrid_entry(identity,
  account_keys,
  second_device,
  repeated(32, 32),
  created_at,
  expires_at,
  wide("2") ?) ?
  assert(register_device_request(pool, protocol(encode_directory_entry(second)) ?).status == 409)
  assert(resolve_devices_request(pool,
  encode_transparency_lookup(TransparencyLookup {
    username : "alice",
    previous_tree_size : 0
  }) ?).status == 404)
  let _ = Pool.execute(pool,
  "CREATE FUNCTION pg_temp.mesh_test_fail_transparency_append() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced transparency append failure'; END $$",
  []) ?
  let _ = Pool.execute(pool,
  "CREATE TRIGGER mesh_test_fail_transparency_append BEFORE INSERT ON transparency_entries FOR EACH ROW EXECUTE FUNCTION pg_temp.mesh_test_fail_transparency_append()",
  []) ?
  let registration_fault = register_device_request(pool, protocol(encode_directory_entry(first)) ?)
  let _ = Pool.execute(pool,
  "DROP TRIGGER mesh_test_fail_transparency_append ON transparency_entries",
  []) ?
  assert(registration_fault.status == 500)
  assert(scalar(pool,
  "SELECT concat((SELECT count(*) FROM messenger_accounts), ':', (SELECT count(*) FROM messenger_mailboxes), ':', (SELECT count(*) FROM messenger_devices), ':', (SELECT count(*) FROM messenger_one_time_prekeys), ':', (SELECT count(*) FROM transparency_entries)) AS value") ? == "0:0:0:0:0")
  assert(register_device_request(pool, protocol(encode_directory_entry(first)) ?).status == 201)
  let first_checkpoint = create_checkpoint(pool, transparency_seed) ?
  assert(verify_checkpoint(first_checkpoint,
  SigningPublicKey { bytes : first_checkpoint.service_public_key }) ?)
  assert(register_device_request(pool, protocol(encode_directory_entry(first)) ?).status == 200)
  assert(entry_count(pool) ? == 1)
  assert(register_device_request(pool, protocol(encode_directory_entry(second)) ?).status == 201)
  let second_checkpoint = create_checkpoint(pool, transparency_seed) ?
  assert(verify_checkpoint(second_checkpoint,
  SigningPublicKey { bytes : first_checkpoint.service_public_key }) ?)
  assert(verify_consistency(first_checkpoint.tree_root,
  second_checkpoint.tree_root,
  consistency_from(pool, U64.to_int(first_checkpoint.tree_size) ?) ?) ?)
  let witness_a = case Crypto.signing_from_seed(Bytes.from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60") ?) do
    Err( _) -> Err("witness generation failed")
    Ok( value) -> Ok(value)
  end ?
  let witness_b = case Crypto.signing_from_seed(Bytes.from_hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb") ?) do
    Err( _) -> Err("witness generation failed")
    Ok( value) -> Ok(value)
  end ?
  let witness_a_key = WitnessKey {
    witness_id : "witness-a",
    public_key : witness_a.public_key.bytes
  }
  let witness_b_key = WitnessKey {
    witness_id : "witness-b",
    public_key : witness_b.public_key.bytes
  }
  assert(submit_witness_request(pool,
  encode_witnesses([sign_witness("witness-a", witness_a.private_key, second_checkpoint) ?]) ?).status == 201)
  assert(submit_witness_request(pool,
  encode_witnesses([sign_witness("witness-b", witness_b.private_key, second_checkpoint) ?]) ?).status == 201)
  let lookup = encode_transparency_lookup(TransparencyLookup {
    username : "alice",
    previous_tree_size : 1
  }) ?
  let _ = decode_transparency_evidence(encode_transparency_evidence(evidence_for_username(pool,
  "alice",
  1,
  transparency_seed) ?) ?) ?
  let resolved = resolve_devices_request(pool, lookup)
  assert(resolved.status == 200)
  let by_account = resolve_devices_request(pool,
  encode_transparency_lookup(TransparencyLookup {
    username : "@" <> Bytes.to_hex(identity.account_id),
    previous_tree_size : 1
  }) ?)
  assert(by_account.status == 200 && Bytes.secure_equals(by_account.body, resolved.body))
  assert(resolve_devices_request(pool,
  encode_transparency_lookup(TransparencyLookup {
    username : "@" <> Bytes.to_hex(repeated(0, 32)),
    previous_tree_size : 1
  }) ?).status == 404)
  let evidence = decode_transparency_evidence(resolved.body) ?
  assert(verify_witnesses(evidence.checkpoint,
  evidence.witnesses,
  [witness_a_key, witness_b_key],
  2) ?)
  assert(Bytes.secure_equals(decode_checkpoint(checkpoint_request(pool).body) ?.tree_root,
  second_checkpoint.tree_root))
  assert(decode_inclusion_proof(inclusion_request(pool, lookup).body) ?.tree_size == 2)
  assert(decode_consistency_proof(consistency_request(pool,
  encode_transparency_tree_query(TransparencyTreeQuery { previous_tree_size : 1 }) ?).body) ?.old_tree_size == 1)
  assert(List.length(decode_witnesses(witnesses_request(pool).body) ?) == 2)
  let device_set = case decode_device_set(evidence.entry_bytes) do
    Err( _) -> Err("invalid device set")
    Ok( value) -> Ok(value)
  end ?
  assert(List.length(device_set.devices) == 2)
  assert(U64.compare(device_set.sequence, wide("2") ?) == 0)
  assert(verify_inclusion(leaf_hash(protocol(encode_device_set(device_set)) ?) ?,
  inclusion_for_account(pool, identity.account_id) ?,
  second_checkpoint.tree_root) ?)
  let queued_delivery = protocol(encode_outer_envelope(OuterEnvelope {
    version : 1,
    envelope_id : repeated(33, 16),
    mailbox_token : second.mailbox_token,
    suite : 1,
    expiration : U64.add(created_at, wide("3600000") ?) ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("queued")
  })) ?
  assert(submit_request(pool, queued_delivery).status == 202)
  let revocation = case issue_device_revocation(account_keys, second_device.device_id, wide("3") ?) do
    Err( _) -> Err("revocation signing failed")
    Ok( value) -> Ok(value)
  end ?
  let _ = Pool.execute_values(pool,
  "INSERT INTO messenger_push_bindings (mailbox_token_hash, wake_token_hash, revision, provider, provider_token_ciphertext) VALUES ($1, $2, 1, 1, $3)",
  [Binary(Crypto.sha256(second.mailbox_token)), Binary(repeated(61, 32)), Binary(repeated(62, 17))]) ?
  let _ = Pool.execute(pool,
  "CREATE TRIGGER mesh_test_fail_transparency_append BEFORE INSERT ON transparency_entries FOR EACH ROW EXECUTE FUNCTION pg_temp.mesh_test_fail_transparency_append()",
  []) ?
  let revocation_fault = revoke_device_request(pool,
  protocol(encode_device_revocation(revocation)) ?)
  let _ = Pool.execute(pool,
  "DROP TRIGGER mesh_test_fail_transparency_append ON transparency_entries",
  []) ?
  assert(revocation_fault.status == 500)
  assert(scalar(pool,
  "SELECT concat((SELECT sequence FROM messenger_accounts WHERE username = 'alice'), ':', (SELECT count(*) FROM messenger_revoked_devices), ':', (SELECT count(*) FROM messenger_devices WHERE revoked_at IS NOT NULL), ':', (SELECT count(*) FROM messenger_mailboxes WHERE NOT active), ':', (SELECT count(*) FROM messenger_one_time_prekeys), ':', (SELECT count(*) FROM messenger_push_bindings), ':', (SELECT count(*) FROM transparency_entries), ':', (SELECT count(*) FROM messenger_envelopes), ':', (SELECT count(*) FROM messenger_outbox_events), ':', (SELECT sum(pending_count) FROM messenger_mailboxes)) AS value") ? == "2:0:0:0:2:1:2:1:1:1")
  assert(revoke_device_request(pool, protocol(encode_device_revocation(revocation)) ?).status == 200)
  let updated = resolve_devices_request(pool,
  encode_transparency_lookup(TransparencyLookup {
    username : "alice",
    previous_tree_size : 2
  }) ?)
  let updated_evidence = decode_transparency_evidence(updated.body) ?
  let updated_set = case decode_device_set(updated_evidence.entry_bytes) do
    Err( _) -> Err("invalid updated device set")
    Ok( value) -> Ok(value)
  end ?
  assert(List.length(updated_set.devices) == 1)
  assert(List.length(updated_set.revoked_device_ids) == 1)
  assert(U64.compare(updated_set.sequence, wide("3") ?) == 0)
  let third_checkpoint = create_checkpoint(pool, transparency_seed) ?
  assert(entry_count(pool) ? == 3)
  assert(verify_consistency(second_checkpoint.tree_root,
  third_checkpoint.tree_root,
  consistency_from(pool, U64.to_int(second_checkpoint.tree_size) ?) ?) ?)
  assert(register_device_request(pool, protocol(encode_directory_entry(second)) ?).status == 409)
  # Revocation also ends the revoked device's authority to read its mailbox.
  assert(fetch_request(pool, signed_fetch(second_device, second.mailbox_token) ?).status == 403)
  assert(fetch_request(pool, signed_fetch(first_device, first.mailbox_token) ?).status == 200)
  let revoked_delivery = protocol(encode_outer_envelope(OuterEnvelope {
    version : 1,
    envelope_id : repeated(34, 16),
    mailbox_token : second.mailbox_token,
    suite : 1,
    expiration : U64.add(created_at, wide("3600000") ?) ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("opaque")
  })) ?
  assert(submit_request(pool, revoked_delivery).status == 410)
  assert_checkpoint_order(pool,
  transparency_seed,
  identity.account_id,
  updated_evidence.entry_bytes,
  4) ?
  assert_checkpoint_refresh(pool, transparency_seed) ?
  Pool.close(pool)
  Ok(true)
end

fn checkpoint_hashes(rows :: List < Map < String, DbValue > >,
index :: Int,
output :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(rows) do
    Ok(output)
  else
    case Map.get(List.get(rows, index), "leaf_hash") do
      Binary( value) -> checkpoint_hashes(rows, index + 1, List.append(output, value))
      _ -> Err("invalid test leaf hash")
    end
  end
end

fn assert_checkpoint_refresh(pool :: PoolHandle, seed :: Bytes) -> Result <(), String > do
  let prior = case latest_checkpoint(pool) ? do
    Some( value) -> Ok(value)
    None -> Err("missing test checkpoint")
  end ?
  let signer = case Crypto.signing_from_seed(seed) do
    Ok( value) -> Ok(value)
    Err( _) -> Err("test signing seed failed")
  end ?
  let hashes = checkpoint_hashes(Pool.query_values(pool,
  "SELECT leaf_hash FROM transparency_entries ORDER BY sequence",
  []) ?,
  0,
  List.new()) ?
  let stale = sign_checkpoint(signer.private_key,
  signer.public_key.bytes,
  prior.sequence,
  hashes,
  prior.previous_checkpoint_hash,
  wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()) - 241000)) ?) ?
  let _ = Pool.execute_values(pool,
  "UPDATE transparency_checkpoints SET timestamp_ms = $1::bigint, service_signature = $2 WHERE sequence = $3::bigint",
  [Text(U64.to_string(stale.timestamp)), Binary(stale.signature), Text(U64.to_string(stale.sequence))]) ?
  let refreshed = create_checkpoint(pool, seed) ?
  assert(U64.to_int(refreshed.sequence) ? == U64.to_int(stale.sequence) ? + 1)
  assert(Bytes.secure_equals(refreshed.tree_root, stale.tree_root))
  assert(Bytes.secure_equals(refreshed.previous_checkpoint_hash, checkpoint_hash(stale) ?))
  assert(verify_checkpoint(refreshed, SigningPublicKey { bytes : signer.public_key.bytes }) ?)
  assert(Bytes.secure_equals(checkpoint_hash(refreshed) ?,
  checkpoint_hash(create_checkpoint(pool, seed) ?) ?))
  Ok(nil)
end

fn assert_checkpoint_order(pool :: PoolHandle,
seed :: Bytes,
account_id :: Bytes,
entry :: Bytes,
sequence :: Int) -> Result <(), String > do
  if sequence > 12 do
    Ok(nil)
  else
    let _ = Repo.transaction(pool,
    fn (conn :: borrow PgConn) -> append_entry_on_connection(conn, account_id, entry, false) end) ?
    let checkpoint = create_checkpoint(pool, seed) ?
    assert(U64.to_int(checkpoint.sequence) ? == sequence)
    let response = checkpoint_request(pool)
    assert(response.status == 200)
    assert(U64.to_int(decode_checkpoint(response.body) ?.sequence) ? == sequence)
    assert_checkpoint_order(pool, seed, account_id, entry, sequence + 1)
  end
end

test("device registration, resolution, revocation, and mailbox disabling are atomic") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end

fn binary_scalar(pool :: PoolHandle, sql :: String) -> Bytes ! String do
  let rows = Pool.query_values(pool, sql, []) ?
  if List.length(rows) == 1 do
    case Map.get(List.head(rows), "value") do
      Binary( value) -> Ok(value)
      _ -> Err("expected binary value")
    end
  else
    Err("expected one row")
  end
end

fn reset_rotation_state(pool :: PoolHandle) -> Result <(), String > do
  let _ = Pool.execute(pool,
  "TRUNCATE messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
  []) ?
  Ok(nil)
end

fn tombstone_registration_prekey(pool :: PoolHandle, account_id :: Bytes, device_id :: Bytes) -> Result <(), String > do
  let changed = Pool.execute_values(pool,
  "UPDATE messenger_one_time_prekeys SET consumed_at = '2020-01-01 00:00:00+00', claim_id_hash = $3, claim_base_bundle_hash = $4 WHERE account_id = $1 AND device_id = $2 AND prekey_id = 2",
  [Binary(account_id), Binary(device_id), Binary(repeated(73, 32)), Binary(repeated(74, 32))]) ?
  if changed == 1 do
    Ok(nil)
  else
    Err("registration prekey tombstone missing")
  end
end

fn mailbox_snapshot(pool :: PoolHandle) -> String ! String do
  scalar(pool,
  "SELECT concat(encode(device.mailbox_token, 'hex'), ':', encode(device.mailbox_token_hash, 'hex'), ':', mailbox.active::text) AS value FROM messenger_devices AS device JOIN messenger_mailboxes AS mailbox ON mailbox.mailbox_token_hash = device.mailbox_token_hash WHERE device.revoked_at IS NULL")
end

fn prekey_snapshot(pool :: PoolHandle) -> String ! String do
  scalar(pool,
  "SELECT concat(count(*)::text, ':', count(*) FILTER (WHERE consumed_at IS NULL)::text, ':', string_agg(concat(prekey_id::text, '/', encode(public_key, 'hex'), '/', consumed_at::text, '/', encode(claim_id_hash, 'hex'), '/', encode(claim_base_bundle_hash, 'hex')), ',' ORDER BY prekey_id)) AS value FROM messenger_one_time_prekeys")
end

fn register_wire_status(pool :: PoolHandle, body :: Bytes) -> Int do
  register_device_request(pool, body).status
end

fn await_registration(job :: Pid < Int >) -> Int ! String do
  case Job.await(job) do
    Err( error) -> Err("concurrent registration failed: #{error}")
    Ok( status) -> Ok(status)
  end
end

fn credential_rotation_proof() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000) ?
  reset_rotation_state(pool) ?
  let created_at = now() ?
  let expires_at = U64.add(created_at, wide("31536000000") ?) ?
  let ( account_keys, identity) = account(created_at) ?
  let primary = device() ?
  let substitute = device() ?
  let mailbox_token = repeated(71, 32)
  let entries = rotation_entries(identity,
  account_keys,
  primary,
  mailbox_token,
  created_at,
  expires_at) ?
  assert(register_device_request(pool, protocol(encode_directory_entry(entries.classical)) ?).status == 201)
  tombstone_registration_prekey(pool, identity.account_id, primary.device_id) ?
  let original_bundle = binary_scalar(pool,
  "SELECT prekey_bundle AS value FROM messenger_devices WHERE revoked_at IS NULL") ?
  let original_mailbox = mailbox_snapshot(pool) ?
  let original_prekeys = prekey_snapshot(pool) ?
  let _ = Pool.execute(pool,
  "CREATE FUNCTION pg_temp.mesh_test_fail_rotation_append() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced rotation append failure'; END $$",
  []) ?
  let _ = Pool.execute(pool,
  "CREATE TRIGGER mesh_test_fail_rotation_append BEFORE INSERT ON transparency_entries FOR EACH ROW EXECUTE FUNCTION pg_temp.mesh_test_fail_rotation_append()",
  []) ?
  assert(register_device_request(pool, protocol(encode_directory_entry(entries.first_hybrid)) ?).status == 500)
  let _ = Pool.execute(pool,
  "DROP TRIGGER mesh_test_fail_rotation_append ON transparency_entries",
  []) ?
  assert(Bytes.secure_equals(binary_scalar(pool,
  "SELECT prekey_bundle AS value FROM messenger_devices WHERE revoked_at IS NULL") ?,
  original_bundle))
  assert(mailbox_snapshot(pool) ? == original_mailbox)
  assert(prekey_snapshot(pool) ? == original_prekeys)
  assert(scalar(pool,
  "SELECT concat((SELECT sequence FROM messenger_accounts WHERE username = 'alice'), ':', (SELECT count(*) FROM transparency_entries)) AS value") ? == "1:1")
  assert(register_device_request(pool,
  protocol(encode_directory_entry(entries.replayed_sequence)) ?).status == 409)
  let moved_mailbox = % { entries.first_hybrid | mailbox_token : repeated(72, 32) }
  assert(register_device_request(pool, protocol(encode_directory_entry(moved_mailbox)) ?).status == 409)
  let substituted = substituted_hybrid_entry(identity,
  account_keys,
  primary.device_id,
  substitute,
  mailbox_token,
  created_at,
  expires_at,
  wide("2") ?) ?
  assert(register_device_request(pool, protocol(encode_directory_entry(substituted)) ?).status == 409)
  assert(register_device_request(pool,
  protocol(encode_directory_entry(entries.swapped_signed_prekey)) ?).status == 409)
  let decoded_hybrid = case decode_prekey_bundle(entries.first_hybrid.prekey_bundle) do
    Err( _) -> Err("hybrid bundle decode failed")
    Ok( value) -> Ok(value)
  end ?
  let decoded_credential = case decode_device_credential(decoded_hybrid.device_credential) do
    Err( _) -> Err("hybrid credential decode failed")
    Ok( value) -> Ok(value)
  end ?
  let unsigned_credential = % { decoded_credential | signature : repeated(0, 64) }
  let unauthorized_bundle = % { decoded_hybrid | device_credential : protocol(encode_device_credential(unsigned_credential)) ? }
  let unauthorized = % { entries.first_hybrid | prekey_bundle : protocol(encode_prekey_bundle(unauthorized_bundle)) ? }
  assert(register_device_request(pool, protocol(encode_directory_entry(unauthorized)) ?).status == 400)
  let first_wire = protocol(encode_directory_entry(entries.first_hybrid)) ?
  let second_wire = protocol(encode_directory_entry(entries.second_hybrid)) ?
  let first_job = Job.async(fn () -> register_wire_status(pool, first_wire) end)
  let second_job = Job.async(fn () -> register_wire_status(pool, second_wire) end)
  let first_status = await_registration(first_job) ?
  let second_status = await_registration(second_job) ?
  let distinct_result = (first_status == 201 && second_status == 409) || (first_status == 409 && second_status == 201)
  assert(distinct_result)
  assert(scalar(pool,
  "SELECT concat((SELECT sequence FROM messenger_accounts WHERE username = 'alice'), ':', (SELECT count(*) FROM transparency_entries)) AS value") ? == "2:2")
  assert(mailbox_snapshot(pool) ? == original_mailbox)
  assert(prekey_snapshot(pool) ? == original_prekeys)
  let accepted = if first_status == 201 do
    entries.first_hybrid
  else
    entries.second_hybrid
  end
  assert(register_device_request(pool, protocol(encode_directory_entry(accepted)) ?).status == 200)
  assert(scalar(pool,
  "SELECT concat((SELECT sequence FROM messenger_accounts WHERE username = 'alice'), ':', (SELECT count(*) FROM transparency_entries)) AS value") ? == "2:2")
  assert(register_device_request(pool, protocol(encode_directory_entry(entries.downgrade)) ?).status == 409)
  let stored_set = case resolve_devices(pool, "alice") ? do
    None -> Err("rotated device set missing")
    Some( value) -> Ok(value)
  end ?
  let stored_entry = List.head(stored_set.devices)
  let stored_bundle = case decode_prekey_bundle(stored_entry.prekey_bundle) do
    Err( _) -> Err("stored hybrid bundle decode failed")
    Ok( value) -> Ok(value)
  end ?
  let stored_credential = case decode_device_credential(stored_bundle.device_credential) do
    Err( _) -> Err("stored hybrid credential decode failed")
    Ok( value) -> Ok(value)
  end ?
  let classical_bundle = case decode_prekey_bundle(entries.classical.prekey_bundle) do
    Err( _) -> Err("classical bundle decode failed")
    Ok( value) -> Ok(value)
  end ?
  let classical_credential = case decode_device_credential(classical_bundle.device_credential) do
    Err( _) -> Err("classical credential decode failed")
    Ok( value) -> Ok(value)
  end ?
  assert(stored_bundle.suite == 2)
  assert(Bytes.length(stored_bundle.post_quantum_prekey) == 1184)
  assert(U64.compare(stored_bundle.signed_prekey_id, classical_bundle.signed_prekey_id) == 0)
  assert(Bytes.secure_equals(stored_bundle.signed_prekey, classical_bundle.signed_prekey))
  assert(U64.compare(stored_bundle.expires_at, classical_bundle.expires_at) == 0)
  assert(!Bytes.secure_equals(stored_bundle.signed_prekey_signature,
  classical_bundle.signed_prekey_signature))
  assert(Bytes.secure_equals(stored_credential.signing_public_key,
  classical_credential.signing_public_key))
  assert(Bytes.secure_equals(stored_credential.dh_public_key, classical_credential.dh_public_key))
  assert(Bytes.secure_equals(stored_entry.mailbox_token, mailbox_token))
  assert(U64.compare(stored_set.sequence, wide("2") ?) == 0)
  assert(entry_count(pool) ? == 2)
  assert(scalar(pool,
  "SELECT concat(count(*)::text, ':', count(*) FILTER (WHERE consumed_at IS NULL)::text, ':', count(*) FILTER (WHERE claim_id_hash IS NOT NULL AND claim_base_bundle_hash IS NOT NULL)::text) AS value FROM messenger_one_time_prekeys") ? == "1:0:1")
  reset_rotation_state(pool) ?
  assert(register_device_request(pool, protocol(encode_directory_entry(entries.classical)) ?).status == 201)
  tombstone_registration_prekey(pool, identity.account_id, primary.device_id) ?
  let identical_wire = protocol(encode_directory_entry(entries.first_hybrid)) ?
  let identical_first_job = Job.async(fn () -> register_wire_status(pool, identical_wire) end)
  let identical_second_job = Job.async(fn () -> register_wire_status(pool, identical_wire) end)
  let identical_first_status = await_registration(identical_first_job) ?
  let identical_second_status = await_registration(identical_second_job) ?
  let identical_result = (identical_first_status == 201 && identical_second_status == 200) || (identical_first_status == 200 && identical_second_status == 201)
  assert(identical_result)
  assert(scalar(pool,
  "SELECT concat((SELECT sequence FROM messenger_accounts WHERE username = 'alice'), ':', (SELECT count(*) FROM transparency_entries)) AS value") ? == "2:2")
  assert(mailbox_snapshot(pool) ? == original_mailbox)
  assert(prekey_snapshot(pool) ? == original_prekeys)
  Pool.close(pool)
  Ok(true)
end

test("same-device credentials rotate once from classical to hybrid without weakening identity") do
  case credential_rotation_proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
