from Mobile.BackupArchive import (
  d4_pending_race_repair,
  pending_backup_export_state,
  resume_pending_backup_export,
  repair_pending_backup_export
)
from Mobile.BackupAuthority import capture_backup_authority
from Mobile.Transparency import store_transparency_origin
from Storage.Keys import platform_key
from Tests.BackupPendingSupport import (
  pending_fixture,
  pending_set_wire,
  d4_pending_descriptor_cipher,
  pending_known_state
)
from Tests.BackupArchiveFixture import d4_core_cleanup, d4_core_all_rows, d4_core_rows_preserved
from Tests.Support import repeated
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs
from Storage.AccountGuard import load_account_basis_bounded, same_account_basis
from Transparency.Config import encode_security_config

fn remaining_pending_invalid_sql_successor() -> Result<(), String> do
  let f = pending_fixture()?
  let _ = capture_backup_authority(f.base.path, f.base.public_profile)?
  let original_descriptor = load_blob(f.base.path, f.descriptor_label)?
  let oversized = case Bytes.repeat(99, 16796865) do
    Err(_) -> return Err("remaining_guard_fixture_allocation")
    Ok(value) -> value
  end
  pending_set_wire(f, oversized, false)?
  let before = d4_core_all_rows(f.base)?
  let successor = %{f | draft_id: repeated(213, 32)?}
  let sealed = d4_pending_descriptor_cipher(successor)?
  println("PENDING_INVALID_SQL_SUCCESSOR_FIXTURE_READY")
  assert(Result.is_err(d4_pending_race_repair(f.base.path,
    f.base.public_profile,
    successor.bundle.wire,
    sealed,
    0)))
  assert(Bytes.secure_equals(load_blob(f.base.path, f.wire_label)?, successor.bundle.wire))
  assert(Bytes.secure_equals(load_blob(f.base.path, f.descriptor_label)?, sealed))
  assert(Bytes.secure_equals(resume_pending_backup_export(f.base.path,
      f.base.public_profile,
      successor.draft_id,
      successor.bundle.recovery_code)?,
    successor.bundle.wire))
  pending_set_wire(f, oversized, false)?
  store_updated_blobs(f.base.path, [f.descriptor_label], [original_descriptor])?
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f.base)?, 0))
  d4_core_cleanup(f.base)
end

test("pending invalid SQL metadata capture cannot erase a bounded authenticated successor") do
  assert(Result.is_ok(remaining_pending_invalid_sql_successor()))
end

fn remaining_pending_realm_rotation() -> Result<(), String> do
  let f = pending_fixture()?
  let authority = capture_backup_authority(f.base.path, f.base.public_profile)?
  let labels = [f.wire_label, f.descriptor_label]
  let before = load_account_basis_bounded(f.base.path, labels, 40000, 16796864, 33554432)?
  let network = Bytes.from_utf8("2\n1\nhttps://core-successor.example\nhttps://edge.example\nhttps://objects.example\nwss://core-successor.example/v1/mailbox/stream\n1")
  let companion = Bytes.from_utf8(String.join([
      "1",
      Bytes.to_hex(Crypto.sha256(network)),
      Bytes.to_hex(Crypto.sha256(encode_security_config(f.base.config)?)),
      "2",
      "off",
      "0"
    ],
    "\n"))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), network))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/rpc-tls-roots/v1"), Bytes.from_hex("0100")?))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"), companion))
  # Old authenticated origin must still refuse the new native service origin.
  assert(Result.is_err(capture_backup_authority(f.base.path, f.base.public_profile)))
  # Fixture-only authenticated origin installation, matching the already verified
  # service-key/trust fixture; the operation still captures its own authority.
  let key = platform_key()?
  let installed = store_transparency_origin(f.base.path, key, "https://core-successor.example")
  Secret.destroy(key)
  installed?
  let _ = capture_backup_authority(f.base.path, f.base.public_profile)?
  println("PENDING_REALM_ROTATION_FIXTURE_READY")
  assert(pending_known_state(pending_backup_export_state(f.base.path, f.base.public_profile),
    2,
    Bytes.empty(),
    U64.parse("0")?,
    0))
  assert(same_account_basis(before,
    load_account_basis_bounded(f.base.path, labels, 40000, 16796864, 33554432)?))
  assert(Result.is_err(resume_pending_backup_export(f.base.path,
    f.base.public_profile,
    f.draft_id,
    f.bundle.recovery_code)))
  assert(repair_pending_backup_export(f.base.path, f.base.public_profile)? == 1)
  let remaining = load_account_basis_bounded(f.base.path, labels, 40000, 16796864, 33554432)?
  assert(Bytes.secure_equals(before.profile, remaining.profile))
  assert(List.length(remaining.records) == 2
    && Bytes.length(List.get(remaining.records, 0)) == 0
    && Bytes.length(List.get(remaining.records, 1)) == 0)
  assert(pending_known_state(pending_backup_export_state(f.base.path, f.base.public_profile),
    0,
    Bytes.empty(),
    U64.parse("0")?,
    0))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    authority.context.network_frame))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"),
    authority.context.companion_frame))
  d4_core_cleanup(f.base)
end

test("pending realm rotation keeps the same physical owner slot and requires explicit repair") do
  assert(Result.is_ok(remaining_pending_realm_rotation()))
end
