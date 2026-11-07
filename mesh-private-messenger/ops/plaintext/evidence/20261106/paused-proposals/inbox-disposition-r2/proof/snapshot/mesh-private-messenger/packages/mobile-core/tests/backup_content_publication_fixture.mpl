##! Authored content around real generated custody, no network capture substitute.
from Tests.BackupArchiveFixture import (
  D4CoreFixture,
  d4_core_fixture,
  d4_core_install_direct_history,
  d4_core_synthetic_content
)
from Tests.Support import repeated
from Backups.PortableV2 import PortableBackupContentArchive
from Backups.ContentArchive import (
  BackupAttachmentPolicy,
  BackupContentScope,
  BackupContentRecord,
  BackupArchiveAttachment
)

pub fn publication_fixture() -> D4CoreFixture!String do
  let fixture = d4_core_fixture()?
  let selector = Bytes.from_utf8("messenger/issuer-tls-root/v1")
  let frame = Bytes.from_hex("01000000000000")?
  if !Test.set_push_token(selector, frame) do
    return Err("preflight_fixture_issuer_frame_install")
  end
  let actual = Host.push_get_token(selector)?
  if !Bytes.secure_equals(actual, frame) do
    return Err("preflight_fixture_issuer_frame_readback")
  end
  println("AUTH_PREFLIGHT_EXPLICIT_ISSUER_FRAME_READY")
  d4_core_install_direct_history(fixture)?
  Ok(fixture)
end

pub fn publication_authored_content(f :: D4CoreFixture,
  policy :: BackupAttachmentPolicy) -> PortableBackupContentArchive!String do
  let identity = d4_core_synthetic_content(f, [], 1, 0, 0, 0, 0, 1)?
  Ok(PortableBackupContentArchive {
    policy: policy,
    owner_account: identity.owner_account,
    owner_authorization_key: identity.owner_authorization_key,
    service_realm: identity.service_realm,
    candidate_count: 1,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 1,
    scopes: [BackupContentScope {
      kind: 1,
      id: repeated(71, 16)?,
      peer: repeated(37, 32)?,
      name: "Authored publication fixture",
      entries: [BackupContentRecord {
        ordinal: 0,
        direction: 2,
        message_id: repeated(24, 16)?,
        sender_account: repeated(37, 32)?,
        sender_device: repeated(38, 16)?,
        timestamp: f.now,
        text: Bytes.from_utf8("actual captured canonical direct text"),
        attachments: [ArchiveAttachmentIncluded(Bytes.from_utf8("fixture.txt"),
          Bytes.from_utf8("text/plain"), Bytes.from_utf8("PUBLICATION FIXTURE BYTES"))]
      }]
    }]
  })
end
