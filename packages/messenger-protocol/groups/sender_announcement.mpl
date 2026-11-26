##! Groups.SenderAnnouncement: the key a member device signs one epoch's group
##! messages with (message version 6), as it tells each other member device
##! over their pairwise session (`protocol/mls-groups-v1.md`, "Deniable sender
##! authentication").
##!
##! `u8 1 || "GSA" || group_id32 || u64 epoch || signing_public_key32`, 76 bytes.
##! It carries no signature and names no sender: the pairwise session that
##! delivers it says who sent it, and either end of that session could have
##! written it.

from Groups.GroupCodec import (
  group_byte,
  group_join,
  group_wire_end,
  group_wire_fixed,
  group_wire_start,
  group_wire_u64,
  group_write_u64
)
from Groups.Mls import GroupError

pub struct GroupSenderAnnouncement do
  group_id :: Bytes
  epoch :: U64
  signing_public_key :: SigningPublicKey
end

pub fn encode_group_sender_announcement(value :: GroupSenderAnnouncement) -> Bytes!GroupError do
  if Bytes.length(value.group_id) != 32 || Bytes.length(value.signing_public_key.bytes) != 32 do
    return Err(InvalidGroup)
  end
  group_join([
      group_byte(1)?,
      Bytes.from_utf8("GSA"),
      value.group_id,
      group_write_u64(value.epoch)?,
      value.signing_public_key.bytes
    ],
    0,
    Bytes.empty())
end

pub fn decode_group_sender_announcement(input :: Bytes) -> GroupSenderAnnouncement!GroupError do
  let group_id = group_wire_fixed(group_wire_start(input, 76, "GSA")?, 32)?
  let epoch = group_wire_u64(group_id.state)?
  let key = group_wire_fixed(epoch.state, 32)?
  group_wire_end(key.state)?
  Ok(GroupSenderAnnouncement {
    group_id: group_id.value,
    epoch: epoch.value,
    signing_public_key: SigningPublicKey { bytes: key.value }
  })
end
