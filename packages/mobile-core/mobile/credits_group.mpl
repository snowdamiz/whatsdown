from Binary.Reader import BinaryReader
from Credits.MailboxExtras import credits_decode_policy
from Groups.Mls import GroupState
from Groups.Tree import GroupMember, IndexedGroupMember, indexed_members
from Identity.Device import DeviceKeys
from Mobile.ContactAddress import (
  confirmed_contact_address,
  deposit_address,
  learned_contact_address_writes
)
from Mobile.CreditsBuy import credits_fields, credits_now, credits_path, credits_store_writes
from Mobile.CreditsStore import (
  CreditWrites,
  credits_clock,
  credits_inbox_label,
  credits_load_sealed,
  credits_merge_writes,
  credits_no_writes,
  credits_sealed_write
)
from Mobile.GroupState import (
  consume_group_state,
  encode_group_packet,
  group_profile,
  load_group,
  load_group_ids
)
from Mobile.Outbox import load_outbox_ids, prepare_outbox_writes
from Mobile.Profile import load_profile, open_device
from Mobile.Transparency import fresh_account_device_set
from Mobile.Transport import sealed_outer_bytes
from Mobile.Types import MobileVerifiedDeviceSet
from Protocol.V1 import DeviceCredential, DirectoryEntry, ProtocolExtension
from Storage.Keys import platform_key
from Storage.Records import store_record_changes
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_u16,
  tcodec_take_u64,
  tcodec_u16,
  tcodec_u32,
  tcodec_u64,
  tcodec_u8
)
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.CreditsGroup: a priced inbox hands its contact address to its groups
##! (protocol/credits-v1.md "Postage"; contact-address-v1.md).
##!
##! Group members who are not direct contacts write to a device's public
##! address, so once it asks a price for message requests their group messages
##! would hit the postage wall. While its price is above zero the device hands
##! every member device of its groups its contact address, once per address,
##! in a group packet of kind 4 (`GRP` kind 4) sealed to each member:
##!
##!   GCH: u8 1 || "GCH" || group_id32 || account_id32 || device_id16 ||
##!        contact_address32 || u64 issued_at_ms || sig64
##!
##! signed by the device's key over "mesh-msg/v1/group-contact-address" || the
##! frame without its signature. A member keeps it when the signature verifies
##! under that member's key in the group, exactly as it keeps an address handed
##! over in a direct message; group fan-out then uses it. Older clients refuse
##! kind 4 as an invalid group packet and drop it without showing anything.
##!
##! Local frame "credits/v1/handed/<group>": contact_hash32 || u16 n || n x
##! (account_id32 || device_id16): who has this address. A new address
##! (blocking rotates it) starts the list again.

struct Handed do
  contact_hash :: Bytes
  members :: List<Bytes>
end

fn handed_label(group_id :: Bytes) -> String do
  "credits/v1/handed/#{Bytes.to_hex(group_id)}"
end

fn signing_label() -> String do
  "mesh-msg/v1/group-contact-address"
end

fn member_key(account_id :: Bytes, device_id :: Bytes) -> Bytes!String do
  tcodec_join([account_id, device_id])
end

fn take_members(state :: BinaryReader,
  count :: Int,
  output :: List<Bytes>) -> (BinaryReader, List<Bytes>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let value = tcodec_take_fixed(state, 48)?
    take_members(value.state, count, List.append(output, value.value))
  end
end

fn load_handed(path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  contact_hash :: Bytes) -> Handed!String do
  let stored = credits_load_sealed(path, wrapping_key, handed_label(group_id))?
  let fresh = Handed { contact_hash: contact_hash, members: List.new() }
  if Bytes.length(stored) < 34 do
    Ok(fresh)
  else
    let state = tcodec_start(stored, 1048576, 1, "GCL")?
    let hash = tcodec_take_fixed(state, 32)?
    let count = tcodec_take_u16(hash.state)?
    let (rest, members) = take_members(count.state, count.value, List.new())?
    tcodec_done(rest)?
    if Bytes.secure_equals(hash.value, contact_hash) do
      Ok(Handed { contact_hash: contact_hash, members: members })
    else
      Ok(fresh)
    end
  end
end

fn handed_write(group_id :: Bytes,
  value :: Handed,
  wrapping_key :: borrow StorageKey) -> CreditWrites!String do
  credits_sealed_write(handed_label(group_id),
    tcodec_join([
      tcodec_u8(1)?,
      Bytes.from_utf8("GCL"),
      value.contact_hash,
      tcodec_u16(List.length(value.members))?
    ]
      ++ value.members)?,
    wrapping_key)
end

fn handover_body(group_id :: Bytes,
  profile :: ClientProfile,
  contact :: Bytes,
  issued_at :: Int) -> Bytes!String do
  tcodec_join([
    tcodec_u8(1)?,
    Bytes.from_utf8("GCH"),
    group_id,
    profile.account_id,
    profile.device_id,
    contact,
    tcodec_u64(issued_at)?
  ])
end

fn signed_handover(signer :: borrow SigningPrivateKey,
  group_id :: Bytes,
  profile :: ClientProfile,
  contact :: Bytes) -> Bytes!String do
  let body = handover_body(group_id, profile, contact, credits_now())?
  let signature = case Crypto.sign(signer,
    tcodec_join([Bytes.from_utf8(signing_label()), body])?) do
    Err(_) -> Err("group_contact_signing_failed")
    Ok(value) -> Ok(value.bytes)
  end?
  tcodec_join([body, signature])
end

# The sealed envelope for one member device, or nothing when this device has
# not verified that member's devices.

fn member_envelope(path :: String,
  wrapping_key :: borrow StorageKey,
  member :: IndexedGroupMember,
  packet :: Bytes) -> Option<Bytes>!String do
  let value = member.member
  case fresh_account_device_set(path, wrapping_key, value.account_id) do
    Err(_) -> Ok(None)
    Ok(devices) -> case group_profile(devices.profiles, value.account_id, value.device_id, 0) do
      Err(_) -> Ok(None)
      Ok(recipient) -> Ok(Some(sealed_outer_bytes(deposit_address(path,
          wrapping_key,
          value.mailbox_token)?,
        packet,
        recipient.credential.dh_public_key,
        credits_clock()?)?))
    end
  end
end

fn member_envelopes(path :: String,
  wrapping_key :: borrow StorageKey,
  members :: List<IndexedGroupMember>,
  packet :: Bytes,
  handed :: Handed,
  envelopes :: List<Bytes>) -> (Handed, List<Bytes>)!String do
  case members do
    [] -> Ok((handed, envelopes))
    member :: rest -> do
      let id = member_key(member.member.account_id, member.member.device_id)?
      if List.any(handed.members, fn known -> Bytes.secure_equals(known, id) end) do
        member_envelopes(path, wrapping_key, rest, packet, handed, envelopes)
      else
        case member_envelope(path, wrapping_key, member, packet)? do
          None -> member_envelopes(path, wrapping_key, rest, packet, handed, envelopes)
          Some(envelope) -> member_envelopes(path,
            wrapping_key,
            rest,
            packet,
            %{handed | members: List.append(handed.members, id)},
            List.append(envelopes, envelope))
        end
      end
    end
  end
end

fn group_handovers(path :: String,
  wrapping_key :: borrow StorageKey,
  signer :: borrow SigningPrivateKey,
  profile :: ClientProfile,
  contact :: Bytes,
  groups :: List<Bytes>,
  writes :: CreditWrites,
  envelopes :: List<Bytes>) -> (CreditWrites, List<Bytes>)!String do
  case groups do
    [] -> Ok((writes, envelopes))
    group_id :: rest -> do
      let state = load_group(path, profile, wrapping_key, group_id)?
      let local_leaf = state.local_leaf
      let members = List.filter(indexed_members(state.tree),
        fn member -> member.leaf_index != local_leaf
          && !Bytes.secure_equals(member.member.account_id, profile.account_id) end)
      consume_group_state(state)
      let before = load_handed(path, wrapping_key, group_id, Crypto.sha256(contact))?
      let packet = encode_group_packet(4, signed_handover(signer, group_id, profile, contact)?)?
      let (handed, added) = member_envelopes(path,
        wrapping_key,
        members,
        packet,
        before,
        List.new())?
      let next = if List.length(added) > 0 do
        credits_merge_writes(writes, handed_write(group_id, handed, wrapping_key)?)
      else
        writes
      end
      group_handovers(path, wrapping_key, signer, profile, contact, rest, next, envelopes ++ added)
    end
  end
end

fn priced(path :: String, wrapping_key :: borrow StorageKey) -> Bool!String do
  let stored = credits_load_sealed(path, wrapping_key, credits_inbox_label())?
  if Bytes.length(stored) == 0 do
    Ok(false)
  else
    Ok(credits_decode_policy(stored)?.postage > 0)
  end
end

## Queues this device's contact address for every group member device that
## does not have it yet, while it asks a price for message requests. Call it
## after the price changes, after sending to a group and after joining one;
## then drain the outbox. Request: vector32(path). Answer: u32 envelopes
## queued.

pub fn credits_group_handover(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 1)?
  let path = credits_path(List.get(fields, 0))?
  let wrapping_key = platform_key()?
  if !priced(path, wrapping_key)? do
    return tcodec_u32(0)
  end
  let contact = confirmed_contact_address(path, wrapping_key)?
  if Bytes.length(contact) != 32 do
    return tcodec_u32(0)
  end
  let profile = decode_client_profile(load_profile(path)?)?
  let device = open_device(profile, wrapping_key, path)?
  let (writes, envelopes) = group_handovers(path,
    wrapping_key,
    device.signing_private_key,
    profile,
    contact,
    load_group_ids(path, wrapping_key)?,
    credits_no_writes(),
    List.new())?
  if List.length(envelopes) == 0 do
    return tcodec_u32(0)
  end
  let (labels, blobs, index_blob) = prepare_outbox_writes(wrapping_key,
    load_outbox_ids(path, wrapping_key)?,
    envelopes,
    path,
    Crypto.sha256(Bytes.from_utf8(signing_label())),
    0,
    0)?
  credits_store_writes(path,
    credits_merge_writes(writes,
      CreditWrites {
        labels: labels ++ ["outbox/v1"],
        blobs: blobs ++ [index_blob],
        removed: List.new()
      }))?
  tcodec_u32(List.length(envelopes))
end

struct Handover do
  group_id :: Bytes
  account_id :: Bytes
  device_id :: Bytes
  contact :: Bytes
  body :: Bytes
  signature :: Bytes
end

fn decode_handover(input :: Bytes) -> Handover!String do
  let state = tcodec_start(input, 188, 1, "GCH")?
  let group_id = tcodec_take_fixed(state, 32)?
  let account_id = tcodec_take_fixed(group_id.state, 32)?
  let device_id = tcodec_take_fixed(account_id.state, 16)?
  let contact = tcodec_take_fixed(device_id.state, 32)?
  let issued = tcodec_take_u64(contact.state)?
  let signature = tcodec_take_fixed(issued.state, 64)?
  tcodec_done(signature.state)?
  Ok(Handover {
    group_id: group_id.value,
    account_id: account_id.value,
    device_id: device_id.value,
    contact: contact.value,
    body: Bytes.slice(input, 0, 124)?,
    signature: signature.value
  })
end

fn verified(value :: Handover, member :: IndexedGroupMember) -> Bool do
  case tcodec_join([Bytes.from_utf8(signing_label()), value.body]) do
    Err(_) -> false
    Ok(message) -> case Crypto.verify(member.member.signing_public_key,
      message,
      Signature { bytes: value.signature }) do
      Ok(valid) -> valid
      Err(_) -> false
    end
  end
end

## A group member's contact address, from a kind 4 group packet. Kept against
## that member's public address when its signature verifies under the key the
## group holds for it; anything else is an invalid group packet.

pub fn credits_group_contact_received(path :: String,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  payload :: Bytes) -> Bytes!String do
  let value = case decode_handover(payload) do
    Err(_) -> Err("invalid_group_packet")
    Ok(decoded)
  end?
  let state = load_group(path, profile, wrapping_key, value.group_id)?
  let members = indexed_members(state.tree)
  consume_group_state(state)
  let member = case List.find(members,
    fn candidate -> Bytes.secure_equals(candidate.member.account_id, value.account_id)
      && Bytes.secure_equals(candidate.member.device_id, value.device_id) end) do
    None -> return Err("invalid_group_packet")
    Some(found) -> found
  end
  if Bytes.secure_equals(value.device_id, profile.device_id) || !verified(value, member) do
    return Err("invalid_group_packet")
  end
  let (labels, blobs, removed) = learned_contact_address_writes(path,
    wrapping_key,
    member.member.mailbox_token,
    [ProtocolExtension { id: 1, mandatory: false, value: value.contact }])?
  store_record_changes(path, labels, blobs, removed)?
  Ok(Bytes.empty())
end
