from Binary.Reader import BinaryReader, reader
from Mobile.Transparency import canonical_transparency_checkpoint, load_transparency_view
from Mobile.Types import MobileTransparencyView
from Protocol.V1 import InnerEnvelope, ProtocolExtension
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local
from Storage.Records import store_updated_blobs
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_u16,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u16,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)
from Transparency.CompactWire import transparency_encode_cosignatures
from Transparency.Gossip import (
  GossipAnswer,
  GossipHint,
  gossip_decode_answer,
  gossip_decode_request,
  gossip_hint_action,
  gossip_hint_extension,
  gossip_hint_from_extensions
)
from Transparency.Merkle import TransparencyCheckpoint, verify_checkpoint
from Transparency.Wire import encode_checkpoint

##! Mobile.GossipState: what checkpoint gossip (protocol/checkpoint-gossip-v1.md,
##! plan §6.16) keeps on this device, and what the send and receive paths ask
##! of it. Every direct message this device sends carries inner-envelope
##! extension 2, the size and root of the newest checkpoint it verified, and
##! every authenticated message from a contact device is noted here: a hint
##! it has not verified yet, or a checkpoint request (GCQ) or answer (GCA)
##! arriving as an inner message of type 7. Mobile.GossipRun acts on the notes.
##!
##! Local frame "checkpoint-gossip/v1": u8 1 || "CGS" || u8 v || v x (u64
##! size || root32) || u16 c || c x contact || u8 p || p x vector32(item).
##! verified: hints proven prefixes of (or extensions of) this device's view,
##! newest last. contact = account32 || u64 proof_at_ms || u64 asked_at_ms ||
##! u64 answered_at_ms: when this device last fetched a consistency proof for
##! the conversation, last asked the contact (or last refused a checkpoint
##! from it), and last answered it. item = u8 kind || account32 || device16 ||
##! u64 received_at_ms || u64 size || root32 || u8 ask_back || vector32(KTK or
##! empty) || vector32(KTW v2 or empty); kinds 1 check (a hint to prove with
##! a consistency proof), 2 ask (send GCQ about the hint), 3 answer (send
##! GCA, ask_back as given), 4 compare (a contact's signed checkpoint).

pub struct GossipContact do
  account :: Bytes
  proof_at :: Int
  asked_at :: Int
  answered_at :: Int
end

pub struct GossipItem do
  kind :: Int
  account :: Bytes
  device :: Bytes
  received_at :: Int
  hint :: GossipHint
  ask_back :: Bool
  checkpoint :: Bytes
  witnesses :: Bytes
end

pub struct GossipState do
  verified :: List<GossipHint>
  contacts :: List<GossipContact>
  pending :: List<GossipItem>
end

struct ReadHints do
  state :: BinaryReader
  value :: List<GossipHint>
end

struct ReadContacts do
  state :: BinaryReader
  value :: List<GossipContact>
end

struct ReadItems do
  state :: BinaryReader
  value :: List<GossipItem>
end

# The inner message type of GCQ and GCA frames (5 and 6 are session reset).

pub fn gossip_control_type() -> Int do
  7
end

pub fn gossip_kind_check() -> Int do
  1
end

pub fn gossip_kind_ask() -> Int do
  2
end

pub fn gossip_kind_answer() -> Int do
  3
end

pub fn gossip_kind_compare() -> Int do
  4
end

# Plan §7: at most one consistency proof per conversation per hour, at most one
# checkpoint request per contact per day. An answer goes at most hourly.

pub fn gossip_proof_interval_ms() -> Int do
  3_600_000
end

pub fn gossip_ask_interval_ms() -> Int do
  86_400_000
end

pub fn gossip_answer_interval_ms() -> Int do
  3_600_000
end

# A note not acted on within two days is dropped.

fn item_lifetime_ms() -> Int do
  172_800_000
end

fn label() -> String do
  "checkpoint-gossip/v1"
end

fn verified_limit() -> Int do
  64
end

fn contact_limit() -> Int do
  1024
end

fn pending_limit() -> Int do
  32
end

pub fn gossip_now_ms() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn flag(value :: Bool) -> Bytes!String do
  tcodec_u8(if value do
    1
  else
    0
  end)
end

fn encode_hint_point(value :: GossipHint) -> Bytes!String do
  tcodec_join([tcodec_u64(value.tree_size)?, value.root])
end

fn encode_contact(value :: GossipContact) -> Bytes!String do
  tcodec_join([
    value.account,
    tcodec_u64(value.proof_at)?,
    tcodec_u64(value.asked_at)?,
    tcodec_u64(value.answered_at)?
  ])
end

fn encode_item(value :: GossipItem) -> Bytes!String do
  tcodec_join([
    tcodec_u8(value.kind)?,
    value.account,
    value.device,
    tcodec_u64(value.received_at)?,
    encode_hint_point(value.hint)?,
    flag(value.ask_back)?,
    tcodec_vector(value.checkpoint)?,
    tcodec_vector(value.witnesses)?
  ])
end

fn encode_state(value :: GossipState) -> Bytes!String do
  let verified = for hint in value.verified do
    encode_hint_point(hint)?
  end
  let contacts = for contact in value.contacts do
    encode_contact(contact)?
  end
  let items = for item in value.pending do
    tcodec_vector(encode_item(item)?)?
  end
  tcodec_join([tcodec_u8(1)?, Bytes.from_utf8("CGS"), tcodec_u8(List.length(value.verified))?]
    ++ verified
    ++ [tcodec_u16(List.length(value.contacts))?]
    ++ contacts
    ++ [tcodec_u8(List.length(value.pending))?]
    ++ items)
end

fn take_point(state :: BinaryReader) -> (BinaryReader, GossipHint)!String do
  let size = tcodec_take_u64(state)?
  let root = tcodec_take_fixed(size.state, 32)?
  Ok((root.state, GossipHint { tree_size: size.value, root: root.value }))
end

fn take_points(state :: BinaryReader,
  count :: Int,
  output :: List<GossipHint>) -> ReadHints!String do
  if List.length(output) >= count do
    Ok(ReadHints { state: state, value: output })
  else
    let (next, point) = take_point(state)?
    take_points(next, count, List.append(output, point))
  end
end

fn take_contacts(state :: BinaryReader,
  count :: Int,
  output :: List<GossipContact>) -> ReadContacts!String do
  if List.length(output) >= count do
    Ok(ReadContacts { state: state, value: output })
  else
    let account = tcodec_take_fixed(state, 32)?
    let proof = tcodec_take_u64(account.state)?
    let asked = tcodec_take_u64(proof.state)?
    let answered = tcodec_take_u64(asked.state)?
    take_contacts(answered.state,
      count,
      List.append(output,
        GossipContact {
          account: account.value,
          proof_at: proof.value,
          asked_at: asked.value,
          answered_at: answered.value
        }))
  end
end

fn decode_item(input :: Bytes) -> GossipItem!String do
  let state = case reader(input, 8192) do
    Err(_) -> Err("invalid_gossip_state")
    Ok(value)
  end?
  let kind = tcodec_take_u8(state)?
  let account = tcodec_take_fixed(kind.state, 32)?
  let device = tcodec_take_fixed(account.state, 16)?
  let received = tcodec_take_u64(device.state)?
  let (after_hint, hint) = take_point(received.state)?
  let ask_back = tcodec_take_u8(after_hint)?
  let checkpoint = tcodec_take_vector(ask_back.state, 188)?
  let witnesses = tcodec_take_vector(checkpoint.state, 2646)?
  tcodec_done(witnesses.state)?
  Ok(GossipItem {
    kind: kind.value,
    account: account.value,
    device: device.value,
    received_at: received.value,
    hint: hint,
    ask_back: ask_back.value == 1,
    checkpoint: checkpoint.value,
    witnesses: witnesses.value
  })
end

fn take_items(state :: BinaryReader,
  count :: Int,
  output :: List<GossipItem>) -> ReadItems!String do
  if List.length(output) >= count do
    Ok(ReadItems { state: state, value: output })
  else
    let record = tcodec_take_vector(state, 8192)?
    take_items(record.state, count, List.append(output, decode_item(record.value)?))
  end
end

fn decode_state(input :: Bytes) -> GossipState!String do
  let state = tcodec_start(input, 1048576, 1, "CGS")?
  let verified_count = tcodec_take_u8(state)?
  let verified = take_points(verified_count.state, verified_count.value, List.new())?
  let contact_count = tcodec_take_u16(verified.state)?
  let contacts = take_contacts(contact_count.state, contact_count.value, List.new())?
  let item_count = tcodec_take_u8(contacts.state)?
  let items = take_items(item_count.state, item_count.value, List.new())?
  tcodec_done(items.state)?
  Ok(GossipState { verified: verified.value, contacts: contacts.value, pending: items.value })
end

pub fn gossip_state_empty() -> GossipState do
  GossipState { verified: List.new(), contacts: List.new(), pending: List.new() }
end

# Gossip only ever adds evidence: a record that does not read starts over.

pub fn gossip_state_load(database_path :: String,
  wrapping_key :: borrow StorageKey) -> GossipState!String do
  case load_blob(database_path, label()) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(gossip_state_empty())
    else
      Err(error)
    end
    Ok(blob) -> case open_local(blob, wrapping_key, local_context(label())?) do
      Err(_) -> Ok(gossip_state_empty())
      Ok(frame) -> case decode_state(frame) do
        Err(_) -> Ok(gossip_state_empty())
        Ok(value)
      end
    end
  end
end

fn bounded(value :: GossipState) -> GossipState do
  GossipState {
    verified: List.drop(value.verified, List.length(value.verified) - verified_limit()),
    contacts: List.drop(value.contacts, List.length(value.contacts) - contact_limit()),
    pending: List.drop(value.pending, List.length(value.pending) - pending_limit())
  }
end

pub fn gossip_state_store(database_path :: String,
  wrapping_key :: borrow StorageKey,
  value :: GossipState) -> ()!String do
  let blob = seal_local(encode_state(bounded(value))?, wrapping_key, local_context(label())?)?
  store_updated_blobs(database_path, [label()], [blob])
end

fn same_point(left :: GossipHint, right :: GossipHint) -> Bool do
  left.tree_size == right.tree_size && Bytes.secure_equals(left.root, right.root)
end

pub fn gossip_point_verified(value :: GossipState, hint :: GossipHint) -> Bool do
  List.any(value.verified, fn point -> same_point(point, hint) end)
end

pub fn gossip_with_verified(value :: GossipState, hints :: List<GossipHint>) -> GossipState do
  let fresh = List.filter(hints, fn hint -> !gossip_point_verified(value, hint) end)
  %{value | verified: value.verified ++ fresh}
end

pub fn gossip_contact(value :: GossipState, account :: Bytes) -> GossipContact do
  case List.find(value.contacts, fn contact -> Bytes.secure_equals(contact.account, account) end) do
    Some(contact) -> contact
    None -> GossipContact { account: account, proof_at: 0, asked_at: 0, answered_at: 0 }
  end
end

# The contact's record, moved to the end: the least recently touched go first.

pub fn gossip_with_contact(value :: GossipState, contact :: GossipContact) -> GossipState do
  let others = List.filter(value.contacts,
    fn existing -> !Bytes.secure_equals(existing.account, contact.account) end)
  %{value | contacts: List.append(others, contact)}
end

fn same_slot(left :: GossipItem, right :: GossipItem) -> Bool do
  left.kind == right.kind
    && Bytes.secure_equals(left.account, right.account)
    && Bytes.secure_equals(left.device, right.device)
end

# One note per kind and contact device: a newer one replaces it.

pub fn gossip_with_item(value :: GossipState, item :: GossipItem) -> GossipState do
  let others = List.filter(value.pending, fn existing -> !same_slot(existing, item) end)
  %{value | pending: List.append(others, item)}
end

pub fn gossip_without_asks(value :: GossipState, account :: Bytes) -> GossipState do
  %{value |
    pending: List.filter(value.pending,
      fn item -> !(item.kind == gossip_kind_ask()
        && Bytes.secure_equals(item.account, account)) end)
  }
end

pub fn gossip_live(value :: GossipState, now :: Int) -> GossipState do
  %{value |
    pending: List.filter(value.pending, fn item -> now - item.received_at < item_lifetime_ms() end)
  }
end

# This device's view as a hint: the newest checkpoint it verified.

pub fn gossip_view_point(checkpoint :: TransparencyCheckpoint) -> GossipHint!String do
  Ok(GossipHint { tree_size: U64.to_int(checkpoint.tree_size)?, root: checkpoint.tree_root })
end

fn own_view(database_path :: String,
  wrapping_key :: borrow StorageKey) -> Option<(MobileTransparencyView, TransparencyCheckpoint)> do
  case load_transparency_view(database_path, wrapping_key) do
    Err(_) -> None
    Ok(view) -> case canonical_transparency_checkpoint(view.checkpoint) do
      Err(_) -> None
      Ok(checkpoint) -> Some((view, checkpoint))
    end
  end
end

fn hint_extension(checkpoint :: TransparencyCheckpoint) -> List<ProtocolExtension> do
  case gossip_view_point(checkpoint) do
    Err(_) -> List.new()
    Ok(point) -> case gossip_hint_extension(point) do
      Err(_) -> List.new()
      Ok(extension) -> [extension]
    end
  end
end

# What every direct message carries: extension 2 once this device has a
# verified view, nothing before. Never an error: gossip must not stop a send.

pub fn gossip_hint_extensions(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<ProtocolExtension> do
  case own_view(database_path, wrapping_key) do
    None -> List.new()
    Some((_, checkpoint)) -> hint_extension(checkpoint)
  end
end

fn item_of(kind :: Int,
  account :: Bytes,
  device :: Bytes,
  hint :: GossipHint,
  now :: Int) -> GossipItem do
  GossipItem {
    kind: kind,
    account: account,
    device: device,
    received_at: now,
    hint: hint,
    ask_back: false,
    checkpoint: Bytes.empty(),
    witnesses: Bytes.empty()
  }
end

fn noted_hint(value :: GossipState,
  own :: TransparencyCheckpoint,
  account :: Bytes,
  device :: Bytes,
  hint :: GossipHint,
  now :: Int) -> Option<GossipState>!String do
  let point = gossip_view_point(own)?
  let action = gossip_hint_action(point.tree_size, point.root, hint)
  if action == "skip" || gossip_point_verified(value, hint) do
    Ok(None)
  else if action == "ask" do
    Ok(Some(gossip_with_item(value, item_of(gossip_kind_ask(), account, device, hint, now))))
  else
    Ok(Some(gossip_with_item(value, item_of(gossip_kind_check(), account, device, hint, now))))
  end
end

# A checkpoint that fails the log's signature is dropped, and the contact is
# not asked again that day (plan §6.16 step 7).

fn noted_answer(value :: GossipState,
  view :: MobileTransparencyView,
  account :: Bytes,
  device :: Bytes,
  answer :: GossipAnswer,
  now :: Int) -> Option<GossipState>!String do
  let signed = case verify_checkpoint(answer.checkpoint,
    SigningPublicKey { bytes: view.service_public_key }) do
    Ok(valid) -> valid
    Err(_) -> false
  end
  if !signed do
    let contact = gossip_contact(value, account)
    Ok(Some(gossip_with_contact(gossip_without_asks(value, account), %{contact | asked_at: now})))
  else
    let point = gossip_view_point(answer.checkpoint)?
    let compare = %{item_of(gossip_kind_compare(), account, device, point, now) |
      checkpoint: encode_checkpoint(answer.checkpoint)?,
      witnesses: transparency_encode_cosignatures(answer.witnesses)?
    }
    let noted = gossip_with_item(value, compare)
    if answer.ask_back do
      Ok(Some(gossip_with_item(noted, item_of(gossip_kind_answer(), account, device, point, now))))
    else
      Ok(Some(noted))
    end
  end
end

fn noted_control(value :: GossipState,
  view :: MobileTransparencyView,
  account :: Bytes,
  device :: Bytes,
  body :: Bytes,
  now :: Int) -> Option<GossipState>!String do
  case gossip_decode_request(body) do
    Ok(hint) -> Ok(Some(gossip_with_item(value,
      %{item_of(gossip_kind_answer(), account, device, hint, now) | ask_back: true})))
    Err(_) -> case gossip_decode_answer(body) do
      Ok(answer) -> noted_answer(value, view, account, device, answer, now)
      Err(_) -> Ok(None)
    end
  end
end

fn note(database_path :: String,
  wrapping_key :: borrow StorageKey,
  account :: Bytes,
  device :: Bytes,
  inner :: InnerEnvelope) -> ()!String do
  let (view, own) = case own_view(database_path, wrapping_key) do
    None -> return Ok(nil)
    Some(found) -> found
  end
  let value = gossip_state_load(database_path, wrapping_key)?
  let now = gossip_now_ms()
  let changed = if inner.message_type == gossip_control_type() do
    noted_control(value, view, account, device, inner.body, now)?
  else
    case gossip_hint_from_extensions(inner.extensions) do
      None
      Some(hint) -> noted_hint(value, own, account, device, hint, now)?
    end
  end
  case changed do
    None -> Ok(nil)
    Some(next) -> gossip_state_store(database_path, wrapping_key, next)
  end
end

## What an authenticated message from the device (account, device) says to
## checkpoint gossip. Only contacts this device listens to (an accepted,
## unblocked conversation) are heard. Kept in its own write, like a contact
## address: a message delivered again says the same. Never an error: gossip
## must not stop a message from arriving.

pub fn gossip_received(database_path :: String,
  wrapping_key :: borrow StorageKey,
  listening :: Bool,
  account :: Bytes,
  device :: Bytes,
  inner :: InnerEnvelope) do
  if listening do
    case note(database_path, wrapping_key, account, device, inner) do
      Ok(_) -> nil
      Err(_) -> nil
    end
  end
end
