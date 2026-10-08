from Mobile.AnchorEvidence import anchor_filing
from Mobile.AnchorSteps import (
  AnchorContext,
  AnchorExchange,
  AnchorStop,
  anchor_asks,
  anchor_call,
  anchor_context,
  anchor_kind_directory,
  anchor_kind_relay,
  anchor_lift,
  anchor_local,
  anchor_parse_input,
  anchor_step
)
from Mobile.Codec import current_time, random_bytes
from Mobile.ContactAddress import deposit_address, outgoing_extensions
from Mobile.GossipEvidence import (
  gossip_contradiction_proofs,
  gossip_fork_proofs,
  gossip_own_cosignatures
)
from Mobile.GossipState import (
  GossipContact,
  GossipItem,
  GossipState,
  gossip_answer_interval_ms,
  gossip_ask_interval_ms,
  gossip_contact,
  gossip_control_type,
  gossip_kind_answer,
  gossip_kind_ask,
  gossip_kind_check,
  gossip_kind_compare,
  gossip_live,
  gossip_point_verified,
  gossip_proof_interval_ms,
  gossip_state_load,
  gossip_state_store,
  gossip_view_point,
  gossip_with_contact,
  gossip_with_item,
  gossip_with_verified,
  gossip_without_asks
)
from Mobile.Healing import with_session_features
from Mobile.Outbox import load_outbox_ids, outbox_capacity, prepare_outbox_writes
from Mobile.Profile import load_profile
from Mobile.Sessions import (
  find_device_session,
  find_peer_session,
  inner_bytes,
  load_session_ids,
  ratchet_bytes,
  restore_session,
  seal_session_ids,
  seal_updated_session,
  self_sync_conversation_id
)
from Mobile.Transparency import canonical_transparency_checkpoint, load_transparency_view
from Mobile.Transport import sealed_outer_bytes
from Mobile.TrustAlarm import trust_alarm_for_fork, trust_alarm_raise
from Mobile.Types import MobileLoadedSession, MobilePreparedSend, MobileTransparencyView
from Protocol.V1 import InnerEnvelope
from Session.Handshake import RatchetState
from Session.Ratchet import RatchetMessage, encrypt_sealed
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Storage.Records import store_outbound
from Transparency.CompactWire import (
  CompactConsistency,
  TransparencyTreeQueryV2,
  transparency_decode_consistency_v2,
  transparency_decode_cosignatures,
  transparency_encode_tree_query_v2
)
from Transparency.Gossip import (
  GossipAnswer,
  GossipHint,
  GossipVerdict,
  gossip_compare,
  gossip_encode_answer,
  gossip_encode_request
)
from Transparency.Merkle import TransparencyCheckpoint
from Transparency.Tree import tlog_empty_root, tlog_verify_consistency
from Transparency.Wire import decode_checkpoint
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  direct_conversation_id,
  encode_packet,
  session_aad
)

##! Mobile.GossipRun: acting on what contacts' messages said about the key log
##! (Mobile.GossipState, plan §6.16). One run settles every note through the
##! anchor check's request steps (Mobile.AnchorSteps): the app performs the
##! directory reads, finder-address requests and relay posts each step asks
##! for, and calls again with every exchange of the run. The app runs it after
##! each pass over the mailbox (`mesh_messenger_gossip_check`).
##!
##! - A hint of another size is proven a prefix (or an extension) of this
##!   device's view with one consistency proof (KTS v2), at most one per
##!   conversation per hour. Proven: remembered, and never checked again.
##! - A hint of the same size with another root, a proof that does not verify
##!   or that the directory refuses: the device asks the sender for the signed
##!   checkpoint behind it (GCQ), at most once per contact per day.
##! - A GCQ is answered with this device's checkpoint and the attestations it
##!   verified (GCA, ask_back 1), at most once per contact per hour; a GCA
##!   with ask_back 1 is answered the same way with ask_back 0.
##! - A contact's checkpoint that fails the log's signature is dropped and the
##!   contact is not asked again that day. One that cannot be true alongside
##!   this device's (gossip_compare; for sizes in order without a proof, the
##!   leaf search of Mobile.GossipEvidence) becomes FRK proofs and a
##!   `contact_fork` trust alarm, which the same run files with every pinned
##!   relay. The alarm blocks new sessions and key changes until relays and
##!   the chain settle it; which phone was targeted is the one whose view the
##!   anchor check also finds at odds with the public record.
##!
##! GCQ and GCA travel inside the end-to-end session as inner messages of type
##! 7 on the conversation (the self-sync conversation for the account's own
##! devices), never in history. Only a device that sent extension 2, or a GCQ,
##! is ever sent one, so a build without gossip never receives either.

struct GossipView do
  view :: MobileTransparencyView
  own :: TransparencyCheckpoint
  point :: GossipHint
end

# action: 0 keep the note, 1 done, 2 ask the sender (GCQ), 3 answer (GCA),
# 4 fork (raise the alarm with frks), 5 refused (a checkpoint failed the
# log's signature). proof: the conversation's consistency proof was spent.

struct GossipDecision do
  item :: GossipItem
  action :: Int
  verified :: List<GossipHint>
  frks :: List<Bytes>
  proof :: Bool
end

struct Settled do
  result :: Result<GossipDecision, AnchorStop>
  proof :: Bool
end

fn decided(item :: GossipItem, action :: Int, proof :: Bool) -> Settled do
  Settled {
    result: Ok(GossipDecision {
      item: item,
      action: action,
      verified: List.new(),
      frks: List.new(),
      proof: proof
    }),
    proof: proof
  }
end

fn proven(item :: GossipItem, point :: GossipHint, proof :: Bool) -> Settled do
  Settled {
    result: Ok(GossipDecision {
      item: item,
      action: 1,
      verified: [point],
      frks: List.new(),
      proof: proof
    }),
    proof: proof
  }
end

fn forked(item :: GossipItem, frks :: List<Bytes>, proof :: Bool) -> Settled do
  Settled {
    result: Ok(GossipDecision {
      item: item,
      action: 4,
      verified: List.new(),
      frks: frks,
      proof: proof
    }),
    proof: proof
  }
end

fn waiting(stop :: AnchorStop, proof :: Bool) -> Settled do
  Settled { result: Err(stop), proof: proof }
end

fn same_point(left :: GossipHint, right :: GossipHint) -> Bool do
  left.tree_size == right.tree_size && Bytes.secure_equals(left.root, right.root)
end

fn gossip_view(database_path :: String, wrapping_key :: borrow StorageKey) -> Option<GossipView> do
  case load_transparency_view(database_path, wrapping_key) do
    Err(_) -> None
    Ok(view) -> case canonical_transparency_checkpoint(view.checkpoint) do
      Err(_) -> None
      Ok(own) -> case gossip_view_point(own) do
        Err(_) -> None
        Ok(point) -> Some(GossipView { view: view, own: own, point: point })
      end
    end
  end
end

# The directory's KTC v2 between two sizes of the Morse tree, asked for once
# per conversation and pair of sizes in a run.

fn consistency(ctx :: AnchorContext,
  account :: Bytes,
  old_size :: Int,
  new_size :: Int) -> Result<AnchorExchange, AnchorStop> do
  let query = anchor_lift(transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
      old_size: old_size,
      new_size: new_size,
      tree: 1
    }),
    "invalid_anchor_request")?
  anchor_call(ctx,
    anchor_kind_directory(),
    "gossip-consistency:#{Bytes.to_hex(account)}:#{old_size}:#{new_size}",
    "/v1/transparency/consistency",
    query)
end

fn served_path(answer :: AnchorExchange, old_size :: Int, new_size :: Int) -> Option<List<Bytes>> do
  if answer.status != 200 do
    None
  else
    case transparency_decode_consistency_v2(answer.answer) do
      Err(_) -> None
      Ok(proof) -> if proof.old_size == old_size && proof.new_size == new_size do
        Some(proof.path)
      else
        None
      end
    end
  end
end

fn ordered(first :: GossipHint, second :: GossipHint) -> (GossipHint, GossipHint) do
  if first.tree_size < second.tree_size do
    (first, second)
  else
    (second, first)
  end
end

fn empty_prefix(older :: GossipHint) -> Bool do
  case tlog_empty_root(1) do
    Ok(root) -> Bytes.secure_equals(older.root, root)
    Err(_) -> false
  end
end

# A hint of another size: proven with one consistency proof when the
# conversation's proof for this hour is free, else it waits.

fn settle_check(ctx :: AnchorContext,
  g :: GossipView,
  state :: GossipState,
  item :: GossipItem,
  budget :: Bool) -> Settled do
  let hint = item.hint
  if same_point(hint, g.point) || gossip_point_verified(state, hint) do
    return decided(item, 1, false)
  end
  if hint.tree_size == g.point.tree_size do
    return decided(item, 2, false)
  end
  let (older, newer) = ordered(hint, g.point)
  if older.tree_size == 0 do
    return if empty_prefix(older) do
      proven(item, hint, false)
    else
      decided(item, 2, false)
    end
  end
  if !budget do
    return decided(item, 0, false)
  end
  case consistency(ctx, item.account, older.tree_size, newer.tree_size) do
    Err(stop) -> waiting(stop, true)
    Ok(answer) -> if answer.status == 0 do
      decided(item, 0, true)
    else
      case served_path(answer, older.tree_size, newer.tree_size) do
        Some(path) -> if tlog_verify_consistency(1,
          older.tree_size,
          newer.tree_size,
          path,
          older.root,
          newer.root) do
          proven(item, hint, true)
        else
          decided(item, 2, true)
        end
        None -> decided(item, 2, true)
      end
    end
  end
end

fn fork_settled(ctx :: AnchorContext,
  item :: GossipItem,
  proofs :: Result<List<Bytes>, AnchorStop>,
  proof :: Bool,
  always :: Bool) -> Settled do
  case proofs do
    Err(stop) -> waiting(stop, proof)
    Ok(frks) -> if always || List.length(frks) > 0 do
      forked(item, frks, proof)
    else
      decided(item, 1, proof)
    end
  end
end

# The contact's signed checkpoint, after sizes that agree in order failed to
# prove consistent on their own: one consistency proof when the hour allows,
# then the leaf search.

fn settle_ordered(ctx :: AnchorContext,
  g :: GossipView,
  item :: GossipItem,
  other :: TransparencyCheckpoint,
  budget :: Bool) -> Settled do
  if !budget do
    return decided(item, 0, false)
  end
  let point = case gossip_view_point(other) do
    Ok(value) -> value
    Err(_) -> return decided(item, 1, false)
  end
  let (older, newer) = ordered(point, g.point)
  let witnesses = case transparency_decode_cosignatures(item.witnesses) do
    Ok(values) -> values
    Err(_) -> List.new()
  end
  case consistency(ctx, item.account, older.tree_size, newer.tree_size) do
    Err(stop) -> waiting(stop, true)
    Ok(answer) -> if answer.status == 0 do
      decided(item, 0, true)
    else
      let path = case served_path(answer, older.tree_size, newer.tree_size) do
        Some(value) -> value
        None -> List.new()
      end
      let key = SigningPublicKey { bytes: g.view.service_public_key }
      case gossip_compare(g.own, other, key, path) do
        Ok(verdict) -> if verdict.outcome == "consistent" do
          proven(item, point, true)
        else
          fork_settled(ctx, item, gossip_contradiction_proofs(ctx, other, witnesses), true, false)
        end
        Err(_) -> decided(item, 5, true)
      end
    end
  end
end

fn settle_compare(ctx :: AnchorContext,
  g :: GossipView,
  item :: GossipItem,
  budget :: Bool) -> Settled do
  let other = case decode_checkpoint(item.checkpoint) do
    Ok(value) -> value
    Err(_) -> return decided(item, 1, false)
  end
  let key = SigningPublicKey { bytes: g.view.service_public_key }
  case gossip_compare(g.own, other, key, List.new()) do
    Err(_) -> decided(item, 5, false)
    Ok(verdict) -> if verdict.outcome == "consistent" do
      case gossip_view_point(other) do
        Ok(point) -> proven(item, point, false)
        Err(_) -> decided(item, 1, false)
      end
    else if verdict.outcome == "fork" do
      let witnesses = case transparency_decode_cosignatures(item.witnesses) do
        Ok(values) -> values
        Err(_) -> List.new()
      end
      fork_settled(ctx,
        item,
        gossip_fork_proofs(ctx, g.own, other, witnesses, verdict.fork_kind),
        false,
        true)
    else
      settle_ordered(ctx, g, item, other, budget)
    end
  end
end

fn settle(ctx :: AnchorContext,
  g :: GossipView,
  state :: GossipState,
  item :: GossipItem,
  budget :: Bool) -> Settled do
  if item.kind == gossip_kind_check() do
    settle_check(ctx, g, state, item, budget)
  else if item.kind == gossip_kind_ask() do
    decided(item, 2, false)
  else if item.kind == gossip_kind_answer() do
    decided(item, 3, false)
  else if item.kind == gossip_kind_compare() do
    settle_compare(ctx, g, item, budget)
  else
    decided(item, 1, false)
  end
end

fn spent(used :: List<Bytes>, account :: Bytes) -> Bool do
  List.any(used, fn value -> Bytes.secure_equals(value, account) end)
end

# Notes are settled in order; a conversation's hourly consistency proof goes to
# the first that needs it.

fn settle_all(ctx :: AnchorContext,
  g :: GossipView,
  state :: GossipState,
  index :: Int,
  used :: List<Bytes>,
  output :: List<Result<GossipDecision, AnchorStop>>) -> List<Result<GossipDecision, AnchorStop>> do
  if index >= List.length(state.pending) do
    output
  else
    let item = List.get(state.pending, index)
    let contact = gossip_contact(state, item.account)
    let budget = ctx.now - contact.proof_at >= gossip_proof_interval_ms()
      && !spent(used, item.account)
    let settled = settle(ctx, g, state, item, budget)
    let next_used = if settled.proof do
      List.append(used, item.account)
    else
      used
    end
    settle_all(ctx, g, state, index + 1, next_used, List.append(output, settled.result))
  end
end

fn wire_conversation(local :: ClientProfile, account :: Bytes) -> Bytes!String do
  if Bytes.secure_equals(account, local.account_id) do
    self_sync_conversation_id(local.account_id)
  else
    direct_conversation_id(local.account_id, account)
  end
end

fn control_inner(local :: ClientProfile,
  loaded :: MobileLoadedSession,
  body :: Bytes,
  database_path :: String,
  wrapping_key :: borrow StorageKey) -> InnerEnvelope!String do
  Ok(InnerEnvelope {
    version: 1,
    sender_account_id: local.account_id,
    sender_device_id: local.device_id,
    recipient_device_id: loaded.record.peer_device_id,
    conversation_id: wire_conversation(local, loaded.record.peer_account_id)?,
    client_message_id: random_bytes(16)?,
    client_timestamp: current_time()?,
    message_type: gossip_control_type(),
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: with_session_features(outgoing_extensions(database_path, wrapping_key)?)?
  })
end

fn sendable(loaded :: MobileLoadedSession, policy :: MobileLoadedSession) -> Bool do
  !policy.record.blocked
    && policy.record.request_state == 1
    && Bytes.length(loaded.record.snapshot) > 0
    && loaded.record.reset_state != 2
    && Bytes.length(loaded.record.peer_identity_key) == 32
end

fn encrypted_control(database_path :: String,
  wrapping_key :: borrow StorageKey,
  loaded :: MobileLoadedSession,
  inner :: InnerEnvelope,
  session_ids :: List<Bytes>,
  pending_ids :: List<Bytes>) -> Bool!String do
  let state = restore_session(loaded, wrapping_key)?
  case encrypt_sealed(state, inner_bytes(inner)?, session_aad(loaded.session_id)?) do
    Err(_) -> Err("message_encryption_failed")
    Ok(value) -> do
      let (next_state, message) = value
      let session_blob = seal_updated_session(next_state, loaded, wrapping_key)?
      let outer = sealed_outer_bytes(deposit_address(database_path,
          wrapping_key,
          loaded.record.peer_mailbox)?,
        encode_packet(RatchetPacket(ratchet_bytes(message)?))?,
        loaded.record.peer_identity_key,
        inner.client_timestamp)?
      let (labels, blobs, index_blob) = prepare_outbox_writes(wrapping_key,
        pending_ids,
        [outer],
        database_path,
        Bytes.empty(),
        0,
        0)?
      store_outbound(database_path,
        [
          MobilePreparedSend {
            envelope: outer,
            session_id: loaded.session_id,
            session_label: loaded.label,
            session_blob: session_blob,
            new_session: false
          }
        ],
        List.new(),
        seal_session_ids(session_ids, wrapping_key)?,
        List.new(),
        List.new(),
        labels,
        blobs,
        index_blob)?
      Ok(true)
    end
  end
end

# A control frame to one contact device, in its current session, through the
# outbox like any message. False when that conversation cannot carry it now
# (no session, blocked, not accepted, replaced, or the outbox is full).

fn send_control(database_path :: String,
  wrapping_key :: borrow StorageKey,
  account :: Bytes,
  device :: Bytes,
  body :: Bytes) -> Bool!String do
  let local = decode_client_profile(load_profile(database_path)?)?
  let session_ids = load_session_ids(database_path, wrapping_key)?
  let found = case find_device_session(database_path,
    wrapping_key,
    account,
    device,
    session_ids,
    0) do
    Err(error) -> if error == "session_not_found" do
      Ok(None)
    else
      Err(error)
    end
    Ok(loaded) -> Ok(Some(loaded))
  end?
  let loaded = case found do
    None -> return Ok(false)
    Some(value) -> value
  end
  let policy = find_peer_session(database_path, wrapping_key, account, session_ids, 0)?
  let pending_ids = load_outbox_ids(database_path, wrapping_key)?
  if !sendable(loaded, policy) || List.length(pending_ids) >= outbox_capacity() do
    Ok(false)
  else
    let inner = control_inner(local, loaded, body, database_path, wrapping_key)?
    encrypted_control(database_path, wrapping_key, loaded, inner, session_ids, pending_ids)
  end
end

fn answer_body(database_path :: String, g :: GossipView, ask_back :: Bool) -> Bytes!String do
  gossip_encode_answer(GossipAnswer {
    checkpoint: g.own,
    witnesses: gossip_own_cosignatures(database_path, g.own)?,
    ask_back: ask_back
  })
end

fn asked(ctx :: AnchorContext,
  wrapping_key :: borrow StorageKey,
  state :: GossipState,
  contact :: GossipContact,
  item :: GossipItem) -> GossipState!String do
  if ctx.now - contact.asked_at < gossip_ask_interval_ms() do
    Ok(gossip_with_item(state, %{item | kind: gossip_kind_ask()}))
  else if send_control(ctx.database_path,
    wrapping_key,
    item.account,
    item.device,
    gossip_encode_request(item.hint)?)? do
    Ok(gossip_with_contact(state, %{contact | asked_at: ctx.now}))
  else
    Ok(state)
  end
end

fn answered(ctx :: AnchorContext,
  wrapping_key :: borrow StorageKey,
  g :: GossipView,
  state :: GossipState,
  contact :: GossipContact,
  item :: GossipItem) -> GossipState!String do
  if ctx.now - contact.answered_at < gossip_answer_interval_ms() do
    Ok(state)
  else if send_control(ctx.database_path,
    wrapping_key,
    item.account,
    item.device,
    answer_body(ctx.database_path, g, item.ask_back)?)? do
    Ok(gossip_with_contact(state, %{contact | answered_at: ctx.now}))
  else
    Ok(state)
  end
end

fn raised(ctx :: AnchorContext,
  g :: GossipView,
  decision :: GossipDecision) -> Result<(), String> do
  let other = decode_checkpoint(decision.item.checkpoint)?
  trust_alarm_raise(ctx.database_path, trust_alarm_for_fork(g.own, other, decision.frks)?)
end

fn applied(ctx :: AnchorContext,
  wrapping_key :: borrow StorageKey,
  g :: GossipView,
  state :: GossipState,
  decision :: GossipDecision) -> GossipState!String do
  let item = decision.item
  let before = gossip_contact(state, item.account)
  let contact = if decision.proof do
    %{before | proof_at: ctx.now}
  else
    before
  end
  let base = gossip_with_verified(gossip_with_contact(state, contact), decision.verified)
  if decision.action == 0 do
    Ok(gossip_with_item(base, item))
  else if decision.action == 2 do
    asked(ctx, wrapping_key, base, contact, item)
  else if decision.action == 3 do
    answered(ctx, wrapping_key, g, base, contact, item)
  else if decision.action == 4 do
    raised(ctx, g, decision)?
    Ok(base)
  else if decision.action == 5 do
    Ok(gossip_with_contact(gossip_without_asks(base, item.account), %{contact | asked_at: ctx.now}))
  else
    Ok(base)
  end
end

fn apply_all(ctx :: AnchorContext,
  wrapping_key :: borrow StorageKey,
  g :: GossipView,
  state :: GossipState,
  decisions :: List<GossipDecision>,
  index :: Int) -> GossipState!String do
  if index >= List.length(decisions) do
    Ok(state)
  else
    let next = applied(ctx, wrapping_key, g, state, List.get(decisions, index))?
    apply_all(ctx, wrapping_key, g, next, decisions, index + 1)
  end
end

# ponytail: each control message is written with its session and outbox entry,
# the gossip record after them; a crash in between repeats one control at most.

fn committed(ctx :: AnchorContext,
  wrapping_key :: borrow StorageKey,
  g :: GossipView,
  state :: GossipState,
  decisions :: List<GossipDecision>) -> Bool!String do
  let next = apply_all(ctx, wrapping_key, g, %{state | pending: List.new()}, decisions, 0)?
  gossip_state_store(ctx.database_path, wrapping_key, next)?
  Ok(List.any(decisions, fn decision -> decision.action == 4 end))
end

fn decisions_of(settled :: List<Result<GossipDecision, AnchorStop>>) -> List<GossipDecision> do
  List.flat_map(settled,
    fn value -> case value do
      Ok(decision) -> [decision]
      Err(_) -> List.new()
    end end)
end

## One step of a gossip run (Mobile.AnchorSteps framing, the same as the
## anchor check): the requests still needed, or done once every note is
## settled and any new alarm's proofs were filed. `offset_ms` moves the clock
## (tests); the export passes 0.

pub fn gossip_check_at(input :: Bytes, offset_ms :: Int) -> Bytes!String do
  let (database_path, exchanges) = anchor_parse_input(input)?
  if String.length(database_path) > 4096 do
    return Err("invalid_database_path")
  end
  ensure_schema(database_path)?
  let base = anchor_context(database_path, exchanges)?
  let ctx = %{base | now: base.now + offset_ms}
  let wrapping_key = platform_key()?
  let state = gossip_live(gossip_state_load(database_path, wrapping_key)?, ctx.now)
  let view = gossip_view(database_path, wrapping_key)
  let settled = case view do
    None -> List.new()
    Some(g) -> settle_all(ctx, g, state, 0, List.new(), List.new())
  end
  let asks = List.flat_map(settled, fn value -> anchor_asks(value) end)
  if List.length(asks) > 0 do
    return anchor_step(false, asks)
  end
  let fresh = case view do
    None -> false
    Some(g) -> committed(ctx, wrapping_key, g, state, decisions_of(settled))?
  end
  # Proofs go to the relays in the run that raised them; a relay that did not
  # answer is tried again by the daily anchor check.
  let filing = fresh
    || List.any(ctx.exchanges, fn exchange -> exchange.kind == anchor_kind_relay() end)
  let filed = if filing do
    anchor_asks(anchor_filing(ctx))
  else
    List.new()
  end
  anchor_step(List.length(filed) == 0, filed)
end

pub fn gossip_check(input :: Bytes) -> Bytes!String do
  gossip_check_at(input, 0)
end
