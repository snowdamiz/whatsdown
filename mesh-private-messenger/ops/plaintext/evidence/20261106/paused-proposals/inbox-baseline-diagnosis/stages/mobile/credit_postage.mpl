from Protocol.DirectoryWire import decode_device_set
from Protocol.V1 import DeviceSet
from Credits.PostagePolicy import postage_policy_from_device_set
from Mobile.PostageCandidates import require_postage_fanout
from Mobile.PostageQueue import (
  load_postage_queue,
  postage_queue_cache,
  forget_postage_queue,
  postage_outbox_guards
)
from Credits.ActionWire import decode_credit_action_receipt
from Credits.Cancellation import decode_credit_cancellation
from Credits.Action import credit_action_id, encode_credit_action, decode_credit_action
from Credits.ActionWire import CreditActionSubmission, encode_credit_action_submission
from Credits.Postage import (
  decode_credit_postage_request,
  credit_postage_request_for_devices,
  encode_credit_postage_request,
  credit_postage_action,
  decode_credit_postage_result,
  credit_postage_effect_id
)
from Credits.PostageBox import (
  SealedPostageBatch,
  postage_batch_digest,
  seal_postage_credit_box,
  encode_sealed_postage_batch,
  decode_sealed_postage_batch
)
from Credits.PostageReply import open_postage_reply, open_postage_reply_for_digest
from Credits.Wire import decode_credit_frame
from Mobile.Codec import canonical_outer, mobile_byte, mobile_write_u64, mobile_read_u64
from Mobile.CreditState import (
  CreditRecord,
  credit_record_id,
  find_credit_record,
  put_credit_record,
  pack_credit_parts,
  unpack_credit_parts
)
from Mobile.CreditWallet import (
  CreditSpendPlan,
  reserve_credit_postage_spend,
  accept_credit_postage_receipt,
  accept_credit_cancellation,
  stored_credit_receipt,
  recover_credit_reservation
)
from Mobile.DeviceSet import verified_device_set
from Mobile.Transparency import require_transparency_device_set
from Mobile.Outbox import load_postage_outbox_entries, acknowledge_outbox
from Mobile.Types import MobilePayloadRequest
from Privacy.Edge import seal_delivery, encode_sealed_delivery
from Storage.Credits import (
  CreditWalletIdentity,
  load_credit_wallet,
  commit_credit_wallet,
  commit_credit_wallet_with_cache,
  seal_credit_payload,
  open_credit_payload,
  credit_context
)
from Storage.Keys import seal_x25519, open_x25519, context

pub struct CreditPostagePlan do
  nonce :: Bytes
  batch :: Bytes
  spend :: CreditSpendPlan
end

struct TerminalPostage do
  request :: Bytes
  username :: String
  message_id :: Bytes
  count :: Int
  credits :: Int
  reply_key :: Bytes
end

struct PostageMaterial do
  request :: Bytes
  devices :: Bytes
  outers :: List<Bytes>
  deliveries :: List<Bytes>
  reply_key :: Bytes
  batch :: Bytes
  core_key :: Bytes
  message_id :: Bytes
end

fn postage_label(nonce :: Bytes) -> String do
  "postage/#{Bytes.to_hex(nonce)}"
end

fn postage_reply_context(who :: CreditWalletIdentity, nonce :: Bytes) -> Bytes!String do
  context(who.account_id,
    who.device_id,
    "postage-reply/v1/#{Bytes.to_hex(who.service_key)}/#{who.purpose}/#{Bytes.to_hex(nonce)}",
    8)
end

fn postage_ids(outers :: List<Bytes>) -> List<Bytes>!String do
  let values = for outer in outers do
    canonical_outer(outer)?.envelope_id
  end
  Ok(values)
end

fn postage_metadata_ids(record :: CreditRecord) -> List<Bytes>!String do
  if record.kind != 8 || Bytes.length(record.metadata) < 56 do
    return Err("invalid_credit_postage_material")
  end
  let offset = if terminal_marker(record) do
    45
  else
    32
  end
  if Bytes.length(record.metadata) < offset + 24 do
    return Err("invalid_credit_postage_material")
  end
  let ids = unpack_credit_parts(Bytes.slice(record.metadata,
      offset,
      Bytes.length(record.metadata) - offset)?,
    8,
    16)?
  if List.length(ids) < 1 || List.any(ids, fn(value) -> Bytes.length(value) != 16 end) do
    return Err("invalid_credit_postage_material")
  end
  for index in 0..List.length(ids) do
    for prior in 0..index do
      if Bytes.secure_equals(List.get(ids, prior), List.get(ids, index)) do
        return Err("invalid_credit_postage_material")
      end
    end
  end
  Ok(ids)
end

fn postage_intent(devices :: Bytes, ids :: List<Bytes>, core :: Bytes) -> Bytes!String do
  Ok(Crypto.sha256(pack_credit_parts([devices, pack_credit_parts(ids)?, core])?))
end

fn material_parts(value :: PostageMaterial) -> Bytes!String do
  pack_credit_parts([
    value.request,
    value.devices,
    pack_credit_parts(value.outers)?,
    pack_credit_parts(value.deliveries)?,
    value.reply_key,
    value.batch,
    value.core_key,
    value.message_id
  ])
end

fn read_postage(record :: CreditRecord,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> PostageMaterial!String do
  let ids = postage_metadata_ids(record)?
  let parts = unpack_credit_parts(open_credit_payload(record.payload,
      wrapping,
      who,
      postage_label(record.id))?,
    8,
    1100000)?
  if List.length(parts) != 8 do
    return Err("invalid_credit_postage_material")
  end
  let value = PostageMaterial {
    request: List.get(parts, 0),
    devices: List.get(parts, 1),
    outers: unpack_credit_parts(List.get(parts, 2), 8, 65606)?,
    deliveries: unpack_credit_parts(List.get(parts, 3), 8, 65674)?,
    reply_key: List.get(parts, 4),
    batch: List.get(parts, 5),
    core_key: List.get(parts, 6),
    message_id: List.get(parts, 7)
  }
  let request = decode_credit_postage_request(value.request)?
  if !Bytes.secure_equals(request.operation_nonce, record.id)
    || !Bytes.secure_equals(request.device_set_sha256, Crypto.sha256(value.devices))
    || !Bytes.secure_equals(request.batch_digest, postage_batch_digest(value.deliveries)?)
    || !Bytes.secure_equals(pack_credit_parts(ids)?, pack_credit_parts(postage_ids(value.outers)?)?)
    || !Bytes.secure_equals(Bytes.slice(record.metadata, 0, 32)?,
      postage_intent(value.devices, ids, value.core_key)?)
    || Bytes.length(value.core_key) != 32
    || Bytes.length(value.message_id) != 16
    || List.length(value.outers) != List.length(value.deliveries) do
    return Err("invalid_credit_postage_material")
  end
  if Bytes.length(value.batch) > 0 do
    let batch = decode_sealed_postage_batch(value.batch)?
    if !Bytes.secure_equals(pack_credit_parts(batch.deliveries)?,
      pack_credit_parts(value.deliveries)?) do
      return Err("invalid_credit_postage_material")
    end
  end
  Ok(value)
end

fn postage_payload(record :: CreditRecord,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> List<Bytes>!String do
  unpack_credit_parts(open_credit_payload(record.payload, wrapping, who, postage_label(record.id))?,
    8,
    1100000)
end

fn terminal_marker(record :: CreditRecord) -> Bool do
  Bytes.length(record.metadata) >= 45
    && case Bytes.slice(record.metadata, 32, 4) do
      Err(_) -> false
      Ok(value) -> Bytes.to_hex(value) == "0150544d"
    end
end

fn read_terminal(record :: CreditRecord,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> TerminalPostage!String do
  let parts = postage_payload(record, wrapping, who)?
  if List.length(parts) != 6
    || Bytes.to_hex(List.head(parts)) != "0150544d"
    || Bytes.length(List.get(parts, 4)) != 2
    || Bytes.length(List.get(parts, 3)) != 16
    || Bytes.length(List.get(parts, 2)) > 64 do
    return Err("invalid_credit_postage_terminal")
  end
  let request = decode_credit_postage_request(List.get(parts, 1))?
  let count = Bytes.get(List.get(parts, 4), 0)?
  let credits = Bytes.get(List.get(parts, 4), 1)?
  if !Bytes.secure_equals(request.operation_nonce, record.id)
    || count != List.length(postage_metadata_ids(record)?)
    || !List.contains([1, 5, 25], credits) do
    return Err("invalid_credit_postage_terminal")
  end
  Ok(TerminalPostage {
    request: List.get(parts, 1),
    username: Bytes.to_utf8(List.get(parts, 2))?,
    message_id: List.get(parts, 3),
    count: count,
    credits: credits,
    reply_key: List.get(parts, 5)
  })
end

# Compact material is authenticated storage, created only after the exact pinned
# receipt was verified and the outbox ownership transition completed. It retains
# the immutable request and reply key for authenticated response replay.
fn terminal_plan(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  record :: CreditRecord) -> CreditPostagePlan!String do
  let material = read_terminal(record, wrapping, who)?
  let request = decode_credit_postage_request(material.request)?
  let action = credit_postage_action(request)?
  let spend = recover_credit_reservation(path, wrapping, who, credit_action_id(action)?)?
  if spend.status == 0
    || spend.credits != material.credits
    || !Bytes.secure_equals(spend.request_body, material.request)
    || !Bytes.secure_equals(spend.action, encode_credit_action(action)?) do
    return Err("invalid_credit_postage_terminal")
  end
  let raw = case stored_credit_receipt(path, wrapping, who, spend.operation_id)? do
    None -> return Err("credit_effect_receipt_missing")
    Some(value) -> value
  end
  if spend.status == 1 do
    let receipt = decode_credit_action_receipt(raw)?
    let result = decode_credit_postage_result(receipt.result)?
    if !Bytes.secure_equals(receipt.effect_id, credit_postage_effect_id(action)?)
      || !Bytes.secure_equals(result.recipient_account_id, request.recipient_account_id)
      || !Bytes.secure_equals(result.batch_digest, request.batch_digest)
      || result.policy_revision != request.policy_revision
      || result.device_set_revision != request.device_set_revision
      || result.enqueued_count != material.count
      || result.charged_credits != material.credits do
      return Err("invalid_credit_postage_terminal")
    end
    nil
  else
    nil
  end
  Ok(CreditPostagePlan { nonce: record.id, batch: Bytes.empty(), spend: spend })
end

fn compact_postage(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  record :: CreditRecord,
  material :: PostageMaterial,
  credits :: Int) -> Result<(), String> do
  let before = load_credit_wallet(path, wrapping, who)?
  let current = case find_credit_record(before.wallet, 8, record.id) do
    None -> return Err("credit_postage_not_found")
    Some(value) -> value
  end
  if terminal_marker(current) do
    terminal_plan(path, wrapping, who, current)?
    return Ok(nil)
  end
  let count_price = case Bytes.from_list([List.length(material.deliveries), credits]) do
    Err(_) -> return Err("invalid_credit_postage_terminal")
    Ok(value) -> value
  end
  let payload = pack_credit_parts([
    Bytes.from_hex("0150544d")?,
    material.request,
    Bytes.from_utf8(decode_postage_device_set(material.devices)?.username),
    material.message_id,
    count_price,
    material.reply_key
  ])?
  let plan = recover_credit_reservation(path,
    wrapping,
    who,
    credit_action_id(credit_postage_action(decode_credit_postage_request(material.request)?)?)?)?
  if plan.status != 1 && plan.status != 2 do
    return Err("invalid_credit_postage_terminal")
  end
  let terminal_metadata = Bytes.concat(Bytes.concat(Bytes.concat(Bytes.concat(Bytes.slice(current.metadata,
            0,
            32)?,
          Bytes.from_hex("0150544d")?)?,
        mobile_byte(plan.status)?)?,
      mobile_write_u64(decode_credit_postage_request(material.request)?.action_expires_at)?)?,
    pack_credit_parts(postage_metadata_ids(current)?)?)?
  let updated = %{current |
    metadata: terminal_metadata,
    payload: seal_credit_payload(payload, wrapping, who, postage_label(record.id))?
  }
  let wallet = put_credit_record(%{before.wallet |
      revision: U64.add(before.wallet.revision, U64.parse("1")?)?
    },
    updated)
  commit_credit_wallet(path, wrapping, who, before, wallet)
end

fn acknowledge_postage(path :: String, outers :: List<Bytes>) -> Result<(), String> do
  for outer in outers do
    acknowledge_outbox(MobilePayloadRequest { database_path: path, payload: outer })?
    nil
  end
  Ok(nil)
end

fn finish_postage(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  record :: CreditRecord,
  material :: PostageMaterial,
  now_ms :: U64) -> CreditPostagePlan!String do
  let request = decode_credit_postage_request(material.request)?
  let action = credit_postage_action(request)?
  let spend = reserve_credit_postage_spend(path,
    wrapping,
    who,
    encode_credit_action(action)?,
    material.request,
    material.devices,
    material.deliveries,
    U64.divide(now_ms, U64.parse("1000")?)?)?
  let wire = if Bytes.length(material.batch) > 0 do
    material.batch
  else
    let submission = CreditActionSubmission {
      action: action,
      request_body: material.request,
      frame: decode_credit_frame(spend.frame)?
    }
    let box = seal_postage_credit_box(X25519PublicKey { bytes: material.core_key },
      material.deliveries,
      submission)?
    let wire = encode_sealed_postage_batch(SealedPostageBatch {
      deliveries: material.deliveries,
      credit_box: box
    })?
    let before = load_credit_wallet(path, wrapping, who)?
    let current = case find_credit_record(before.wallet, 8, record.id) do
      None -> return Err("credit_postage_not_found")
      Some(value) -> value
    end
    let saved = read_postage(current, wrapping, who)?
    if Bytes.length(saved.batch) > 0 do
      saved.batch
    else
      let updated = %{current |
        payload: seal_credit_payload(material_parts(%{material | batch: wire})?,
          wrapping,
          who,
          postage_label(record.id))?
      }
      let wallet = put_credit_record(%{before.wallet |
          revision: U64.add(before.wallet.revision, U64.parse("1")?)?
        },
        updated)
      commit_credit_wallet(path, wrapping, who, before, wallet)?
      wire
    end
  end
  if spend.status == 1 do
    let receipt = case stored_credit_receipt(path, wrapping, who, spend.operation_id)? do
      None -> return Err("credit_effect_receipt_missing")
      Some(value) -> value
    end
    accept_credit_postage_receipt(path,
      wrapping,
      who,
      material.devices,
      material.deliveries,
      receipt)?
    acknowledge_postage(path, material.outers)?
    forget_postage_queue(path, wrapping, record.id)?
    compact_postage(path, wrapping, who, record, material, spend.credits)?
    nil
  else if spend.status == 2 do
    forget_postage_queue(path, wrapping, record.id)?
    compact_postage(path, wrapping, who, record, material, spend.credits)?
    nil
  else
    nil
  end
  if spend.status != 0 do
    return recover_credit_postage(path, wrapping, who, record.id, now_ms)
  end
  Ok(CreditPostagePlan { nonce: record.id, batch: wire, spend: spend })
end

pub fn recover_credit_postage(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  nonce :: Bytes,
  now_ms :: U64) -> CreditPostagePlan!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 8, nonce) do
    None -> return Err("credit_postage_not_found")
    Some(value) -> value
  end
  if terminal_marker(record) do
    terminal_plan(path, wrapping, who, record)
  else
    finish_postage(path, wrapping, who, record, read_postage(record, wrapping, who)?, now_ms)
  end
end

# Only native outbox IDs enter this builder. Current witnessed recipient state,
# ciphertext, reply handle and its exact PST are durable before token selection;
# then the complete PSB is durable before any network bytes are returned.
pub fn prepare_credit_postage(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  nonce :: Bytes,
  devices_wire :: Bytes,
  ids :: List<Bytes>,
  core :: X25519PublicKey,
  now_ms :: U64) -> CreditPostagePlan!String do
  if !credit_record_id(nonce) || List.length(ids) < 1 || List.length(ids) > 8 do
    return Err("invalid_credit_postage_intent")
  end
  let intent = postage_intent(devices_wire, ids, core.bytes)?
  let before = load_credit_wallet(path, wrapping, who)?
  case find_credit_record(before.wallet, 8, nonce) do
    Some(record) -> do
      if !Bytes.secure_equals(Bytes.slice(record.metadata, 0, 32)?, intent) do
        return Err("credit_postage_intent_changed")
      end
      return recover_credit_postage(path, wrapping, who, nonce, now_ms)
    end
    None -> nil
  end
  let records = List.filter(before.wallet.records, fn(value) -> value.kind == 8 end)
  let full = for record in records do
    if terminal_marker(record) do
      0
    else
      1
    end
  end
  if List.reduce(full, 0, fn(total, value) -> total + value end) >= 16 do
    return Err("credit_postage_capacity")
  end
  for record in records do
    let blocks = if terminal_marker(record) do
      Bytes.get(record.metadata, 36)? != 2
    else
      true
    end
    if blocks
      && List.any(postage_metadata_ids(record)?, fn(prior) -> List.contains(ids, prior) end) do
      return Err("credit_postage_message_already_reserved")
    end
  end
  let devices = verified_device_set(devices_wire)?
  require_transparency_device_set(path, wrapping, devices)?
  if List.length(devices.expired) > 0 || List.length(ids) != List.length(devices.value.devices) do
    return Err("invalid_credit_postage_set")
  end
  let outbox_guards = postage_outbox_guards(path)?
  let candidate = require_postage_fanout(path, wrapping, devices, ids)?
  let outers = load_postage_outbox_entries(path, wrapping, ids)?
  for index in 0..List.length(outers) do
    if !Bytes.secure_equals(canonical_outer(List.get(outers, index))?.mailbox_token,
      List.get(devices.value.devices, index).mailbox_token) do
      return Err("invalid_credit_postage_outbox")
    end
  end
  let deliveries = for outer in outers do
    encode_sealed_delivery(seal_delivery(outer, core)?)?
  end
  let reply = case Crypto.x25519_generate() do
    Err(_) -> return Err("postage_reply_key_unavailable")
    Ok(value) -> value
  end
  let request = credit_postage_request_for_devices(devices.value,
    deliveries,
    nonce,
    reply.public_key,
    U64.add(U64.divide(now_ms, U64.parse("1000")?)?, U64.parse("600")?)?)?
  let material = PostageMaterial {
    request: encode_credit_postage_request(request)?,
    devices: devices_wire,
    outers: outers,
    deliveries: deliveries,
    reply_key: seal_x25519(reply.private_key, wrapping, postage_reply_context(who, nonce)?)?,
    batch: Bytes.empty(),
    core_key: core.bytes,
    message_id: candidate.message_id
  }
  let metadata = Bytes.concat(intent, pack_credit_parts(ids)?)?
  let record = CreditRecord {
    kind: 8,
    id: nonce,
    metadata: metadata,
    payload: seal_credit_payload(material_parts(material)?, wrapping, who, postage_label(nonce))?
  }
  let wallet = put_credit_record(%{before.wallet |
      revision: U64.add(before.wallet.revision, U64.parse("1")?)?
    },
    record)
  let queue = postage_queue_cache(load_postage_queue(path, wrapping)?, nonce, ids, wrapping)?
  commit_credit_wallet_with_cache(path, wrapping, who, before, wallet, [queue] ++ outbox_guards)?
  finish_postage(path, wrapping, who, record, material, now_ms)
end

pub fn accept_credit_postage_response(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  nonce :: Bytes,
  response :: Bytes,
  now_ms :: U64) -> CreditPostagePlan!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 8, nonce) do
    None -> return Err("credit_postage_not_found")
    Some(value) -> value
  end
  if terminal_marker(record) do
    let material = read_terminal(record, wrapping, who)?
    let request = decode_credit_postage_request(material.request)?
    let reply = open_x25519(material.reply_key, wrapping, postage_reply_context(who, nonce)?)?
    let receipt = open_postage_reply_for_digest(reply, request.batch_digest, response)?
    let plan = terminal_plan(path, wrapping, who, record)?
    let stored = case stored_credit_receipt(path, wrapping, who, plan.spend.operation_id)? do
      None -> return Err("credit_effect_receipt_missing")
      Some(value) -> value
    end
    if !Bytes.secure_equals(receipt, stored) do
      return Err("credit_postage_receipt_changed")
    end
    return Ok(plan)
  end
  let material = read_postage(record, wrapping, who)?
  let reply = open_x25519(material.reply_key, wrapping, postage_reply_context(who, nonce)?)?
  let receipt = open_postage_reply(reply, material.deliveries, response)?
  let expected = credit_action_id(credit_postage_action(decode_credit_postage_request(material.request)?)?)?
  let operation = if Bytes.to_hex(Bytes.slice(receipt, 0, 4)?) == "01434352" do
    decode_credit_cancellation(receipt)?.operation_id
  else
    decode_credit_action_receipt(receipt)?.operation_id
  end
  if !Bytes.secure_equals(operation, expected) do
    return Err("invalid_credit_postage_receipt")
  end
  if Bytes.to_hex(Bytes.slice(receipt, 0, 4)?) == "01434352" do
    accept_credit_cancellation(path, wrapping, who, receipt)?
    nil
  else
    accept_credit_postage_receipt(path,
      wrapping,
      who,
      material.devices,
      material.deliveries,
      receipt)?
    acknowledge_postage(path, material.outers)?
    nil
  end
  recover_credit_postage(path, wrapping, who, nonce, now_ms)
end

pub struct CreditPostageInventory do
  nonce :: Bytes
  message_id :: Bytes
  account_id :: Bytes
  username :: String
  operation_id :: Bytes
  status :: Int
  credits :: Int
  expires_at :: U64
  ids :: List<Bytes>
end

pub fn credit_postage_inventory(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> List<CreditPostageInventory>!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let records = List.filter(before.wallet.records, fn(record) -> record.kind == 8 end)
  let rows = for record in records do
    if terminal_marker(record) do
      let material = read_terminal(record, wrapping, who)?
      let request = decode_credit_postage_request(material.request)?
      let plan = terminal_plan(path, wrapping, who, record)?
      CreditPostageInventory {
        nonce: record.id,
        message_id: material.message_id,
        account_id: request.recipient_account_id,
        username: material.username,
        operation_id: plan.spend.operation_id,
        status: plan.spend.status,
        credits: plan.spend.credits,
        expires_at: request.action_expires_at,
        ids: postage_metadata_ids(record)?
      }
    else
      let material = read_postage(record, wrapping, who)?
      let request = decode_credit_postage_request(material.request)?
      let operation = credit_action_id(credit_postage_action(request)?)?
      let policy = case postage_policy_from_device_set(decode_postage_device_set(material.devices)?)? do
        None -> return Err("invalid_credit_postage_material")
        Some(value) -> value
      end
      let reserved = case find_credit_record(before.wallet, 4, operation) do
        None
        Some(_) -> Some(recover_credit_reservation(path, wrapping, who, operation)?)
      end
      CreditPostageInventory {
        nonce: record.id,
        message_id: material.message_id,
        account_id: request.recipient_account_id,
        username: decode_postage_device_set(material.devices)?.username,
        operation_id: operation,
        status: case reserved do
          None -> 3
          Some(value) -> value.status
        end,
        credits: case reserved do
          None -> policy.credits
          Some(value) -> value.credits
        end,
        expires_at: request.action_expires_at,
        ids: postage_metadata_ids(record)?
      }
    end
  end
  let pending = List.filter(rows, fn(row) -> row.status == 0 || row.status == 3 end)
  if List.length(pending) > 16 do
    return Err("credit_postage_capacity")
  end
  let terminal = List.sort(List.filter(rows, fn(row) -> row.status == 1 || row.status == 2 end),
    fn(left, right) do
      let order = U64.compare(right.expires_at, left.expires_at)
      if order == 0 do
        if Bytes.to_hex(left.nonce) < Bytes.to_hex(right.nonce) do
          -1
        else if Bytes.to_hex(left.nonce) > Bytes.to_hex(right.nonce) do
          1
        else
          0
        end
      else
        order
      end
    end)
  Ok(pending ++ List.take(terminal, 128))
end

fn decode_postage_device_set(input :: Bytes) -> DeviceSet!String do
  case decode_device_set(input) do
    Err(_) -> Err("invalid_credit_postage_material")
    Ok(value)
  end
end
