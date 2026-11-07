from Attachments.Layout import attachment_bucket_capacity
from Mobile.AttachmentMetadata import attachment_input_admitted
from Mobile.AttachmentRecipients import (
  require_attachment_authorization,
  require_padded_attachment_authorization
)
from Credits.Action import decode_credit_action, credit_action_id, encode_credit_action
from Credits.ActionWire import decode_credit_action_receipt
from Credits.Attachment import credit_attachment_action, encode_credit_attachment_grant
from Credits.Policy import attachment_credits
from Mobile.Attachments import attachment_manifest, decode_reference, open_attachment_chunk
from Mobile.AttachmentTransport import attachment_http
from Mobile.Types import MobileAttachmentChunkRequest
from Mobile.Codec import (
  current_time,
  mobile_byte,
  mobile_read_u32,
  mobile_write_u32,
  mobile_write_u64,
  mobile_utf8
)
from Mobile.CreditNonce import issued_credit_intent_nonce, require_fresh_credit_intent_nonce
from Mobile.CreditAttachment import (
  CreditAttachmentPlan,
  prepare_credit_attachment,
  recover_credit_attachment,
  saved_credit_attachment_grant,
  credit_attachment_reference
)
from Mobile.CreditAttachmentParts import (
  seal_credit_attachment_part,
  recover_credit_attachment_part,
  prune_credit_attachment_parts
)
from Mobile.CreditState import (
  pack_credit_parts,
  unpack_credit_parts,
  find_credit_record,
  credit_attachment_cursor
)
from Mobile.CreditWallet import (
  accept_credit_attachment_receipt,
  credit_wallet_balance,
  recover_credit_reservation
)
from Mobile.Platform import native_security_config
from Mobile.NetworkPins import native_network_pins
from Mobile.Profile import load_profile, open_device
from Storage.Credits import CreditWalletIdentity, load_credit_wallet
from Storage.Keys import platform_key
from Transparency.Config import SecurityConfig, encode_security_config
from Transport.Packet import decode_client_profile, ClientProfile

struct NativeAttachmentRequest do
  path :: String
  parts :: List<Bytes>
end

fn parsed_attachment_request(input :: Bytes, count :: Int) -> NativeAttachmentRequest!String do
  if Bytes.length(input) > 70800 do
    return Err("invalid_credit_attachment_request")
  end
  let parts = unpack_credit_parts(input, count, 65536)?
  if List.length(parts) != count
    || Bytes.length(List.head(parts)) < 1
    || Bytes.length(List.head(parts)) > 4096 do
    return Err("invalid_credit_attachment_request")
  end
  Ok(NativeAttachmentRequest {
    path: mobile_utf8(List.head(parts), "invalid_credit_attachment_request")?,
    parts: parts
  })
end

pub struct CreditAttachmentPrepareRequest do
  path :: String
  nonce :: Bytes
  filename :: Plaintext<Bytes>
  mime_type :: Plaintext<Bytes>
  plaintext_size :: Int
  recipient_ticket :: Bytes
end

pub fn parse_credit_attachment_prepare_request(input :: Bytes) -> CreditAttachmentPrepareRequest!String do
  let raw = parsed_attachment_request(input, 6)?
  let filename :: Plaintext<Bytes> = List.get(raw.parts, 2)
  let mime_type :: Plaintext<Bytes> = List.get(raw.parts, 3)
  if Bytes.length(List.get(raw.parts, 1)) != 32
    || !attachment_input_admitted(filename, mime_type, false)
    || Bytes.length(List.get(raw.parts, 4)) != 4 do
    return Err("invalid_credit_attachment_request")
  end
  Ok(CreditAttachmentPrepareRequest {
    path: raw.path,
    nonce: List.get(raw.parts, 1),
    filename: filename,
    mime_type: mime_type,
    plaintext_size: mobile_read_u32(List.get(raw.parts, 4))?,
    recipient_ticket: List.get(raw.parts, 5)
  })
end

# Match the native credit boundary: release-pinned service key, purpose and
# issuer/edge origin. Neither a response nor JS supplies those trust values.
fn attachment_wallet_identity(path :: String,
  config :: SecurityConfig) -> CreditWalletIdentity!String do
  if config.issuer_origin == "-" || config.log_version != 2 do
    return Err("credits_disabled")
  end
  let selector = case Host.push_get_token(Bytes.from_utf8("messenger/credits/v1")) do
    Err(_) -> return Err("credits_disabled")
    Ok(value) -> value
  end
  if Bytes.length(selector) != 2 || Bytes.get(selector, 0)? != 1 || Bytes.get(selector, 1)? > 1 do
    return Err("credits_disabled")
  end
  let profile = decode_client_profile(load_profile(path)?)?
  Ok(CreditWalletIdentity {
    account_id: profile.account_id,
    device_id: profile.device_id,
    service_key: config.service_public_key,
    purpose: Bytes.get(selector, 1)?
  })
end

# Counted MCA vectors: tag,nonce,operation,status,revision,origin,grant path,
# CAP,reference,EAM,OCP,ODL. Status0 requests authorization; status1 can upload;
# status2 is cancelled. Both reserved and completed status retain the exact
# grant route/body: core success may need to repair a lost local object commit.
fn native_attachment_output(value :: CreditAttachmentPlan,
  config :: SecurityConfig) -> Bytes!String do
  pack_credit_parts([
    Bytes.from_hex("014d4341")?,
    value.nonce,
    value.spend.operation_id,
    mobile_byte(value.spend.status)?,
    mobile_write_u64(value.spend.revision)?,
    Bytes.from_utf8(config.issuer_origin),
    Bytes.from_utf8(if value.spend.status != 2 do
      "/v1/attachments/paid-grant"
    else
      ""
    end),
    if value.spend.status != 2 do
      value.submission
    else
      Bytes.empty()
    end,
    value.reference,
    value.encrypted_manifest,
    value.complete,
    value.delete
  ])
end

# prepare: [database,nonce32,filename<=255,mime1..127,plaintext_size:u32BE,recipient_ticket]
pub fn native_credit_attachment_prepare(input :: Bytes) -> Bytes!String do
  let request = parse_credit_attachment_prepare_request(input)?
  require_padded_attachment_authorization(request.path, request.recipient_ticket)?
  let config = native_security_config()?
  let who = attachment_wallet_identity(request.path, config)?
  let wrapping = platform_key()?
  let profile = decode_client_profile(load_profile(request.path)?)?
  let device = open_device(profile, wrapping, request.path)?
  let timestamp = current_time()?
  require_fresh_credit_intent_nonce(request.path, wrapping, who, 1, request.nonce, timestamp)?
  native_attachment_output(prepare_credit_attachment(request.path,
      wrapping,
      who,
      device,
      request.nonce,
      request.filename,
      request.mime_type,
      request.plaintext_size,
      timestamp)?,
    config)
end

# recover: [database,nonce32]
pub fn native_credit_attachment_recover(input :: Bytes) -> Bytes!String do
  let request = parsed_attachment_request(input, 2)?
  let config = native_security_config()?
  let who = attachment_wallet_identity(request.path, config)?
  let wrapping = platform_key()?
  native_attachment_output(recover_credit_attachment(request.path,
      wrapping,
      who,
      List.get(request.parts, 1),
      current_time()?)?,
    config)
end

# receipt: [database,CAR462]; exact saved CAP and pinned core verify before CAS.
pub fn native_credit_attachment_receipt(input :: Bytes) -> Bytes!String do
  let request = parsed_attachment_request(input, 2)?
  let config = native_security_config()?
  let who = attachment_wallet_identity(request.path, config)?
  let wrapping = platform_key()?
  let spend = accept_credit_attachment_receipt(request.path,
    wrapping,
    who,
    List.get(request.parts, 1))?
  native_attachment_output(recover_credit_attachment(request.path,
      wrapping,
      who,
      decode_credit_action(spend.action)?.operation_nonce,
      current_time()?)?,
    config)
end

# part: [database,nonce32,index:u32BE,plaintext1..65536]. Returns the exact
# persisted ACH (41..65576B), for PUT at object part index+1, never a whole file.
pub fn native_credit_attachment_part(input :: Bytes) -> Bytes!String do
  let request = parsed_attachment_request(input, 4)?
  if Bytes.length(List.get(request.parts, 2)) != 4 do
    return Err("invalid_credit_attachment_request")
  end
  let config = native_security_config()?
  let who = attachment_wallet_identity(request.path, config)?
  let wrapping = platform_key()?
  let profile = decode_client_profile(load_profile(request.path)?)?
  let device = open_device(profile, wrapping, request.path)?
  seal_credit_attachment_part(request.path,
    wrapping,
    who,
    device,
    List.get(request.parts, 1),
    mobile_read_u32(List.get(request.parts, 2))?,
    List.get(request.parts, 3),
    current_time()?)
end

# part recovery: [database,nonce32,index:u32BE] -> saved ACH without file access.
pub fn native_credit_attachment_part_recover(input :: Bytes) -> Bytes!String do
  let request = parsed_attachment_request(input, 3)?
  if Bytes.length(List.get(request.parts, 2)) != 4 do
    return Err("invalid_credit_attachment_request")
  end
  let config = native_security_config()?
  let who = attachment_wallet_identity(request.path, config)?
  let wrapping = platform_key()?
  recover_credit_attachment_part(request.path,
    wrapping,
    who,
    List.get(request.parts, 1),
    mobile_read_u32(List.get(request.parts, 2))?)
end

# bounded cleanup: [database,nonce32,cursor:u32BE] -> next cursor:u32BE.
# Cursor begins at0 and advances by128. Core/object expiry+7d must have passed.
pub fn native_credit_attachment_prune(input :: Bytes) -> Bytes!String do
  let request = parsed_attachment_request(input, 3)?
  if Bytes.length(List.get(request.parts, 2)) != 4 do
    return Err("invalid_credit_attachment_request")
  end
  let config = native_security_config()?
  let who = attachment_wallet_identity(request.path, config)?
  let wrapping = platform_key()?
  mobile_write_u32(prune_credit_attachment_parts(request.path,
    wrapping,
    who,
    List.get(request.parts, 1),
    mobile_read_u32(List.get(request.parts, 2))?,
    current_time()?)?)
end

# Price-only preview: no material, token reservation, or wallet write. The nonce
# comes from native entropy and is retained by the host for explicit confirmation.
# APV9: tag,nonce,purpose,size,price,available,delayed,reserved,wallet revision.
pub fn native_credit_attachment_preview(input :: Bytes) -> Bytes!String do
  let request = parsed_attachment_request(input, 2)?
  if Bytes.length(List.get(request.parts, 1)) != 4 do
    return Err("invalid_credit_attachment_request")
  end
  let size = mobile_read_u32(List.get(request.parts, 1))?
  let price = attachment_credits(size)?
  let who = attachment_wallet_identity(request.path, native_security_config()?)?
  let wrapping = platform_key()?
  let now = U64.divide(current_time()?, U64.parse("1000")?)?
  let balance = credit_wallet_balance(request.path, wrapping, who, now)?
  let wallet = load_credit_wallet(request.path, wrapping, who)?.wallet
  pack_credit_parts([
    Bytes.from_hex("01415056")?,
    issued_credit_intent_nonce(current_time()?)?,
    mobile_byte(who.purpose)?,
    mobile_write_u32(size)?,
    mobile_write_u32(price)?,
    mobile_write_u32(balance.available)?,
    mobile_write_u32(balance.delayed)?,
    mobile_write_u32(balance.reserved)?,
    mobile_write_u64(wallet.revision)?
  ])
end

struct AttachmentInventoryRow do
  wire :: Bytes
  status :: Int
  expires :: U64
  nonce :: Bytes
end

# AIV: tag,revision,then at most128 bounded metadata rows. Listing never invokes
# recover_credit_attachment, whose plan may reserve tokens for material-only
# intents. Status3 explicitly identifies that interrupted pre-reservation state.
pub fn native_credit_attachments(input :: Bytes) -> Plaintext<Bytes>!String do
  let request = parsed_attachment_request(input, 1)?
  let who = attachment_wallet_identity(request.path, native_security_config()?)?
  let wrapping = platform_key()?
  let profile = decode_client_profile(load_profile(request.path)?)?
  let device = open_device(profile, wrapping, request.path)?
  let wallet = load_credit_wallet(request.path, wrapping, who)?.wallet
  let records = List.filter(wallet.records, fn(record) do record.kind == 6 end)
  let rows = for record in records do
    let grant = saved_credit_attachment_grant(request.path, wrapping, who, record.id)?
    let reference = credit_attachment_reference(request.path, wrapping, who, record.id)?
    let manifest = attachment_manifest(device, reference)?
    if (grant.layout_version == 1
      && (manifest.version != 2 || manifest.plaintext_size != grant.size_bytes))
      || (grant.layout_version == 2
        && (manifest.version != 4
          || manifest.plaintext_size <= 16777216
          || attachment_bucket_capacity(manifest.plaintext_size)? != grant.size_bytes)) do
      return Err("invalid_credit_attachment_material")
    end
    let action = credit_attachment_action(grant)?
    let id = credit_action_id(action)?
    let status = case find_credit_record(wallet, 4, id) do
      None -> 3
      Some(_) -> do
        let spend = recover_credit_reservation(request.path, wrapping, who, id)?
        if !Bytes.secure_equals(spend.action, encode_credit_action(action)?)
          || !Bytes.secure_equals(spend.request_body, encode_credit_attachment_grant(grant)?) do
          return Err("invalid_credit_attachment_material")
        end
        spend.status
      end
    end
    let wire = pack_credit_parts([
      record.id,
      id,
      mobile_byte(status)?,
      manifest.filename,
      manifest.mime_type,
      mobile_write_u32(manifest.plaintext_size)?,
      mobile_write_u32(attachment_credits(grant.size_bytes)?)?,
      mobile_write_u64(grant.action_expires_at)?,
      mobile_write_u64(grant.expires_at_ms)?,
      mobile_write_u32(credit_attachment_cursor(record.metadata)?)?,
      mobile_write_u32(manifest.chunk_count)?
    ])?
    AttachmentInventoryRow {
      wire: wire,
      status: status,
      expires: grant.action_expires_at,
      nonce: record.id
    }
  end
  let pending = List.filter(rows, fn(row) -> row.status == 0 || row.status == 3 end)
  if List.length(pending) > 128 do
    return Err("credit_attachment_capacity")
  end
  let terminal = List.sort(List.filter(rows, fn(row) -> row.status == 1 || row.status == 2 end),
    fn(left, right) do
      let order = U64.compare(right.expires, left.expires)
      if order != 0 do
        order
      else if Bytes.to_hex(left.nonce) < Bytes.to_hex(right.nonce) do
        -1
      else if Bytes.to_hex(left.nonce) > Bytes.to_hex(right.nonce) do
        1
      else
        0
      end
    end)
  let selected = pending ++ List.take(terminal, 128 - List.length(pending))
  pack_credit_parts([Bytes.from_hex("01414956")?, mobile_write_u64(wallet.revision)?]
    ++ List.map(selected, fn(row) -> row.wire end))
end

# ADP11 authenticates manifest version and returns the release-pinned paid edge.
# Receiving an existing object is independent of the local credit spending flag.
# Legacy objects keep their configured legacy transport (empty origin/prefix).
pub fn native_attachment_download_plan(input :: Bytes) -> Plaintext<Bytes>!String do
  let request = parsed_attachment_request(input, 2)?
  let reference = List.get(request.parts, 1)
  let wrapping = platform_key()?
  let profile = decode_client_profile(load_profile(request.path)?)?
  let device = open_device(profile, wrapping, request.path)?
  let manifest = attachment_manifest(device, reference)?
  let value = decode_reference(reference)?
  let origin = if manifest.version == 2
    || (manifest.version == 4 && manifest.plaintext_size > 16777216) do
    let config = native_security_config()?
    if config.issuer_origin == "-" do
      return Err("attachment_transport_unavailable")
    end
    config.issuer_origin
  else
    ""
  end
  pack_credit_parts([
    Bytes.from_hex("01414450")?,
    mobile_byte(manifest.version)?,
    Bytes.from_utf8(origin),
    Bytes.from_utf8(if manifest.version == 2
      || (manifest.version == 4 && manifest.plaintext_size > 16777216) do
      "/v2/objects/#{Bytes.to_hex(value.object_id)}/parts/"
    else
      ""
    end),
    reference,
    value.object_id,
    value.download_capability,
    manifest.filename,
    manifest.mime_type,
    mobile_write_u32(manifest.plaintext_size)?,
    mobile_write_u32(manifest.chunk_count)?
  ])
end

fn network_attachment_request(input :: Bytes, count :: Int) -> NativeAttachmentRequest!String do
  let request = parsed_attachment_request(input, count)?
  let nonce = List.get(request.parts, 1)
  if Bytes.length(nonce) != 32
    || Bytes.to_hex(nonce) == String.repeat("00", 32)
    || (count == 3 && Bytes.length(List.get(request.parts, 2)) != 4) do
    return Err("invalid_credit_attachment_request")
  end
  Ok(request)
end

fn attachment_network_fence(path :: String,
  config :: SecurityConfig,
  before :: ClientProfile) -> Unit!String do
  let current = decode_client_profile(load_profile(path)?)?
  if !Bytes.secure_equals(encode_security_config(config)?,
    encode_security_config(native_security_config()?)?)
    || !Bytes.secure_equals(before.account_id, current.account_id)
    || !Bytes.secure_equals(before.device_id, current.device_id) do
    return Err("attachment_identity_changed")
  end
  Ok(nil)
end

# All parts must already be durable before the grant can consume any credits.
# Completed grants are replayed too: a lost object-store commit needs repair.
pub fn native_credit_attachment_grant(input :: Bytes) -> Bytes!String do
  let request = parsed_attachment_request(input, 3)?
  require_attachment_authorization(request.path, List.get(request.parts, 2))?
  let config = native_security_config()?
  let who = attachment_wallet_identity(request.path, config)?
  let profile = decode_client_profile(load_profile(request.path)?)?
  let wrapping = platform_key()?
  let nonce = List.get(request.parts, 1)
  if Bytes.length(nonce) != 32 || Bytes.to_hex(nonce) == String.repeat("00", 32) do
    return Err("invalid_credit_attachment_request")
  end
  let grant = saved_credit_attachment_grant(request.path, wrapping, who, nonce)?
  if grant.layout_version == 2 do
    require_padded_attachment_authorization(request.path, List.get(request.parts, 2))?
  end
  let operation = credit_action_id(credit_attachment_action(grant)?)?
  let before = recover_credit_reservation(request.path, wrapping, who, operation)?
  if before.status == 2 do
    return Err("credit_reservation_cancelled")
  end
  let count = (grant.size_bytes + 65535) / 65536
  for index in 0..count do
    let saved = recover_credit_attachment_part(request.path, wrapping, who, nonce, index)?
    let length = if grant.layout_version == 1 && index + 1 == count do
      grant.size_bytes - index * 65536
    else
      65536
    end
    if Bytes.length(saved) != length + 40 do
      return Err("invalid_credit_attachment_part")
    end
    # Old journals remain readable and a verified completed grant can repair
    # its exact upload. An unconsumed/uncertain grant must recover its receipt
    # first or be cancelled; it may not newly spend credits on legacy chunks.
    if (grant.layout_version == 1 && before.status == 0 && Bytes.get(saved, 0) != Ok(3))
      || (grant.layout_version == 2 && Bytes.get(saved, 0) != Ok(4)) do
      return Err("attachment_legacy_upload")
    end
  end
  let plan = recover_credit_attachment(request.path, wrapping, who, nonce, current_time()?)?
  attachment_network_fence(request.path, config, profile)?
  require_attachment_authorization(request.path, List.get(request.parts, 2))?
  if grant.layout_version == 2 do
    require_padded_attachment_authorization(request.path, List.get(request.parts, 2))?
  end
  let result = attachment_http(config, 0, Bytes.empty(), Bytes.empty(), 0, plan.submission)?
  attachment_network_fence(request.path, config, profile)?
  let current_who = attachment_wallet_identity(request.path, config)?
  if current_who.purpose != who.purpose do
    return Err("attachment_identity_changed")
  end
  let received = decode_credit_action_receipt(result.body)?
  if !Bytes.secure_equals(received.operation_id, plan.spend.operation_id) do
    return Err("invalid_credit_attachment_receipt")
  end
  let accepted = accept_credit_attachment_receipt(request.path, wrapping, who, result.body)?
  if !Bytes.secure_equals(accepted.operation_id, plan.spend.operation_id) || accepted.status != 1 do
    return Err("invalid_credit_attachment_receipt")
  end
  native_attachment_output(recover_credit_attachment(request.path,
      wrapping,
      who,
      nonce,
      current_time()?)?,
    config)
end

fn authorized_attachment_plan(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  nonce :: Bytes) -> CreditAttachmentPlan!String do
  let grant = saved_credit_attachment_grant(path, wrapping, who, nonce)?
  let operation = credit_action_id(credit_attachment_action(grant)?)?
  if recover_credit_reservation(path, wrapping, who, operation)?.status != 1 do
    return Err("credit_attachment_not_authorized")
  end
  recover_credit_attachment(path, wrapping, who, nonce, current_time()?)
end

# One part per call bounds memory and network time. Index0 is the exact saved
# manifest; index1..8192 maps to saved ciphertext0..8191.
pub fn native_credit_attachment_upload(input :: Bytes) -> Bytes!String do
  let request = network_attachment_request(input, 3)?
  let config = native_security_config()?
  let who = attachment_wallet_identity(request.path, config)?
  let profile = decode_client_profile(load_profile(request.path)?)?
  let wrapping = platform_key()?
  let nonce = List.get(request.parts, 1)
  let index = mobile_read_u32(List.get(request.parts, 2))?
  let plan = authorized_attachment_plan(request.path, wrapping, who, nonce)?
  if plan.spend.status != 1 do
    return Err("credit_attachment_not_authorized")
  end
  let grant = saved_credit_attachment_grant(request.path, wrapping, who, nonce)?
  let count = (grant.size_bytes + 65535) / 65536
  if index < 0 || index > count do
    return Err("invalid_attachment_chunk_index")
  end
  let body = if index == 0 do
    plan.encrypted_manifest
  else
    recover_credit_attachment_part(request.path, wrapping, who, nonce, index - 1)?
  end
  attachment_http(config, 1, grant.object_id, grant.upload_capability, index, body)?
  attachment_network_fence(request.path, config, profile)?
  Ok(Bytes.empty())
end

fn native_attachment_control(input :: Bytes, remove :: Bool) -> Bytes!String do
  let request = network_attachment_request(input, 2)?
  let config = native_security_config()?
  let who = attachment_wallet_identity(request.path, config)?
  let profile = decode_client_profile(load_profile(request.path)?)?
  let wrapping = platform_key()?
  let plan = authorized_attachment_plan(request.path, wrapping, who, List.get(request.parts, 1))?
  if plan.spend.status != 1 do
    return Err("credit_attachment_not_authorized")
  end
  let result = attachment_http(config,
    if remove do
      3
    else
      2
    end,
    Bytes.empty(),
    Bytes.empty(),
    0,
    if remove do
      plan.delete
    else
      plan.complete
    end)?
  attachment_network_fence(request.path, config, profile)?
  mobile_byte(if result.status == 202 do
    0
  else
    1
  end)
end

pub fn native_credit_attachment_complete(input :: Bytes) -> Bytes!String do
  native_attachment_control(input, false)
end

pub fn native_credit_attachment_delete(input :: Bytes) -> Bytes!String do
  native_attachment_control(input, true)
end

# Receiving never depends on purchasing being enabled. Authenticate the local
# reference before choosing the native origin, object, capability, length and key.
# Legacy objects use the object-store pin; v2 paid objects use the issuer pin.
pub fn native_attachment_fetch_chunk(input :: Bytes) -> Bytes!String do
  let request = parsed_attachment_request(input, 3)?
  if Bytes.length(List.get(request.parts, 1)) < 1
    || Bytes.length(List.get(request.parts, 1)) > 1024
    || Bytes.length(List.get(request.parts, 2)) != 4 do
    return Err("invalid_paid_attachment")
  end
  let profile_wire = load_profile(request.path)?
  let profile = decode_client_profile(profile_wire)?
  let wrapping = platform_key()?
  let device = open_device(profile, wrapping, request.path)?
  let reference = List.get(request.parts, 1)
  let manifest = attachment_manifest(device, reference)?
  let index = mobile_read_u32(List.get(request.parts, 2))?
  if (manifest.version != 1 && manifest.version != 2 && manifest.version != 4)
    || index < 0
    || index >= manifest.chunk_count do
    return Err("invalid_attachment_chunk_index")
  end
  let value = decode_reference(reference)?
  let ciphertext = if manifest.version == 2
    || (manifest.version == 4 && manifest.plaintext_size > 16777216) do
    let config = native_security_config()?
    let response = attachment_http(config,
      4,
      value.object_id,
      value.download_capability,
      index + 1,
      Bytes.empty())?
    attachment_network_fence(request.path, config, profile)?
    response.body
  else
    let pins = native_network_pins()?
    let route = "/v1/objects/#{Bytes.to_hex(value.object_id)}/parts/#{index + 1}"
    let response = case Http.build(:get, pins.object_origin <> route)
      |> Http.header("Content-Type", "application/octet-stream")
      |> Http.header("Cache-Control", "no-store")
      |> Http.header("X-Object-Capability", Bytes.to_hex(value.download_capability))
      |> Http.timeout(12000)
      |> Http.max_redirects(0)
      |> Http.max_response_bytes(65576)
      |> Http.send() do
      Err(_) -> return Err("attachment_transport_unavailable")
      Ok(result) -> result
    end
    if pins.object_origin != native_network_pins()?.object_origin do
      return Err("attachment_identity_changed")
    end
    if response.status != 200 do
      return Err("attachment_http_" <> Int.to_string(response.status))
    end
    response.body_bytes
  end
  if !Bytes.secure_equals(profile_wire, load_profile(request.path)?) do
    return Err("attachment_identity_changed")
  end
  open_attachment_chunk(MobileAttachmentChunkRequest {
    database_path: request.path,
    reference: reference,
    index: index,
    payload: ciphertext
  })
end
