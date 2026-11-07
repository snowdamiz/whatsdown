from Storage.CreditMaintenance import (
  CreditMaintenanceSnapshot,
  load_credit_maintenance,
  credit_maintenance_write
)
from Credits.Postage import (
  decode_credit_postage_request,
  credit_postage_action,
  credit_postage_request_for_devices,
  encode_credit_postage_request,
  verify_credit_postage_receipt
)
from Credits.PostagePolicy import postage_policy_from_device_set
from Mobile.DeviceSet import verified_device_set
from Mobile.Transparency import require_transparency_device_set
from Protocol.DirectoryWire import decode_device_set
from Credits.Action import (
  CreditAction,
  encode_credit_action,
  decode_credit_action,
  credit_action_id,
  credit_action_price,
  validate_credit_action
)
from Credits.ActionWire import (
  CreditActionSubmission,
  decode_credit_action_receipt,
  verify_credit_action_receipt
)
from Credits.Cancellation import decode_credit_cancellation, verify_credit_cancellation
from Credits.Attachment import (
  decode_credit_attachment_grant,
  credit_attachment_action,
  verify_credit_attachment_receipt
)
from Credits.Signup import decode_credit_signup_request, credit_signup_action
from Credits.SignupPolicy import CreditSignupPolicy, credit_signup_policy_price
from Mobile.CreditSignup import verify_signup_receipt
from Credits.Retention import (
  decode_credit_retention_request,
  credit_retention_action,
  verify_credit_retention_request
)
from Mobile.CreditRetention import verified_retention_until
from Credits.Issuer import (
  CreditIssuerKey,
  decode_issuer_key,
  encode_issuer_key,
  issuer_key_id,
  retain_issuer_key
)
from Credits.Policy import (
  issuer_epoch,
  issuer_epoch_accepted,
  credit_spend_ready,
  spent_retention_until
)
from Credits.Storage import seal_credit_token, open_credit_token
from Credits.Token import verify_credit_token
from Credits.Wire import (
  CreditToken,
  CreditFrame,
  credit_nullifier,
  encode_credit_frame,
  decode_credit_frame,
  check_credit_frame
)
from Mobile.CreditState import (
  CreditRecord,
  CreditWallet,
  credit_record_id,
  find_credit_record,
  put_credit_record,
  pack_credit_parts,
  unpack_credit_parts
)
from Mobile.Codec import (
  mobile_join,
  mobile_byte,
  mobile_write_u16,
  mobile_write_u64,
  mobile_read_u32,
  mobile_read_u64,
  random_bytes
)
from Storage.Credits import (
  CreditWalletIdentity,
  CreditWalletSnapshot,
  CreditCacheWrite,
  credit_context,
  load_credit_wallet,
  commit_credit_wallet,
  commit_credit_wallet_with_cache,
  seal_credit_payload,
  open_credit_payload
)

pub struct CreditBalance do
  available :: Int
  delayed :: Int
  reserved :: Int
  expired :: Int
  pending_purchases :: Int
end

pub struct CreditSpendPlan do
  operation_id :: Bytes
  action :: Bytes
  request_body :: Bytes
  frame :: Bytes
  credits :: Int
  # 0 remains reserved, 1 is completed, 2 is authenticated cancellation.
  status :: Int
  revision :: U64
end

struct TokenState do
  epoch :: U64
  purchased_at :: U64
  key_id :: Bytes
  reservation_id :: Bytes
end

struct ReservationState do
  action :: Bytes
  created_at :: U64
  retain_until :: U64
  status :: Int
  token_ids :: List<Bytes>
end

struct RankedCredit do
  record :: CreditRecord
  rank :: String
end

fn zero_id() -> Bytes!String do
  Bytes.from_hex(String.repeat("00", 32))
end

pub fn credit_issuer_keys(wallet :: CreditWallet, purpose :: Int) -> List<CreditIssuerKey>!String do
  let records = List.filter(wallet.records, fn(record) do record.kind == 1 end)
  if List.length(records) > 2 do
    return Err("invalid_credit_issuer_cache")
  end
  let keys = for record in records do
    let value = decode_issuer_key(record.payload)?
    if value.purpose != purpose
      || Bytes.length(record.metadata) != 0
      || !Bytes.secure_equals(record.id, issuer_key_id(value)?) do
      return Err("invalid_credit_issuer_cache")
    end
    value
  end
  for index in 0..List.length(keys) do
    for previous in 0..index do
      if List.get(keys, index).epoch == List.get(keys, previous).epoch do
        return Err("invalid_credit_issuer_cache")
      end
    end
  end
  Ok(keys)
end

# Internal custody helper. Only the witnessed-admission boundary may call this
# with a network key; it is deliberately not a native/raw-SPKI export.
pub fn add_credit_issuer(wallet :: CreditWallet,
  key :: CreditIssuerKey,
  now :: U64,
  purpose :: Int) -> CreditWallet!String do
  let retained = retain_issuer_key(credit_issuer_keys(wallet, purpose)?, key, now, purpose)?
  let records = for value in retained do
    CreditRecord {
      kind: 1,
      id: issuer_key_id(value)?,
      metadata: Bytes.empty(),
      payload: encode_issuer_key(value)?
    }
  end
  Ok(CreditWallet {
    revision: wallet.revision,
    records: records ++ List.filter(wallet.records, fn(record) do record.kind != 1 end)
  })
end

fn encode_token_state(value :: TokenState) -> Bytes!String do
  mobile_join([
      mobile_write_u64(value.epoch)?,
      mobile_write_u64(value.purchased_at)?,
      value.key_id,
      value.reservation_id
    ],
    0,
    Bytes.empty())
end

fn token_state(record :: CreditRecord) -> TokenState!String do
  if record.kind != 3
    || Bytes.length(record.metadata) != 80
    || Bytes.length(record.payload) < 1
    || Bytes.length(record.payload) > 2048 do
    return Err("invalid_stored_credit")
  end
  let value = TokenState {
    epoch: mobile_read_u64(Bytes.slice(record.metadata, 0, 8)?)?,
    purchased_at: mobile_read_u64(Bytes.slice(record.metadata, 8, 8)?)?,
    key_id: Bytes.slice(record.metadata, 16, 32)?,
    reservation_id: Bytes.slice(record.metadata, 48, 32)?
  }
  if !credit_record_id(record.id) || !credit_record_id(value.key_id) do
    return Err("invalid_stored_credit")
  end
  Ok(value)
end

pub fn completed_credit_record(token :: CreditToken,
  issuer :: CreditIssuerKey,
  purchased_at :: U64,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> CreditRecord!String do
  if !verify_credit_token(issuer, token, who.service_key, purchased_at, who.purpose)? do
    return Err("invalid_credit_token")
  end
  let id = credit_nullifier(token.input)?
  let metadata = encode_token_state(TokenState {
    epoch: issuer.epoch,
    purchased_at: purchased_at,
    key_id: issuer_key_id(issuer)?,
    reservation_id: zero_id()?
  })?
  Ok(CreditRecord {
    kind: 3,
    id: id,
    metadata: metadata,
    payload: seal_credit_token(token, wrapping, credit_context(who, "token/#{Bytes.to_hex(id)}")?)?
  })
end

fn open_token(record :: CreditRecord,
  keys :: List<CreditIssuerKey>,
  now :: U64,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> CreditToken!String do
  let stored = token_state(record)?
  let selected = List.find(keys,
    fn(key) do Bytes.secure_equals(Crypto.sha256(key.spki), stored.key_id) end)
  let issuer = case selected do
    None -> return Err("unknown_credit_issuer")
    Some(key) -> key
  end
  let token = open_credit_token(record.payload,
    wrapping,
    credit_context(who, "token/#{Bytes.to_hex(record.id)}")?)?
  if issuer.epoch != stored.epoch
    || !Bytes.secure_equals(credit_nullifier(token.input)?, record.id)
    || !verify_credit_token(issuer, token, who.service_key, now, who.purpose)? do
    return Err("invalid_stored_credit")
  end
  Ok(token)
end

fn spent_credit_nullifiers(wallet :: CreditWallet) -> Set<String>!String do
  let lists = for record in List.filter(wallet.records, fn(value) -> value.kind == 4 end) do
    let saved = reservation_state(record)?
    if saved.status == 1 do
      List.map(saved.token_ids, fn(id) -> Bytes.to_hex(id) end)
    else
      []
    end
  end
  Ok(Set.from_list(List.flatten(lists)))
end

pub fn credit_nullifier_spent(wallet :: CreditWallet, id :: Bytes) -> Bool!String do
  Ok(Set.contains(spent_credit_nullifiers(wallet)?, Bytes.to_hex(id)))
end

pub fn credit_wallet_balance(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  now :: U64) -> CreditBalance!String do
  let wallet = load_credit_wallet(path, wrapping, who)?.wallet
  let keys = credit_issuer_keys(wallet, who.purpose)?
  let spent = spent_credit_nullifiers(wallet)?
  let pending = for record in List.filter(wallet.records, fn(item) do item.kind == 2 end) do
    if Bytes.length(record.metadata) != 17 || Bytes.get(record.metadata, 0)? > 4 do
      return Err("invalid_credit_purchase")
    end
    Bytes.get(record.metadata, 0)? < 3
  end
  let kinds = for record in List.filter(wallet.records, fn(item) do item.kind == 3 end) do
    let value = token_state(record)?
    if Set.contains(spent, Bytes.to_hex(record.id)) do
      return Err("spent_credit_token_reintroduced")
    end
    if !Bytes.secure_equals(value.reservation_id, zero_id()?) do
      2
    else if !issuer_epoch_accepted(value.epoch, now)? do
      3
    else
      open_token(record, keys, now, wrapping, who)?
      if credit_spend_ready(value.purchased_at, now)? do
        0
      else
        1
      end
    end
  end
  Ok(CreditBalance {
    available: List.length(List.filter(kinds, fn(kind) do kind == 0 end)),
    delayed: List.length(List.filter(kinds, fn(kind) do kind == 1 end)),
    reserved: List.length(List.filter(kinds, fn(kind) do kind == 2 end)),
    expired: List.length(List.filter(kinds, fn(kind) do kind == 3 end)),
    pending_purchases: List.length(List.filter(pending, fn(value) do value end))
  })
end

fn reservation_state(record :: CreditRecord) -> ReservationState!String do
  if record.kind != 4 || Bytes.length(record.metadata) < 160 do
    return Err("invalid_credit_reservation")
  end
  let action = Bytes.slice(record.metadata, 0, 117)?
  let descriptor = decode_credit_action(action)?
  let count = case Bytes.read_u16_be(record.metadata, 126) do
    Err(_) -> return Err("invalid_credit_reservation")
    Ok(value) -> value
  end
  let status = Bytes.get(record.metadata, 125)?
  if count < 1
    || count > 64
    || (Bytes.length(record.metadata) != 128 + count * 32
      && Bytes.length(record.metadata) != 136 + count * 32)
    || (status != 0 && status != 1 && status != 2)
    || !Bytes.secure_equals(record.id, credit_action_id(descriptor)?) do
    return Err("invalid_credit_reservation")
  end
  let ids = for index in 0..count do
    Bytes.slice(record.metadata, 128 + index * 32, 32)?
  end
  for index in 0..count do
    if !credit_record_id(List.get(ids, index)) do
      return Err("invalid_credit_reservation")
    end
    for prior in 0..index do
      if Bytes.secure_equals(List.get(ids, prior), List.get(ids, index)) do
        return Err("invalid_credit_reservation")
      end
    end
  end
  Ok(ReservationState {
    action: action,
    created_at: mobile_read_u64(Bytes.slice(record.metadata, 117, 8)?)?,
    retain_until: if Bytes.length(record.metadata) == 136 + count * 32 do
      mobile_read_u64(Bytes.slice(record.metadata, 128 + count * 32, 8)?)?
    else
      spent_retention_until(issuer_epoch(mobile_read_u64(Bytes.slice(record.metadata, 117, 8)?)?)?)?
    end,
    status: status,
    token_ids: ids
  })
end

pub fn credit_operation_nonce_seen(wallet :: CreditWallet,
  kind :: Int,
  nonce :: Bytes) -> Bool!String do
  let matches = for record in List.filter(wallet.records, fn(value) -> value.kind == 4 end) do
    let action = decode_credit_action(reservation_state(record)?.action)?
    action.kind == kind && Bytes.secure_equals(action.operation_nonce, nonce)
  end
  Ok(List.any(matches, fn(value) -> value end))
end

pub fn credit_reservation_status(wallet :: CreditWallet,
  operation_id :: Bytes) -> Option<Int>!String do
  case find_credit_record(wallet, 4, operation_id) do
    None -> Ok(None)
    Some(record) -> Ok(Some(reservation_state(record)?.status))
  end
end

fn encode_reservation(value :: ReservationState) -> Bytes!String do
  mobile_join([
      value.action,
      mobile_write_u64(value.created_at)?,
      mobile_byte(value.status)?,
      mobile_write_u16(List.length(value.token_ids))?
    ]
      ++ value.token_ids
      ++ [mobile_write_u64(value.retain_until)?],
    0,
    Bytes.empty())
end

fn reservation_plan(wallet :: CreditWallet,
  record :: CreditRecord,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> CreditSpendPlan!String do
  let saved = reservation_state(record)?
  let parts = unpack_credit_parts(open_credit_payload(record.payload,
      wrapping,
      who,
      "reservation/#{Bytes.to_hex(record.id)}")?,
    3,
    65536)?
  if List.length(parts) < 2
    || List.length(parts) > 3
    || (List.length(parts) == 3 && saved.status == 0)
    || (saved.status == 2 && List.length(parts) != 3) do
    return Err("invalid_credit_reservation")
  end
  let body = List.get(parts, 0)
  let frame_bytes = List.get(parts, 1)
  let frame = decode_credit_frame(frame_bytes)?
  let ids = check_credit_frame(frame, body, List.length(saved.token_ids))?
  if !Bytes.secure_equals(decode_credit_action(saved.action)?.request_sha256,
    Crypto.sha256(body)) do
    return Err("invalid_credit_reservation")
  end
  for index in 0..List.length(ids) do
    if !Bytes.secure_equals(List.get(ids, index), List.get(saved.token_ids, index)) do
      return Err("invalid_credit_reservation")
    end
    if saved.status == 0 do
      let token = case find_credit_record(wallet, 3, List.get(ids, index)) do
        None -> return Err("invalid_credit_reservation")
        Some(value) -> value
      end
      if !Bytes.secure_equals(token_state(token)?.reservation_id, record.id) do
        return Err("invalid_credit_reservation")
      end
    end
  end
  if saved.status == 2 do
    if !verify_credit_cancellation(decode_credit_cancellation(List.get(parts, 2))?,
      SigningPublicKey { bytes: who.service_key },
      CreditActionSubmission {
        action: decode_credit_action(saved.action)?,
        request_body: body,
        frame: frame
      })? do
      return Err("invalid_credit_cancellation")
    end
  end
  Ok(CreditSpendPlan {
    operation_id: record.id,
    action: saved.action,
    request_body: body,
    frame: frame_bytes,
    credits: List.length(saved.token_ids),
    status: saved.status,
    revision: wallet.revision
  })
end

# Each completion adapter verifies its exact result and pinned core signature
# before entering the shared immutable receipt/CAS transition.
pub fn accept_credit_retention_receipt(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  mailbox_hash :: Bytes,
  response :: Bytes) -> CreditSpendPlan!String do
  let receipt = decode_credit_action_receipt(response)?
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 4, receipt.operation_id) do
    None -> return Err("credit_reservation_not_found")
    Some(value) -> value
  end
  let plan = reservation_plan(before.wallet, record, wrapping, who)?
  let submission = CreditActionSubmission {
    action: decode_credit_action(plan.action)?,
    request_body: plan.request_body,
    frame: decode_credit_frame(plan.frame)?
  }
  verified_retention_until(submission,
    SigningPublicKey { bytes: who.service_key },
    mailbox_hash,
    response)?
  commit_verified_credit_receipt(path, wrapping, who, before, record, plan, response)
end

pub fn accept_credit_signup_receipt(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  response :: Bytes) -> CreditSpendPlan!String do
  let receipt = decode_credit_action_receipt(response)?
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 4, receipt.operation_id) do
    None -> return Err("credit_reservation_not_found")
    Some(value) -> value
  end
  let plan = reservation_plan(before.wallet, record, wrapping, who)?
  verify_signup_receipt(CreditActionSubmission {
      action: decode_credit_action(plan.action)?,
      request_body: plan.request_body,
      frame: decode_credit_frame(plan.frame)?
    },
    SigningPublicKey { bytes: who.service_key },
    who.account_id,
    response)?
  commit_verified_credit_receipt(path, wrapping, who, before, record, plan, response)
end

pub fn accept_credit_attachment_receipt(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  response :: Bytes) -> CreditSpendPlan!String do
  let receipt = decode_credit_action_receipt(response)?
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 4, receipt.operation_id) do
    None -> return Err("credit_reservation_not_found")
    Some(value) -> value
  end
  let plan = reservation_plan(before.wallet, record, wrapping, who)?
  verify_credit_attachment_receipt(CreditActionSubmission {
      action: decode_credit_action(plan.action)?,
      request_body: plan.request_body,
      frame: decode_credit_frame(plan.frame)?
    },
    SigningPublicKey { bytes: who.service_key },
    response)?
  commit_verified_credit_receipt(path, wrapping, who, before, record, plan, response)
end

fn commit_verified_credit_receipt(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  before :: CreditWalletSnapshot,
  record :: CreditRecord,
  plan :: CreditSpendPlan,
  response :: Bytes) -> CreditSpendPlan!String do
  commit_verified_credit_receipt_with_cache(path, wrapping, who, before, record, plan, response, [])
end

fn commit_verified_credit_receipt_with_cache(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  before :: CreditWalletSnapshot,
  record :: CreditRecord,
  plan :: CreditSpendPlan,
  response :: Bytes,
  cache :: List<CreditCacheWrite>) -> CreditSpendPlan!String do
  let parts = unpack_credit_parts(open_credit_payload(record.payload,
      wrapping,
      who,
      "reservation/#{Bytes.to_hex(record.id)}")?,
    3,
    65536)?
  if plan.status == 2 do
    return Err("credit_reservation_cancelled")
  end
  if plan.status == 1 do
    if List.length(parts) != 3 || !Bytes.secure_equals(List.get(parts, 2), response) do
      return Err("credit_receipt_changed")
    end
    if List.length(cache) > 0 do
      return commit_guarded_signup_view(path, wrapping, who, before, plan, cache)
    end
    return Ok(plan)
  end
  let saved = reservation_state(record)?
  let completed = CreditRecord {
    kind: 4,
    id: record.id,
    metadata: encode_reservation(ReservationState {
      action: saved.action,
      created_at: saved.created_at,
      retain_until: saved.retain_until,
      status: 1,
      token_ids: saved.token_ids
    })?,
    payload: seal_credit_payload(pack_credit_parts([plan.request_body, plan.frame, response])?,
      wrapping,
      who,
      "reservation/#{Bytes.to_hex(record.id)}")?
  }
  let remaining = List.filter(before.wallet.records,
    fn(value) do value.kind != 3
      || !List.any(saved.token_ids, fn(id) do Bytes.secure_equals(id, value.id) end) end)
  let wallet = put_credit_record(CreditWallet {
      revision: U64.add(before.wallet.revision, U64.parse("1")?)?,
      records: remaining
    },
    completed)
  commit_credit_wallet_with_cache(path, wrapping, who, before, wallet, cache)?
  reservation_plan(wallet, completed, wrapping, who)
end

# An unresolved retention submission may already have applied remotely. Keep
# keys conservatively until its latest possible requested horizon plus the
# existing four-day delivery safety margin; a signed receipt narrows that bound.
pub fn credit_retention_deadline(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  mailbox_hash :: Bytes,
  device_key :: SigningPublicKey) -> U64!String do
  let wallet = load_credit_wallet(path, wrapping, who)?.wallet
  let deadlines = for record in List.filter(wallet.records, fn(value) do value.kind == 4 end) do
    let saved = reservation_state(record)?
    let action = decode_credit_action(saved.action)?
    if saved.status == 2 do
      reservation_plan(wallet, record, wrapping, who)?
      U64.parse("0")?
    else if action.kind != 2 || !Bytes.secure_equals(action.target, mailbox_hash) do
      U64.parse("0")?
    else
      let plan = reservation_plan(wallet, record, wrapping, who)?
      let request = decode_credit_retention_request(plan.request_body)?
      if !Bytes.secure_equals(encode_credit_action(credit_retention_action(request)?)?, plan.action)
        || !verify_credit_retention_request(request, device_key, request.issued_at_ms)? do
        return Err("invalid_stored_retention")
      end
      let parts = unpack_credit_parts(open_credit_payload(record.payload,
          wrapping,
          who,
          "reservation/#{Bytes.to_hex(record.id)}")?,
        3,
        65536)?
      let until = if saved.status == 1 do
        if List.length(parts) != 3 do
          return Err("unverified_stored_retention")
        end
        verified_retention_until(CreditActionSubmission {
            action: action,
            request_body: plan.request_body,
            frame: decode_credit_frame(plan.frame)?
          },
          SigningPublicKey { bytes: who.service_key },
          mailbox_hash,
          List.get(parts, 2))?
      else
        U64.add(U64.multiply(action.expires_at, U64.parse("1000")?)?,
          U64.multiply(U64.parse(Int.to_string(request.days))?, U64.parse("86400000")?)?)?
      end
      U64.add(until, U64.parse("345600000")?)?
    end
  end
  Ok(List.reduce(deadlines,
    U64.parse("0")?,
    fn(maximum, value) do
      if U64.compare(value, maximum) > 0 do
        value
      else
        maximum
      end
    end))
end

pub fn recover_credit_reservation(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  operation_id :: Bytes) -> CreditSpendPlan!String do
  if !credit_record_id(operation_id) do
    return Err("invalid_credit_operation")
  end
  let wallet = load_credit_wallet(path, wrapping, who)?.wallet
  let record = case find_credit_record(wallet, 4, operation_id) do
    None -> return Err("credit_reservation_not_found")
    Some(value) -> value
  end
  reservation_plan(wallet, record, wrapping, who)
end

pub fn pending_credit_retention(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  mailbox_hash :: Bytes) -> Option<CreditSpendPlan>!String do
  let wallet = load_credit_wallet(path, wrapping, who)?.wallet
  let matches = List.flat_map(List.filter(wallet.records, fn(value) do value.kind == 4 end),
    fn(record) do
      case reservation_state(record) do
        Err(_) -> [record]
        Ok(saved) -> case decode_credit_action(saved.action) do
          Err(_) -> [record]
          Ok(action) -> if saved.status == 0
            && action.kind == 2
            && Bytes.secure_equals(action.target, mailbox_hash) do
            [record]
          else
            []
          end
        end
      end
    end)
  if List.length(matches) > 1 do
    return Err("ambiguous_pending_retention")
  end
  if List.length(matches) == 0 do
    Ok(None)
  else
    Ok(Some(reservation_plan(wallet, List.head(matches), wrapping, who)?))
  end
end

fn rank_order(left :: RankedCredit, right :: RankedCredit) -> Int do
  if left.rank < right.rank do
    -1
  else if left.rank > right.rank do
    1
  else
    0
  end
end

fn select_tokens(wallet :: CreditWallet, count :: Int, now :: U64) -> List<CreditRecord>!String do
  let spent = spent_credit_nullifiers(wallet)?
  let candidates = for record in List.filter(wallet.records, fn(item) do item.kind == 3 end) do
    let meta = token_state(record)?
    if Set.contains(spent, Bytes.to_hex(record.id)) do
      return Err("spent_credit_token_reintroduced")
    end
    if Bytes.secure_equals(meta.reservation_id, zero_id()?)
      && issuer_epoch_accepted(meta.epoch, now)?
      && credit_spend_ready(meta.purchased_at, now)? do
      Some(record)
    else
      None
    end
  end
  let available = List.flat_map(candidates,
    fn(value) do
      case value do
        Some(record) -> [record]
        None -> []
      end
    end)
  if List.length(available) < count do
    return Err("insufficient_credit_balance")
  end
  if List.length(available) > 4096 do
    return Err("credit_wallet_capacity")
  end
  # Independent CSPRNG ranks give a random permutation; duplicate ranks fail
  # closed rather than introduce a deterministic tie into token selection.
  let ranked = List.sort(for record in available do
      RankedCredit { record: record, rank: Bytes.to_hex(random_bytes(32)?) }
    end,
    rank_order)
  for index in 1..List.length(ranked) do
    if List.get(ranked, index).rank == List.get(ranked, index - 1).rank do
      return Err("credit_entropy_unavailable")
    end
  end
  Ok(for index in 0..count do
    List.get(ranked, index).record
  end)
end

fn reserve_with_policy(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  action_bytes :: Bytes,
  body :: Bytes,
  signup_policy :: Option<CreditSignupPolicy>,
  postage_price :: Option<Int>,
  cache :: List<CreditCacheWrite>,
  now :: U64) -> CreditSpendPlan!String do
  let clock = load_credit_maintenance(path, wrapping, who)?
  let now = if U64.compare(now, clock.watermark) < 0 do
    clock.watermark
  else
    now
  end
  let descriptor = decode_credit_action(action_bytes)?
  let id = credit_action_id(descriptor)?
  let before = load_credit_wallet(path, wrapping, who)?
  if descriptor.kind == 4 && List.length(cache) > 0 do
    let prior = signup_credit_reservations(before.wallet, wrapping, who)?
    if List.any(prior, fn(plan) do plan.status == 1 end) do
      return Err("signup_already_completed")
    end
    let pending = List.filter(prior, fn(plan) do plan.status == 0 end)
    if List.length(pending) > 1 do
      return Err("ambiguous_pending_signup")
    end
    if List.length(pending) == 1 do
      let plan = List.head(pending)
      if !Bytes.secure_equals(decode_credit_signup_request(body)?.entry,
        decode_credit_signup_request(plan.request_body)?.entry) do
        return Err("credit_reservation_conflict")
      end
      return commit_guarded_signup_view(path, wrapping, who, before, plan, cache)
    end
  end
  case find_credit_record(before.wallet, 4, id) do
    Some(record) -> do
      let plan = reservation_plan(before.wallet, record, wrapping, who)?
      if !Bytes.secure_equals(plan.action, action_bytes)
        || !Bytes.secure_equals(plan.request_body, body) do
        return Err("credit_reservation_conflict")
      end
      if List.length(cache) > 0 do
        return commit_guarded_signup_view(path, wrapping, who, before, plan, cache)
      end
      return Ok(plan)
    end
    None -> nil
  end
  validate_credit_action(descriptor, body, now)?
  # No caller supplies a count. Signup additionally needs a signed policy;
  # postage awaits an authenticated recipient policy.
  if descriptor.kind != 1 && descriptor.kind != 2 && descriptor.kind != 3 && descriptor.kind != 4 do
    return Err("unsupported_mobile_credit_action")
  end
  if descriptor.kind == 1 do
    let grant = decode_credit_attachment_grant(body)?
    if !Bytes.secure_equals(encode_credit_action(credit_attachment_action(grant)?)?,
      action_bytes) do
      return Err("invalid_credit_attachment_action")
    end
  else if descriptor.kind == 2 do
    let request = decode_credit_retention_request(body)?
    if !Bytes.secure_equals(encode_credit_action(credit_retention_action(request)?)?,
      action_bytes) do
      return Err("invalid_credit_retention_action")
    end
  else if descriptor.kind == 3 do
    let request = decode_credit_postage_request(body)?
    if !Bytes.secure_equals(encode_credit_action(credit_postage_action(request)?)?, action_bytes) do
      return Err("invalid_credit_postage_action")
    end
  else
    let request = decode_credit_signup_request(body)?
    if !Bytes.secure_equals(encode_credit_action(credit_signup_action(request)?)?, action_bytes)
      || !Bytes.secure_equals(descriptor.target, who.account_id) do
      return Err("invalid_credit_signup_action")
    end
  end
  let count = if descriptor.kind == 4 do
    let policy = case signup_policy do
      None -> return Err("untrusted_credit_signup_policy")
      Some(value) -> value
    end
    credit_signup_policy_price(policy,
      SigningPublicKey { bytes: who.service_key },
      who.purpose,
      now)?
  else if descriptor.kind == 3 do
    case postage_price do
      None -> return Err("untrusted_credit_postage_policy")
      Some(value) -> credit_action_price(descriptor, value, 1, 1)?
    end
  else
    credit_action_price(descriptor, 0, 1, 1)?
  end
  if count < 1 do
    return Err("credits_not_required")
  end
  let pending = for record in List.filter(before.wallet.records,
    fn(record) -> record.kind == 4 end) do
    reservation_state(record)?.status == 0
  end
  if List.length(List.filter(pending, fn(value) -> value end)) >= 128 do
    return Err("credit_reservation_capacity")
  end
  let chosen = select_tokens(before.wallet, count, now)?
  let keys = credit_issuer_keys(before.wallet, who.purpose)?
  let tokens = for record in chosen do
    open_token(record, keys, now, wrapping, who)?
  end
  let ids = for token in tokens do
    credit_nullifier(token.input)?
  end
  let frame = encode_credit_frame(CreditFrame { binding: Crypto.sha256(body), tokens: tokens })?
  let payload = seal_credit_payload(pack_credit_parts([body, frame])?,
    wrapping,
    who,
    "reservation/#{Bytes.to_hex(id)}")?
  let reservation = CreditRecord {
    kind: 4,
    id: id,
    metadata: encode_reservation(ReservationState {
      action: action_bytes,
      created_at: now,
      retain_until: List.reduce(for record in chosen do
          spent_retention_until(token_state(record)?.epoch)?
        end,
        descriptor.expires_at,
        fn(maximum, value) -> if U64.compare(value, maximum) > 0 do
          value
        else
          maximum
        end end),
      status: 0,
      token_ids: ids
    })?,
    payload: payload
  }
  let maintenance = prepare_credit_history(before.wallet, wrapping, who, clock, now)?
  if List.length(List.filter(maintenance.wallet.records,
    fn(record) -> record.kind == 4 end)) >= 2176 do
    return Err("credit_history_capacity")
  end
  let records = for record in maintenance.wallet.records do
    if record.kind == 3
      && List.any(ids, fn(selected) do Bytes.secure_equals(selected, record.id) end) do
      let meta = token_state(record)?
      CreditRecord {
        kind: 3,
        id: record.id,
        payload: record.payload,
        metadata: encode_token_state(TokenState {
          epoch: meta.epoch,
          purchased_at: meta.purchased_at,
          key_id: meta.key_id,
          reservation_id: id
        })?
      }
    else
      record
    end
  end
  let wallet = CreditWallet {
    revision: U64.add(before.wallet.revision, U64.parse("1")?)?,
    records: [reservation] ++ records
  }
  commit_credit_wallet_with_cache(path,
    wrapping,
    who,
    before,
    wallet,
    cache ++ [maintenance.cache])?
  reservation_plan(wallet, reservation, wrapping, who)
end

pub fn reserve_credit_spend(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  action_bytes :: Bytes,
  body :: Bytes,
  now :: U64) -> CreditSpendPlan!String do
  if decode_credit_action(action_bytes)?.kind == 4 do
    return Err("untrusted_credit_signup_policy")
  end
  if decode_credit_action(action_bytes)?.kind == 3 do
    return Err("use_opaque_postage_builder")
  end
  reserve_with_policy(path, wrapping, who, action_bytes, body, None, None, [], now)
end

pub fn reserve_credit_signup_spend(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  action_bytes :: Bytes,
  body :: Bytes,
  policy :: CreditSignupPolicy,
  now :: U64) -> CreditSpendPlan!String do
  if decode_credit_action(action_bytes)?.kind != 4 do
    return Err("invalid_credit_signup_action")
  end
  reserve_with_policy(path, wrapping, who, action_bytes, body, Some(policy), None, [], now)
end

# Internal only: an authenticated core-result adapter must establish successful
# consumption before calling this. Expiry or a network error is never success.
# There is deliberately no native completion/release export accepting a Bool.
pub fn complete_credit_reservation(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  operation_id :: Bytes) -> Result<(), String> do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 4, operation_id) do
    None -> return Err("credit_reservation_not_found")
    Some(value) -> value
  end
  let saved = reservation_state(record)?
  reservation_plan(before.wallet, record, wrapping, who)?
  if saved.status == 2 do
    return Err("credit_reservation_cancelled")
  end
  if saved.status == 1 do
    return Ok(nil)
  end
  let completed = CreditRecord {
    kind: 4,
    id: record.id,
    payload: record.payload,
    metadata: encode_reservation(ReservationState {
      action: saved.action,
      created_at: saved.created_at,
      retain_until: saved.retain_until,
      status: 1,
      token_ids: saved.token_ids
    })?
  }
  let remaining = List.filter(before.wallet.records,
    fn(value) do value.kind != 3
      || !List.any(saved.token_ids, fn(id) do Bytes.secure_equals(id, value.id) end) end)
  let updated = put_credit_record(CreditWallet {
      revision: U64.add(before.wallet.revision, U64.parse("1")?)?,
      records: remaining
    },
    completed)
  commit_credit_wallet(path, wrapping, who, before, updated)
end

# A transport failure, HTTP error or elapsed clock never releases tokens.
# Only the pinned core's proof for this exact expired reservation can do so.
pub fn accept_credit_cancellation(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  response :: Bytes) -> CreditSpendPlan!String do
  let cancellation = decode_credit_cancellation(response)?
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 4, cancellation.operation_id) do
    None -> return Err("credit_reservation_not_found")
    Some(value) -> value
  end
  let plan = reservation_plan(before.wallet, record, wrapping, who)?
  if !verify_credit_cancellation(cancellation,
    SigningPublicKey { bytes: who.service_key },
    CreditActionSubmission {
      action: decode_credit_action(plan.action)?,
      request_body: plan.request_body,
      frame: decode_credit_frame(plan.frame)?
    })? do
    return Err("invalid_credit_cancellation")
  end
  if plan.status == 1 do
    return Err("credit_reservation_completed")
  end
  if plan.status == 2 do
    let parts = unpack_credit_parts(open_credit_payload(record.payload,
        wrapping,
        who,
        "reservation/#{Bytes.to_hex(record.id)}")?,
      3,
      65536)?
    if !Bytes.secure_equals(List.get(parts, 2), response) do
      return Err("credit_receipt_changed")
    end
    return Ok(plan)
  end
  let saved = reservation_state(record)?
  let cancelled = CreditRecord {
    kind: 4,
    id: record.id,
    metadata: encode_reservation(%{saved | status: 2})?,
    payload: seal_credit_payload(pack_credit_parts([plan.request_body, plan.frame, response])?,
      wrapping,
      who,
      "reservation/#{Bytes.to_hex(record.id)}")?
  }
  let records = for value in before.wallet.records do
    if value.kind == 3
      && List.any(saved.token_ids, fn(id) do Bytes.secure_equals(id, value.id) end) do
      let state = token_state(value)?
      if !Bytes.secure_equals(state.reservation_id, record.id) do
        return Err("invalid_credit_reservation")
      end
      %{value | metadata: encode_token_state(%{state | reservation_id: zero_id()?})?}
    else
      value
    end
  end
  let wallet = put_credit_record(CreditWallet {
      revision: U64.add(before.wallet.revision, U64.parse("1")?)?,
      records: records
    },
    cancelled)
  commit_credit_wallet(path, wrapping, who, before, wallet)?
  reservation_plan(wallet, cancelled, wrapping, who)
end

# Draft builders use this fresh-wallet check plus fixed profile/draft CAS guards.
# Existing public adapters keep their original unguarded receipt semantics.
pub fn signup_credit_reservations(wallet :: CreditWallet,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> List<CreditSpendPlan>!String do
  let values = for record in List.filter(wallet.records, fn(item) do item.kind == 4 end) do
    let saved = reservation_state(record)?
    let action = decode_credit_action(saved.action)?
    if action.kind == 4 && Bytes.secure_equals(action.target, who.account_id) do
      let plan = reservation_plan(wallet, record, wrapping, who)?
      if plan.status == 1 do
        let parts = unpack_credit_parts(open_credit_payload(record.payload,
            wrapping,
            who,
            "reservation/#{Bytes.to_hex(record.id)}")?,
          3,
          65536)?
        if List.length(parts) != 3 do
          return Err("unverified_stored_signup")
        end
        verify_signup_receipt(CreditActionSubmission {
            action: action,
            request_body: plan.request_body,
            frame: decode_credit_frame(plan.frame)?
          },
          SigningPublicKey { bytes: who.service_key },
          who.account_id,
          List.get(parts, 2))?
      else
        nil
      end
      Some(plan)
    else
      None
    end
  end
  Ok(List.flat_map(values,
    fn(value) do
      case value do
        None -> []
        Some(plan) -> [plan]
      end
    end))
end

fn commit_guarded_signup_view(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  before :: CreditWalletSnapshot,
  plan :: CreditSpendPlan,
  cache :: List<CreditCacheWrite>) -> CreditSpendPlan!String do
  let revision = U64.add(before.wallet.revision, U64.parse("1")?)?
  commit_credit_wallet_with_cache(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: revision, records: before.wallet.records },
    cache)?
  Ok(%{plan | revision: revision})
end

fn valid_signup_draft_guards(cache :: List<CreditCacheWrite>) -> Bool do
  List.length(cache) == 2
    && List.any(cache,
      fn(write) do write.label == "profile/v1" && Bytes.length(write.value) == 0 end)
    && List.any(cache, fn(write) do write.label == "signup-draft/v1" end)
    && List.all(cache, fn(write) do Bytes.length(write.previous) > 0 end)
end

pub fn reserve_credit_signup_spend_guarded(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  action :: Bytes,
  body :: Bytes,
  policy :: CreditSignupPolicy,
  cache :: List<CreditCacheWrite>,
  now :: U64) -> CreditSpendPlan!String do
  if decode_credit_action(action)?.kind != 4
    || !valid_signup_draft_guards(cache)
    || List.any(cache, fn(write) do Bytes.length(write.value) != 0 end) do
    return Err("invalid_signup_draft_guard")
  end
  reserve_with_policy(path, wrapping, who, action, body, Some(policy), None, cache, now)
end

pub fn accept_credit_signup_receipt_guarded(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  response :: Bytes,
  cache :: List<CreditCacheWrite>) -> CreditSpendPlan!String do
  if !valid_signup_draft_guards(cache) do
    return Err("invalid_signup_draft_guard")
  end
  let receipt = decode_credit_action_receipt(response)?
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 4, receipt.operation_id) do
    None -> return Err("credit_reservation_not_found")
    Some(value) -> value
  end
  let plan = reservation_plan(before.wallet, record, wrapping, who)?
  verify_signup_receipt(CreditActionSubmission {
      action: decode_credit_action(plan.action)?,
      request_body: plan.request_body,
      frame: decode_credit_frame(plan.frame)?
    },
    SigningPublicKey { bytes: who.service_key },
    who.account_id,
    response)?
  commit_verified_credit_receipt_with_cache(path,
    wrapping,
    who,
    before,
    record,
    plan,
    response,
    cache)
end

# This is the only postage reservation entry point. A fresh reservation derives
# its count from the exact locally admitted witnessed recipient snapshot. An
# already durable exact reservation can recover after that snapshot ages out.
pub fn reserve_credit_postage_spend(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  action_bytes :: Bytes,
  body :: Bytes,
  devices_wire :: Bytes,
  deliveries :: List<Bytes>,
  now :: U64) -> CreditSpendPlan!String do
  let action = decode_credit_action(action_bytes)?
  if action.kind != 3 do
    return Err("invalid_credit_postage_action")
  end
  let before = load_credit_wallet(path, wrapping, who)?
  case find_credit_record(before.wallet, 4, credit_action_id(action)?) do
    Some(_) -> return reserve_with_policy(path,
      wrapping,
      who,
      action_bytes,
      body,
      None,
      None,
      [],
      now)
    None -> nil
  end
  let devices = verified_device_set(devices_wire)?
  require_transparency_device_set(path, wrapping, devices)?
  let request = decode_credit_postage_request(body)?
  let expected = credit_postage_request_for_devices(devices.value,
    deliveries,
    request.operation_nonce,
    X25519PublicKey { bytes: request.reply_public_key },
    request.action_expires_at)?
  if !Bytes.secure_equals(encode_credit_postage_request(expected)?, body)
    || !Bytes.secure_equals(encode_credit_action(credit_postage_action(request)?)?, action_bytes) do
    return Err("invalid_credit_postage_action")
  end
  let policy = case postage_policy_from_device_set(devices.value)? do
    None -> return Err("credits_not_required")
    Some(value) -> value
  end
  reserve_with_policy(path, wrapping, who, action_bytes, body, None, Some(policy.credits), [], now)
end

pub fn accept_credit_postage_receipt(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  devices_wire :: Bytes,
  deliveries :: List<Bytes>,
  response :: Bytes) -> CreditSpendPlan!String do
  let receipt = decode_credit_action_receipt(response)?
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 4, receipt.operation_id) do
    None -> return Err("credit_reservation_not_found")
    Some(value) -> value
  end
  let plan = reservation_plan(before.wallet, record, wrapping, who)?
  let devices = case decode_device_set(devices_wire) do
    Err(_) -> return Err("invalid_credit_postage_set")
    Ok(value) -> value
  end
  let submission = CreditActionSubmission {
    action: decode_credit_action(plan.action)?,
    request_body: plan.request_body,
    frame: decode_credit_frame(plan.frame)?
  }
  if !verify_credit_postage_receipt(receipt,
    SigningPublicKey { bytes: who.service_key },
    submission,
    devices,
    deliveries)? do
    return Err("invalid_credit_postage_receipt")
  end
  commit_verified_credit_receipt(path, wrapping, who, before, record, plan, response)
end

pub fn stored_credit_receipt(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  operation_id :: Bytes) -> Option<Bytes>!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 4, operation_id) do
    None -> return Err("credit_reservation_not_found")
    Some(value) -> value
  end
  let plan = reservation_plan(before.wallet, record, wrapping, who)?
  if plan.status == 0 do
    return Ok(None)
  end
  let parts = unpack_credit_parts(open_credit_payload(record.payload,
      wrapping,
      who,
      "reservation/#{Bytes.to_hex(operation_id)}")?,
    3,
    65536)?
  if List.length(parts) != 3 do
    return Err("credit_effect_receipt_missing")
  end
  let response = List.get(parts, 2)
  if plan.status == 1
    && !verify_credit_action_receipt(decode_credit_action_receipt(response)?,
      SigningPublicKey { bytes: who.service_key },
      CreditActionSubmission {
        action: decode_credit_action(plan.action)?,
        request_body: plan.request_body,
        frame: decode_credit_frame(plan.frame)?
      })? do
    return Err("invalid_credit_receipt")
  end
  Ok(Some(response))
end

pub struct CreditHistoryPrune do
  scanned :: Int
  removed :: Int
  revision :: U64
end

struct PreparedCreditHistory do
  wallet :: CreditWallet
  cache :: CreditCacheWrite
  scanned :: Int
  removed :: Int
end

fn later_credit_deadline(left :: U64, right :: U64) -> U64 do
  if U64.compare(left, right) >= 0 do
    left
  else
    right
  end
end

# New metadata pins the actual selected tokens' retention deadline. Legacy
# reservations conservatively use their creation epoch, which is never older
# than an eligible selected token. A paid retention effect may outlive both.
fn credit_history_deadline(wallet :: CreditWallet,
  record :: CreditRecord,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> Option<U64>!String do
  let saved = reservation_state(record)?
  if saved.status == 0 do
    return Ok(None)
  end
  let action = decode_credit_action(saved.action)?
  # The one successful signup remains a permanent local admission fence.
  if action.kind == 4 && saved.status == 1 do
    return Ok(None)
  end
  if action.kind == 1 && Option.is_some(find_credit_record(wallet, 6, action.operation_nonce)) do
    return Ok(None)
  end
  case find_credit_record(wallet, 8, action.operation_nonce) do
    Some(material) -> do
      # A CAR may have committed before local outbox acknowledgement. Cleanup
      # must not discard the only remaining means to finish that transition.
      if Bytes.length(material.metadata) < 45
        || Bytes.to_hex(Bytes.slice(material.metadata, 32, 4)?) != "0150544d" do
        return Ok(None)
      end
    end
    None -> nil
  end
  let plan = reservation_plan(wallet, record, wrapping, who)?
  let parts = unpack_credit_parts(open_credit_payload(record.payload,
      wrapping,
      who,
      "reservation/#{Bytes.to_hex(record.id)}")?,
    3,
    65536)?
  # Legacy internal completion without a signed receipt cannot justify pruning.
  if List.length(parts) != 3 do
    return Ok(None)
  end
  let response = List.get(parts, 2)
  let submission = CreditActionSubmission {
    action: action,
    request_body: plan.request_body,
    frame: decode_credit_frame(plan.frame)?
  }
  let until = later_credit_deadline(saved.retain_until, action.expires_at)
  if saved.status == 1 do
    if !verify_credit_action_receipt(decode_credit_action_receipt(response)?,
      SigningPublicKey { bytes: who.service_key },
      submission)? do
      return Err("invalid_credit_receipt")
    end
    if action.kind == 2 do
      let horizon = verified_retention_until(submission,
        SigningPublicKey { bytes: who.service_key },
        action.target,
        response)?
      # Ceil milliseconds and retain the existing four-day key safety margin.
      let seconds = U64.divide(U64.add(horizon, U64.parse("999")?)?, U64.parse("1000")?)?
      return Ok(Some(later_credit_deadline(until, U64.add(seconds, U64.parse("345600")?)?)))
    else if action.kind == 1 do
      let grant = verify_credit_attachment_receipt(submission,
        SigningPublicKey { bytes: who.service_key },
        response)?
      return Ok(Some(later_credit_deadline(until,
        U64.divide(U64.add(grant.expires_at_ms, U64.parse("999")?)?, U64.parse("1000")?)?)))
    else
      nil
    end
  else
    nil
  end
  Ok(Some(until))
end

fn credit_history_key(record :: CreditRecord) -> Bytes!String do
  Bytes.concat(mobile_byte(record.kind)?, record.id)
end

fn prepare_credit_history(wallet :: CreditWallet,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  clock :: CreditMaintenanceSnapshot,
  now :: U64) -> PreparedCreditHistory!String do
  let watermark = later_credit_deadline(now, clock.watermark)
  let records = List.sort(List.filter(wallet.records,
      fn(record) -> record.kind == 3 || record.kind == 4 end),
    fn(left, right) do
      if left.kind < right.kind do
        -1
      else if left.kind > right.kind do
        1
      else if Bytes.to_hex(left.id) < Bytes.to_hex(right.id) do
        -1
      else if Bytes.to_hex(left.id) > Bytes.to_hex(right.id) do
        1
      else
        0
      end
    end)
  let following = for record in records do
    if Bytes.to_hex(credit_history_key(record)?) > Bytes.to_hex(clock.cursor) do
      Some(record)
    else
      None
    end
  end
  let subsequent = List.flat_map(following,
    fn(value) do
      case value do
        None -> []
        Some(record) -> [record]
      end
    end)
  let candidates = List.take(if List.length(subsequent) == 0 do
      records
    else
      subsequent
    end,
    64)
  let removed = for record in candidates do
    let until = if record.kind == 3 do
      let token = token_state(record)?
      if Bytes.secure_equals(token.reservation_id, zero_id()?) do
        Some(spent_retention_until(token.epoch)?)
      else
        None
      end
    else
      credit_history_deadline(wallet, record, wrapping, who)?
    end
    case until do
      None
      Some(value) -> if U64.compare(watermark, value) >= 0 do
        Some(record)
      else
        None
      end
    end
  end
  let expired = List.flat_map(removed,
    fn(value) do
      case value do
        None -> []
        Some(record) -> [record]
      end
    end)
  let operations = List.filter(expired, fn(record) -> record.kind == 4 end)
  let nonces = for record in operations do
    decode_credit_action(reservation_state(record)?.action)?.operation_nonce
  end
  let remaining = List.filter(wallet.records,
    fn(record) do !List.any(expired,
      fn(prior) -> prior.kind == record.kind && Bytes.secure_equals(prior.id, record.id) end)
      && !(record.kind == 8 && List.contains(nonces, record.id)) end)
  let cursor = if List.length(candidates) == 0 do
    clock.cursor
  else
    credit_history_key(List.last(candidates))?
  end
  Ok(PreparedCreditHistory {
    wallet: %{wallet | records: remaining},
    cache: credit_maintenance_write(clock, cursor, watermark, wrapping, who)?,
    scanned: List.length(candidates),
    removed: List.length(wallet.records) - List.length(remaining)
  })
end

# Called on explicit balance refresh and composed into each new reservation's
# existing CAS. At most64 token/reservation records are examined per call;
# unresolved records and their tokens are never removed, including after expiry.
pub fn prune_credit_history(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  now :: U64) -> CreditHistoryPrune!String do
  prune_credit_history_after_attachment(path, wrapping, who, now, None)
end

pub fn prune_credit_history_after_attachment(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  now :: U64,
  attachment_cursor :: Option<Bytes>) -> CreditHistoryPrune!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let clock = load_credit_maintenance(path, wrapping, who)?
  let updated_clock = case attachment_cursor do
    None -> clock
    Some(value) -> %{clock | attachment_cursor: value}
  end
  let prepared = prepare_credit_history(before.wallet, wrapping, who, updated_clock, now)?
  let wallet = %{prepared.wallet | revision: U64.add(before.wallet.revision, U64.parse("1")?)?}
  commit_credit_wallet_with_cache(path, wrapping, who, before, wallet, [prepared.cache])?
  Ok(CreditHistoryPrune {
    scanned: prepared.scanned,
    removed: prepared.removed,
    revision: wallet.revision
  })
end
