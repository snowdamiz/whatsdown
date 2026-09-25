from Binary.Reader import BinaryReader
from Mobile.Attachments import validate_attachment
from Mobile.Codec import mobile_reader, mobile_finish
from Mobile.Codec import (
  mobile_read_byte,
  mobile_read_u32,
  mobile_utf8,
  take_group_vector,
  take_optional_vector,
  take_vector,
  take_vector_error
)
from Mobile.Types import (
  MobileAccountRequest,
  MobileAttachmentChunkRequest,
  MobileAttachmentPrepareRequest,
  MobileBatchRequest,
  MobileFanoutPrekeyReservationRequest,
  MobileFanoutPrepareRequest,
  MobileFanoutRequest,
  MobileFanoutTargetsRequest,
  MobileGroupAddRequest,
  MobileGroupReferenceRequest,
  MobileGroupRemoveRequest,
  MobileGroupSendRequest,
  MobilePayloadRequest,
  MobilePeerRequest,
  MobilePolicyRequest,
  MobilePrekeyReconcileRequest,
  MobilePrekeyRequest,
  MobilePushActionCompletion,
  MobilePushIntentRequest,
  MobileReadBytes,
  MobileReceiveRequest,
  MobileStartRequest,
  MobileStoreRequest,
  MobileTransparencyRequest,
  MobileTriplePayloadRequest
)

##! Mobile.Requests implementation.

pub fn parse_store_request(input :: Bytes) -> MobileStoreRequest!String do
  if Bytes.length(input) > 69854 do
    Err("store_request_too_large")
  else
    let state = mobile_reader(input, 69854, "invalid_store_request")?
    let path = take_vector(state, 4096)?
    let record_key = take_vector(path.state, 128)?
    let envelope = take_vector(record_key.state, 65606)?
    mobile_finish(envelope.state, "invalid_store_request")?
    case Bytes.to_utf8(path.value) do
      Err(_) -> Err("invalid_database_path")
      Ok(database_path) -> if String.length(database_path) == 0 || Bytes.length(record_key.value) == 0 do
        Err("invalid_store_request")
      else
        Ok(MobileStoreRequest {
          database_path: database_path,
          record_key: record_key.value,
          envelope: envelope.value
        })
      end
    end
  end
end

pub fn parse_account_request(input :: Bytes) -> MobileAccountRequest!String do
  if Bytes.length(input) > 4168 do
    Err("account_request_too_large")
  else
    let state = mobile_reader(input, 4168, "invalid_account_request")?
    let path = take_vector(state, 4096)?
    let username = take_vector(path.state, 64)?
    mobile_finish(username.state, "invalid_account_request")?
    Ok(MobileAccountRequest { database_path: path.value, username: username.value })
  end
end

pub fn parse_prekey_request(input :: Bytes) -> MobilePrekeyRequest!String do
  let state = mobile_reader(input, 4108, "invalid_prekey_request")?
  let path = take_vector(state, 4096)?
  let count = take_vector(path.state, 4)?
  mobile_finish(count.state, "invalid_prekey_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  let count_value = mobile_read_u32(count.value)?
  if String.length(database_path) == 0 || count_value > 64 do
    Err("invalid_prekey_request")
  else
    Ok(MobilePrekeyRequest { database_path: database_path, count: count_value })
  end
end

pub fn parse_prekey_reconcile_request(input :: Bytes) -> MobilePrekeyReconcileRequest!String do
  let state = mobile_reader(input, 4669, "invalid_prekey_reconcile_request")?
  let path = take_vector(state, 4096)?
  let response = take_vector(path.state, 565)?
  mobile_finish(response.state, "invalid_prekey_reconcile_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 do
    Err("invalid_prekey_reconcile_request")
  else
    Ok(MobilePrekeyReconcileRequest { database_path: database_path, response: response.value })
  end
end

pub fn parse_start_request(input :: Bytes) -> MobileStartRequest!String do
  let state = mobile_reader(input, 89398, "invalid_start_request")?
  let path = take_vector(state, 4096)?
  let peer_profile = take_vector(path.state, 36134)?
  let body = take_vector(peer_profile.state, 32768)?
  let attachment = take_optional_vector(body.state, 16384, "invalid_start_request")?
  mobile_finish(attachment.state, "invalid_start_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 || (Bytes.length(body.value) == 0 && Bytes.length(attachment.value) == 0) do
    Err("invalid_start_request")
  else
    validate_attachment(attachment.value)?
    Ok(MobileStartRequest {
      database_path: database_path,
      peer_profile: peer_profile.value,
      body: body.value,
      attachment: attachment.value
    })
  end
end

pub fn parse_fanout_targets_request(input :: Bytes) -> MobileFanoutTargetsRequest!String do
  let state = mobile_reader(input, 614628, "invalid_fanout_request")?
  let path = take_vector(state, 4096)?
  let peer_device_set = take_vector(path.state, 305260)?
  let local_device_set = take_vector(peer_device_set.state, 305260)?
  mobile_finish(local_device_set.state, "invalid_fanout_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 do
    Err("invalid_fanout_request")
  else
    Ok(MobileFanoutTargetsRequest {
      database_path: database_path,
      peer_device_set: peer_device_set.value,
      local_device_set: local_device_set.value
    })
  end
end

pub fn parse_fanout_prepare_request(input :: Bytes) -> MobileFanoutPrepareRequest!String do
  let state = mobile_reader(input, 616680, "invalid_fanout_request")?
  let path = take_vector(state, 4096)?
  let peer_device_set = take_vector(path.state, 305260)?
  let local_device_set = take_vector(peer_device_set.state, 305260)?
  let directory_url = take_vector(local_device_set.state, 2048)?
  mobile_finish(directory_url.state, "invalid_fanout_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  let url = mobile_utf8(directory_url.value, "invalid_fanout_request")?
  if String.length(database_path) == 0 || String.length(url) == 0 do
    Err("invalid_fanout_request")
  else
    Ok(MobileFanoutPrepareRequest {
      database_path: database_path,
      peer_device_set: peer_device_set.value,
      local_device_set: local_device_set.value,
      directory_url: url
    })
  end
end

pub fn parse_fanout_prekey_reservation_request(input :: Bytes) -> MobileFanoutPrekeyReservationRequest!String do
  let state = mobile_reader(input, 633944, "invalid_fanout_request")?
  let path = take_vector(state, 4096)?
  let peer_device_set = take_vector(path.state, 305260)?
  let local_device_set = take_vector(peer_device_set.state, 305260)?
  let claimed_prekey = take_vector(local_device_set.state, 19312)?
  mobile_finish(claimed_prekey.state, "invalid_fanout_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 || Bytes.length(claimed_prekey.value) == 0 do
    Err("invalid_fanout_request")
  else
    Ok(MobileFanoutPrekeyReservationRequest {
      database_path: database_path,
      peer_device_set: peer_device_set.value,
      local_device_set: local_device_set.value,
      claimed_prekey: claimed_prekey.value
    })
  end
end

pub fn parse_fanout_request(input :: Bytes) -> MobileFanoutRequest!String do
  let state = mobile_reader(input, 663020, "invalid_fanout_request")?
  let path = take_vector(state, 4096)?
  let peer_device_set = take_vector(path.state, 305260)?
  let local_device_set = take_vector(peer_device_set.state, 305260)?
  let body = take_vector(local_device_set.state, 32000)?
  let attachment = take_optional_vector(body.state, 16384, "invalid_fanout_request")?
  mobile_finish(attachment.state, "invalid_fanout_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 || (Bytes.length(body.value) == 0 && Bytes.length(attachment.value) == 0) do
    Err("invalid_fanout_request")
  else
    validate_attachment(attachment.value)?
    Ok(MobileFanoutRequest {
      database_path: database_path,
      peer_device_set: peer_device_set.value,
      local_device_set: local_device_set.value,
      body: body.value,
      attachment: attachment.value
    })
  end
end

pub fn parse_receive_request(input :: Bytes) -> MobileReceiveRequest!String do
  let state = mobile_reader(input, 69710, "invalid_receive_request")?
  let path = take_vector(state, 4096)?
  let outer = take_vector(path.state, 65606)?
  mobile_finish(outer.state, "invalid_receive_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 do
    Err("invalid_receive_request")
  else
    Ok(MobileReceiveRequest { database_path: database_path, outer: outer.value })
  end
end

pub fn parse_policy_request(input :: Bytes) -> MobilePolicyRequest!String do
  let state = mobile_reader(input, 40251, "invalid_policy_request")?
  let path = take_vector(state, 4096)?
  let peer_profile = take_vector(path.state, 36134)?
  let action = take_vector(peer_profile.state, 1)?
  let value = take_vector(action.state, 4)?
  mobile_finish(value.state, "invalid_policy_request")?
  Ok(MobilePolicyRequest {
    database_path: mobile_utf8(path.value, "invalid_database_path")?,
    peer_profile: peer_profile.value,
    action: mobile_read_byte(action.value)?,
    value: mobile_read_u32(value.value)?
  })
end

pub fn parse_peer_request(input :: Bytes) -> MobilePeerRequest!String do
  let state = mobile_reader(input, 40238, "invalid_peer_request")?
  let path = take_vector(state, 4096)?
  let peer_profile = take_vector(path.state, 36134)?
  mobile_finish(peer_profile.state, "invalid_peer_request")?
  Ok(MobilePeerRequest {
    database_path: mobile_utf8(path.value, "invalid_database_path")?,
    peer_profile: peer_profile.value
  })
end

pub fn parse_batch_request(input :: Bytes) -> MobileBatchRequest!String do
  let state = mobile_reader(input, 604104, "invalid_batch_request")?
  let path = take_vector(state, 4096)?
  let batch = take_vector(path.state, 600000)?
  mobile_finish(batch.state, "invalid_batch_request")?
  Ok(MobileBatchRequest {
    database_path: mobile_utf8(path.value, "invalid_database_path")?,
    batch: batch.value
  })
end

pub fn parse_payload_request(input :: Bytes) -> MobilePayloadRequest!String do
  let state = mobile_reader(input, 309364, "invalid_payload_request")?
  let path = take_vector(state, 4096)?
  let payload = take_vector(path.state, 305260)?
  mobile_finish(payload.state, "invalid_payload_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 || Bytes.length(payload.value) == 0 do
    Err("invalid_payload_request")
  else
    Ok(MobilePayloadRequest { database_path: database_path, payload: payload.value })
  end
end

fn parse_push_bind_request_inner(input :: Bytes) -> MobilePayloadRequest!String do
  let state = mobile_reader(input, 4140, "invalid")?
  let path = take_vector(state, 4096)?
  let project_id = take_vector(path.state, 36)?
  mobile_finish(project_id.state, "invalid")?
  let database_path = mobile_utf8(path.value, "invalid")?
  if String.length(database_path) == 0 do
    Err("invalid")
  else
    Ok(MobilePayloadRequest { database_path: database_path, payload: project_id.value })
  end
end

pub fn parse_push_bind_request(input :: Bytes) -> MobilePayloadRequest!String do
  case parse_push_bind_request_inner(input) do
    Err(_) -> Err("invalid_payload_request")
    Ok(value)
  end
end

pub fn parse_push_intent_request(input :: Bytes) -> MobilePushIntentRequest!String do
  let state = mobile_reader(input, 4105, "invalid_push_intent")?
  let path = take_vector_error(state, 4096, "invalid_push_intent")?
  let intent = take_vector_error(path.state, 1, "invalid_push_intent")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  let intent_value = mobile_read_byte(intent.value)?
  if String.length(database_path) == 0 || (intent_value != 0 && intent_value != 1 && intent_value != 2) do
    Err("invalid_push_intent")
  else
    mobile_finish(intent.state, "invalid_push_intent")?
    Ok(MobilePushIntentRequest { database_path: database_path, intent: intent_value })
  end
end

pub fn parse_push_action_completion(input :: Bytes) -> MobilePushActionCompletion!String do
  let state = mobile_reader(input, 4852, "invalid_push_action_completion")?
  let path = take_vector_error(state, 4096, "invalid_push_action_completion")?
  let action = take_vector_error(path.state, 743, "invalid_push_action_completion")?
  let outcome = take_vector_error(action.state, 1, "invalid_push_action_completion")?
  mobile_finish(outcome.state, "invalid_push_action_completion")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  let outcome_value = mobile_read_byte(outcome.value)?
  if String.length(database_path) == 0 || Bytes.length(action.value) < 18 || (outcome_value != 0 && outcome_value != 1) do
    Err("invalid_push_action_completion")
  else
    Ok(MobilePushActionCompletion {
      database_path: database_path,
      action: action.value,
      outcome: outcome_value
    })
  end
end

pub fn parse_triple_payload_request(input :: Bytes) -> MobileTriplePayloadRequest!String do
  let state = mobile_reader(input, 614628, "invalid_payload_request")?
  let path = take_vector(state, 4096)?
  let first = take_vector(path.state, 305260)?
  let second = take_vector(first.state, 305260)?
  mobile_finish(second.state, "invalid_payload_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 || Bytes.length(first.value) == 0 || Bytes.length(second.value) == 0 do
    Err("invalid_payload_request")
  else
    Ok(MobileTriplePayloadRequest {
      database_path: database_path,
      first: first.value,
      second: second.value
    })
  end
end

pub fn parse_group_add_request(input :: Bytes) -> MobileGroupAddRequest!String do
  let state = mobile_reader(input, 309773, "invalid_group_request")?
  let path = take_group_vector(state, 4096)?
  let group_id = take_group_vector(path.state, 32)?
  let device_set = take_group_vector(group_id.state, 305260)?
  let key_package = take_group_vector(device_set.state, 369)?
  mobile_finish(key_package.state, "invalid_group_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 || Bytes.length(group_id.value) != 32 || Bytes.length(device_set.value) == 0 || Bytes.length(key_package.value) != 369 do
    Err("invalid_group_request")
  else
    Ok(MobileGroupAddRequest {
      database_path: database_path,
      group_id: group_id.value,
      device_set: device_set.value,
      key_package: key_package.value
    })
  end
end

pub fn parse_group_remove_request(input :: Bytes) -> MobileGroupRemoveRequest!String do
  let state = mobile_reader(input, 4192, "invalid_group_request")?
  let path = take_vector(state, 4096)?
  let group_id = take_vector(path.state, 32)?
  let account_id = take_vector(group_id.state, 32)?
  let device_id = take_vector(account_id.state, 16)?
  mobile_finish(device_id.state, "invalid_group_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 || Bytes.length(group_id.value) != 32 || Bytes.length(account_id.value) != 32 || Bytes.length(device_id.value) != 16 do
    Err("invalid_group_request")
  else
    Ok(MobileGroupRemoveRequest {
      database_path: database_path,
      group_id: group_id.value,
      account_id: account_id.value,
      device_id: device_id.value
    })
  end
end

pub fn parse_group_reference_request(input :: Bytes) -> MobileGroupReferenceRequest!String do
  let state = mobile_reader(input, 4136, "invalid_group_request")?
  let path = take_vector(state, 4096)?
  let group_id = take_vector(path.state, 32)?
  mobile_finish(group_id.state, "invalid_group_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 || Bytes.length(group_id.value) != 32 do
    Err("invalid_group_request")
  else
    Ok(MobileGroupReferenceRequest { database_path: database_path, group_id: group_id.value })
  end
end

pub fn parse_group_send_request(input :: Bytes) -> MobileGroupSendRequest!String do
  let state = mobile_reader(input, 85875, "invalid_group_request")?
  let path = take_vector(state, 4096)?
  let group_id = take_vector(path.state, 32)?
  let body = take_vector(group_id.state, 65347)?
  let attachment = take_optional_vector(body.state, 16384, "invalid_group_request")?
  mobile_finish(attachment.state, "invalid_group_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  # Empty bodies stay valid: the app sends them to announce presentation changes.
  if String.length(database_path) == 0 || Bytes.length(group_id.value) != 32 do
    Err("invalid_group_request")
  else
    validate_attachment(attachment.value)?
    Ok(MobileGroupSendRequest {
      database_path: database_path,
      group_id: group_id.value,
      body: body.value,
      attachment: attachment.value
    })
  end
end

pub fn parse_attachment_prepare_request(input :: Bytes) -> MobileAttachmentPrepareRequest!String do
  let state = mobile_reader(input, 4506, "invalid_attachment_request")?
  let path = take_vector_error(state, 4096, "invalid_attachment_request")?
  let filename = take_vector_error(path.state, 255, "invalid_attachment_request")?
  let mime_type = take_vector_error(filename.state, 127, "invalid_attachment_request")?
  let plaintext_size = take_vector_error(mime_type.state, 4, "invalid_attachment_request")?
  let difficulty = take_vector_error(plaintext_size.state, 4, "invalid_attachment_request")?
  mobile_finish(difficulty.state, "invalid_attachment_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  mobile_utf8(filename.value, "invalid_attachment_request")?
  mobile_utf8(mime_type.value, "invalid_attachment_request")?
  let difficulty_value = mobile_read_u32(difficulty.value)?
  if String.length(database_path) == 0 || Bytes.length(mime_type.value) == 0 || difficulty_value < 1 || difficulty_value > 24 do
    Err("invalid_attachment_request")
  else
    Ok(MobileAttachmentPrepareRequest {
      database_path: database_path,
      filename: filename.value,
      mime_type: mime_type.value,
      plaintext_size: mobile_read_u32(plaintext_size.value)?,
      difficulty: difficulty_value
    })
  end
end

pub fn parse_attachment_chunk_request(input :: Bytes) -> MobileAttachmentChunkRequest!String do
  let state = mobile_reader(input, 70724, "invalid_attachment_request")?
  let path = take_vector_error(state, 4096, "invalid_attachment_request")?
  let reference = take_vector_error(path.state, 1024, "invalid_attachment_request")?
  let index = take_vector_error(reference.state, 4, "invalid_attachment_request")?
  let payload = take_vector_error(index.state, 65576, "invalid_attachment_request")?
  mobile_finish(payload.state, "invalid_attachment_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 || Bytes.length(reference.value) == 0 || Bytes.length(payload.value) == 0 do
    Err("invalid_attachment_request")
  else
    Ok(MobileAttachmentChunkRequest {
      database_path: database_path,
      reference: reference.value,
      index: mobile_read_u32(index.value)?,
      payload: payload.value
    })
  end
end

pub fn parse_transparency_request(input :: Bytes) -> MobileTransparencyRequest!String do
  let state = mobile_reader(input, 574447, "invalid_transparency_request")?
  let path = take_vector(state, 4096)?
  let username = take_vector(path.state, 65)?
  let evidence = take_vector(username.state, 570274)?
  mobile_finish(evidence.state, "invalid_transparency_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  let expected_username = mobile_utf8(username.value, "invalid_username")?
  if String.length(database_path) == 0 || String.length(expected_username) == 0 || Bytes.length(evidence.value) == 0 do
    Err("invalid_transparency_request")
  else
    Ok(MobileTransparencyRequest {
      database_path: database_path,
      username: expected_username,
      evidence: evidence.value
    })
  end
end
