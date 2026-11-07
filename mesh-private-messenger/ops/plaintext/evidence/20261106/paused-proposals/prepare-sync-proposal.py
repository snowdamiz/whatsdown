from pathlib import Path
import difflib, hashlib, json
root=Path.cwd(); source=root/'mesh-private-messenger/packages/mobile-core/mobile/messages.mpl'; before=source.read_text(); after=before.replace('  parse_sync_payload,','  parse_sync_payload_typed,\n  SyncPayloadError,')
start=after.index('fn peer_sync_payload('); stop=after.index('\npub fn receive_initial_message', start)
after=after[:start]+'''fn peer_sync_status(parsed :: MobileSyncPayload!SyncPayloadError,
  local_account_id :: Bytes) -> Int do
  case parsed do
    Err(SyncInvalidPayload) -> 1
    Err(SyncInvalidStoreRequest) -> 2
    Err(SyncInvalidSafetyNumber) -> 3
    Ok(sync) -> if Bytes.secure_equals(sync.peer_account_id, local_account_id) do
      1
    else
      0
    end
  end
end

fn peer_sync_payload(inner :: InnerEnvelope, local_account_id :: Bytes) -> MobileSyncPayload!String do
  let parsed = parse_sync_payload_typed(inner.body)
  let status = declassify(peer_sync_status(parsed, local_account_id),
    "authenticated same-account type2 initial or ratchet receive releases only self-sync admission status0 or the existing invalid_sync_payload invalid_store_request invalid_safety_number classification after identity conversation and blocked checks; body fields and arbitrary error payloads remain private")
  case status do
    1 -> Err("invalid_sync_payload")
    2 -> Err("invalid_store_request")
    3 -> Err("invalid_safety_number")
    0 -> do
      let sync = Result.unwrap_or(parsed, MobileSyncPayload {
        peer_username: "",
        peer_account_id: Bytes.empty(),
        conversation_id: Bytes.empty(),
        client_message_id: Bytes.empty(),
        client_timestamp: inner.client_timestamp,
        body: Bytes.empty(),
        disappearing_seconds: 0,
        safety_number: Bytes.empty()
      })
      let (peer_account_id, conversation_id, peer_username, disappearing_seconds, safety_number) = declassify((sync.peer_account_id,
        sync.conversation_id,
        sync.peer_username,
        sync.disappearing_seconds,
        sync.safety_number),
        "admitted authenticated same-account type2 initial or ratchet receive releases only the sibling-supplied peer account conversation username disappearance policy and safety number required by existing alias routing and session metadata; body client message ID client timestamp and attachment manifest remain private or on their existing separate path")
      Ok(MobileSyncPayload {
        peer_username: peer_username,
        peer_account_id: peer_account_id,
        conversation_id: conversation_id,
        client_message_id: sync.client_message_id,
        client_timestamp: sync.client_timestamp,
        body: sync.body,
        disappearing_seconds: disappearing_seconds,
        safety_number: safety_number
      })
    end
    _ -> Err("invalid_sync_payload")
  end
end
''' + after[stop:]
assert after.count('peer_sync_payload(inner.body, local.account_id)')==2
after=after.replace('peer_sync_payload(inner.body, local.account_id)', 'peer_sync_payload(inner, local.account_id)')
out=root/'.morse/decoded-body-labels/self-sync-proposal'; out.mkdir(exist_ok=True)
(out/'messages.mpl.candidate').write_text(after)
(out/'source.json').write_text(json.dumps({'status':'PROPOSAL ONLY; no policy approval; reserved source unmodified','message_source':str(source),'message_sha256':hashlib.sha256(before.encode()).hexdigest(),'sessions_sha256':hashlib.sha256((root/'mesh-private-messenger/packages/mobile-core/mobile/sessions.mpl').read_bytes()).hexdigest()},indent=2)+'\n')
label='mesh-private-messenger/packages/mobile-core/mobile/messages.mpl'
(out/'self-sync-proposal.patch').write_text(''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='a/'+label,tofile='b/'+label)))
