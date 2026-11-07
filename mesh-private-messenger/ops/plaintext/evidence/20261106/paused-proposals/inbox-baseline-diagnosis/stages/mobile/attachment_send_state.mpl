from Mobile.SessionPolicy import NativeSessionPolicy
from Mobile.AccountState import load_bound_account
from Mobile.FanoutState import capture_fanout_sources
from Mobile.Types import MobilePreparedSend
from Storage.FanoutCommit import (
  FanoutSnapshot,
  commit_fanout_snapshot,
  commit_fanout_snapshot_at_policy
)
from Storage.OutboxGuard import PreparedOutboxIndex
from Storage.Records import store_outbound
from Transport.Packet import ClientProfile, direct_conversation_id

## Direct exports use the same custody, recipient, ratchet and history fence
## as account-wide fanout. HE text writes also preserve this source basis.
pub fn capture_direct_attachment(path :: String,
  key :: borrow StorageKey,
  profile :: Bytes,
  peer :: ClientProfile) -> FanoutSnapshot!String do
  let who = load_bound_account(path, profile, true)?
  let conversation = direct_conversation_id(who.profile.account_id, peer.account_id)?
  capture_fanout_sources(path,
    key,
    who.before.profile,
    who.profile,
    [peer],
    [who.profile],
    ["history/v1/#{Bytes.to_hex(conversation)}"])
end

pub fn commit_direct_attachment(path :: String,
  before :: Option<FanoutSnapshot>,
  prepared :: List<MobilePreparedSend>,
  removed :: List<String>,
  sessions :: Bytes,
  history_labels :: List<String>,
  histories :: List<Bytes>,
  outbox_labels :: List<String>,
  outbox_blobs :: List<Bytes>,
  index :: PreparedOutboxIndex) -> Unit!String do
  case before do
    Some(snapshot) -> commit_fanout_snapshot(path,
      snapshot,
      prepared,
      removed,
      sessions,
      history_labels,
      histories,
      outbox_labels,
      outbox_blobs,
      index)
    None -> store_outbound(path,
      prepared,
      removed,
      sessions,
      history_labels,
      histories,
      outbox_labels,
      outbox_blobs,
      index)
  end
end

# A new-session writer must retain both its original account sources and its
# captured release policy; the legacy manual writer keeps its old signature.
pub fn commit_direct_attachment_at_policy(path :: String,
  before :: Option<FanoutSnapshot>,
  policy :: NativeSessionPolicy,
  prepared :: List<MobilePreparedSend>,
  removed :: List<String>,
  sessions :: Bytes,
  history_labels :: List<String>,
  histories :: List<Bytes>,
  outbox_labels :: List<String>,
  outbox_blobs :: List<Bytes>,
  index :: PreparedOutboxIndex) -> Unit!String do
  case before do
    Some(snapshot) -> commit_fanout_snapshot_at_policy(path,
      snapshot,
      policy,
      prepared,
      removed,
      sessions,
      history_labels,
      histories,
      outbox_labels,
      outbox_blobs,
      index)
    None -> Err("invalid_fanout_snapshot")
  end
end
