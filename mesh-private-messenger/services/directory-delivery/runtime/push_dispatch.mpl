from Runtime.FakePushProvider import generic_push_payload, send_local_fake_push
from Storage.Outbox import OutboxEvent, PushResult
from Storage.Push import find_push_binding_for_mailbox

pub fn dispatch_push(pool :: PoolHandle, event :: OutboxEvent, local_fake_available :: Bool) -> PushResult ! String do
  case find_push_binding_for_mailbox(pool, event.mailbox_token_hash) ? do
    None -> Ok(PushDelivered)
    Some( binding) -> Ok(send_local_fake_push(binding, generic_push_payload(), local_fake_available))
  end
end
