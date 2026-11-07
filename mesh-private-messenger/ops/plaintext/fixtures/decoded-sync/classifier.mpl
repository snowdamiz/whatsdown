from Mobile.Sessions import SyncPayloadError

fn classify(error :: SyncPayloadError) -> Int do
  case error do
    SyncInvalidPayload -> 1
    SyncInvalidStoreRequest -> 2
    SyncInvalidSafetyNumber -> 3
  end
end

fn main() do nil end
