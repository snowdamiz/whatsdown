from Mobile.Inbox import process_delivery_batch
from Mobile.Types import MobileBatchRequest

fn batch_caller_pc(flag :: Bool, request :: MobileBatchRequest) -> Bytes!String do
  if flag do
    process_delivery_batch(request)
  else
    Ok(Bytes.empty())
  end
end

fn batch_selected(flag :: Bool, first :: MobileBatchRequest, second :: MobileBatchRequest) -> Bytes!String do
  let selected = if flag do first else second end
  process_delivery_batch(selected)
end

fn batch_path_selected(flag :: Bool, first_path :: String, second_path :: String, batch :: Bytes) -> Bytes!String do
  let path = if flag do first_path else second_path end
  process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })
end

fn batch_whole_argument(request :: MobileBatchRequest) -> Bytes!String do
  process_delivery_batch(request)
end

fn batch_wire_argument(batch :: Bytes, path :: String) -> Bytes!String do
  process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })
end

fn main() do nil end
