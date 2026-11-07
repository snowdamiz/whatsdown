from Mobile.Inbox import process_delivery_batch
from Mobile.Types import MobileBatchRequest

@export("mesh_inbox_proof_caller_pc") pub fn proof_caller_pc(input :: Bytes) -> Bytes!String do
  let flag :: Bool = Bytes.length(input) > 0
  if flag do
    process_delivery_batch(MobileBatchRequest { database_path: "/never-open/proof-a.db", batch: input })
  else
    Ok(Bytes.empty())
  end
end

@export("mesh_inbox_proof_batch_selection") pub fn proof_batch_selection(input :: Bytes) -> Bytes!String do
  let flag :: Bool = Bytes.length(input) > 0
  let first = MobileBatchRequest { database_path: "/never-open/proof-a.db", batch: input }
  let second = MobileBatchRequest { database_path: "/never-open/proof-b.db", batch: input }
  let selected = if flag do first else second end
  process_delivery_batch(selected)
end

@export("mesh_inbox_proof_path_selection") pub fn proof_path_selection(input :: Bytes) -> Bytes!String do
  let flag :: Bool = Bytes.length(input) > 0
  let path = if flag do "/never-open/proof-a.db" else "/never-open/proof-b.db" end
  process_delivery_batch(MobileBatchRequest { database_path: path, batch: input })
end

@export("mesh_inbox_proof_whole_argument") pub fn proof_whole_argument(input :: Bytes) -> Bytes!String do
  let request :: MobileBatchRequest = MobileBatchRequest { database_path: "/never-open/proof-a.db", batch: input }
  process_delivery_batch(request)
end

@export("mesh_inbox_proof_wire_argument") pub fn proof_wire_argument(input :: Bytes) -> Bytes!String do
  let batch :: Bytes = input
  process_delivery_batch(MobileBatchRequest { database_path: "/never-open/proof-a.db", batch: batch })
end


fn main() do nil end
