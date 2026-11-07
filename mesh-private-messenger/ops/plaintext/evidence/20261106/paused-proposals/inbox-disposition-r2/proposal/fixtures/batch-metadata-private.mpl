from Mobile.Inbox import process_delivery_batch
from Mobile.Types import MobileBatchRequest
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.MailboxWire import encode_delivery_batch
from Protocol.V1 import DeliveredEnvelope, OuterEnvelope

fn prior_private_return(flag :: Plaintext<Bool>, request :: MobileBatchRequest) -> Bytes!String do
  if flag do
    return Ok(Bytes.empty())
  end
  process_delivery_batch(request)
end

fn private_whole_request(request :: Plaintext<MobileBatchRequest>) -> Bytes!String do
  process_delivery_batch(request)
end

fn private_sequence(path :: String, wire :: Bytes, sequence :: Plaintext<U64>) -> Bytes!String do
  let batch = case encode_delivery_batch([DeliveredEnvelope { sequence: sequence, envelope: wire }]) do
    Err(_) -> return Err("invalid_fixture")
    Ok(value) -> value
  end
  process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })
end

fn private_envelope_id(path :: String, outer :: OuterEnvelope, id :: Plaintext<Bytes>, sequence :: U64) -> Bytes!String do
  let wire = case encode_outer_envelope(%{outer | envelope_id: id}) do
    Err(_) -> return Err("invalid_fixture")
    Ok(value) -> value
  end
  let batch = case encode_delivery_batch([DeliveredEnvelope { sequence: sequence, envelope: wire }]) do
    Err(_) -> return Err("invalid_fixture")
    Ok(value) -> value
  end
  process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })
end

fn main() do nil end
