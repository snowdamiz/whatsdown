from Api.Binary import BinaryResult
from Storage.AnchorReceipts import AnchorReceiptWrite, load_anchor_receipt, store_anchor_receipt
from Transparency.AnchorReceipt import AnchorReceipt, decode_anchor_receipt, anchor_receipt_json

fn empty(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

pub fn anchor_receipt_request_for(pool :: PoolHandle,
  version :: Int,
  sequence :: String) -> BinaryResult do
  if (version != 1 && version != 2) || String.length(sequence) > 20 do
    return empty(400)
  end
  let number = case U64.parse(sequence) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  if U64.to_string(number) != sequence || sequence == "0" do
    return empty(400)
  end
  case load_anchor_receipt(pool, version, number) do
    Err(_) -> empty(503)
    Ok(None) -> empty(404)
    Ok(Some(value)) -> case anchor_receipt_json(value) do
      Err(_) -> empty(503)
      Ok(document) -> BinaryResult { status: 200, body: Bytes.from_utf8(document) }
    end
  end
end

pub fn record_anchor_receipt_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  let receipt = case decode_anchor_receipt(body) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case store_anchor_receipt(pool, receipt) do
    Err(error) -> empty(if error == "invalid_anchor_receipt" do
      400
    else
      503
    end)
    Ok(ReceiptCreated) -> empty(201)
    Ok(ReceiptUnchanged) -> empty(200)
    Ok(ReceiptMissing) -> empty(404)
    Ok(ReceiptConflict) -> empty(409)
  end
end
