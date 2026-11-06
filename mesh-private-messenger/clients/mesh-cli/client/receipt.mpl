from Client.ChainRead import ChainReadOptions, load_chain_read_options
from Transparency.Config import SecurityConfig, valid_witness_id
from Transparency.SlashReceiptRead import (
  ConfirmedSlashReceipt,
  read_slash_receipt,
  slash_receipt_report
)

pub struct ReceiptQuery do
  log_name :: String
  proof_hash :: Bytes
end

pub fn parse_receipt_command(args :: List<String>) -> ReceiptQuery!String do
  let usage = "usage: morse receipt --log LOG_NAME --proof LOWERCASE_SHA256_HEX"
  if List.length(args) != 6
    || List.get(args, 1) != "receipt"
    || List.get(args, 2) != "--log"
    || List.get(args, 4) != "--proof"
    || !valid_witness_id(List.get(args, 3))
    || String.length(List.get(args, 3)) > 32 do
    return Err(usage)
  end
  let hash = case Bytes.from_hex(List.get(args, 5)) do
    Err(_) -> return Err(usage)
    Ok(value) -> value
  end
  if Bytes.length(hash) != 32 || Bytes.to_hex(hash) != List.get(args, 5) do
    return Err(usage)
  end
  Ok(ReceiptQuery { log_name: List.get(args, 3), proof_hash: hash })
end

pub fn run_receipt_command(args :: List<String>) -> Int!String do
  let query = parse_receipt_command(args)?
  let options = load_chain_read_options(query.log_name, "receipt")?
  let result = read_slash_receipt(options.pins,
    options.config.service_public_key,
    options.version,
    options.mint,
    query.proof_hash,
    options.minimum_slot)?
  println(slash_receipt_report(result))
  Ok(0)
end
