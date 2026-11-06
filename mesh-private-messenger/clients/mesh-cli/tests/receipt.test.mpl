from Client.Receipt import ReceiptQuery, parse_receipt_command

test("receipt queries require an explicit log and canonical finder-independent proof hash") do
  let hash = String.repeat("12", 32)
  case parse_receipt_command(["morse", "receipt", "--log", "morse-main", "--proof", hash]) do
    Err(_) -> assert(false)
    Ok(value) -> do
      assert(value.log_name == "morse-main")
      assert(Bytes.to_hex(value.proof_hash) == hash)
    end
  end
  for args in [
    ["morse", "receipt"],
    ["morse", "receipt", "--log", "Morse-main", "--proof", hash],
    ["morse", "receipt", "--log", "morse-main", "--proof", ""],
    ["morse", "receipt", "--log", "morse-main", "--proof", String.repeat("AB", 32)],
    ["morse", "receipt", "--log", "morse-main", "--proof", String.repeat("gg", 32)],
    ["morse", "receipt", "--log", "morse-main", "--proof", hash, "extra"],
    ["morse", "receipt", "--log", String.repeat("a", 33), "--proof", hash]
  ] do
    case parse_receipt_command(args) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
end
