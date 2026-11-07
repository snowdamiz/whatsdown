# Compile only. These functions are deliberately uncalled.
from Protocol.V1 import ProtocolError

fn proof_private_text(input :: Bytes) do
  let (_, text) = console_display_value(input)
  println(text)
end

fn proof_private_metadata(input :: Plaintext<Bytes>) do
  case decode_inner_envelope(input) do
    Err(_) -> nil
    Ok(value) -> println(Bytes.to_hex(value.sender_account_id))
  end
end

fn proof_private_decode_error(input :: Plaintext<Bytes>) do
  case decode_inner_envelope(input) do
    Err(error) -> println("#{error == ProtocolError.UnsupportedVersion}")
    Ok(_) -> nil
  end
end

fn proof_private_utf8_error(input :: Bytes) do
  case decode_inner_envelope(input) do
    Err(_) -> nil
    Ok(value) -> case Bytes.to_utf8(value.body) do
      Err(error) -> println(error)
      Ok(_) -> nil
    end
  end
end

fn proof_private_caller(flag :: Plaintext<Bool>) do
  if flag do
    display(Bytes.empty())
  end
end
