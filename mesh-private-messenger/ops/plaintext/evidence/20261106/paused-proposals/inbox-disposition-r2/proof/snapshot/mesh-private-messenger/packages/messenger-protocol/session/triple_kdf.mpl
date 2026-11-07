##! Inactive consuming combiner. No ratchet extraction or authentication authority.
from Session.State import RatchetError

pub fn triple_message_material(configuration :: Bytes,
  session :: Bytes,
  ec :: consume SecretBytes,
  pq :: consume SecretBytes) -> SecretBytes!RatchetError do
  let result = if Bytes.length(configuration) != 32 || Bytes.length(session) != 32 do
    Err(InvalidMessage)
  else
    let zero = case Bytes.from_list([0]) do
      Err(_) -> return Err(InvalidMessage)
      Ok(value) -> value
    end
    case Bytes.concat_many([Bytes.from_utf8("mesh-msg/triple/v1"), zero, configuration, session],
      83) do
      Err(_) -> Err(InvalidMessage)
      Ok(info) -> case Crypto.hkdf_sha256_secret_salt(ec, pq, info, 32) do
        Err(_) -> Err(CryptoFailure)
        Ok(value)
      end
    end
  end
  Secret.destroy(ec)
  Secret.destroy(pq)
  result
end
