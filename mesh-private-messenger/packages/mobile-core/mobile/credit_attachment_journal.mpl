from Mobile.Codec import mobile_write_u32
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts, credit_attachment_journal_parts

pub struct AttachmentIntentBinding do
  digest :: Plaintext<Bytes>
end

# The caller supplies the wallet-specific structured credit context with the
# exact nonce in its attachment-intent/v2 label. Generic financial APIs are unchanged.
pub fn seal_attachment_binding(binding :: Plaintext<Bytes>,
  wrapping :: borrow StorageKey,
  aad :: Bytes) -> Bytes!String do
  case declassify_discriminant(StorageKey.seal_bytes(binding, wrapping, aad),
    "attachment intent storage exposes only seal success or failure; filename, MIME, binding digest, storage error payloads and unrelated private control remain private") do
    Err(_) -> Err("credit_attachment_intent_seal_failed")
    Ok(value)
  end
end

pub fn open_attachment_binding(payload :: Bytes,
  wrapping :: borrow StorageKey,
  aad :: Bytes) -> AttachmentIntentBinding!String do
  let parts = attachment_journal_parts(payload)?
  case StorageKey.unseal_bytes(List.get(parts, 2), wrapping, aad) do
    Err(_) -> Err("credit_attachment_intent_open_failed")
    Ok(value) -> do
      let binding :: Plaintext<Bytes> = value
      Ok(AttachmentIntentBinding { digest: binding })
    end
  end
end

pub fn attachment_intent_matches(saved :: Plaintext<Bytes>,
  proposed :: Plaintext<Bytes>) -> Bool do
  declassify(Bytes.secure_equals(saved, proposed),
    "attachment retry exposes only whether the caller supplied exactly the already saved filename MIME and public size; metadata bytes and binding digests remain private")
end

pub fn attachment_journal_parts(payload :: Bytes) -> List<Bytes>!String do
  credit_attachment_journal_parts(payload)
end

pub fn attachment_journal_payload(material :: Bytes, sealed_binding :: Bytes) -> Bytes!String do
  pack_credit_parts([Bytes.from_hex("02414950")?, material, sealed_binding])
end

# Review each primitive before it is matched or propagated. Reviewing the
# generic packer's final Result would retain its earlier private branch control.
fn attachment_framing(value :: Bytes!String) -> Bytes!String do
  case declassify_discriminant(value,
    "attachment intent framing exposes only primitive encoding success or failure for bounded filename MIME and public size; private bytes, exact lengths, binding digest and error payloads remain private") do
    Err(_) -> Err("invalid_credit_attachment_metadata")
    Ok(value)
  end
end

fn append_binding(left :: Bytes, right :: Bytes) -> Bytes!String do
  attachment_framing(Bytes.concat(left, right))
end

fn binding_length(length :: Int) -> Bytes!String do
  case declassify_discriminant(Bytes.from_list([
      (length / 16777216) % 256,
      (length / 65536) % 256,
      (length / 256) % 256,
      length % 256
    ]),
    "attachment intent length framing exposes only four-byte writer success or failure; exact metadata lengths encoded in private bytes and error payloads remain private") do
    Err(_) -> Err("invalid_credit_attachment_metadata")
    Ok(value)
  end
end

pub fn attachment_binding(filename :: Plaintext<Bytes>, mime_type :: Plaintext<Bytes>, size :: Int) -> AttachmentIntentBinding!String do
  # Exact legacy pack_credit_parts([filename,mime,u32(size)]) representation.
  let name_length = binding_length(Bytes.length(filename))?
  let mime_length = binding_length(Bytes.length(mime_type))?
  let public_size = mobile_write_u32(size)?
  let prefix = Bytes.from_hex("00000003")?
  let name = append_binding(append_binding(prefix, name_length)?, filename)?
  let mime = append_binding(append_binding(name, mime_length)?, mime_type)?
  let framed = append_binding(append_binding(mime, Bytes.from_hex("00000004")?)?, public_size)?
  Ok(AttachmentIntentBinding { digest: Crypto.sha256(framed) })
end
