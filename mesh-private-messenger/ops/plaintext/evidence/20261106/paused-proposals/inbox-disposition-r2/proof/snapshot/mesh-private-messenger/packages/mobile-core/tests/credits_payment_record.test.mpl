from Mobile.CreditState import (
  CreditRecord,
  CreditWallet,
  encode_credit_wallet,
  decode_credit_wallet,
  pack_credit_parts
)
from Mobile.Codec import mobile_write_u32
from Mobile.CreditAttachmentJournal import attachment_journal_payload, seal_attachment_binding
from Storage.Credits import (
  CreditWalletIdentity,
  seal_credit_payload,
  credit_attachment_intent_context
)
from Storage.Keys import platform_key
from Tests.Support import repeated

fn attachment_record() -> CreditRecord!String do
  let wrapping = platform_key()?
  let who = CreditWalletIdentity {
    account_id: repeated(21, 32)?,
    device_id: repeated(22, 16)?,
    service_key: repeated(23, 32)?,
    purpose: 1
  }
  let id = repeated(31, 32)?
  let material = seal_credit_payload(pack_credit_parts([
      Bytes.from_utf8("fixture grant"),
      Bytes.from_utf8("fixture reference")
    ])?,
    wrapping,
    who,
    "attachment/#{Bytes.to_hex(id)}")?
  let binding = seal_attachment_binding(repeated(17, 32)?,
    wrapping,
    credit_attachment_intent_context(who, id)?)?
  Ok(CreditRecord {
    kind: 6,
    id: id,
    metadata: Bytes.concat(Bytes.from_hex("0241494a")?, mobile_write_u32(0)?)?,
    payload: attachment_journal_payload(material, binding)?
  })
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let attachment = attachment_record()?
  for kind in [6, 7, 8] do
    let record = if kind == 6 do
      attachment
    else
      CreditRecord {
        kind: kind,
        id: repeated(31, 32)?,
        metadata: Bytes.from_hex("00")?,
        payload: Bytes.from_hex("0102")?
      }
    end
    let wallet = CreditWallet { revision: U64.parse("1")?, records: [record] }
    let decoded = decode_credit_wallet(encode_credit_wallet(wallet)?)?
    assert(decoded.revision == wallet.revision)
    assert(List.head(decoded.records) == record)
  end
  # Kind6 is supported only with its canonical authenticated-storage envelope.
  # The old toy payload must not regain generic wallet admission.
  assert(Result.is_err(encode_credit_wallet(CreditWallet {
    revision: U64.parse("1")?,
    records: [%{attachment | metadata: Bytes.from_hex("00")?, payload: Bytes.from_hex("0102")?}]
  })))
  for kind in [0, 5, 9, 255] do
    assert(Result.is_err(encode_credit_wallet(CreditWallet {
      revision: U64.parse("1")?,
      records: [
        CreditRecord {
          kind: kind,
          id: repeated(31, 32)?,
          metadata: Bytes.empty(),
          payload: Bytes.empty()
        }
      ]
    })))
  end
  Ok(true)
end

test("credit journal reserves only supported attachment, payment and postage record kinds") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
