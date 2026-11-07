from Mobile.BountyTransferNative import (
  native_bounty_transfer_status,
  native_bounty_transfer_prepare,
  native_bounty_transfer_commit,
  native_bounty_transfer_submit,
  native_bounty_transfer_recover,
  native_bounty_transfer_cancel
)
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Tests.Support import database_path, repeated
from Storage.Blobs import ensure_schema

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("bounty-transfer-native")?
  ensure_schema(path)?
  # A wallet-only installation can inspect its journal with credits disabled.
  let blank = unpack_credit_parts(native_bounty_transfer_status(Bytes.from_utf8(path))?, 12, 4096)?
  assert(List.length(blank) == 12 && Bytes.to_hex(List.head(blank)) == "01424d57")
  assert(Bytes.length(List.get(blank, 1)) == 0 && Bytes.to_hex(List.get(blank, 2)) == "00")
  for request in [Bytes.empty(), repeated(1, 5501)?, pack_credit_parts([Bytes.from_utf8(path)])?] do
    assert(Result.is_err(native_bounty_transfer_prepare(request)))
    assert(Result.is_err(native_bounty_transfer_commit(request)))
    assert(Result.is_err(native_bounty_transfer_submit(request)))
    assert(Result.is_err(native_bounty_transfer_recover(request)))
    assert(Result.is_err(native_bounty_transfer_cancel(request)))
  end
  assert(Result.is_err(native_bounty_transfer_prepare(pack_credit_parts([
    Bytes.from_utf8(path),
    repeated(8, 31)?,
    repeated(9, 32)?
  ])?)))
  # Generic caller input cannot supply mint/amount/index or a self-certified
  # settlement. Only a destination and native SDK payer enter preparation.
  assert(Result.is_err(native_bounty_transfer_prepare(pack_credit_parts([
    Bytes.from_utf8(path),
    repeated(8, 32)?,
    repeated(9, 32)?,
    repeated(1, 166)?
  ])?)))
  assert(Result.is_err(native_bounty_transfer_prepare(pack_credit_parts([
    Bytes.from_utf8(path),
    repeated(8, 32)?,
    repeated(9, 32)?
  ])?)))
  Ok(true)
end

test("native bounty movement keeps read-only status wallet-only and rejects caller authority") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
