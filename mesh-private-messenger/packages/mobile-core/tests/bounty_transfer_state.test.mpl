from Mobile.Bounty import bounty_state, set_bounty_enabled, commit_bounty_address
from Mobile.BountyTransferState import (
  load_bounty_transfer,
  prepare_bounty_transfer,
  commit_bounty_transfer,
  acknowledge_bounty_transfer,
  cancel_bounty_transfer,
  settle_bounty_transfer
)
from Bounty.Settlement import BountyTransferSettlement
from Mobile.TransparencySafety import retain_fork
from Bounty.Transfer import BountyTransfer, encode_bounty_transfer, bounty_transfer_instructions
from Solana.Read import Pubkey, Hash
from Solana.Tx import compile_legacy_message, serialize_legacy_message
from Solana.TransactionWrite import serialize_signed_legacy_transaction
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key
from Storage.Records import erase_local_state
from Storage.BountyTransfer import store_bounty_transfer_snapshot
from Tests.Support import database_path, repeated, append
from Tests.ForkFilingSupport import filing_fixture
from Transparency.Config import encode_security_config

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test key")
    Ok(value)
  end
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let payer = pair()?
  let finder = pair()?
  let path = database_path("bounty-transfer-state")?
  ensure_schema(path)?
  assert(load_bounty_transfer(path, key)? == None)
  let (proof, config) = filing_fixture()?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(config)?))
  set_bounty_enabled(path, key, true)?
  retain_fork(path, key, proof)?
  let selected = bounty_state(path, key)?
  commit_bounty_address(path,
    key,
    selected.proof_identity,
    append(Bytes.from_hex("0300000000000000")?, finder.public_key.bytes)?)?
  let usdc = repeated(9, 32)?
  let intent = BountyTransfer {
    index: U64.parse("3")?,
    finder: finder.public_key.bytes,
    destination: payer.public_key.bytes,
    mint: usdc,
    amount: U64.parse("9007199254740993")?,
    blockhash: repeated(8, 32)?,
    issued_at: U64.parse("1000")?,
    expires_at: U64.parse("1300")?,
    purpose: 1,
    decimals: 6
  }
  let id = repeated(77, 32)?
  let first = prepare_bounty_transfer(path,
    key,
    id,
    intent,
    payer.public_key.bytes,
    usdc,
    U64.parse("50")?,
    U64.parse("90")?,
    U64.parse("60")?,
    intent.issued_at)?
  assert(first.status == 1)
  assert(Bytes.secure_equals(first.intent, encode_bounty_transfer(intent)?))
  assert(Result.is_err(prepare_bounty_transfer(path,
    key,
    id,
    %{intent | destination: repeated(18, 32)?},
    payer.public_key.bytes,
    usdc,
    first.context_slot,
    first.last_valid_block_height,
    U64.parse("60")?,
    intent.issued_at)))
  assert(Result.is_err(prepare_bounty_transfer(path,
    key,
    id,
    %{intent | finder: repeated(18, 32)?},
    payer.public_key.bytes,
    usdc,
    first.context_slot,
    first.last_valid_block_height,
    U64.parse("60")?,
    intent.issued_at)))
  let before = load_blob(path, "bounty-transfer/v1")?
  let retry = prepare_bounty_transfer(path,
    key,
    id,
    %{intent | blockhash: repeated(21, 32)?},
    payer.public_key.bytes,
    usdc,
    first.context_slot,
    first.last_valid_block_height,
    U64.parse("60")?,
    intent.issued_at)?
  assert(Bytes.secure_equals(retry.intent, first.intent))
  assert(Bytes.secure_equals(before, load_blob(path, "bounty-transfer/v1")?))
  let message = compile_legacy_message(Pubkey { bytes: payer.public_key.bytes },
    Hash { bytes: intent.blockhash },
    bounty_transfer_instructions(intent, Pubkey { bytes: payer.public_key.bytes })?)?
  let body = serialize_legacy_message(message)?
  let p = case Crypto.sign(payer.private_key, body) do
    Err(_) -> return Err("test sign")
    Ok(value) -> value
  end
  let f = case Crypto.sign(finder.private_key, body) do
    Err(_) -> return Err("test sign")
    Ok(value) -> value
  end
  let packet = serialize_signed_legacy_transaction(message, [p, f])?
  # A native prompt cannot authorize an already-expired intent/hash.
  assert(Result.is_err(commit_bounty_transfer(path,
    key,
    id,
    packet,
    U64.parse("91")?,
    U64.parse("1100")?)))
  assert(Result.is_err(commit_bounty_transfer(path,
    key,
    id,
    packet,
    U64.parse("70")?,
    intent.expires_at)))
  let signed = commit_bounty_transfer(path, key, id, packet, U64.parse("70")?, U64.parse("1100")?)?
  assert(signed.status == 2 && Bytes.secure_equals(signed.signature, p.bytes))
  assert(Bytes.secure_equals(signed.wire, packet))
  assert(Result.is_err(cancel_bounty_transfer(path, key, id)))
  assert(Result.is_err(commit_bounty_transfer(path,
    key,
    id,
    repeated(31, 32)?,
    U64.parse("70")?,
    U64.parse("1100")?)))
  # Signed bytes survive restart/timeouts and are never refreshed by prepare.
  let resumed = prepare_bounty_transfer(path,
    key,
    id,
    %{intent |
      blockhash: repeated(21, 32)?,
      issued_at: U64.parse("1400")?,
      expires_at: U64.parse("1700")?
    },
    payer.public_key.bytes,
    usdc,
    U64.parse("80")?,
    U64.parse("130")?,
    U64.parse("100")?,
    U64.parse("1400")?)?
  assert(resumed.status == 2 && Bytes.secure_equals(resumed.wire, packet))
  assert(Result.is_err(acknowledge_bounty_transfer(path, key, id, repeated(3, 64)?)))
  let ack = acknowledge_bounty_transfer(path, key, id, signed.signature)?
  assert(ack.status == 3)
  assert(commit_bounty_transfer(path,
    key,
    id,
    packet,
    U64.parse("100")?,
    U64.parse("1500")?)?.status == 3)
  let failed = BountyTransferSettlement {
    signature: signed.signature,
    wire_hash: Crypto.sha256(packet),
    slot: U64.parse("95")?,
    fee: U64.parse("10000")?,
    execution_error: "\"InsufficientFundsForFee\""
  }
  assert(Result.is_err(settle_bounty_transfer(path, key, id, %{failed | slot: U64.parse("49")?})))
  assert(Result.is_err(settle_bounty_transfer(path,
    key,
    id,
    %{failed | signature: repeated(8, 64)?})))
  assert(settle_bounty_transfer(path, key, id, failed)?.status == 5)
  assert(settle_bounty_transfer(path, key, id, failed)?.status == 5)
  assert(Result.is_err(settle_bounty_transfer(path, key, id, %{failed | execution_error: ""})))
  let next = %{intent |
    blockhash: repeated(22, 32)?,
    issued_at: U64.parse("1400")?,
    expires_at: U64.parse("1700")?
  }
  assert(Result.is_err(prepare_bounty_transfer(path,
    key,
    id,
    next,
    payer.public_key.bytes,
    usdc,
    U64.parse("94")?,
    U64.parse("180")?,
    U64.parse("120")?,
    next.issued_at)))
  let fresh = prepare_bounty_transfer(path,
    key,
    id,
    next,
    payer.public_key.bytes,
    usdc,
    U64.parse("100")?,
    U64.parse("180")?,
    U64.parse("120")?,
    next.issued_at)?
  assert(fresh.status == 1)
  assert(Bytes.length(load_blob(path,
    "bounty-transfer/v1/history/" <> Bytes.to_hex(signed.signature))?) > 0)
  assert(Result.is_err(commit_bounty_transfer(path,
    key,
    id,
    packet,
    U64.parse("120")?,
    next.issued_at)))
  assert(Result.is_err(acknowledge_bounty_transfer(path, key, id, signed.signature)))
  assert(cancel_bounty_transfer(path, key, id)?.status == 0)
  let changed = prepare_bounty_transfer(path,
    key,
    id,
    %{next | destination: repeated(18, 32)?},
    payer.public_key.bytes,
    usdc,
    U64.parse("100")?,
    U64.parse("180")?,
    U64.parse("120")?,
    next.issued_at)?
  assert(changed.status == 1)
  let stale_guard = load_blob(path, "fork-bounty/v1")?
  let stale_blob = load_blob(path, "bounty-transfer/v1")?
  # Erasing native proof custody also erases the movement journal. A delayed
  # prompt or network response cannot recreate a new selected bounty.
  erase_local_state(path)?
  # Directly model erasure between the last read and first journal INSERT.
  assert(Result.is_err(store_bounty_transfer_snapshot(path,
    ["bounty-transfer/v1"],
    [stale_blob],
    Bytes.empty(),
    stale_guard)))
  assert(Result.is_err(commit_bounty_transfer(path,
    key,
    id,
    packet,
    U64.parse("70")?,
    U64.parse("1100")?)))
  assert(Result.is_err(acknowledge_bounty_transfer(path, key, id, signed.signature)))
  assert(Result.is_err(prepare_bounty_transfer(path,
    key,
    id,
    intent,
    payer.public_key.bytes,
    usdc,
    U64.parse("50")?,
    U64.parse("90")?,
    U64.parse("60")?,
    intent.issued_at)))
  assert(load_bounty_transfer(path, key)? == None)
  Ok(true)
end

test("bounty journal persists the exact signed packet before send and fences expiry and erasure") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
