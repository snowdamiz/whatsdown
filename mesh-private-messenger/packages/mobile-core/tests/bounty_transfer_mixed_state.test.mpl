from Mobile.Bounty import bounty_state, set_bounty_enabled, commit_bounty_address
from Mobile.BountyTransferState import (
  BountyTransferAuthority,
  bounty_transfer_claim_id,
  admit_bounty_transfer_root,
  read_bounty_transfer_movement,
  read_bounty_transfer_route,
  prepare_bounty_transfer_route,
  load_bounty_transfer,
  load_bounty_transfer_identity,
  commit_bounty_transfer,
  commit_bounty_transfer_route,
  bounty_transfer_attempt_handle,
  cancel_bounty_transfer,
  settle_bounty_transfer
)
from Mobile.TransparencySafety import retain_fork
from Bounty.Transfer import BountyTransfer, encode_bounty_transfer, bounty_transfer_instructions
from Bounty.Settlement import BountyTransferSettlement
from Solana.Read import Pubkey, Hash
from Solana.Tx import compile_legacy_message, serialize_legacy_message
from Solana.TransactionWrite import serialize_signed_legacy_transaction
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, local_context, seal_local
from Storage.Records import store_blobs
from Storage.BountyTransfer import bounty_transfer_row_label
from Tests.Support import database_path, repeated, append
from Tests.ForkFilingSupport import filing_fixture
from Transparency.Config import encode_security_config

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test key")
    Ok(value)
  end
end

fn select(path :: String, key :: borrow StorageKey, finder :: Bytes) -> Bytes!String do
  ensure_schema(path)?
  store_blobs(path,
    ["profile/v1"],
    [seal_local(Bytes.from_utf8("account"), key, local_context("profile/v1")?)?])?
  let (proof, config) = filing_fixture()?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(config)?))
  set_bounty_enabled(path, key, true)?
  retain_fork(path, key, proof)?
  let selected = bounty_state(path, key)?
  commit_bounty_address(path,
    key,
    selected.proof_identity,
    append(Bytes.from_hex("0300000000000000")?, finder)?)?
  Ok(selected.proof_identity)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let payer = pair()?
  let finder = pair()?
  let path = database_path("bounty-independent-legs")?
  let proof_identity = select(path, key, finder.public_key.bytes)?
  let zero = U64.parse("0")?
  let usdc = repeated(9, 32)?
  let morse = repeated(10, 32)?
  let authority = BountyTransferAuthority {
    claim_id: bounty_transfer_claim_id(proof_identity, finder.public_key.bytes, U64.parse("3")?)?,
    proof_identity: proof_identity,
    proof_hash: repeated(11, 32)?,
    finder: finder.public_key.bytes,
    index: U64.parse("3")?,
    namespace: repeated(12, 32)?,
    purpose: 1,
    receipt: repeated(13, 32)?,
    terms_hash: repeated(14, 32)?,
    admission_binding: repeated(15, 32)?,
    admission_slot: U64.parse("40")?,
    usdc_mint: usdc,
    usdc_units: U64.parse("11")?,
    morse_mint: morse,
    morse_units: U64.parse("37")?,
    legacy_identity: Bytes.empty()
  }
  admit_bounty_transfer_root(path, key, authority)?
  let root_cipher = load_blob(path, "bounty-authority/v2")?
  let marker_cipher = load_blob(path, "bounty-transfer/v1")?
  let original = admit_bounty_transfer_root(path,
    key,
    %{authority | admission_binding: repeated(16, 32)?, admission_slot: U64.parse("80")?})?
  assert(Bytes.secure_equals(original.admission_binding, authority.admission_binding))
  assert(original.admission_slot == authority.admission_slot)
  assert(Bytes.secure_equals(load_blob(path, "bounty-authority/v2")?, root_cipher))
  assert(Result.is_err(admit_bounty_transfer_root(path,
    key,
    %{authority | namespace: repeated(17, 32)?})))
  assert(Result.is_err(admit_bounty_transfer_root(path,
    key,
    %{authority | usdc_units: U64.parse("12")?})))
  assert(Result.is_err(load_bounty_transfer(path, key)))
  let base = BountyTransfer {
    index: authority.index,
    finder: authority.finder,
    destination: payer.public_key.bytes,
    mint: usdc,
    amount: authority.usdc_units,
    blockhash: repeated(20, 32)?,
    issued_at: U64.parse("1000")?,
    expires_at: U64.parse("1300")?,
    purpose: 1,
    decimals: 6
  }
  let signed = for asset in 1..3 do
    let intent = if asset == 1 do
      base
    else
      %{base |
        mint: morse,
        amount: authority.morse_units,
        decimals: 9,
        blockhash: repeated(21, 32)?
      }
    end
    let before = prepare_bounty_transfer_route(path,
      key,
      asset,
      authority.admission_binding,
      intent,
      payer.public_key.bytes,
      usdc,
      U64.parse("50")?,
      U64.parse("90")?,
      U64.parse("60")?,
      intent.issued_at)?
    assert(Bytes.length(before.intent) == 166)
    # Fresh authenticated binding rotation preserves exact intent but invalidates
    # an earlier prompt handle, independent of blockhash or wall-clock changes.
    let stale_handle = bounty_transfer_attempt_handle(read_bounty_transfer_route(path,
      key,
      asset)?)?
    let rebound = repeated(22 + asset, 32)?
    let refreshed = prepare_bounty_transfer_route(path,
      key,
      asset,
      rebound,
      intent,
      payer.public_key.bytes,
      usdc,
      U64.parse("50")?,
      U64.parse("90")?,
      U64.parse("60")?,
      intent.issued_at)?
    assert(Bytes.secure_equals(refreshed.intent, before.intent))
    assert(Bytes.secure_equals(read_bounty_transfer_route(path, key, asset)?.attempt_binding,
      rebound))
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
    let wire = serialize_signed_legacy_transaction(message, [p, f])?
    # Deterministic prompt/RPC barrier: captured handle precedes the binding
    # update above. The stale prompt cannot commit even though wire is identical.
    assert(Result.is_err(commit_bounty_transfer_route(path,
      key,
      asset,
      stale_handle,
      wire,
      U64.parse("70")?,
      U64.parse("1100")?)))
    let fresh_handle = bounty_transfer_attempt_handle(read_bounty_transfer_route(path,
      key,
      asset)?)?
    commit_bounty_transfer_route(path,
      key,
      asset,
      fresh_handle,
      wire,
      U64.parse("70")?,
      U64.parse("1100")?)?
  end
  let a = List.get(signed, 0)
  let b = List.get(signed, 1)
  assert(!Bytes.secure_equals(a.identity, b.identity))
  assert(Bytes.secure_equals(load_bounty_transfer_identity(path, key, a.identity)?.wire, a.wire))
  assert(Bytes.secure_equals(load_bounty_transfer_identity(path, key, b.identity)?.wire, b.wire))
  let a_outcome = BountyTransferSettlement {
    signature: a.signature,
    wire_hash: Crypto.sha256(a.wire),
    slot: U64.parse("70")?,
    fee: U64.parse("5000")?,
    execution_error: ""
  }
  settle_bounty_transfer(path, key, a.identity, a_outcome)?
  let a_label = bounty_transfer_row_label(Bytes.to_hex(authority.claim_id), 1)?
  let completed_a = load_blob(path, a_label)?
  let b_outcome = BountyTransferSettlement {
    signature: b.signature,
    wire_hash: Crypto.sha256(b.wire),
    slot: U64.parse("75")?,
    fee: U64.parse("10000")?,
    execution_error: "failed"
  }
  settle_bounty_transfer(path, key, b.identity, b_outcome)?
  let retry = %{base |
    mint: morse,
    amount: authority.morse_units,
    decimals: 9,
    blockhash: repeated(30, 32)?,
    issued_at: U64.parse("1400")?,
    expires_at: U64.parse("1700")?
  }
  assert(Result.is_err(prepare_bounty_transfer_route(path,
    key,
    2,
    repeated(31, 32)?,
    retry,
    payer.public_key.bytes,
    usdc,
    U64.parse("74")?,
    U64.parse("180")?,
    U64.parse("100")?,
    retry.issued_at)))
  let retried = prepare_bounty_transfer_route(path,
    key,
    2,
    repeated(31, 32)?,
    retry,
    payer.public_key.bytes,
    usdc,
    U64.parse("80")?,
    U64.parse("180")?,
    U64.parse("100")?,
    retry.issued_at)?
  assert(retried.status == 1)
  let b_label = bounty_transfer_row_label(Bytes.to_hex(authority.claim_id), 2)?
  assert(Bytes.length(load_blob(path, b_label <> "/history/" <> Bytes.to_hex(b.signature))?) > 0)
  assert(Bytes.secure_equals(load_blob(path, a_label)?, completed_a))
  assert(Result.is_err(commit_bounty_transfer(path,
    key,
    b.identity,
    b.wire,
    U64.parse("100")?,
    retry.issued_at)))
  cancel_bounty_transfer(path, key, b.identity)?
  # Cancelling unsigned state preserves its durable observation floor.
  assert(Result.is_err(prepare_bounty_transfer_route(path,
    key,
    2,
    repeated(32, 32)?,
    %{retry | blockhash: repeated(33, 32)?},
    payer.public_key.bytes,
    usdc,
    U64.parse("79")?,
    U64.parse("180")?,
    U64.parse("100")?,
    retry.issued_at)))
  let aggregate = read_bounty_transfer_movement(path, key)?
  let a_route = case aggregate.usdc do
    None -> return Err("missing A")
    Some(value) -> value
  end
  let b_route = case aggregate.morse do
    None -> return Err("missing B")
    Some(value) -> value
  end
  let a_final = case a_route.journal do
    None -> return Err("missing A journal")
    Some(value) -> value
  end
  let b_final = case b_route.journal do
    None -> return Err("missing B journal")
    Some(value) -> value
  end
  assert(a_final.status == 4 && b_final.status == 0)
  assert(Bytes.secure_equals(a_final.wire, a.wire))
  assert(Bytes.secure_equals(load_blob(path, "bounty-authority/v2")?, root_cipher))
  assert(Bytes.secure_equals(load_blob(path, "bounty-transfer/v1")?, marker_cipher))
  # Explicit zero terms survive a restart and never allocate an attempted row.
  let zero_path = database_path("bounty-zero-terms")?
  let zero_proof = select(zero_path, key, finder.public_key.bytes)?
  let zero_root = %{authority |
    proof_identity: zero_proof,
    claim_id: bounty_transfer_claim_id(zero_proof, authority.finder, authority.index)?,
    usdc_units: zero,
    morse_units: zero
  }
  admit_bounty_transfer_root(zero_path, key, zero_root)?
  assert(read_bounty_transfer_route(zero_path, key, 1)?.journal == None)
  assert(read_bounty_transfer_route(zero_path, key, 2)?.journal == None)
  assert(Result.is_err(load_blob(zero_path,
    bounty_transfer_row_label(Bytes.to_hex(zero_root.claim_id), 1)?)))
  assert(Result.is_err(prepare_bounty_transfer_route(zero_path,
    key,
    1,
    authority.admission_binding,
    base,
    payer.public_key.bytes,
    usdc,
    U64.parse("50")?,
    U64.parse("90")?,
    U64.parse("60")?,
    base.issued_at)))
  Ok(true)
end

test("independent mixed rows retain signed packets, rotate fresh bindings, archive failure and preserve zero") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
