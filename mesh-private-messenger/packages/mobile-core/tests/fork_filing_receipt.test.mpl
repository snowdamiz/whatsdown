from Mobile.ForkFilingReceipt import mixed_filing_observation
from Transparency.TokenProofWrite import decode_token_prepared_proof
from Transparency.Fork import ForkProof, ForkTarget, decode_fork
from Transparency.Merkle import checkpoint_hash
from Solana.Read import pubkey

fn sample(root :: Json, name :: String) -> Json!String do
  let snapshots = Json.object_get(root, "snapshots")?
  for index in 0..Json.array_length(snapshots)? do
    let value = Json.array_get(snapshots, index)?
    if Json.as_string(Json.object_get(value, "name")?)? == name do
      return Ok(value)
    end
  end
  Err("missing_actual_sbf_receipt")
end

fn prove() -> Bool!String do
  let fixture = Env.get("MORSE_TOKEN_CUSTODY_FIXTURES_PATH", "")
  let evidence = Env.get("MORSE_PHONE_FILING_EVIDENCE", "")
  if fixture == "" || evidence == "" do
    return Err("actual_sbf_receipts_and_matching_frk_required")
  end
  let root = Json.parse(File.read(fixture)?)?
  let proof = decode_fork(File.read_bytes(evidence, 0, 8192)?)?
  let hash = case proof.second do
    SignedCheckpoint(second) -> checkpoint_hash(second)?
    AnchorReference(_) -> return Err("signed_fixture_required")
  end
  let zero = U64.parse("0")?
  for name in ["mixed-proof-prepared", "mixed-proof-settled"] do
    let s = sample(root, name)?
    let program = pubkey(Json.as_string(Json.object_get(s, "program")?)?)?
    let account = Json.object_get(Json.object_get(s, "accounts")?, "proof")?
    let raw = Bytes.from_hex(Json.as_string(Json.object_get(account, "data_hex")?)?)?
    let receipt = decode_token_prepared_proof(raw)?
    let slot = U64.parse(Json.as_string(Json.object_get(s, "context_slot")?)?)?
    let result = mixed_filing_observation(program, receipt.log_id, proof, hash, receipt, slot)?
    assert(result.status == if receipt.settled do
        "settled"
      else
        "prepared"
      end)
    assert(result.finder == receipt.finder && result.receipt_format == 2)
    assert(result.units == receipt.usdc_finder && result.morse_units == receipt.morse_finder)
    if !receipt.settled do
      assert(result.units == zero && result.morse_units == zero)
    end
    # A different local requested finder cannot change the chain winner.
    let requested = %{proof | finder: Bytes.from_hex(String.repeat("42", 32))?}
    assert(mixed_filing_observation(program,
      receipt.log_id,
      requested,
      hash,
      receipt,
      slot)? == result)
    let wrong = Bytes.from_hex(String.repeat("43", 32))?
    for bad in [
      %{receipt | first_hash: wrong},
      %{receipt | second_hash: wrong},
      %{receipt | proof_hash: wrong},
      %{receipt | finder: wrong},
      %{receipt | submitter: wrong},
      %{receipt | stage: wrong},
      %{receipt | anchored: true},
      %{receipt | kind: 3}
    ] do
      assert(Result.is_err(mixed_filing_observation(program,
        receipt.log_id,
        proof,
        hash,
        bad,
        slot)))
    end
    let row = List.head(receipt.rows)
    for bad in [%{row | witness: wrong}, %{row | identity: wrong}, %{row | public_key: wrong}] do
      assert(Result.is_err(mixed_filing_observation(program,
        receipt.log_id,
        proof,
        hash,
        %{receipt | rows: [bad] ++ List.tail(receipt.rows)},
        slot)))
    end
  end
  Ok(true)
end

test("phone binds actual SBF prepared and settled receipts to signed local evidence and the winning stage") do
  case prove() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
