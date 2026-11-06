from Client.Security import (
  security_policy,
  verify_cli_evidence,
  work_difficulty,
  resolution_path,
  session_minimum
)
from Transparency.Merkle import (
  compact_consistency_proof,
  compact_inclusion_proof,
  leaf_hash,
  sign_checkpoint,
  sign_witness,
  leaf_hash_for,
  sign_tree_checkpoint_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for
)
from Transparency.Wire import TransparencyEvidence

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("key generation failed")
    Ok(value)
  end
end

fn proof() -> Bool!String do
  let signer = pair()?
  let a = pair()?
  let b = pair()?
  let c = pair()?
  let frame = String.join([
      "2",
      Bytes.to_hex(signer.public_key.bytes),
      String.repeat("11", 32),
      "8",
      "2",
      "3",
      "witness-a " <> Bytes.to_hex(a.public_key.bytes) <> " Morse",
      "witness-b " <> Bytes.to_hex(b.public_key.bytes) <> " Outside",
      "witness-c " <> Bytes.to_hex(c.public_key.bytes) <> " Outside",
      "-",
      "0",
      "-"
    ],
    "\n")
  let environment = Map.put(Map.new(), "MESSENGER_SECURITY_CONFIG", frame)
  let policy = security_policy(environment)?
  assert(session_minimum(Map.new())? == 1)
  assert(session_minimum(environment)? == 1)
  let wrapped = Map.put(environment, "MESSENGER_SECURITY_CONFIG", "6\n2\n" <> frame)
  assert(session_minimum(wrapped)? == 2)
  assert(resolution_path(security_policy(wrapped)?) == resolution_path(policy))
  for invalid in [
    "",
    "6\n0\n" <> frame,
    "6\n3\n" <> frame,
    "6\n02\n" <> frame,
    "6\n2\n6\n1\n" <> frame,
    "6\n2\n" <> frame <> "\n"
  ] do
    assert(Result.is_err(session_minimum(Map.put(environment,
      "MESSENGER_SECURITY_CONFIG",
      invalid))))
  end
  assert(work_difficulty(environment)? == 8)
  # A registration-only fixture needs the deployment's work difficulty, not
  # lookup pins. Keep that legacy CLI entry point usable.
  assert(work_difficulty(Map.new())? == 16)
  assert(work_difficulty(Map.put(Map.new(), "MESSENGER_ABUSE_DIFFICULTY", "8"))? == 8)
  assert(policy.threshold == 2
    && List.length(policy.witnesses) == 3
    && policy.abuse_difficulty == 8)
  let entry = Bytes.from_utf8("CLI evidence")
  let leaves = [leaf_hash(entry)?]
  let now = U64.parse("1000000")?
  let checkpoint = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    U64.parse("1")?,
    leaves,
    Bytes.from_hex(String.repeat("00", 32))?,
    now)?
  let first = sign_witness("witness-a", a.private_key, checkpoint)?
  let third = sign_witness("witness-c", c.private_key, checkpoint)?
  let evidence = TransparencyEvidence {
    entry_bytes: entry,
    checkpoint: checkpoint,
    inclusion: compact_inclusion_proof(leaves, 0)?,
    consistency: compact_consistency_proof(List.new(), leaves)?,
    witnesses: [first, third]
  }
  assert(verify_cli_evidence(evidence, policy, now)?)
  assert(!verify_cli_evidence(%{evidence | witnesses: [first, first]}, policy, now)?)
  assert(!verify_cli_evidence(evidence, policy, U64.parse("1300001")?)?)
  let native_rows = String.split(frame, "\n")
  let migration = String.join(["3"]
      ++ List.drop(native_rows, 1)
      ++ [
        "2",
        "2",
        "2",
        "witness-a " <> Bytes.to_hex(a.public_key.bytes) <> " Morse",
        "witness-b " <> Bytes.to_hex(b.public_key.bytes) <> " Outside"
      ],
    "\n")
  let rfc_policy = security_policy(Map.put(Map.new(), "MESSENGER_SECURITY_CONFIG", migration))?
  assert(resolution_path(policy) == "/v1/devices/resolve")
  assert(resolution_path(rfc_policy) == "/v2/devices/resolve")
  let rfc_leaf = leaf_hash_for(2, entry)?
  let rfc_checkpoint = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    U64.parse("1")?,
    U64.parse("1")?,
    rfc_leaf,
    Bytes.from_hex(String.repeat("00", 32))?,
    now)?
  let rfc = TransparencyEvidence {
    entry_bytes: entry,
    checkpoint: rfc_checkpoint,
    inclusion: compact_inclusion_proof_for(2, [rfc_leaf], 0)?,
    consistency: compact_consistency_proof_for(2, List.new(), [rfc_leaf])?,
    witnesses: [
      sign_witness("witness-a", a.private_key, rfc_checkpoint)?,
      sign_witness("witness-c", c.private_key, rfc_checkpoint)?
    ]
  }
  assert(verify_cli_evidence(rfc, rfc_policy, now)?)
  assert(!verify_cli_evidence(rfc, policy, now)?)
  assert(!verify_cli_evidence(evidence, rfc_policy, now)?)
  let legacy = Map.new()
    |> Map.put("MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX", Bytes.to_hex(signer.public_key.bytes))
    |> Map.put("MESSENGER_WITNESS_A_PUBLIC_KEY_HEX", Bytes.to_hex(a.public_key.bytes))
    |> Map.put("MESSENGER_WITNESS_B_PUBLIC_KEY_HEX", Bytes.to_hex(b.public_key.bytes))
  assert(!verify_cli_evidence(evidence, security_policy(legacy)?, now)?)
  let second = sign_witness("witness-b", b.private_key, checkpoint)?
  assert(verify_cli_evidence(%{evidence | witnesses: [first, second]},
    security_policy(legacy)?,
    now)?)
  # An explicitly provisioned but invalid frame cannot fall back to legacy pins.
  case security_policy(Map.put(legacy, "MESSENGER_SECURITY_CONFIG", frame <> "\n")) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case security_policy(Map.put(legacy, "MESSENGER_SECURITY_CONFIG", "")) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case security_policy(Map.put(legacy, "MESSENGER_ABUSE_DIFFICULTY", "08")) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("CLI honors native majority pins, legacy pins, freshness and invalid-config failures") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
