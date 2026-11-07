from Transparency.C2sp import (
  sign_checkpoint_note,
  decode_checkpoint_note,
  verify_checkpoint_note,
  verified_cosignature
)
from Transparency.C2spText import cosignature_fresh_at
from Transparency.Merkle import (
  checkpoint_hash,
  leaf_hash_for,
  merkle_root_for,
  compact_consistency_proof_for,
  sign_tree_checkpoint_for
)

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn push_checkpoint(old_size :: Int, hashes :: List<Bytes>, note :: Bytes) -> HttpResponse!String do
  let lines = String.join(for hash in hashes do
      Bytes.to_base64(hash) <> "\n"
    end,
    "")
  let body = Bytes.concat(Bytes.from_utf8("old #{old_size}\n" <> lines <> "\n"), note)?
  Http.build(:post, Env.get("MORSE_C2SP_TEST_URL", "") <> "/add-checkpoint")
    |> Http.body_bytes(body)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(196608)
    |> Http.timeout(5000)
    |> Http.send()
end

fn verify_reply(note :: Bytes,
  response :: HttpResponse,
  log_key :: SigningPublicKey,
  witness_key :: SigningPublicKey) -> Bool!String do
  assert(response.status == 200)
  let parsed = decode_checkpoint_note(Bytes.concat(note, response.body_bytes)?)?
  assert(verify_checkpoint_note(parsed, log_key)?)
  let cosignature = verified_cosignature(parsed, Env.get("MORSE_C2SP_TEST_NAME", ""), witness_key)?
  let now = wide(DateTime.to_unix_ms(DateTime.utc_now()))?
  assert(cosignature_fresh_at(cosignature, now)?)
  Ok(true)
end

fn proof() -> Bool!String do
  let signer = case Crypto.signing_from_seed(Bytes.from_hex("6161616161616161616161616161616161616161616161616161616161616161")?) do
    Err(_) -> return Err("test signing key failed")
    Ok(value) -> value
  end
  let witness = SigningPublicKey {
    bytes: Bytes.from_hex(Env.get("MORSE_C2SP_TEST_PUBLIC_KEY", ""))?
  }
  let zero = Bytes.from_hex("0000000000000000000000000000000000000000000000000000000000000000")?
  let leaves = for index in 0..7 do
    leaf_hash_for(2, Bytes.from_utf8("third-party/#{index}"))?
  end
  let first_leaves = List.take(leaves, 3)
  let now = wide(DateTime.to_unix_ms(DateTime.utc_now()))?
  let first = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(3)?,
    merkle_root_for(2, first_leaves)?,
    zero,
    now)?
  let first_note = sign_checkpoint_note(first, signer.private_key)?
  assert(verify_reply(first_note,
    push_checkpoint(0, List.new(), first_note)?,
    signer.public_key,
    witness)?)
  let next = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(2)?,
    wide(7)?,
    merkle_root_for(2, leaves)?,
    checkpoint_hash(first)?,
    now)?
  let next_note = sign_checkpoint_note(next, signer.private_key)?
  let consistency = compact_consistency_proof_for(2, first_leaves, leaves)?
  assert(push_checkpoint(3,
    [zero] ++ List.drop(consistency.leaf_hashes, 1),
    next_note)?.status == 422)
  let stale = push_checkpoint(0, List.new(), next_note)?
  assert(stale.status == 409 && Bytes.to_utf8(stale.body_bytes)? == "3\n")
  assert(verify_reply(next_note,
    push_checkpoint(3, consistency.leaf_hashes, next_note)?,
    signer.public_key,
    witness)?)
  assert(verify_reply(next_note,
    push_checkpoint(7, List.new(), next_note)?,
    signer.public_key,
    witness)?)
  let fork = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(3)?,
    wide(7)?,
    Crypto.sha256(Bytes.from_utf8("fork")),
    checkpoint_hash(next)?,
    now)?
  assert(push_checkpoint(7,
    List.new(),
    sign_checkpoint_note(fork, signer.private_key)?)?.status == 422)
  Ok(true)
end

test("a third-party C2SP witness cosigns Mesh checkpoints and rejects forks and bad proofs") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
