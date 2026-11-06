from Witness.History import verify_history_header, verify_history_proof
from Transparency.Merkle import (
  TransparencyCheckpoint,
  ConsistencyProof,
  checkpoint_hash,
  sign_checkpoint,
  sign_tree_checkpoint_for,
  compact_consistency_proof
)

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn signed(pair :: borrow SigningKeyPair,
  sequence :: Int,
  timestamp :: Int,
  previous :: Bytes) -> TransparencyCheckpoint!String do
  sign_checkpoint(pair.private_key,
    pair.public_key.bytes,
    wide(sequence)?,
    [Crypto.sha256(Bytes.from_utf8("leaf"))],
    previous,
    wide(timestamp)?)
end

fn rejected(previous :: Option<TransparencyCheckpoint>,
  current :: TransparencyCheckpoint,
  public_key :: SigningPublicKey,
  now :: Int) -> Bool!String do
  case verify_history_header(previous, current, public_key, wide(now)?) do
    Err(_) -> Ok(true)
    Ok(_) -> Ok(false)
  end
end

fn proof() -> Bool!String do
  let pair = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("test signer failed")
  end
  let zero = Bytes.from_hex(String.join(for _ in 0..32 do
      "00"
    end,
    ""))?
  let prior = signed(pair, 1, 1000000, zero)?
  let current = signed(pair, 2, 1000001, checkpoint_hash(prior)?)?
  verify_history_header(Some(prior), current, pair.public_key, wide(1000001)?)?
  verify_history_header(Some(current), current, pair.public_key, wide(1000001)?)?
  assert(rejected(None, signed(pair, 1, 1060002, zero)?, pair.public_key, 1000001)?)
  assert(rejected(None, signed(pair, 1, 940000, zero)?, pair.public_key, 1000001)?)
  assert(rejected(Some(prior),
    signed(pair, 2, 1000000, checkpoint_hash(prior)?)?,
    pair.public_key,
    1000001)?)
  assert(rejected(Some(prior),
    signed(pair, 2, 999999, checkpoint_hash(prior)?)?,
    pair.public_key,
    1000001)?)
  assert(rejected(Some(prior), signed(pair, 2, 1000001, zero)?, pair.public_key, 1000001)?)
  assert(rejected(Some(prior), signed(pair, 1, 1000001, zero)?, pair.public_key, 1000001)?)
  assert(rejected(Some(current), prior, pair.public_key, 1000001)?)
  # A skipped sequence has an unknown direct parent; the compact consistency
  # proof, verified separately, establishes its append-only relationship.
  verify_history_header(Some(prior),
    signed(pair, 4, 1000002, zero)?,
    pair.public_key,
    wide(1000002)?)?
  verify_history_header(None, signed(pair, 1, 940001, zero)?, pair.public_key, wide(1000001)?)?
  verify_history_header(None, signed(pair, 1, 1060001, zero)?, pair.public_key, wide(1000001)?)?
  let proof = compact_consistency_proof([Crypto.sha256(Bytes.from_utf8("leaf"))],
    [Crypto.sha256(Bytes.from_utf8("leaf"))])?
  assert(verify_history_proof(prior, current, proof)?)
  assert(!verify_history_proof(prior, %{current | tree_size: wide(2)?}, proof)?)
  let v2 = sign_tree_checkpoint_for(2,
    pair.private_key,
    pair.public_key.bytes,
    wide(2)?,
    prior.tree_size,
    prior.tree_root,
    checkpoint_hash(prior)?,
    wide(1000001)?)?
  assert(rejected(Some(prior), v2, pair.public_key, 1000001)?)
  assert(!verify_history_proof(prior, v2, proof)?)
  # A one-leaf tree has no internal nodes, so its root alone cannot distinguish
  # proof profiles. The authenticated version must choose the proof algorithm.
  assert(!verify_history_proof(v2, v2, proof)?)
  assert(verify_history_proof(v2, v2, %{proof | version: 3})?)
  Ok(true)
end

test("witness rejects skew, time regression, broken adjacent links and changed retries") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
