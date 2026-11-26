# Driven by scripts/c2sp-interop.sh against a real C2SP witness (litewitness).
# MESSENGER_C2SP_INTEROP_PHASE=prepare writes the log's verifier key and the
# add-checkpoint requests into MESSENGER_C2SP_INTEROP_DIR; =verify reads the
# witness's answers back and checks them with Transparency.Note and the v2
# client. Without those variables the test does nothing.

from Transparency.Client import transparency_verify_evidence_v2
from Transparency.CompactWire import (
  CompactConsistency,
  CompactInclusion,
  TransparencyEvidenceV2,
  WitnessCosignature
)
from Transparency.Merkle import TransparencyCheckpoint, WitnessKey, leaf_hash, sign_checkpoint
from Transparency.Note import (
  NoteCosignature,
  note_add_checkpoint_request,
  note_checkpoint_body,
  note_open_checkpoint,
  note_read_cosignatures,
  note_sign,
  note_verifier_key
)
from Transparency.Tree import (
  tlog_consistency_path,
  tlog_inclusion_path,
  tlog_leaf,
  tlog_list_oracle,
  tlog_root
)
from Transparency.Wire import encode_checkpoint

fn origin() -> String do
  "morseapp.io/log/interop"
end

fn signer(seed :: Int) -> SigningKeyPair!String do
  let bytes = case Bytes.repeat(seed, 32) do
    Err(_) -> Err("seed failed")
    Ok(value)
  end?
  case Crypto.signing_from_seed(bytes) do
    Err(_) -> Err("signing key failed")
    Ok(value)
  end
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn morse_leaves(forked :: Bool) -> List<Bytes>!String do
  let values = for index in 0..9 do
    if forked && index == 7 do
      leaf_hash(Bytes.from_utf8("interop-entry-7-forked"))?
    else
      leaf_hash(Bytes.from_utf8("interop-entry-#{index}"))?
    end
  end
  Ok(values)
end

fn rfc_leaves(values :: List<Bytes>) -> List<Bytes>!String do
  let wrapped = for value in values do
    tlog_leaf(2, value)?
  end
  Ok(wrapped)
end

fn checkpoint(values :: List<Bytes>,
  sequence :: Int,
  size :: Int) -> TransparencyCheckpoint!String do
  let log = signer(101)?
  let zero = case Bytes.repeat(0, 32) do
    Err(_) -> Err("bytes failed")
    Ok(value)
  end?
  sign_checkpoint(log.private_key,
    log.public_key.bytes,
    wide(sequence)?,
    List.take(values, size),
    zero,
    wide(1_790_000_000_000 + sequence)?)
end

fn body(values :: List<Bytes>, sequence :: Int, size :: Int) -> String!String do
  let rfc = rfc_leaves(values)?
  note_checkpoint_body(origin(),
    size,
    tlog_root(2, tlog_list_oracle(2, rfc), size)?,
    encode_checkpoint(checkpoint(values, sequence, size)?)?)
end

fn signed_note(text :: String, seed :: Int) -> String!String do
  let key = signer(seed)?
  note_sign(text, origin(), key.private_key, key.public_key.bytes)
end

fn prepare(dir :: String) -> Bool!String do
  let honest = morse_leaves(false)?
  let forked = morse_leaves(true)?
  let log = signer(101)?
  let first = signed_note(body(honest, 1, 5)?, 101)?
  let second = signed_note(body(honest, 2, 9)?, 101)?
  let fork = signed_note(body(forked, 2, 9)?, 101)?
  let foreign = signed_note(body(honest, 2, 9)?, 102)?
  let proof = tlog_consistency_path(2, tlog_list_oracle(2, rfc_leaves(honest)?), 5, 9)?
  File.write(dir <> "/origin", origin())?
  File.write(dir <> "/log.vkey", note_verifier_key(origin(), 1, log.public_key.bytes)?)?
  File.write(dir <> "/request-1.txt", note_add_checkpoint_request(0, [], first)?)?
  File.write(dir <> "/request-2.txt", note_add_checkpoint_request(5, proof, second)?)?
  File.write(dir <> "/request-fork.txt", note_add_checkpoint_request(9, [], fork)?)?
  File.write(dir <> "/request-stale.txt", note_add_checkpoint_request(0, [], first)?)?
  File.write(dir <> "/request-foreign.txt", note_add_checkpoint_request(9, [], foreign)?)?
  Ok(true)
end

fn ssh_public_key(line :: String) -> Bytes!String do
  let fields = String.split(String.trim(line), " ")
  let blob = case Bytes.from_base64(List.get(fields, 1)) do
    Err(_) -> Err("bad ssh key")
    Ok(value)
  end?
  if List.get(fields, 0) != "ssh-ed25519" || Bytes.length(blob) != 51 do
    Err("witness key is not ssh-ed25519")
  else
    case Bytes.slice(blob, 19, 32) do
      Err(_) -> Err("bad ssh key")
      Ok(value)
    end
  end
end

fn one_cosignature(dir :: String,
  response :: String,
  name :: String,
  key :: Bytes,
  text :: String) -> NoteCosignature!String do
  let values = note_read_cosignatures(File.read(dir <> "/" <> response)?, name, key, text)?
  if List.length(values) != 1 do
    Err(response <> ": expected one cosignature from " <> name)
  else
    Ok(List.get(values, 0))
  end
end

# The witness's cosignature on checkpoint 2 must count, through the dual
# inclusion rule, for a phone that pins the witness key and the origin.

fn evidence_from(cosignature :: NoteCosignature) -> TransparencyEvidenceV2!String do
  let honest = morse_leaves(false)?
  let second = checkpoint(honest, 2, 9)?
  let rfc = rfc_leaves(honest)?
  Ok(TransparencyEvidenceV2 {
    entry_bytes: Bytes.from_utf8("interop-entry-6"),
    inclusion: CompactInclusion {
      leaf_index: 6,
      tree_size: 9,
      path: tlog_inclusion_path(1, tlog_list_oracle(1, honest), 6, 9)?
    },
    consistency: CompactConsistency { old_size: 0, new_size: 9, path: [] },
    checkpoint: second,
    witnesses: [
      WitnessCosignature {
        kind: 2,
        witness_id: "litewitness",
        checkpoint_hash: Bytes.empty(),
        timestamp: cosignature.timestamp,
        signature: cosignature.signature
      }
    ],
    c2sp_root: tlog_root(2, tlog_list_oracle(2, rfc), 9)?,
    c2sp_path: tlog_inclusion_path(2, tlog_list_oracle(2, rfc), 6, 9)?
  })
end

fn verify(dir :: String) -> Bool!String do
  let name = String.trim(File.read(dir <> "/witness.name")?)
  let key = ssh_public_key(File.read(dir <> "/witness.pub")?)?
  let honest = morse_leaves(false)?
  let first_body = body(honest, 1, 5)?
  let second_body = body(honest, 2, 9)?
  let log = signer(101)?
  let first = one_cosignature(dir, "response-1.txt", name, key, first_body)?
  let second = one_cosignature(dir, "response-2.txt", name, key, second_body)?
  assert(first.timestamp > 1_700_000_000 && second.timestamp >= first.timestamp)
  let cosigned = signed_note(second_body, 101)? <> File.read(dir <> "/response-2.txt")?
  assert(note_open_checkpoint(cosigned, origin(), log.public_key.bytes)?.tree_size == 9)
  let evidence = evidence_from(second)?
  let pinned = [WitnessKey { witness_id: "litewitness", public_key: key }]
  let now = wide(second.timestamp * 1000)?
  assert(transparency_verify_evidence_v2(evidence,
    log.public_key,
    pinned,
    1,
    origin(),
    Bytes.empty(),
    now)?)
  assert(!transparency_verify_evidence_v2(evidence,
    log.public_key,
    pinned,
    1,
    "-",
    Bytes.empty(),
    now)?)
  Ok(true)
end

test("C2SP interop with a real witness") do
  let dir = Env.get("MESSENGER_C2SP_INTEROP_DIR", "")
  let phase = Env.get("MESSENGER_C2SP_INTEROP_PHASE", "")
  let result = if dir == "" do
    Ok(true)
  else if phase == "prepare" do
    prepare(dir)
  else if phase == "verify" do
    verify(dir)
  else
    Err("MESSENGER_C2SP_INTEROP_PHASE must be prepare or verify")
  end
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
