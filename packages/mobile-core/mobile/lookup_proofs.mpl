from Binary.Reader import BinaryReader, reader
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_path,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_path,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)
from Transparency.Merkle import WitnessAttestation

##! Mobile.LookupProofs: what this device keeps of its recent lookups so a
##! fork it later catches can be proven (plan §6.7): the checkpoint each lookup
##! verified, the Morse witness attestations it verified on it, and the looked-up
##! leaf with its audit path. A contradiction proof (FRK kind 2) against the
##! public record names one of these leaves.
##!
##! Local frame: u8 1 || "KLP" || u8 count || count x vector32(record), newest
##! last; record = KTK188 || u8 a || a x (u8 id length || id || hash32 ||
##! sig64) || u64 leaf index || leaf32 || u8 p || p x 32.

pub struct LookupProof do
  checkpoint :: Bytes
  attestations :: List<WitnessAttestation>
  leaf_index :: Int
  leaf :: Bytes
  path :: List<Bytes>
end

struct ReadAttestations do
  state :: BinaryReader
  value :: List<WitnessAttestation>
end

fn limit() -> Int do
  8
end

fn label() -> String do
  "transparency-lookup-proofs/v1"
end

pub fn lookup_proofs_label() -> String do
  label()
end

fn encode_attestation(value :: WitnessAttestation) -> Bytes!String do
  let id = Bytes.from_utf8(value.witness_id)
  tcodec_join([tcodec_u8(Bytes.length(id))?, id, value.checkpoint_hash, value.signature])
end

fn encode_record(value :: LookupProof) -> Bytes!String do
  let attestations = for attestation in value.attestations do
    encode_attestation(attestation)?
  end
  tcodec_join([value.checkpoint, tcodec_u8(List.length(value.attestations))?]
    ++ attestations
    ++ [tcodec_u64(value.leaf_index)?, value.leaf, tcodec_path(value.path, 64)?])
end

fn take_attestations(state :: BinaryReader,
  count :: Int,
  output :: List<WitnessAttestation>) -> ReadAttestations!String do
  if List.length(output) >= count do
    Ok(ReadAttestations { state: state, value: output })
  else
    let length = tcodec_take_u8(state)?
    let id = tcodec_take_fixed(length.state, length.value)?
    let hash = tcodec_take_fixed(id.state, 32)?
    let signature = tcodec_take_fixed(hash.state, 64)?
    let text = case Bytes.to_utf8(id.value) do
      Err(_) -> Err("invalid_lookup_proofs")
      Ok(value)
    end?
    take_attestations(signature.state,
      count,
      List.append(output,
        WitnessAttestation {
          witness_id: text,
          checkpoint_hash: hash.value,
          signature: signature.value
        }))
  end
end

fn decode_record(input :: Bytes) -> LookupProof!String do
  let state = case reader(input, 16384) do
    Err(_) -> Err("invalid_lookup_proofs")
    Ok(value)
  end?
  let checkpoint = tcodec_take_fixed(state, 188)?
  let count = tcodec_take_u8(checkpoint.state)?
  let attestations = take_attestations(count.state, count.value, List.new())?
  let index = tcodec_take_u64(attestations.state)?
  let leaf = tcodec_take_fixed(index.state, 32)?
  let path = tcodec_take_path(leaf.state, 64)?
  tcodec_done(path.state)?
  Ok(LookupProof {
    checkpoint: checkpoint.value,
    attestations: attestations.value,
    leaf_index: index.value,
    leaf: leaf.value,
    path: path.value
  })
end

fn take_records(state :: BinaryReader,
  count :: Int,
  output :: List<LookupProof>) -> List<LookupProof>!String do
  if List.length(output) >= count do
    tcodec_done(state)?
    Ok(output)
  else
    let record = tcodec_take_vector(state, 16384)?
    take_records(record.state, count, List.append(output, decode_record(record.value)?))
  end
end

fn decode_list(input :: Bytes) -> List<LookupProof>!String do
  let state = tcodec_start(input, 16 + limit() * 16388, 1, "KLP")?
  let count = tcodec_take_u8(state)?
  take_records(count.state, count.value, List.new())
end

pub fn lookup_proofs_load(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<LookupProof>!String do
  case load_blob(database_path, label()) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok(blob) -> case decode_list(open_local(blob, wrapping_key, local_context(label())?)?) do
      Err(_) -> Ok(List.new())
      Ok(value)
    end
  end
end

# The sealed list with `added` appended: an older proof of the same leaf is
# replaced, and the oldest past the limit are dropped.

pub fn lookup_proofs_blob(existing :: List<LookupProof>,
  added :: LookupProof,
  wrapping_key :: borrow StorageKey) -> Bytes!String do
  let kept = List.filter(existing, fn value -> value.leaf_index != added.leaf_index end) ++ [added]
  let recent = List.drop(kept, List.length(kept) - limit())
  let records = for value in recent do
    tcodec_vector(encode_record(value)?)?
  end
  let frame = tcodec_join([tcodec_u8(1)?, Bytes.from_utf8("KLP"), tcodec_u8(List.length(recent))?]
    ++ records)?
  seal_local(frame, wrapping_key, local_context(label())?)
end
