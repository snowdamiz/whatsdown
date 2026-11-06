from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Mobile.AnchorCheck import AnchorObservation, AnchorView, check_anchor_attested_at
from Mobile.Codec import mobile_join, mobile_byte, mobile_append
from Mobile.TransparencySafety import retained_fork, require_log_changes_allowed
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, open_local, local_context
from Tests.Support import database_path, repeated
from Tests.GroupConsistencySupport import signing_pair, wide
from Solana.Read import Pubkey, pubkey
from Transparency.AnchorEvidence import evidence_anchor
from Transparency.AnchorContext import (
  AnchorEvidenceContext,
  decode_anchor_context,
  encode_anchor_context
)
from Transparency.AnchorRing import AnchorEntry, decode_anchor_entry
from Transparency.AnchorWitnessSet import AnchorWitnessSet, decode_anchor_witness_set
from Transparency.Fork import (
  ForkProof,
  ForkTarget,
  ForkPaths,
  ForkVerdict,
  decode_fork,
  encode_fork,
  fork_at_anchor
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  WitnessAttestation,
  checkpoint_hash,
  sign_tree_checkpoint_for,
  sign_witness
)
from Transparency.Wire import encode_checkpoint, encode_witnesses, decode_witnesses
from Transparency.C2spText import checkpoint_note_text

fn little(value :: Int, length :: Int) -> Bytes!String do
  if length == 0 do
    return Ok(Bytes.empty())
  end
  mobile_append(mobile_byte(value % 256)?, little(value / 256, length - 1)?)
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  mobile_join(parts, 0, Bytes.empty())
end

fn member(pin :: WitnessKey, index :: Int) -> Bytes!String do
  join([
    repeated(index, 32)?,
    mobile_byte(String.length(pin.witness_id))?,
    repeated(0, 7)?,
    Bytes.from_utf8(pin.witness_id),
    repeated(0, 64 - String.length(pin.witness_id))?,
    pin.public_key,
    repeated(index + 10, 32)?
  ])
end

fn records(checkpoint :: TransparencyCheckpoint,
  witnesses :: List<WitnessKey>) -> List<Bytes>!String do
  let addresses = anchor_addresses(pubkey(String.repeat("1", 32))?, "morse-main")?
  let header = join([
    Bytes.from_hex("4d524701")?,
    addresses.log_id,
    little(0, 2)?,
    little(1, 2)?,
    little(9, 8)?,
    little(7, 8)?,
    little(50, 8)?
  ])?
  let entry = join([
    little(9, 8)?,
    little(7, 8)?,
    checkpoint.tree_root,
    checkpoint_hash(checkpoint)?,
    little(2000, 8)?,
    little(50, 8)?,
    little(3, 2)?,
    mobile_byte(2)?,
    mobile_byte(0)?,
    little(1, 2)?,
    little(7, 2)?
  ])?
  # The active pointer has rotated; the entry still belongs to generation 7.
  let log = join([
    Bytes.from_hex("4d4c470102000a00")?,
    Bytes.from_utf8("morse-main"),
    repeated(0, 22)?,
    addresses.log_id,
    checkpoint.service_public_key,
    repeated(2, 32)?,
    addresses.ring.bytes,
    repeated(3, 32)?,
    little(100, 8)?,
    little(8, 2)?,
    little(10, 2)?,
    Bytes.from_utf8("morse-main"),
    repeated(0, 130)?
  ])?
  let set = join([
    Bytes.from_hex("4d575301")?,
    addresses.log_id,
    little(7, 2)?,
    mobile_byte(2)?,
    mobile_byte(0)?,
    little(10, 8)?,
    repeated(0, 16)?,
    member(List.get(witnesses, 0), 1)?,
    member(List.get(witnesses, 1), 2)?,
    repeated(0, 14 * 168)?
  ])?
  Ok([header, entry, log, set])
end

actor rpc(port :: Int, accounts :: List<Bytes>, mode :: String, calls :: String) do
  HTTP.router()
    |> HTTP.on_post("/",
      fn(request :: Request) do
        let body = Request.body(request)
        if String.contains(body, "getBlockTime") do
          return HTTP.response(200, """{"jsonrpc":"2.0","id":1,"result":9000}""")
        end
        let index = if String.contains(body, "\"length\":2752") do
          3
        else if String.contains(body, "\"length\":352") do
          2
        else if String.contains(body, "\"length\":104") do
          1
        else
          0
        end
        if index == 3 do
          File.append(calls, "s")
          if !String.contains(body, "CGqsSLyfU419ptwTTGdpiwKPGrMs9niP7sM3kEAtnPDU")
            || !String.contains(body, "\"minContextSlot\":51") do
            return HTTP.response(400, "wrong historical address or floor")
          end
          if File.read(mode).unwrap_or("down") == "down" do
            return HTTP.response(503, "")
          end
        end
        let bytes = List.get(accounts, index)
        HTTP.response(200,
          """{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":51},"value":{"data":["#{Bytes.to_base64(bytes)}","base64"],"executable":false,"lamports":1,"owner":"11111111111111111111111111111111","rentEpoch":0}}}""")
      end)
    |> HTTP.serve(port)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let log = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  let outside = signing_pair()?
  let pins = [
    WitnessKey { witness_id: "a", public_key: a.public_key.bytes },
    WitnessKey { witness_id: "b", public_key: b.public_key.bytes }
  ]
  let zero = repeated(0, 32)?
  let private = sign_tree_checkpoint_for(2,
    log.private_key,
    log.public_key.bytes,
    wide(8)?,
    wide(7)?,
    repeated(1, 32)?,
    zero,
    wide(1000)?)?
  let public = sign_tree_checkpoint_for(2,
    log.private_key,
    log.public_key.bytes,
    wide(9)?,
    wide(7)?,
    repeated(2, 32)?,
    zero,
    wide(2000)?)?
  let signature = case Crypto.sign(b.private_key,
    Bytes.from_utf8("cosignature/v1\ntime 1\n"
      <> checkpoint_note_text(encode_checkpoint(private)?)?)) do
    Err(_) -> return Err("signing failed")
    Ok(value) -> value.bytes
  end
  let signatures = [
    sign_witness("a", a.private_key, private)?,
    WitnessAttestation {
      witness_id: "b",
      checkpoint_hash: checkpoint_hash(private)?,
      signature: mobile_append(Bytes.from_hex("0000000000000001")?, signature)?
    },
    sign_witness("outside", outside.private_key, private)?
  ]
  let accounts = records(public, pins)?
  let mode = database_path("anchor-attribution-mode")?
  let calls = database_path("anchor-attribution-calls")?
  File.write(mode, "up")?
  File.write(calls, "")?
  for port in 19091..19094 do
    let _rpc = spawn(rpc, port, accounts, mode, calls)
  end
  Timer.sleep(100)
  let addresses = anchor_addresses(pubkey(String.repeat("1", 32))?, "morse-main")?
  let anchor_pins = AnchorPins {
    program: pubkey(String.repeat("1", 32))?,
    ring: addresses.ring,
    log_name: "morse-main",
    log_id: addresses.log_id,
    endpoints: ["http://127.0.0.1:19091/", "http://127.0.0.1:19092/", "http://127.0.0.1:19093/"]
  }
  let view = AnchorView {
    checkpoint: encode_checkpoint(private)?,
    origin: "http://127.0.0.1:19094",
    witnesses: signatures,
    leaf: Bytes.empty()
  }
  # A rejected candidate never enters the checkpoint/witness cache. Its private
  # signatures must commit with the pause even when the set RPC is unavailable.
  for setting in ["up", "down"] do
    File.write(mode, setting)?
    let path = database_path("anchor-attribution-#{setting}")?
    ensure_schema(path)?
    assert(check_anchor_attested_at(path,
      key,
      anchor_pins,
      log.public_key.bytes,
      2,
      wide(9000000)?,
      true,
      pins,
      view)?.status == "mismatch")
    let retained = decode_fork(retained_fork(path, key)?)?
    assert(List.length(retained.attestations) == 2)
    assert(List.map(retained.attestations, fn(value) do value.witness_id end) == ["a", "b"])
    let bytes = open_local(load_blob(path, "transparency-fork-anchor/v1")?,
      key,
      local_context("transparency-fork-anchor/v1")?)?
    let context = decode_anchor_context(bytes)?
    assert(Bytes.secure_equals(encode_anchor_context(context)?, bytes))
    assert(Bytes.secure_equals(context.witnesses, encode_witnesses(signatures)?))
    assert(Bytes.secure_equals(context.checkpoint, view.checkpoint))
    assert(Bytes.secure_equals(context.entry, List.get(accounts, 1)))
    assert(Bytes.secure_equals(context.fork, retained_fork(path, key)?))
    assert(Bytes.length(context.witness_set) == if setting == "up" do
        2752
      else
        0
      end)
    # A relay independently resolves the historical accounts. Recorded context
    # alone grants no chain trust, even though it retains the exact bytes read.
    let anchor = evidence_anchor(addresses.log_id,
      0,
      log.public_key.bytes,
      decode_anchor_entry(List.get(accounts, 1))?,
      decode_anchor_witness_set(List.get(accounts, 3))?)?
    assert(List.length(fork_at_anchor(retained, log.public_key, pins, anchor)?.witnesses) == 2)
    case require_log_changes_allowed(path, key) do
      Err(error) -> assert(error == "transparency_fork_detected")
      Ok(_) -> assert(false)
    end
    # The context codec is bounded, canonical and rejects truncated/trailing data.
    for invalid in [
      Bytes.slice(bytes, 0, Bytes.length(bytes) - 1)?,
      mobile_append(bytes, mobile_byte(0)?)?
    ] do
      case decode_anchor_context(invalid) do
        Err(_) -> nil
        Ok(_) -> assert(false)
      end
    end
    # Upgrade old sealed records without inventing signatures or registry data.
    let v2_length = Bytes.length(bytes) - 8 - Bytes.length(context.private_leaf) - Bytes.length(context.served_leaf)
    let v2 = decode_anchor_context(mobile_append(Bytes.from_utf8("ACV2"),
      Bytes.slice(bytes, 4, v2_length - 4)?)?)?
    assert(Bytes.length(v2.private_leaf) == 0 && Bytes.length(v2.served_leaf) == 0)
    assert(Bytes.secure_equals(v2.witnesses, context.witnesses))
    let legacy_length = v2_length - 8 - Bytes.length(context.witnesses) - Bytes.length(context.witness_set)
    let legacy = decode_anchor_context(mobile_append(Bytes.from_utf8("ACV1"),
      Bytes.slice(bytes, 4, legacy_length - 4)?)?)?
    assert(Bytes.length(legacy.witnesses) == 0 && Bytes.length(legacy.witness_set) == 0)
    assert(Bytes.secure_equals(legacy.fork, context.fork))
    # The observation codec retains even the largest canonical v3 frame.
    # Its paths/signatures are intentionally unverified: framing is not admission.
    let maximum_proof = encode_fork(%{retained |
      kind: 2,
      second: SignedCheckpoint(retained.first),
      attestations: for index in 0..32 do
        WitnessAttestation {
          witness_id: String.repeat("a", 62) <> Int.to_string(index + 10),
          checkpoint_hash: checkpoint_hash(retained.first)?,
          signature: repeated(0, 72)?
        }
      end,
      contradiction: Some(ForkPaths {
        leaf_index: wide(0)?,
        first_path: for _ in 0..32 do
          repeated(0, 32)?
        end,
        first_leaf: repeated(1, 32)?,
        second_path: for _ in 0..32 do
          repeated(0, 32)?
        end,
        second_leaf: repeated(2, 32)?
      })
    })?
    assert(Bytes.length(maximum_proof) == 8009)
    let maximum_context = encode_anchor_context(%{context | fork: maximum_proof})?
    assert(Bytes.secure_equals(decode_anchor_context(maximum_context)?.fork, maximum_proof))
    for oversized in [
      %{context | origin: String.repeat("x", 2049)},
      %{context | fork: repeated(0, 8010)?},
      %{context | witnesses: repeated(0, 2775)?},
      %{context | witness_set: repeated(0, 2753)?},
      %{context | private_leaf: repeated(0, 1075)?},
      %{context | served_leaf: repeated(0, 1075)?}
    ] do
      case encode_anchor_context(oversized) do
        Err(_) -> nil
        Ok(_) -> assert(false)
      end
    end
    File.delete(path)?
  end
  assert(String.length(File.read(calls)?) == 5)
  File.delete(mode)?
  File.delete(calls)?
  Ok(true)
end

test("anchor forks retain private attestations and resolve historical witness keys without depending on RPC availability") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
