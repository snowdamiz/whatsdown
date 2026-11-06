from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.RpcTransport import webpki_rpc_transport
from Mobile.AnchorCheck import (
  AnchorObservation,
  AnchorView,
  check_anchor_attested_at,
  check_anchor_at,
  check_anchor_view_at,
  load_anchor_observation,
  anchor_identity
)
from Mobile.TransparencySafety import require_log_changes_allowed, retained_fork
from Mobile.AnchorSchedule import AnchorSchedule, load_anchor_schedule
from Mobile.Codec import mobile_join, mobile_append, mobile_byte
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, seal_local, open_local, local_context
from Storage.Records import store_updated_blobs
from Solana.Read import Pubkey, pubkey
from Transparency.AnchorConsistency import AnchorConsistency, compare_anchor
from Mobile.Codec import mobile_read_u64, mobile_write_u64
from Tests.GroupConsistencySupport import signing_pair, wide
from Tests.Support import database_path, repeated
from Transparency.AnchorRing import AnchorEntry
from Transparency.AnchorContext import AnchorEvidenceContext, decode_anchor_context
from Transparency.LeafProof import LeafProof, encode_leaf_proof
from Transparency.Merkle import (
  TransparencyCheckpoint,
  checkpoint_hash,
  sign_tree_checkpoint_for,
  compact_consistency_proof_for,
  compact_inclusion_proof_for,
  merkle_root_for
)
from Transparency.Wire import (
  encode_checkpoint,
  decode_checkpoint,
  encode_consistency_proof,
  decode_transparency_tree_query
)
from Transparency.Fork import ForkProof, ForkTarget, decode_fork

fn entry(checkpoint :: TransparencyCheckpoint) -> AnchorEntry!String do
  Ok(AnchorEntry {
    sequence: checkpoint.sequence,
    tree_size: checkpoint.tree_size,
    tree_root: checkpoint.tree_root,
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    timestamp: checkpoint.timestamp,
    slot: wide(50)?,
    cosign_bitmap: 0,
    log_version: checkpoint.version,
    rollback: false,
    native_bitmap: 0,
    witness_generation: 0
  })
end

fn little(value :: Int, count :: Int) -> Bytes!String do
  if count == 0 do
    return Ok(Bytes.empty())
  end
  mobile_append(mobile_byte(value % 256)?, little(value / 256, count - 1)?)
end

fn rpc_bytes(checkpoint :: TransparencyCheckpoint, length :: Int) -> Bytes!String do
  let addresses = anchor_addresses(pubkey(String.repeat("1", 32))?, "morse-main")?
  if length == 64 do
    return mobile_join([
        Bytes.from_hex("4d524701")?,
        addresses.log_id,
        little(0, 2)?,
        little(1, 2)?,
        little(U64.to_int(checkpoint.sequence)?, 8)?,
        little(U64.to_int(checkpoint.tree_size)?, 8)?,
        little(50, 8)?
      ],
      0,
      Bytes.empty())
  else if length == 104 do
    return mobile_join([
        little(U64.to_int(checkpoint.sequence)?, 8)?,
        little(U64.to_int(checkpoint.tree_size)?, 8)?,
        checkpoint.tree_root,
        checkpoint_hash(checkpoint)?,
        little(U64.to_int(checkpoint.timestamp)?, 8)?,
        little(50, 8)?,
        little(0, 2)?,
        mobile_byte(2)?,
        mobile_byte(0)?,
        little(0, 4)?
      ],
      0,
      Bytes.empty())
  else
    return mobile_join([
        Bytes.from_hex("4d4c470102000a00")?,
        Bytes.from_utf8("morse-main"),
        repeated(0, 22)?,
        addresses.log_id,
        checkpoint.service_public_key,
        repeated(2, 32)?,
        addresses.ring.bytes,
        repeated(3, 32)?,
        little(100, 8)?,
        little(0, 2)?,
        little(10, 2)?,
        Bytes.from_utf8("morse-main"),
        repeated(0, 130)?
      ],
      0,
      Bytes.empty())
  end
end

actor rpc(port :: Int, checkpoint :: TransparencyCheckpoint, mode :: String) do
  HTTP.router()
    |> HTTP.on_post("/",
      fn(request :: Request) do
        let body = Request.body(request)
        if String.contains(body, "getBlockTime") do
          HTTP.response(200, """{"jsonrpc":"2.0","id":1,"result":9000}""")
        else
          let length = if String.contains(body, "\"length\":352") do
            352
          else if String.contains(body, "\"length\":104") do
            104
          else
            64
          end
          let active = case File.read(mode <> ".active") do
            Err(_) -> checkpoint
            Ok(hex) -> case Bytes.from_hex(hex) do
              Err(_) -> checkpoint
              Ok(bytes) -> decode_checkpoint(bytes).unwrap_or(checkpoint)
            end
          end
          let advanced = File.exists(mode <> ".advanced")
          case rpc_bytes(active, length) do
            Err(error) -> HTTP.response(500, error)
            Ok(bytes) -> do
              let adjusted = if advanced && length == 64 do
                mobile_join([
                    Bytes.slice(bytes, 0, 36).unwrap_or(Bytes.empty()),
                    little(1, 2).unwrap_or(Bytes.empty()),
                    little(2, 2).unwrap_or(Bytes.empty()),
                    Bytes.slice(bytes, 40, 16).unwrap_or(Bytes.empty()),
                    little(52, 8).unwrap_or(Bytes.empty())
                  ],
                  0,
                  Bytes.empty()).unwrap_or(Bytes.empty())
              else if advanced && length == 104 do
                mobile_join([
                    Bytes.slice(bytes, 0, 88).unwrap_or(Bytes.empty()),
                    little(52, 8).unwrap_or(Bytes.empty()),
                    Bytes.slice(bytes, 96, 8).unwrap_or(Bytes.empty())
                  ],
                  0,
                  Bytes.empty()).unwrap_or(Bytes.empty())
              else
                bytes
              end
              let slot = if advanced do
                "53"
              else
                "51"
              end
              HTTP.response(200,
                """{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{slot}},"value":{"data":["#{Bytes.to_base64(adjusted)}","base64"],"executable":false,"lamports":1,"owner":"11111111111111111111111111111111","rentEpoch":0}}}""")
            end
          end
        end
      end)
    |> HTTP.serve(port)
end

fn scheduled(local :: TransparencyCheckpoint,
  baseline :: TransparencyCheckpoint,
  anchored :: TransparencyCheckpoint,
  contradictory :: TransparencyCheckpoint,
  divergent :: TransparencyCheckpoint,
  private_leaf :: Bytes,
  pending_private :: TransparencyCheckpoint,
  earlier_public :: TransparencyCheckpoint,
  earlier_good :: TransparencyCheckpoint,
  mode :: String) -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("scheduled-anchor-consistency")?
  ensure_schema(path)?
  let addresses = anchor_addresses(pubkey(String.repeat("1", 32))?, "morse-main")?
  let pins = AnchorPins {
    program: pubkey(String.repeat("1", 32))?,
    ring: addresses.ring,
    log_name: "morse-main",
    log_id: addresses.log_id,
    rpc: webpki_rpc_transport(["http://127.0.0.1:19084/", "http://127.0.0.1:19085/", "http://127.0.0.1:19086/"])?
  }
  for port in 19084..19087 do
    let _rpc = spawn(rpc, port, anchored, mode)
  end
  Timer.sleep(100)
  let labels = ["transparency-checkpoint/v1", "transparency-origin/v1"]
  let values = [encode_checkpoint(local)?, Bytes.from_utf8("http://127.0.0.1:19081")]
  store_updated_blobs(path,
    labels,
    for index in 0..2 do
      seal_local(List.get(values, index), key, local_context(List.get(labels, index))?)?
    end)?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    Bytes.from_utf8(String.join([
        "4",
        Bytes.to_hex(local.service_public_key),
        String.repeat("22", 32),
        "8",
        "2",
        "2",
        "a #{String.repeat("01", 32)} Morse",
        "b #{String.repeat("02", 32)} Outside",
        "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb",
        "3",
        "https://one.example",
        "https://two.example",
        "https://three.example",
        "-",
        "2",
        "2",
        "2",
        "a #{String.repeat("01", 32)} Morse",
        "b #{String.repeat("02", 32)} Outside",
        String.repeat("1", 32),
        "morse-main"
      ],
      "\n"))))
  File.write(mode, "proof")?
  let mismatch = check_anchor_at(path,
    key,
    pins,
    local.service_public_key,
    2,
    wide(9000000)?,
    false)?
  assert(mismatch.status == "mismatch")
  case require_log_changes_allowed(path, key) do
    Err(error) -> assert(error == "anchor_mismatch")
    Ok(_) -> assert(false)
  end
  let evidence = load_blob(path, "anchor-evidence/v1")?
  assert(Bytes.length(open_local(evidence, key, local_context("anchor-evidence/v1")?)?) > 188)
  assert(Bytes.length(retained_fork(path, key)?) == 0)
  File.write(mode, "down")?
  assert(check_anchor_at(path,
    key,
    pins,
    local.service_public_key,
    2,
    wide(12600000)?,
    false)?.status == "mismatch")
  assert(Bytes.secure_equals(load_blob(path, "anchor-evidence/v1")?, evidence))
  File.write(mode, "good")?
  assert(check_anchor_at(path,
    key,
    pins,
    local.service_public_key,
    2,
    wide(16200000)?,
    false)?.status == "consistent")
  require_log_changes_allowed(path, key)?
  let identity = anchor_identity(pins, local.service_public_key, 2)?
  assert(load_anchor_observation(path, key, identity)?.status == "consistent")
  assert(U64.to_string(load_anchor_schedule(path, key, identity)?.next_daily) == "102600000")
  let fork_path = database_path("scheduled-anchor-fork")?
  ensure_schema(fork_path)?
  # The candidate has not replaced the cache. The actual key-change path must
  # compare it, retain the authenticated anchor context and pause atomically.
  File.write(mode, "down")?
  assert(check_anchor_view_at(fork_path,
    key,
    pins,
    local.service_public_key,
    2,
    wide(9000000)?,
    true,
    encode_checkpoint(contradictory)?,
    "http://127.0.0.1:19081")?.status == "mismatch")
  let saved_fork = decode_fork(retained_fork(fork_path, key)?)?
  assert(saved_fork.kind == 1 && saved_fork.second == AnchorReference(0))
  let context = open_local(load_blob(fork_path, "transparency-fork-anchor/v1")?,
    key,
    local_context("transparency-fork-anchor/v1")?)?
  assert(Bytes.to_utf8(Bytes.slice(context, 0, 4)?)? == "ACV3")
  assert(Bytes.secure_equals(Bytes.slice(context, 36, 8)?, mobile_write_u64(wide(9000000)?)?))
  case require_log_changes_allowed(fork_path, key) do
    Err(error) -> assert(error == "transparency_fork_detected")
    Ok(_) -> assert(false)
  end
  File.delete(fork_path)?
  # Keep the rejected candidate's private leaf even when the public path is
  # unavailable. A later foreground check must retry that candidate, not clear
  # its pause by comparing the older benign checkpoint still in the cache.
  let f2_path = database_path("scheduled-anchor-f2")?
  ensure_schema(f2_path)?
  let prior_values = [encode_checkpoint(baseline)?, List.get(values, 1)]
  store_updated_blobs(f2_path,
    labels,
    for index in 0..2 do
      seal_local(List.get(prior_values, index), key, local_context(List.get(labels, index))?)?
    end)?
  File.write(mode, "leaf-down")?
  assert(check_anchor_attested_at(f2_path,
    key,
    pins,
    local.service_public_key,
    2,
    wide(9000000)?,
    true,
    [],
    AnchorView {
      checkpoint: encode_checkpoint(divergent)?,
      origin: "http://127.0.0.1:19081",
      witnesses: [],
      leaf: private_leaf
    })?.status == "mismatch")
  assert(Bytes.length(retained_fork(f2_path, key)?) == 0)
  let pending = decode_anchor_context(open_local(load_blob(f2_path, "anchor-evidence/v1")?,
    key,
    local_context("anchor-evidence/v1")?)?)?
  assert(Bytes.secure_equals(pending.private_leaf, private_leaf))
  File.write(mode, "good")?
  assert(check_anchor_at(f2_path,
    key,
    pins,
    local.service_public_key,
    2,
    wide(12600000)?,
    false)?.status == "mismatch")
  assert(decode_fork(retained_fork(f2_path, key)?)?.kind == 2)
  let filed = decode_anchor_context(open_local(load_blob(f2_path, "transparency-fork-anchor/v1")?,
    key,
    local_context("transparency-fork-anchor/v1")?)?)?
  assert(Bytes.secure_equals(filed.private_leaf, private_leaf)
    && Bytes.length(filed.served_leaf) > 0)
  case require_log_changes_allowed(f2_path, key) do
    Err(error) -> assert(error == "transparency_fork_detected")
    Ok(_) -> assert(false)
  end
  File.delete(f2_path)?
  # A public fork cannot disappear from the pause merely by switching the
  # latest public root to the private branch. The old public view must extend.
  for index in 0..2 do
    let history_path = database_path("scheduled-anchor-history")?
    ensure_schema(history_path)?
    let history_values = [encode_checkpoint(pending_private)?, List.get(values, 1)]
    store_updated_blobs(history_path,
      labels,
      for index in 0..2 do
        seal_local(List.get(history_values, index), key, local_context(List.get(labels, index))?)?
      end)?
    File.write(mode <> ".active",
      Bytes.to_hex(encode_checkpoint(List.get([earlier_public, earlier_good], index))?))?
    assert(check_anchor_at(history_path,
      key,
      pins,
      local.service_public_key,
      2,
      wide(9000000)?,
      false)?.status == "mismatch")
    let first_context = load_blob(history_path, "anchor-evidence/v1")?
    File.delete(mode <> ".active")?
    File.write(mode <> ".advanced", "yes")?
    assert(check_anchor_at(history_path,
      key,
      pins,
      local.service_public_key,
      2,
      wide(12600000)?,
      false)?.status == if index == 0 do
        "mismatch"
      else
        "consistent"
      end)
    assert(Bytes.secure_equals(load_blob(history_path, "anchor-evidence/v1")?, first_context))
    assert(Bytes.length(retained_fork(history_path, key)?) == 0)
    File.delete(mode <> ".advanced")?
    File.delete(history_path)?
  end
  File.delete(path)?
  Ok(nil)
end

fn fixture_response(path :: String) -> Response do
  case File.read(path) do
    Err(error) -> HTTP.response(500, error)
    Ok(value) -> case Bytes.from_hex(value) do
      Err(error) -> HTTP.response(500, error)
      Ok(bytes) -> HTTP.response_bytes(200, bytes)
    end
  end
end

actor directory(port :: Int,
  checkpoint :: Bytes,
  proof :: Bytes,
  mode :: String,
  calls :: String) do
  HTTP.router()
    |> HTTP.on_post("/v2/transparency/leaf",
      fn(_request :: Request) do
        File.append(calls, "l")
        if File.read(mode).unwrap_or("down") == "leaf-down" do
          HTTP.response(503, "")
        else
          case File.read(mode <> ".leaf") do
            Err(error) -> HTTP.response(500, error)
            Ok(value) -> case Bytes.from_hex(value) do
              Err(error) -> HTTP.response(500, error)
              Ok(bytes) -> HTTP.response_bytes(200, bytes)
            end
          end
        end
      end)
    |> HTTP.on_post("/v2/transparency/checkpoint",
      fn(request :: Request) do
        File.append(calls, "c")
        let setting = File.read(mode).unwrap_or("down")
        if setting == "down" do
          HTTP.response(503, "")
        else if setting == "missing" do
          HTTP.response(404, "")
        else if (case mobile_read_u64(Request.body_bytes(request)) do
          Err(_) -> true
          Ok(value) -> U64.to_string(value) != "9"
        end) do
          HTTP.response(400, "wrong sequence")
        else if setting == "checkpoint" do
          HTTP.response(200, "bad checkpoint")
        else if setting == "served-fork" do
          case File.read(mode <> ".checkpoint") do
            Err(error) -> HTTP.response(500, error)
            Ok(value) -> case Bytes.from_hex(value) do
              Err(error) -> HTTP.response(500, error)
              Ok(bytes) -> HTTP.response_bytes(200, bytes)
            end
          end
        else
          HTTP.response_bytes(200, checkpoint)
        end
      end)
    |> HTTP.on_post("/v2/transparency/consistency",
      fn(request :: Request) do
        File.append(calls, "p")
        let setting = File.read(mode).unwrap_or("down")
        case decode_transparency_tree_query(Request.body_bytes(request)) do
          Err(_) -> HTTP.response(400, "")
          Ok(query) -> if (query.previous_tree_size != 1
            && query.previous_tree_size != 3
            && query.previous_tree_size != 5)
            || query.new_tree_size != 7 do
            HTTP.response(400, "wrong range")
          else if setting == "proof" do
            HTTP.response(200, "bad proof")
          else if setting == "proof-down" do
            HTTP.response(503, "")
          else if query.previous_tree_size == 3 do
            HTTP.response_bytes(200, proof)
          else
            let suffix = if query.previous_tree_size == 1 do
              ".baseline"
            else
              ".continuity"
            end
            fixture_response(mode <> suffix)
          end
        end
      end)
    |> HTTP.serve(port)
end

fn proof() -> Bool!String do
  let signer = signing_pair()?
  let leaves = for index in 0..7 do
    Crypto.sha256(Bytes.from_utf8("anchor/#{index}"))
  end
  let local = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(8)?,
    wide(3)?,
    merkle_root_for(2, List.take(leaves, 3))?,
    repeated(0, 32)?,
    wide(1000)?)?
  let anchored = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(9)?,
    wide(7)?,
    merkle_root_for(2, leaves)?,
    checkpoint_hash(local)?,
    wide(2000)?)?
  let public_entry = entry(anchored)?
  let mode = database_path("anchor-consistency-mode")?
  let calls = mode <> ".calls"
  File.write(mode, "good")?
  File.write(calls, "")?
  let _server = spawn(directory,
    19081,
    encode_checkpoint(anchored)?,
    encode_consistency_proof(compact_consistency_proof_for(2, List.take(leaves, 3), leaves)?)?,
    mode,
    calls)
  Timer.sleep(100)
  let origin = "http://127.0.0.1:19081"
  let good = compare_anchor(origin, local, public_entry, 7, signer.public_key.bytes, fn() do Ok(nil) end)?
  assert(good.status == "consistent" && Bytes.length(good.fork) == 0)
  assert(Bytes.secure_equals(good.checkpoint, encode_checkpoint(anchored)?))
  assert(File.read(calls)? == "cp")
  # When the phone is ahead of the writer, verify that the public tree is a
  # prefix of the cached view, instead of treating normal writer lag as a fork.
  let earlier = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(9)?,
    wide(3)?,
    local.tree_root,
    checkpoint_hash(local)?,
    wide(2000)?)?
  let newer = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(10)?,
    wide(7)?,
    anchored.tree_root,
    checkpoint_hash(earlier)?,
    wide(3000)?)?
  let _earlier_server = spawn(directory,
    19082,
    encode_checkpoint(earlier)?,
    encode_consistency_proof(compact_consistency_proof_for(2, List.take(leaves, 3), leaves)?)?,
    mode,
    calls)
  Timer.sleep(100)
  assert(compare_anchor("http://127.0.0.1:19082/",
    newer,
    entry(earlier)?,
    7,
    signer.public_key.bytes,
    fn() do Ok(nil) end)?.status == "consistent")
  for setting in ["missing", "checkpoint", "proof", "down", "proof-down"] do
    File.write(mode, setting)?
    let result = compare_anchor(origin, local, public_entry, 7, signer.public_key.bytes, fn() do Ok(nil) end)?
    let expected = if setting == "down" || setting == "proof-down" do
      "proof_unavailable"
    else
      "mismatch"
    end
    assert(result.status == expected)
    # Neither refusal nor an invalid proof supplies a signed contradiction.
    assert(Bytes.length(result.fork) == 0)
  end
  File.write(mode, "good")?
  assert(compare_anchor(origin,
    local,
    %{public_entry | checkpoint_hash: repeated(5, 32)?},
    7,
    signer.public_key.bytes,
    fn() do Ok(nil) end)?.status == "mismatch")
  # Equal sizes still require the exact served checkpoint commitment.
  assert(compare_anchor(origin,
    anchored,
    public_entry,
    7,
    signer.public_key.bytes,
    fn() do Ok(nil) end)?.status == "consistent")
  let contradictory = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(10)?,
    wide(7)?,
    repeated(9, 32)?,
    checkpoint_hash(anchored)?,
    wide(3000)?)?
  File.write(mode <> ".checkpoint", Bytes.to_hex(encode_checkpoint(contradictory)?))?
  File.write(mode, "served-fork")?
  let served_fork = compare_anchor(origin, local, public_entry, 7, signer.public_key.bytes, fn() do Ok(nil) end)?
  assert(served_fork.status == "mismatch")
  assert(decode_fork(served_fork.fork)?.kind == 1)
  assert(decode_fork(served_fork.fork)?.second == AnchorReference(7))
  let earlier_fork = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    local.sequence,
    local.tree_size,
    repeated(9, 32)?,
    local.previous_checkpoint_hash,
    local.timestamp)?
  File.write(mode <> ".checkpoint", Bytes.to_hex(encode_checkpoint(earlier_fork)?))?
  let signed = decode_fork(compare_anchor(origin,
    local,
    public_entry,
    7,
    signer.public_key.bytes,
    fn() do Ok(nil) end)?.fork)?
  assert(signed.kind == 1 && signed.second == SignedCheckpoint(earlier_fork))
  File.write(mode <> ".checkpoint",
    Bytes.to_hex(encode_checkpoint(%{contradictory | signature: repeated(0, 64)?})?))?
  let forged = compare_anchor(origin, local, public_entry, 7, signer.public_key.bytes, fn() do Ok(nil) end)?
  assert(forged.status == "mismatch" && Bytes.length(forged.fork) == 0)
  File.delete(mode <> ".checkpoint")?
  File.write(mode, "down")?
  let conflict = compare_anchor(origin, contradictory, public_entry, 7, signer.public_key.bytes, fn() do Ok(nil) end)?
  assert(conflict.status == "mismatch")
  let fork = decode_fork(conflict.fork)?
  assert(fork.kind == 1 && fork.second == AnchorReference(7))
  # A later sequence with a smaller tree is provable even if no proof server answers.
  let rollback = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(10)?,
    wide(3)?,
    local.tree_root,
    checkpoint_hash(anchored)?,
    wide(3000)?)?
  let smaller = compare_anchor(origin, rollback, public_entry, 7, signer.public_key.bytes, fn() do Ok(nil) end)?
  assert(smaller.status == "mismatch" && decode_fork(smaller.fork)?.kind == 3)
  # A cached checkpoint from another version/key is never treated as a fork.
  for invalid in [%{local | version: 1}, %{local | signature: repeated(0, 64)?}] do
    case compare_anchor(origin, invalid, public_entry, 7, signer.public_key.bytes, fn() do Ok(nil) end) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  let private_leaves = [
    List.get(leaves, 0),
    Crypto.sha256(Bytes.from_utf8("private leaf")),
    List.get(leaves, 2)
  ]
  let divergent = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    local.sequence,
    local.tree_size,
    merkle_root_for(2, private_leaves)?,
    local.previous_checkpoint_hash,
    local.timestamp)?
  let private_leaf = encode_leaf_proof(LeafProof {
    leaf_hash: List.get(private_leaves, 1),
    inclusion: compact_inclusion_proof_for(2, private_leaves, 1)?
  })?
  File.write(mode <> ".leaf",
    Bytes.to_hex(encode_leaf_proof(LeafProof {
      leaf_hash: List.get(leaves, 1),
      inclusion: compact_inclusion_proof_for(2, leaves, 1)?
    })?))?
  let baseline = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(7)?,
    wide(1)?,
    merkle_root_for(2, List.take(leaves, 1))?,
    repeated(0, 32)?,
    wide(500)?)?
  let pending_private = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(7)?,
    wide(3)?,
    local.tree_root,
    repeated(0, 32)?,
    wide(500)?)?
  let earlier_public = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(8)?,
    wide(5)?,
    merkle_root_for(2, private_leaves ++ [List.get(leaves, 3), List.get(leaves, 4)])?,
    checkpoint_hash(pending_private)?,
    wide(1000)?)?
  let earlier_good = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(8)?,
    wide(5)?,
    merkle_root_for(2, List.take(leaves, 5))?,
    checkpoint_hash(pending_private)?,
    wide(1000)?)?
  File.write(mode <> ".baseline",
    Bytes.to_hex(encode_consistency_proof(compact_consistency_proof_for(2,
      List.take(leaves, 1),
      leaves)?)?))?
  File.write(mode <> ".continuity",
    Bytes.to_hex(encode_consistency_proof(compact_consistency_proof_for(2,
      List.take(leaves, 5),
      leaves)?)?))?
  scheduled(local,
    baseline,
    anchored,
    contradictory,
    divergent,
    private_leaf,
    pending_private,
    earlier_public,
    earlier_good,
    mode)?
  File.delete(mode <> ".baseline")?
  File.delete(mode <> ".continuity")?
  File.delete(mode <> ".leaf")?
  File.delete(mode)?
  File.delete(calls)?
  Ok(true)
end

test("anchor comparison checks exact commitments and consistency without fabricating evidence from outages") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
