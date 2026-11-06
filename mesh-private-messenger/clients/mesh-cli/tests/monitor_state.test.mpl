from Monitor.State import (
  MonitorState,
  MonitorAttendance,
  MonitorAttendanceCounts,
  load_monitor_state,
  save_monitor_state,
  pending_monitor_attendance,
  finish_monitor_attendance,
  monitor_attendance_counts,
  claim_monitor_attendance
)
from Transparency.Merkle import TransparencyCheckpoint, sign_checkpoint, checkpoint_hash
from Transparency.Wire import encode_checkpoint
from Transparency.Fork import ForkProof, ForkTarget, fork_same_size, encode_fork

fn join(parts :: List<Bytes>) -> Bytes!String do
  if List.length(parts) == 0 do
    Ok(Bytes.empty())
  else
    Bytes.concat(List.head(parts), join(List.tail(parts))?)
  end
end

fn preserve_evidence(path :: String,
  identity :: Bytes,
  state :: MonitorState) -> Result<(), String> do
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("signing fixture failed")
    Ok(value) -> value
  end
  let zero = Bytes.from_hex(String.repeat("00", 32))?
  let first = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    U64.parse("1")?,
    [Crypto.sha256(Bytes.from_utf8("first"))],
    zero,
    U64.parse("1000")?)?
  let second = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    U64.parse("2")?,
    [Crypto.sha256(Bytes.from_utf8("conflict"))],
    checkpoint_hash(first)?,
    U64.parse("2000")?)?
  let fork = ForkProof {
    kind: 1,
    finder: zero,
    service_public_key: signer.public_key.bytes,
    first: first,
    second: SignedCheckpoint(second),
    attestations: [],
    contradiction: None
  }
  fork_same_size(fork, signer.public_key, [])?
  let encoded = encode_fork(fork)?
  let entry = join([
    Bytes.write_uint_le("1", 8)?,
    Bytes.write_uint_le("1", 8)?,
    first.tree_root,
    checkpoint_hash(first)?,
    Bytes.write_uint_le("1000", 8)?,
    Bytes.write_uint_le("10", 8)?,
    Bytes.from_hex("0000010000000000")?
  ])?
  save_monitor_state(path,
    identity,
    state.revision,
    %{state | pending_index: 0, pending_entry: entry})?
  let pending = load_monitor_state(path, identity)?
  assert(Bytes.secure_equals(pending.pending_entry, entry))
  case save_monitor_state(path,
    identity,
    pending.revision,
    %{pending | pending_index: -1, pending_entry: Bytes.empty()}) do
    Err(error) -> assert(error == "monitor_pending_comparison_lost")
    Ok(_) -> assert(false)
  end
  save_monitor_state(path,
    identity,
    pending.revision,
    %{pending |
      ring_index: 0,
      entry: entry,
      checkpoint: encode_checkpoint(first)?,
      proof: encoded,
      pending_index: -1,
      pending_entry: Bytes.empty()
    })?
  let saved = load_monitor_state(path, identity)?
  assert(Bytes.secure_equals(saved.proof, encoded) && Bytes.secure_equals(saved.entry, entry))
  save_monitor_state(path,
    identity,
    saved.revision,
    %{saved | proof: encode_fork(%{fork | finder: Bytes.from_hex(String.repeat("09", 32))?})?})?
  assert(Bytes.secure_equals(load_monitor_state(path, identity)?.proof, encoded))
  let waiting = pending_monitor_attendance(path, identity)?
  assert(List.length(waiting) == 1 && List.head(waiting).ring_index == 0)
  assert(Bytes.secure_equals(List.head(waiting).entry, entry))
  finish_monitor_attendance(path, identity, List.head(waiting), "met")?
  assert(List.length(pending_monitor_attendance(path, identity)?) == 0)
  let counts = monitor_attendance_counts(path, identity)?
  assert(counts.met == 1 && counts.pending == 0 && counts.missed == 0 && counts.lost == 0)
  # A retry cannot reset an accepted historical threshold or double-count it.
  finish_monitor_attendance(path, identity, List.head(waiting), "missed")?
  assert(monitor_attendance_counts(path, identity)?.met == 1)
  let db = Sqlite.open(path)?
  let rows = Sqlite.query(db, "SELECT count(*) AS total FROM monitor_history", [])?
  assert(Map.get(List.head(rows), "total") == "1")
  # Forty still-pending postings simulate a provider refusing historical
  # witness-set reads. The second reservation must include the newer eight.
  for index in 0..40 do
    let posted = Int.to_string(20 + index)
    let queued = join([
      Bytes.slice(entry, 0, 88)?,
      Bytes.write_uint_le(posted, 8)?,
      Bytes.slice(entry, 96, 8)?
    ])?
    Sqlite.execute_values(db,
      "INSERT INTO monitor_attendance (checkpoint_hash, posted_slot, ring_index, entry) VALUES (?, ?, ?, ?)",
      [
        Text(Bytes.to_hex(checkpoint_hash(first)?)),
        Text(posted),
        Text(Int.to_string(index)),
        Binary(queued)
      ])?
  end
  Sqlite.close(db)
  let first_batch = claim_monitor_attendance(path, identity)?
  let second_batch = claim_monitor_attendance(path, identity)?
  assert(List.length(first_batch) == 32 && List.length(second_batch) == 32)
  assert(!List.any(first_batch, fn(value) do value.ring_index == 39 end))
  assert(List.any(second_batch, fn(value) do value.ring_index == 39 end))
  assert(monitor_attendance_counts(path, identity)?.pending == 40)
  Ok(nil)
end

fn proof() -> Bool!String do
  let path = "/tmp/morse-monitor-" <> Crypto.uuid4() <> ".sqlite"
  let identity = Crypto.sha256(Bytes.from_utf8("monitor-a"))
  let initial = load_monitor_state(path, identity)?
  assert(U64.to_string(initial.revision) == "0")
  assert(Bytes.length(initial.entry) == 0)
  assert(initial.ring_index == -1)
  let changed = %{initial |
    context_slot: U64.parse("9007199254740993")?,
    report: "{\"healthy\":false}",
    registry: "{\"witnesses\":[]}"
  }
  save_monitor_state(path, identity, initial.revision, changed)?
  let reopened = load_monitor_state(path, identity)?
  assert(U64.to_string(reopened.revision) == "1")
  assert(U64.to_string(reopened.context_slot) == "9007199254740993")
  assert(reopened.report == changed.report && reopened.registry == changed.registry)
  case save_monitor_state(path, identity, initial.revision, initial) do
    Err(error) -> assert(error == "monitor_state_changed")
    Ok(_) -> assert(false)
  end
  case load_monitor_state(path, Crypto.sha256(Bytes.from_utf8("monitor-b"))) do
    Err(error) -> assert(error == "monitor_identity_changed")
    Ok(_) -> assert(false)
  end
  case save_monitor_state(path,
    identity,
    reopened.revision,
    %{reopened | context_slot: U64.parse("1")?}) do
    Err(error) -> assert(error == "monitor_context_regressed")
    Ok(_) -> assert(false)
  end
  assert(U64.to_string(load_monitor_state(path, identity)?.revision) == "1")
  preserve_evidence(path, identity, reopened)?
  File.delete(path)?
  Ok(true)
end

test("monitor commits progress atomically and rejects stale writers, changed pins and regressed RPC context") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
