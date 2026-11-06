from Mobile.Bounty import (
  bounty_state,
  set_bounty_enabled,
  commit_bounty_address,
  abandon_bounty_address,
  disclosable_fork
)
from Mobile.TransparencySafety import retain_fork, retained_fork, require_log_changes_allowed
from MobileCore import transparency_fork_export, fork_filing_export
from Mobile.ForkFiling import native_filing_current
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_session, erase_local_state
from Tests.Support import database_path, repeated, append
from Tests.ForkFilingSupport import filing_fixture
from Transparency.Config import encode_security_config
from Transparency.Fork import decode_fork, encode_fork, fork_hash

fn fixture() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let (sample, config) = filing_fixture()?
  let proof = %{sample | finder: repeated(0, 32)?}
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(config)?))
  let key = platform_key()?
  let opted_out = database_path("bounty-out")?
  let opted_in = database_path("bounty-in")?
  let failed = database_path("bounty-failed")?
  let legacy = database_path("bounty-legacy")?
  for path in [opted_out, opted_in, failed, legacy] do
    ensure_schema(path)?
  end
  assert(!bounty_state(opted_out, key)?.enabled)
  assert(bounty_state(opted_out, key)?.status == 0)
  assert(Bytes.length(disclosable_fork(opted_out, key)?) == 0)
  retain_fork(opted_out, key, proof)?
  let zero = disclosable_fork(opted_out, key)?
  assert(Bytes.secure_equals(zero, encode_fork(proof)?))
  assert(bounty_state(opted_out, key)?.status == 2)
  # Changing the preference after detection cannot change already exportable
  # evidence or retry identity, including when the original finder is zero.
  set_bounty_enabled(opted_out, key, true)?
  assert(Bytes.secure_equals(zero, disclosable_fork(opted_out, key)?))
  let sdk = append(Bytes.from_hex("0200000000000000")?, repeated(71, 32)?)?
  assert(Result.is_err(commit_bounty_address(opted_out, key, Crypto.sha256(zero), sdk)))
  set_bounty_enabled(opted_in, key, true)?
  retain_fork(opted_in, key, proof)?
  let pending = bounty_state(opted_in, key)?
  assert(pending.enabled && pending.status == 1)
  assert(Bytes.secure_equals(pending.proof_identity, Crypto.sha256(encode_fork(proof)?)))
  # The security pause exists while the host reserves an address. No evidence
  # may escape with a temporary zero finder before the durable decision.
  assert(Result.is_err(require_log_changes_allowed(opted_in, key)))
  assert(Result.is_err(disclosable_fork(opted_in, key)))
  assert(Result.is_err(transparency_fork_export(Bytes.from_utf8(opted_in))))
  assert(Result.is_err(fork_filing_export(Bytes.from_utf8(opted_in))))
  assert(Result.is_err(commit_bounty_address(opted_in, key, repeated(8, 32)?, sdk)))
  assert(Result.is_err(commit_bounty_address(opted_in,
    key,
    pending.proof_identity,
    append(Bytes.from_hex("0000008000000000")?, repeated(71, 32)?)?)))
  assert(Result.is_err(commit_bounty_address(opted_in,
    key,
    pending.proof_identity,
    append(Bytes.from_hex("0200000000000000")?, repeated(0, 32)?)?)))
  assert(Result.is_err(commit_bounty_address(opted_in,
    key,
    pending.proof_identity,
    repeated(9, 41)?)))
  let chosen = commit_bounty_address(opted_in, key, pending.proof_identity, sdk)?
  assert(chosen.status == 3 && chosen.index == U64.parse("2")?)
  assert(Bytes.secure_equals(chosen.finder, repeated(71, 32)?))
  let selected_wire = disclosable_fork(opted_in, key)?
  assert(Bytes.secure_equals(transparency_fork_export(Bytes.from_utf8(opted_in))?, selected_wire))
  let selected_proof = decode_fork(selected_wire)?
  assert(Bytes.secure_equals(selected_proof.finder, chosen.finder))
  assert(Bytes.secure_equals(fork_hash(selected_proof)?, fork_hash(proof)?))
  assert(Bytes.secure_equals(retained_fork(opted_in, key)?, encode_fork(proof)?))
  assert(commit_bounty_address(opted_in, key, pending.proof_identity, sdk)?.status == 3)
  # A losing cross-process reservation burns its own index but cannot replace
  # the winning address, including after app restart or preference changes.
  let loser = append(Bytes.from_hex("0300000000000000")?, repeated(72, 32)?)?
  assert(Result.is_err(commit_bounty_address(opted_in, key, pending.proof_identity, loser)))
  assert(Result.is_err(abandon_bounty_address(opted_in, key, pending.proof_identity)))
  set_bounty_enabled(opted_in, key, false)?
  assert(Bytes.secure_equals(disclosable_fork(opted_in, key)?, selected_wire))
  assert(Bytes.secure_equals(bounty_state(opted_in, key)?.finder, chosen.finder))
  assert(native_filing_current(opted_in, encode_security_config(config)?, selected_wire))
  assert(!native_filing_current(opted_in, encode_security_config(config)?, zero))
  # A second valid fork cannot evict the original or allocate another address.
  let later = %{proof |
    first: case proof.second do
      SignedCheckpoint(value) -> value
      _ -> proof.first
    end,
    second: SignedCheckpoint(proof.first)
  }
  retain_fork(opted_in, key, later)?
  assert(Bytes.secure_equals(disclosable_fork(opted_in, key)?, selected_wire))
  # Wallet storage failure must not suppress portable evidence. The fallback
  # is durable and visible, with no later opportunistic finder substitution.
  set_bounty_enabled(failed, key, true)?
  retain_fork(failed, key, proof)?
  let failed_id = bounty_state(failed, key)?.proof_identity
  assert(abandon_bounty_address(failed, key, failed_id)?.status == 4)
  assert(abandon_bounty_address(failed, key, failed_id)?.status == 4)
  assert(Bytes.secure_equals(disclosable_fork(failed, key)?, encode_fork(proof)?))
  assert(Result.is_err(commit_bounty_address(failed, key, failed_id, sdk)))
  # Evidence retained by the old build may already have been filed. Migration
  # freezes its exact finder, even when the current preference is enabled.
  set_bounty_enabled(legacy, key, true)?
  let old_wire = encode_fork(sample)?
  store_updated_session(legacy,
    "transparency-fork/v1",
    seal_local(old_wire, key, local_context("transparency-fork/v1")?)?)?
  assert(Bytes.secure_equals(disclosable_fork(legacy, key)?, old_wire))
  assert(bounty_state(legacy, key)?.status == 5)
  assert(Result.is_err(commit_bounty_address(legacy, key, Crypto.sha256(old_wire), sdk)))
  # Raw address and derivation index are inside the encrypted native record.
  let stored = load_blob(opted_in, "fork-bounty/v1")?
  assert(!String.contains(Bytes.to_hex(stored), Bytes.to_hex(chosen.finder)))
  erase_local_state(opted_in)?
  assert(!native_filing_current(opted_in, encode_security_config(config)?, selected_wire))
  for path in [opted_out, opted_in, failed, legacy] do
    File.delete(path)?
  end
  Ok(true)
end

test("finder selection is opt-in, sealed, stable across retry and never blocks filing after wallet failure") do
  case fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
