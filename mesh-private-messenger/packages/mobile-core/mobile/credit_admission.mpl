from Credits.Discovery import CreditIssuerQuery, encode_credit_issuer_query
from Credits.Issuer import verify_issuer_key, issuer_key_id
from Mobile.CreditState import CreditWallet
from Mobile.CreditWallet import add_credit_issuer
from Mobile.Transparency import check_transparency_baseline, transparency_view_storage
from Mobile.TransparencySafety import require_log_changes_allowed
from Mobile.AnchorCheck import check_native_anchor_view
from Mobile.Types import MobileTransparencyView
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import open_local, seal_local, local_context
from Storage.Credits import (
  CreditWalletIdentity,
  CreditCacheWrite,
  load_credit_wallet,
  commit_credit_wallet_with_cache
)
from Transparency.Config import SecurityConfig, witness_policy_for_log
from Transparency.LeafProof import LeafProof, compact_leaf_proof, encode_leaf_proof
from Transparency.Merkle import leaf_hash_for
from Transparency.Wire import (
  decode_checkpoint,
  encode_checkpoint,
  encode_witnesses,
  encode_consistency_proof,
  decode_transparency_evidence
)

pub struct CreditDiscoveryPlan do
  origin :: String
  body :: Bytes
end

fn require_policy(who :: CreditWalletIdentity, config :: SecurityConfig) -> Result<(), String> do
  if config.issuer_origin == "-" || String.length(config.issuer_origin) == 0 do
    return Err("credits_disabled")
  end
  if who.purpose != 0 && who.purpose != 1 do
    return Err("credits_disabled")
  end
  if !Bytes.secure_equals(who.service_key, config.service_public_key)
    || config.log_version != 2
    || witness_policy_for_log(config, 2)?.threshold < 1 do
    return Err("credit_trust_unconfigured")
  end
  Ok(nil)
end

fn raw_cache(path :: String, label :: String) -> Bytes!String do
  case load_blob(path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(value)
  end
end

fn checkpoint_from_raw(raw :: Bytes, wrapping :: borrow StorageKey) -> Bytes!String do
  if Bytes.length(raw) == 0 do
    Ok(Bytes.empty())
  else
    let checkpoint = open_local(raw, wrapping, local_context("transparency-checkpoint/v1")?)?
    if decode_checkpoint(checkpoint)?.version != 2 do
      return Err("credit_log_migration_required")
    end
    Ok(checkpoint)
  end
end

pub fn credit_discovery_plan(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  config :: SecurityConfig) -> CreditDiscoveryPlan!String do
  require_policy(who, config)?
  ensure_schema(path)?
  require_log_changes_allowed(path, wrapping)?
  let previous = checkpoint_from_raw(raw_cache(path, "transparency-checkpoint/v1")?, wrapping)?
  check_transparency_baseline(path, wrapping, config, previous)?
  let size = if Bytes.length(previous) == 0 do
    U64.parse("0")?
  else
    decode_checkpoint(previous)?.tree_size
  end
  Ok(CreditDiscoveryPlan {
    origin: config.issuer_origin,
    body: encode_credit_issuer_query(CreditIssuerQuery {
      purpose: who.purpose,
      previous_size: size
    })?
  })
end

pub fn admit_credit_issuer(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  config :: SecurityConfig,
  response :: Bytes,
  now :: U64) -> Bytes!String do
  require_policy(who, config)?
  ensure_schema(path)?
  let previous_raw = raw_cache(path, "transparency-checkpoint/v1")?
  let previous = checkpoint_from_raw(previous_raw, wrapping)?
  check_transparency_baseline(path, wrapping, config, previous)?
  let evidence = decode_transparency_evidence(response)?
  let policy = witness_policy_for_log(config, 2)?
  let issuer = verify_issuer_key(evidence,
    SigningPublicKey { bytes: config.service_public_key },
    policy.keys,
    policy.threshold,
    previous,
    now,
    who.purpose)?
  let checkpoint = encode_checkpoint(evidence.checkpoint)?
  let leaf = encode_leaf_proof(compact_leaf_proof(LeafProof {
      leaf_hash: leaf_hash_for(2, evidence.entry_bytes)?,
      inclusion: evidence.inclusion
    },
    evidence.checkpoint)?)?
  # The existing anchor scheduler observes the same newly authenticated view.
  # It may retain a slash/fork, which is checked again before this transaction.
  check_native_anchor_view(path, None, checkpoint, config.issuer_origin, evidence.witnesses, leaf)?
  let view = transparency_view_storage(MobileTransparencyView {
      checkpoint: checkpoint,
      consistency: encode_consistency_proof(evidence.consistency)?,
      service_public_key: config.service_public_key,
      set_id: policy.set_id,
      witness_threshold: policy.threshold
    },
    wrapping)?
  let labels = view.labels
    ++ ["transparency-checkpoint/v1", "transparency-witnesses/v2", "transparency-leaf/v1"]
  let blobs = view.blobs
    ++ [
      seal_local(checkpoint, wrapping, local_context("transparency-checkpoint/v1")?)?,
      seal_local(encode_witnesses(evidence.witnesses)?,
        wrapping,
        local_context("transparency-witnesses/v2")?)?,
      seal_local(leaf, wrapping, local_context("transparency-leaf/v1")?)?
    ]
  let writes = for index in 0..List.length(labels) do
    let label = List.get(labels, index)
    CreditCacheWrite {
      label: label,
      previous: raw_cache(path, label)?,
      value: List.get(blobs, index)
    }
  end
  let current_raw = raw_cache(path, "transparency-checkpoint/v1")?
  if !Bytes.secure_equals(previous_raw, current_raw)
    || !Bytes.secure_equals(List.get(writes, List.length(view.labels)).previous, previous_raw) do
    return Err("credit_transparency_changed")
  end
  let guards = for label in ["transparency-fork/v1", "anchor-schedule/v1"] do
    CreditCacheWrite { label: label, previous: raw_cache(path, label)?, value: Bytes.empty() }
  end
  require_log_changes_allowed(path, wrapping)?
  check_transparency_baseline(path, wrapping, config, previous)?
  let before = load_credit_wallet(path, wrapping, who)?
  let updated = add_credit_issuer(before.wallet, issuer, now, who.purpose)?
  let wallet = CreditWallet {
    revision: U64.add(updated.revision, U64.parse("1")?)?,
    records: updated.records
  }
  commit_credit_wallet_with_cache(path, wrapping, who, before, wallet, writes ++ guards)?
  issuer_key_id(issuer)
end
