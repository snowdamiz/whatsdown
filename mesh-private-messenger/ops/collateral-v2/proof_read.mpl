##! Bounded proof context. All account pieces must describe one finalized bank.
from Read import (
  CollateralOperatorPins,
  CollateralOperatorState,
  collateral_operator_keys,
  validate_collateral_operator_sources,
  collateral_operator_freshness,
  collateral_selection_digest,
  decode_collateral_operator_unpriced_snapshot,
  decode_operator_bond
)
from Accounts import (
  operator_owned,
  operator_required,
  operator_absent,
  operator_number,
  operator_optional_vault,
  operator_snapshot_digest
)
from Solana.Read import (
  Pubkey,
  AccountSliceAtSlot,
  OptionalAccountSlicesAtSlot,
  pubkey,
  get_account_info_slice_request,
  get_multiple_accounts_slice_request,
  account_slice_from_response,
  optional_accounts_slice_from_response,
  rpc_send
)
from Transparency.TokenCollateralWrite import (
  TokenCollateralSubject,
  token_collateral_addresses,
  token_collateral_subject,
  collateral_derived,
  collateral_public_key
)
from Transparency.TokenChain import token_payout_address
from Transparency.TokenProofWrite import (
  TokenPreparedProof,
  decode_token_prepared_proof,
  token_proof_stage_address
)
from Transparency.TokenCustody import TokenCollateralBond
from Transparency.Relay import RelayVerification, validate_relay_submission
from Transparency.RelayStage import RelayStagePlan, prepare_relay_stage
from Transparency.RelayStageRead import RelayStageState, decode_relay_stage
from Transparency.AnchorBond import bond_witness_identity
from Transparency.AnchorRing import (
  decode_anchor_header,
  decode_anchor_entry,
  anchor_bitmap_contains
)
from Transparency.AnchorWitnessSet import decode_anchor_witness_set, anchor_cosigners
from Transparency.Fork import (
  ForkProof,
  ForkVerdict,
  ForkTarget,
  ForkAnchor,
  fork_same_size,
  fork_contradiction,
  fork_rollback,
  fork_at_anchor,
  fork_hash
)
from Transparency.Merkle import WitnessKey, checkpoint_hash

pub struct CollateralProofIntent do
  fee_payer :: Pubkey
  submitter :: Pubkey
  wire :: Bytes
  witnesses :: List<WitnessKey>
  close :: Bool
end

pub struct CollateralProofAnchor do
  header :: AccountSliceAtSlot
  entry :: AccountSliceAtSlot
  witnesses :: AccountSliceAtSlot
end

pub struct CollateralProofState do
  base :: CollateralOperatorState
  digest :: Bytes
  selection :: Bytes
  plan :: RelayStagePlan
  stage :: RelayStageState
  receipt :: Option<TokenPreparedProof>
  second_hash :: Bytes
  anchor_generation :: Option<Int>
  deadline_ms :: U64
  directory :: TokenCollateralBond
  subjects :: List<TokenCollateralBond>
  legacy_subjects :: List<TokenCollateralSubject>
  usdc_amount :: U64
  morse_amount :: U64
  payout_missing :: List<Int>
end

pub fn collateral_proof_keys(pins :: CollateralOperatorPins,
  intent :: CollateralProofIntent) -> List<Pubkey>!String do
  let c = pins.context
  let a = token_collateral_addresses(c)?
  let proof = validate_relay_submission(pins.service_key, pins.log_version, intent.wire)?
  if !collateral_public_key(intent.fee_payer)
    || Bytes.length(intent.wire) > 8009
    || List.length(intent.witnesses) > 16 do
    return Err("collateral_proof_bounds")
  end
  let subjects = for index in 0..List.length(intent.witnesses) do
    let key = List.get(intent.witnesses, index)
    for prior in 0..index do
      let p = List.get(intent.witnesses, prior)
      if key.witness_id == p.witness_id || key.public_key == p.public_key do
        return Err("collateral_proof_duplicate_key")
      end
    end
    let u = token_collateral_subject(c, CollateralWitness(key), 0)?
    let m = token_collateral_subject(c, CollateralWitness(key), 1)?
    [
      case u.witness do
        None -> return Err("collateral_proof_key")
        Some(v) -> v
      end,
      u.bond,
      u.vault,
      m.vault
    ]
  end
  let finder = Pubkey {
    bytes: if Bytes.to_hex(proof.finder) == String.repeat("00", 32) do
      intent.submitter.bytes
    else
      proof.finder
    end
  }
  let locked = collateral_derived(c.judge, [Bytes.from_utf8("locked"), a.log_id])?
  Ok(collateral_operator_keys(pins, CollateralDirectory, intent.submitter)?
    ++ List.flatten(subjects)
    ++ [
      token_proof_stage_address(c, intent.submitter, intent.wire)?,
      collateral_derived(c.judge, [Bytes.from_utf8("proof"), a.log_id, fork_hash(proof)?])?,
      token_payout_address(finder, c.usdc_mint)?,
      token_payout_address(locked, c.usdc_mint)?,
      token_payout_address(finder, a.morse_mint)?,
      token_payout_address(locked, a.morse_mint)?
    ])
end

fn anchored(pins :: CollateralOperatorPins,
  proof :: ForkProof,
  snapshot :: OptionalAccountSlicesAtSlot,
  now :: U64,
  aux :: Option<CollateralProofAnchor>) -> (ForkAnchor, Int, U64)!String do
  let index = case proof.second do
    AnchorReference(v) -> v
    _ -> return Err("collateral_proof_anchor_required")
  end
  let aux = case aux do
    None -> return Err("collateral_proof_anchor_missing")
    Some(v) -> v
  end
  let a = token_collateral_addresses(pins.context)?
  for piece in [aux.header, aux.entry, aux.witnesses] do
    if piece.slot != snapshot.slot do
      return Err("collateral_proof_mixed_bank")
    end
  end
  let h = case aux.header.account do
    None -> return Err("collateral_proof_anchor_missing")
    Some(v) -> v
  end
  let e = case aux.entry.account do
    None -> return Err("collateral_proof_anchor_missing")
    Some(v) -> v
  end
  let w = case aux.witnesses.account do
    None -> return Err("collateral_proof_anchor_missing")
    Some(v) -> v
  end
  for value in [h, e, w] do
    if value.info.owner != pins.context.judge
      || value.info.executable
      || value.info.lamports == U64.parse("0")? do
      return Err("collateral_proof_anchor_owner")
    end
  end
  if h.space != U64.parse("426048")? || e.space != h.space || w.space != U64.parse("2752")? do
    return Err("collateral_proof_anchor_space")
  end
  let header = decode_anchor_header(h.info.data)?
  let entry = decode_anchor_entry(e.info.data)?
  let set = decode_anchor_witness_set(w.info.data)?
  if header.log_id != a.log_id
    || index < 0
    || index >= header.count
    || U64.compare(header.last_slot, snapshot.slot) > 0
    || U64.compare(entry.slot, snapshot.slot) > 0
    || set.log_id != a.log_id
    || set.generation != entry.witness_generation
    || U64.compare(set.ready_at, now) > 0 do
    return Err("collateral_proof_anchor_binding")
  end
  let cosigners = anchor_cosigners(entry, set)?
  let all = for row in cosigners do
    WitnessKey { witness_id: row.witness_id, public_key: row.public_key }
  end
  let native = for row in cosigners when row.native do
    WitnessKey { witness_id: row.witness_id, public_key: row.public_key }
  end
  Ok((ForkAnchor {
      ring_index: index,
      log_version: entry.log_version,
      service_public_key: pins.service_key,
      sequence: entry.sequence,
      tree_size: entry.tree_size,
      tree_root: entry.tree_root,
      checkpoint_hash: entry.checkpoint_hash,
      cosigners: all,
      native_cosigners: native
    },
    set.generation,
    entry.timestamp))
end

pub fn decode_collateral_proof_snapshot(pins :: CollateralOperatorPins,
  intent :: CollateralProofIntent,
  minimum :: U64,
  reference_time :: U64,
  snapshot :: OptionalAccountSlicesAtSlot,
  aux :: Option<CollateralProofAnchor>) -> CollateralProofState!String do
  let keys = collateral_proof_keys(pins, intent)?
  if List.length(snapshot.accounts) != List.length(keys) do
    return Err("collateral_proof_snapshot")
  end
  let base = decode_collateral_operator_unpriced_snapshot(pins,
    CollateralDirectory,
    intent.submitter,
    minimum,
    reference_time,
    OptionalAccountSlicesAtSlot {
      slot: snapshot.slot,
      accounts: List.take(snapshot.accounts, 27)
    })?
  let binding = case base.binding do
    None -> return Err("collateral_binding_inactive")
    Some(v) -> v
  end
  if base.legacy_economics || binding.activated_at == U64.parse("0")? do
    return Err("collateral_binding_inactive")
  end
  let c = pins.context
  let a = token_collateral_addresses(c)?
  let proof = validate_relay_submission(pins.service_key, pins.log_version, intent.wire)?
  let trusted = SigningPublicKey { bytes: pins.service_key }
  let resolved = case proof.second do
    SignedCheckpoint(second) -> (if proof.kind == 1 do
        fork_same_size(proof, trusted, intent.witnesses)?
      else if proof.kind == 2 do
        fork_contradiction(proof, trusted, intent.witnesses)?
      else
        fork_rollback(proof, trusted, intent.witnesses)?
      end,
      checkpoint_hash(second)?,
      None,
      second.timestamp)
    AnchorReference(_) ->
      let (anchor, generation, timestamp) = anchored(pins, proof, snapshot, base.timestamp, aux)?
      (fork_at_anchor(proof, trusted, intent.witnesses, anchor)?,
        anchor.checkpoint_hash,
        Some(generation),
        timestamp)
  end
  let (verdict, second_hash, generation, second_time) = resolved
  let stamp = if U64.compare(proof.first.timestamp, second_time) < 0 do
    proof.first.timestamp
  else
    second_time
  end
  let deadline = U64.add(stamp, U64.parse("2419200000")?)?
  let now = U64.multiply(base.timestamp, U64.parse("1000")?)?
  if U64.compare(proof.first.timestamp, now) > 0 || U64.compare(second_time, now) > 0 do
    return Err("collateral_proof_future")
  end
  let verified = RelayVerification {
    proof: intent.wire,
    proof_hash: fork_hash(proof)?,
    finder: proof.finder,
    verdict: verdict,
    service_slashed: base.log.service_slashed,
    context_slot: snapshot.slot,
    anchor_header: Bytes.empty(),
    anchor_entry: Bytes.empty(),
    witness_set: Bytes.empty(),
    witness_scope: "selected authenticated current registry"
  }
  let plan = prepare_relay_stage(c.judge, a.log_id, intent.submitter, verified)?
  let all_subjects = for index in 0..List.length(intent.witnesses) do
    let key = List.get(intent.witnesses, index)
    let at = 27 + index * 4
    let b = case decode_operator_bond(pins,
      snapshot,
      CollateralWitness(key),
      at + 1,
      base.timestamp)? do
      None -> return Err("collateral_proof_bond_missing")
      Some(v) -> v
    end
    let raw = operator_owned(snapshot, at, c.judge, 320)?
    let len = Bytes.get(raw, 4)?
    if Bytes.to_hex(Bytes.slice(raw, 0, 4)?) != "4d574901"
      || len != String.length(key.witness_id)
      || Bytes.to_utf8(Bytes.slice(raw, 8, len)?)? != key.witness_id
      || Bytes.to_hex(Bytes.slice(raw, 8 + len, 64 - len)?) != String.repeat("00", 64 - len)
      || Bytes.slice(raw, 72, 32)? != key.public_key
      || Bytes.get(raw, 5)? != b.status
      || Bytes.get(raw, 6)? > 1
      || Bytes.get(raw, 7)? != 0
      || Bytes.slice(raw, 104, 32)? != b.owner
      || Bytes.slice(raw, 200, 32)? != a.log_id
      || Bytes.slice(raw, 232, 32)? != b.vault
      || operator_number(raw, 264)? != b.unbond_at
      || Bytes.to_hex(Bytes.slice(raw, 272, 48)?) != String.repeat("00", 48) do
      return Err("collateral_proof_registry")
    end
    let dollars = operator_optional_vault(snapshot, at + 2, c.usdc_mint, List.get(keys, at + 1))?
    let morse = operator_optional_vault(snapshot, at + 3, a.morse_mint, List.get(keys, at + 1))?
    if U64.compare(if b.asset == 0 do
        dollars
      else
        morse
      end,
      b.principal) < 0 do
      return Err("collateral_proof_underfunded")
    end
    (b,
      if b.status == 3 do
        U64.parse("0")?
      else if b.asset == 0 do
        dollars
      else
        morse
      end)
  end
  let subjects = for target in plan.witnesses do
    let selected = List.filter(for index in 0..List.length(intent.witnesses) do
        (List.get(intent.witnesses, index), List.get(all_subjects, index))
      end,
      fn(row) do
        let (key, _) = row
        key == target.key
      end)
    if List.length(selected) != 1 do
      return Err("collateral_proof_subject_selection")
    end
    let (_, row) = List.head(selected)
    row
  end
  let directory = case base.directory do
    None -> return Err("collateral_proof_directory_missing")
    Some(v) -> v
  end
  let subject_bonds = for row in subjects do
    let (b, _) = row
    b
  end
  let di = 27 + List.length(intent.witnesses) * 4
  let stage_account = if operator_absent(List.get(snapshot.accounts, di)) do
    None
  else
    let value = operator_required(snapshot,
      di,
      c.judge,
      U64.parse(Int.to_string(1152 + Bytes.length(intent.wire)))?,
      1152 + Bytes.length(intent.wire),
      false)?
    Some(value.info)
  end
  let stage = decode_relay_stage(c.judge,
    a.log_id,
    intent.submitter,
    intent.wire,
    stage_account,
    snapshot.slot)?
  for earned in stage.verified do
    let matches = List.filter(plan.signatures,
      fn(signature) do signature.ordinal == earned.ordinal end)
    if List.length(matches) != 1 do
      return Err("collateral_proof_unselected_signature")
    end
    let signature = List.head(matches)
    let expected = case signature.witness do
      None -> pins.service_key
      Some(address) ->
        let matches = List.filter(plan.witnesses, fn(target) do target.address == address end)
        if List.length(matches) != 1 do
          return Err("collateral_proof_unselected_signature")
        end
        List.head(matches).key.public_key
    end
    if earned.public_key != expected do
      return Err("collateral_proof_signature_changed")
    end
  end
  let receipt = if operator_absent(List.get(snapshot.accounts, di + 1)) do
    None
  else
    let r = decode_token_prepared_proof(operator_owned(snapshot,
      di + 1,
      c.judge,
      400 + 144 * List.length(plan.witnesses))?)?
    if r.kind != proof.kind
      || r.anchored != (generation != None)
      || r.log_id != a.log_id
      || r.proof_hash != plan.proof_hash
      || r.finder != plan.finder
      || r.submitter != intent.submitter.bytes
      || r.usdc_mint != c.usdc_mint.bytes
      || r.morse_mint != a.morse_mint.bytes
      || r.first_hash != checkpoint_hash(proof.first)?
      || r.second_hash != second_hash
      || r.stage != plan.stage.bytes
      || r.deadline_ms != deadline
      || U64.compare(r.prepared_at, base.timestamp) > 0
      || U64.compare(r.settled_at, base.timestamp) > 0 do
      return Err("collateral_proof_receipt_collision")
    end
    for index in 0..List.length(r.rows) do
      let row = List.get(r.rows, index)
      let key = List.get(plan.witnesses, index).key
      if row.witness != List.get(plan.witnesses, index).address.bytes
        || row.identity != bond_witness_identity(key.witness_id, key.public_key)?
        || row.public_key != key.public_key do
        return Err("collateral_proof_receipt_subject")
      end
    end
    Some(r)
  end
  let done = case receipt do
    None -> false
    Some(r) -> r.settled
  end
  if !done do
    if !intent.close && U64.compare(now, deadline) > 0 do
      return Err("collateral_proof_expired")
    end
    for b in [directory] ++ subject_bonds do
      if b.status < 1 || b.status > 3 do
        return Err("collateral_proof_uncollectible_lifetime")
      end
    end
    case receipt do
      None -> nil
      Some(r) ->
        if directory.asset != r.directory_asset || directory.bonded_at != r.directory_bonded_at do
          return Err("collateral_proof_directory_lifetime")
        end
        for index in 0..List.length(subject_bonds) do
          let b = List.get(subject_bonds, index)
          let row = List.get(r.rows, index)
          if row.asset != b.asset || row.bonded_at != b.bonded_at do
            return Err("collateral_proof_witness_lifetime")
          end
        end
        nil
    end
  end
  let directory_balance = if directory.status == 3 do
    U64.parse("0")?
  else if directory.asset == 0 do
    base.usdc_balance
  else
    base.morse_balance
  end
  let amounts = subjects ++ [(directory, directory_balance)]
  let usd = List.reduce(amounts,
    Ok(U64.parse("0")?),
    fn(total, row) do
      let (b, amount) = row
      if b.asset == 0 do
        U64.add(total?, amount)
      else
        total
      end
    end)?
  let morse = List.reduce(amounts,
    Ok(U64.parse("0")?),
    fn(total, row) do
      let (b, amount) = row
      if b.asset == 1 do
        U64.add(total?, amount)
      else
        total
      end
    end)?
  let usd_finder = List.reduce(amounts,
    Ok(U64.parse("0")?),
    fn(total, row) do
      let (bond, amount) = row
      if bond.asset == 0 do
        U64.add(total?, U64.divide(amount, U64.parse("10")?)?)
      else
        total
      end
    end)?
  let morse_finder = List.reduce(amounts,
    Ok(U64.parse("0")?),
    fn(total, row) do
      let (bond, amount) = row
      if bond.asset == 1 do
        U64.add(total?, U64.divide(amount, U64.parse("10")?)?)
      else
        total
      end
    end)?
  let missing = for index in 0..4 when operator_absent(List.get(snapshot.accounts,
    di + 2 + index)) do
    index
  end
  let finder = Pubkey { bytes: plan.finder }
  let locked = collateral_derived(c.judge, [Bytes.from_utf8("locked"), a.log_id])?
  for index in 0..4 do
    let mint = if index < 2 do
      c.usdc_mint
    else
      a.morse_mint
    end
    let owner = if index % 2 == 0 do
      finder
    else
      locked
    end
    let balance = operator_optional_vault(snapshot, di + 2 + index, mint, owner)?
    U64.add(balance,
      if index == 0 do
        usd_finder
      else if index == 1 do
        U64.subtract(usd, usd_finder)?
      else if index == 2 do
        morse_finder
      else
        U64.subtract(morse, morse_finder)?
      end)?
  end
  let aux_digest = case aux do
    None -> Bytes.empty()
    Some(v) ->
      let generation = case generation do
        None -> return Err("collateral_proof_anchor_missing")
        Some(value) -> value
      end
      let set = collateral_derived(c.judge,
        [
          Bytes.from_utf8("witness-set"),
          a.log_id,
          Bytes.write_uint_le(Int.to_string(generation), 2)?
        ])?
      operator_snapshot_digest([a.ring, a.ring, set],
        OptionalAccountSlicesAtSlot {
          slot: snapshot.slot,
          accounts: [v.header.account, v.entry.account, v.witnesses.account]
        })?
  end
  let legacy_witnesses = List.flatten(for target in plan.witnesses do
    let selected = for index in 0..List.length(intent.witnesses) when List.get(intent.witnesses,
      index) == target.key do
      index
    end
    if List.length(selected) != 1 do
      return Err("collateral_proof_subject_selection")
    end
    let raw = operator_owned(snapshot, 27 + List.head(selected) * 4 + 1, c.judge, 208)?
    if Bytes.to_hex(Bytes.slice(raw, 0, 4)?) == "4d424401" do
      [CollateralWitness(target.key)]
    else
      []
    end
  end)
  let legacy_subjects = (if base.legacy_bond do
    [CollateralDirectory]
  else
    []
  end)
    ++ legacy_witnesses
  Ok(CollateralProofState {
    base: base,
    digest: Crypto.sha256(Bytes.concat(operator_snapshot_digest(keys, snapshot)?, aux_digest)?),
    selection: collateral_proof_selection(pins, intent)?,
    plan: plan,
    stage: stage,
    receipt: receipt,
    second_hash: second_hash,
    anchor_generation: generation,
    deadline_ms: deadline,
    directory: directory,
    subjects: subject_bonds,
    legacy_subjects: legacy_subjects,
    usdc_amount: usd,
    morse_amount: morse,
    payout_missing: missing
  })
end

fn proof_piece(client :: Int,
  url :: String,
  address :: Pubkey,
  offset :: Int,
  count :: Int,
  slot :: U64) -> AccountSliceAtSlot!String do
  let request = get_account_info_slice_request(1, address, "finalized", offset, count, Some(slot))?
  let result = account_slice_from_response(rpc_send(client, url, request, 5000, 16384)?)?
  if result.slot != slot do
    return Err("collateral_proof_mixed_bank")
  end
  Ok(result)
end

pub fn read_collateral_proof_origin(client :: Int,
  url :: String,
  pins :: CollateralOperatorPins,
  intent :: CollateralProofIntent,
  minimum :: U64,
  reference_time :: U64) -> CollateralProofState!String do
  let keys = collateral_proof_keys(pins, intent)?
  let request = get_multiple_accounts_slice_request(1, keys, "finalized", 0, 9216, Some(minimum))?
  let main = optional_accounts_slice_from_response(rpc_send(client, url, request, 5000, 1048576)?)?
  if U64.compare(main.slot, minimum) < 0 do
    return Err("collateral_proof_stale_slot")
  end
  let proof = validate_relay_submission(pins.service_key, pins.log_version, intent.wire)?
  let aux = case proof.second do
    SignedCheckpoint(_) -> None
    AnchorReference(index) ->
      let a = token_collateral_addresses(pins.context)?
      let header = proof_piece(client, url, a.ring, 0, 64, main.slot)?
      let entry = proof_piece(client, url, a.ring, 64 + index * 104, 104, main.slot)?
      let raw = case entry.account do
        None -> return Err("collateral_proof_anchor_missing")
        Some(v) -> v.info.data
      end
      let parsed = decode_anchor_entry(raw)?
      let address = collateral_derived(pins.context.judge,
        [
          Bytes.from_utf8("witness-set"),
          a.log_id,
          Bytes.write_uint_le(Int.to_string(parsed.witness_generation), 2)?
        ])?
      Some(CollateralProofAnchor {
        header: header,
        entry: entry,
        witnesses: proof_piece(client, url, address, 0, 2752, main.slot)?
      })
  end
  decode_collateral_proof_snapshot(pins, intent, minimum, reference_time, main, aux)
end

pub fn collateral_proof_quorum(first :: CollateralProofState!String,
  second :: CollateralProofState!String,
  third :: CollateralProofState!String) -> CollateralProofState!String do
  for pair in [(first, second), (first, third), (second, third)] do
    case pair do
      (Ok(a), Ok(b)) -> if a.digest == b.digest && a.selection == b.selection do
        return Ok(a)
      end
      _ -> nil
    end
  end
  Err("collateral_proof_quorum_unavailable_or_disagreed")
end

pub fn collateral_proof_selection(pins :: CollateralOperatorPins,
  intent :: CollateralProofIntent) -> Bytes!String do
  let body = List.reduce(collateral_proof_keys(pins, intent)?,
    Ok(collateral_selection_digest(pins, CollateralDirectory, intent.submitter)?),
    fn(value, key) do Bytes.concat(value?, key.bytes) end)?
  Ok(Crypto.sha256(Bytes.concat(body, Crypto.sha256(intent.wire))?))
end

# Production entrypoint takes no caller-supplied clock or oracle price.
pub fn read_collateral_proof(client :: Int,
  sources :: List<String>,
  pins :: CollateralOperatorPins,
  intent :: CollateralProofIntent,
  minimum :: U64) -> CollateralProofState!String do
  validate_collateral_operator_sources(sources)?
  let now = U64.parse(Int.to_string(DateTime.to_unix_secs(DateTime.utc_now())))?
  let state = collateral_proof_quorum(read_collateral_proof_origin(client,
      List.get(sources, 0),
      pins,
      intent,
      minimum,
      now),
    read_collateral_proof_origin(client, List.get(sources, 1), pins, intent, minimum, now),
    read_collateral_proof_origin(client, List.get(sources, 2), pins, intent, minimum, now))?
  let finished = U64.parse(Int.to_string(DateTime.to_unix_secs(DateTime.utc_now())))?
  collateral_operator_freshness(state.base, finished)?
  let done = case state.receipt do
    None -> false
    Some(value) -> value.settled
  end
  if !intent.close
    && !done
    && U64.compare(U64.multiply(finished, U64.parse("1000")?)?, state.deadline_ms) > 0 do
    return Err("collateral_proof_local_deadline_elapsed")
  end
  Ok(state)
end
