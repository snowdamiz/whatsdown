##! Permissionless in-place bond migration and independent old-effect reads.
from Transparency.RpcTransport import (
  RpcTransport,
  RpcEndpoint,
  rpc_urls,
  rpc_fatal_error,
  require_rpc_current
)
from Transparency.AnchorRpc import read_anchor_rpc_response
from Input import RelayConfig, text
from ProofRead import CollateralProofIntent, CollateralProofState
from Plan import CollateralOperationPlan
from Receipt import receipt_keys, decode_receipt_snapshot
from Accounts import operator_owned, operator_absent, operator_snapshot_digest
from Read import validate_collateral_operator_sources
from Transparency.TokenCollateralWrite import (
  TokenCollateralSubject,
  token_collateral_addresses,
  token_collateral_subject,
  token_collateral_migrate_instruction
)
from Transparency.TokenCustody import decode_token_collateral_bond
from Transparency.AnchorBond import decode_anchor_bond
from Transparency.TokenChain import token_payout_address
from Transparency.Relay import validate_relay_submission
from Transparency.Fork import fork_hash
from Transparency.Merkle import WitnessKey
from Solana.Read import (
  Pubkey,
  OptionalAccountSlicesAtSlot,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  pubkey_string
)

pub fn migration_operation(config :: RelayConfig,
  intent :: CollateralProofIntent,
  state :: CollateralProofState) -> CollateralOperationPlan!String do
  if List.length(state.legacy_subjects) == 0 do
    return Err("relay_migration_not_selected")
  end
  Ok(CollateralOperationPlan {
    state: "ready",
    reason: "migrate_legacy_bond",
    slot: state.base.slot,
    digest: state.digest,
    fee_payer: intent.fee_payer,
    instruction_signers: [],
    rent_payers: [],
    governance_required: false,
    wait_until: None,
    instructions: [
      token_collateral_migrate_instruction(config.operator.pins.context,
        List.head(state.legacy_subjects))?
    ]
  })
end

pub fn migration_subject(descriptor :: Json) -> TokenCollateralSubject!String do
  let subject = Json.object_get(descriptor, "subject")?
  case text(subject, "kind")? do
    "directory" -> Ok(CollateralDirectory)
    "witness" ->
      let key = text(subject, "public_key")?
      let raw = Bytes.from_hex(key)?
      if Bytes.length(raw) != 32 || Bytes.to_hex(raw) != key do
        return Err("relay_migration_subject")
      end
      Ok(CollateralWitness(WitnessKey {
        witness_id: text(subject, "witness_id")?,
        public_key: raw
      }))
    _ -> Err("relay_migration_subject")
  end
end

pub fn migration_keys(config :: RelayConfig,
  wire :: Bytes,
  descriptor :: Json) -> List<Pubkey>!String do
  if Json.as_int(Json.object_get(descriptor, "schema_version")?)? != 1
    || text(descriptor, "reason")? != "migrate_legacy_bond"
    || text(descriptor, "full_hash")? != Bytes.to_hex(Crypto.sha256(wire)) do
    return Err("relay_migration_binding")
  end
  let p = config.operator.pins
  let proof = validate_relay_submission(p.service_key, p.log_version, wire)?
  let s = token_collateral_subject(p.context, migration_subject(descriptor)?, 0)?
  if text(descriptor, "bond")? != pubkey_string(s.bond) do
    return Err("relay_migration_binding")
  end
  Ok(receipt_keys(p, fork_hash(proof)?)? ++ [s.bond])
end

pub fn decode_migration_snapshot(config :: RelayConfig,
  wire :: Bytes,
  descriptor :: Json,
  minimum :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> Bool!String do
  let keys = migration_keys(config, wire, descriptor)?
  if List.length(snapshot.accounts) != List.length(keys) do
    return Err("relay_migration_snapshot")
  end
  let p = config.operator.pins
  let proof = validate_relay_submission(p.service_key, p.log_version, wire)?
  let receipt = decode_receipt_snapshot(p,
    fork_hash(proof)?,
    minimum,
    OptionalAccountSlicesAtSlot { slot: snapshot.slot, accounts: List.take(snapshot.accounts, 4) })?
  if receipt.status == "settled" do
    return Ok(true)
  end
  if operator_absent(List.get(snapshot.accounts, 4)) do
    return Ok(false)
  end
  let raw = operator_owned(snapshot, 4, p.context.judge, 208)?
  let a = token_collateral_addresses(p.context)?
  let subject = migration_subject(descriptor)?
  let s = token_collateral_subject(p.context, subject, 0)?
  let expected_witness = case s.witness do
    None -> Bytes.from_hex(String.repeat("00", 32))?
    Some(value) -> value.bytes
  end
  let is_witness = case subject do
    CollateralDirectory -> false
    CollateralWitness(_) -> true
  end
  if Bytes.to_hex(Bytes.slice(raw, 0, 4)?) == "4d424401" do
    let bond = decode_anchor_bond(raw)?
    if bond.log_id != a.log_id
      || bond.witness != expected_witness
      || bond.kind != (if is_witness do
          1
        else
          0
        end)
      || bond.mint != p.context.usdc_mint.bytes
      || bond.vault != s.vault.bytes do
      return Err("relay_migration_bond")
    end
    return Ok(false)
  end
  let bond = decode_token_collateral_bond(raw)?
  let mint = if bond.asset == 0 do
    p.context.usdc_mint
  else
    a.morse_mint
  end
  if bond.log_id != a.log_id
    || bond.witness_address != expected_witness
    || bond.witness != is_witness
    || bond.mint != mint.bytes
    || bond.vault != token_payout_address(s.bond, mint)?.bytes do
    return Err("relay_migration_bond")
  end
  Ok(true)
end

fn origin(rpc :: RpcTransport,
  endpoint :: RpcEndpoint,
  config :: RelayConfig,
  wire :: Bytes,
  descriptor :: Json,
  minimum :: U64) -> (Bool, U64, Bytes)!String do
  let keys = migration_keys(config, wire, descriptor)?
  let request = get_multiple_accounts_slice_request(1, keys, "finalized", 0, 9216, Some(minimum))?
  let snapshot = optional_accounts_slice_from_response(read_anchor_rpc_response(rpc,
    endpoint,
    request,
    131072)?)?
  Ok((decode_migration_snapshot(config, wire, descriptor, minimum, snapshot)?,
    snapshot.slot,
    operator_snapshot_digest(keys, snapshot)?))
end

pub fn migration_effect(rpc :: RpcTransport,
  config :: RelayConfig,
  wire :: Bytes,
  descriptor :: Json,
  minimum :: U64) -> String!String do
  require_rpc_current(rpc.require_current)?
  validate_collateral_operator_sources(rpc_urls(rpc))?
  let results = for endpoint in List.take(rpc.sources, 3) do
    let result = origin(rpc, endpoint, config, wire, descriptor, minimum)
    case result do
      Err(error) when rpc_fatal_error(error) -> return Err(error)
      _ -> result
    end
  end
  require_rpc_current(rpc.require_current)?
  let first = List.get(results, 0)
  let second = List.get(results, 1)
  let third = List.get(results, 2)
  for pair in [(first, second), (first, third), (second, third)] do
    case pair do
      (Ok((present, slot, digest)), Ok((_, _, other))) -> if digest == other do
        require_rpc_current(rpc.require_current)?
        return Ok("""{"schema_version":2,"state":"#{if present do
          "present"
        else
          "absent"
        end}","slot":"#{U64.to_string(slot)}"}""")
      end
      _ -> nil
    end
  end
  Err("relay_migration_quorum")
end
