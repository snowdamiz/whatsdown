from Transparency.AnchorCustody import AnchorCustody, AnchorWitnessBond, AnchorBondBalance
from Transparency.AnchorBond import AnchorBond, AnchorEconomics
from Transparency.AnchorLog import AnchorLog
from Solana.Read import Pubkey, pubkey_string

fn quote(value :: String) -> String do
  Json.encode_string(value)
end

fn units(value :: U64) -> String do
  quote(U64.to_string(value))
end

fn address(value :: Bytes) -> String do
  if Bytes.length(value) == 0 do
    "null"
  else
    quote(Bytes.to_base58(value))
  end
end

fn escrow(value :: Option<AnchorBondBalance>) -> String!String do
  case value do
    None -> Ok("null")
    Some(value) -> do
      let bond = value.bond
      let status = List.get(["registered", "active", "unbonding", "slashed", "withdrawn"],
        bond.status)
      let bonded = if bond.status == 1 || bond.status == 2 do
        value.vault_amount
      else
        U64.parse("0")?
      end
      Ok("""{"status":#{quote(status)},"owner":#{address(bond.owner)},"vault":#{address(bond.vault)},"principal_units":#{units(bond.principal)},"vault_units":#{units(value.vault_amount)},"bonded_units":#{units(bonded)},"bonded_at":#{units(bond.bonded_at)},"unbond_requested_at":#{units(bond.unbond_at)},"slashed_at":#{units(bond.slashed_at)}}""")
    end
  end
end

fn policy(value :: Option<AnchorEconomics>) -> String do
  case value do
    None -> "null"
    Some(value) -> """{"minimum_witness_units":#{units(value.minimum_witness)},"minimum_directory_units":#{units(value.minimum_directory)},"ready_at":#{units(value.ready_at)},"pending_witness_units":#{units(value.pending_witness)},"pending_directory_units":#{units(value.pending_directory)},"pending_ready_at":#{units(value.pending_ready)},"witness_principal_units":#{units(value.witness_principal)},"directory_principal_units":#{units(value.directory_principal)}}"""
  end
end

# Only publish an authenticated snapshot. Decimal strings preserve u64 values
# through JSON/JS; vault balances include donations, principal does not. A
# caller supplies the explicit mint pin, so local tokens cannot imply dollars.
pub fn anchor_custody_report(value :: AnchorCustody, expected_mint :: Pubkey) -> String!String do
  let status = case value.economics do
    None -> "unconfigured"
    Some(_) -> "configured"
  end
  let witnesses = for witness in value.witnesses do
    """{"id":#{quote(witness.witness_id)},"public_key":#{quote(Bytes.to_hex(witness.public_key))},"status":#{quote(witness.status)},"operator":#{address(witness.owner)},"payout":#{address(witness.payout)},"bond":#{escrow(witness.escrow)?}}"""
  end
  let slashed = if value.log.service_slashed do
    "true"
  else
    "false"
  end
  Ok("""{"schema_version":1,"status":#{quote(status)},"log":#{quote(value.log.name)},"log_version":#{value.log.version},"mint":#{quote(pubkey_string(expected_mint))},"decimals":6,"context_slot":#{units(value.context_slot)},"service_slashed":#{slashed},"economics":#{policy(value.economics)},"directory":#{escrow(value.directory)?},"witnesses":[#{String.join(witnesses,
    ",")}] }""")
end
