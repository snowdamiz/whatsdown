from HistoryLegacyPins import LegacyHistoryPins, legacy_bond_keys, legacy_context_keys, legacy_pda
from HistoryLegacyContext import LegacyHistoryContext, legacy_context, legacy_digest
from CollateralAccounts import (
  collateral_owned,
  collateral_absent,
  collateral_vault,
  collateral_number
)
from HistoryIndex import (
  PublicHistoryRecord,
  PublicHistoryScope,
  PublicHistorySnapshot,
  PublicHistoryAccount,
  decode_legacy_public_history
)
from Transparency.AnchorChain import anchor_addresses
from Transparency.AnchorBond import decode_anchor_bond
from Transparency.Merkle import WitnessKey
from Transparency.SlashReceipt import decode_slash_receipt, slash_receipt_address
from Solana.Read import Pubkey, OptionalAccountSlicesAtSlot, pubkey_string

fn q(value :: String) -> String do
  Json.encode_string(value)
end

fn units(value :: U64) -> String do
  q(U64.to_string(value))
end

fn flag(value :: Bool) -> String do
  if value do
    "true"
  else
    "false"
  end
end

fn address(value :: Bytes) -> String do
  q(Bytes.to_base58(value))
end

pub fn legacy_page_header(pins :: LegacyHistoryPins,
  context :: LegacyHistoryContext,
  digest :: Bytes) -> String do
  """"schema_version":1,"context_kind":"legacy-v1","availability":"available","selection_scope":"explicit-indexed-records-only","bank_scope":"this-value-page-only","context_slot":#{units(context.slot)},"source_time_unix":#{units(context.timestamp)},"snapshot_digest":#{q(Bytes.to_hex(digest))},"code_current":#{flag(context.code_current)},"judge":#{q(pubkey_string(pins.judge))},"log_name":#{q(pins.log_name)},"log_id":#{q(Bytes.to_hex(context.log.log_id))},"service_public_key":#{q(Bytes.to_hex(pins.service_key))},"mint":#{q(pubkey_string(pins.mint))},"decimals":6,"asset_scope":#{q("configured-legacy-mint")}"""
end

fn bond_row(pins :: LegacyHistoryPins,
  context :: LegacyHistoryContext,
  keys :: List<Pubkey>,
  snapshot :: OptionalAccountSlicesAtSlot,
  at :: Int,
  selected :: Option<PublicHistoryRecord>) -> String!String do
  let bond_address = List.get(keys, at)
  if !collateral_absent(List.get(snapshot.accounts, at + 1)) do
    return Err("legacy_history_pending_layout")
  end
  if collateral_absent(List.get(snapshot.accounts, at)) do
    case selected do
      Some(_) -> return Err("legacy_history_bond_missing")
      None -> nil
    end
    if context.economics.directory_status != 0 do
      return Err("legacy_history_directory_missing")
    end
    return Ok("""{"kind":"directory","status":"unbonded","address":#{q(pubkey_string(bond_address))},"witness_id":"","public_key":null,"principal_units":null,"vault_balance_units":null,"donation_surplus_units":null,"pending_units":null}""")
  end
  let bond = decode_anchor_bond(collateral_owned(snapshot, at, pins.judge, 208)?)?
  if bond.log_id != context.log.log_id
    || bond.mint != pins.mint.bytes
    || bond.vault != List.get(keys, at + 2).bytes
    || U64.compare(bond.bonded_at, context.timestamp) > 0
    || U64.compare(bond.unbond_at, context.timestamp) > 0
    || U64.compare(bond.slashed_at, context.timestamp) > 0 do
    return Err("legacy_history_bond_identity")
  end
  let (kind, id, key) = case selected do
    None -> do
      if bond.kind != 0
        || bond.owner != context.economics.directory_owner
        || bond.status != context.economics.directory_status
        || bond.principal != context.economics.directory_principal
        || context.log.directory_bond_vault != bond.vault
        || context.log.service_slashed != (bond.status == 3) do
        return Err("legacy_history_directory_identity")
      end
      ("directory", "", "null")
    end
    Some(expected) -> do
      let raw = case List.get(snapshot.accounts, at - 1) do
        None -> return Err("legacy_history_witness_missing")
        Some(value) -> value
      end
      let verified = decode_legacy_public_history(PublicHistoryScope {
          kind: 1,
          program: pins.judge,
          binding: context.log.log_id,
          usdc: pins.mint.bytes,
          morse: Bytes.empty(),
          treasury: Bytes.empty()
        },
        PublicHistorySnapshot {
          slot: snapshot.slot,
          accounts: [
            PublicHistoryAccount {
              address: List.get(keys, at - 1),
              account: raw.info,
              space: raw.space
            }
          ]
        },
        context.slot,
        1)?
      let record = List.head(verified.records)
      if record.verification != "supported"
        || record.address != expected.address
        || record.witness_id != expected.witness_id
        || record.public_key != expected.public_key
        || bond.kind != 1
        || bond.witness != expected.address.bytes
        || record.registry_status != bond.status
        || Bytes.slice(raw.info.data, 104, 32)? != bond.owner
        || Bytes.to_hex(Bytes.slice(raw.info.data, 136, 32)?) == String.repeat("00", 32)
        || Bytes.slice(raw.info.data, 232, 32)? != bond.vault
        || collateral_number(raw.info.data, 264)? != bond.unbond_at do
        return Err("legacy_history_witness_identity")
      end
      ("witness", expected.witness_id, q(Bytes.to_hex(expected.public_key)))
    end
  end
  let balance = case collateral_vault(snapshot, at + 2, pins.mint, bond_address)? do
    None -> return Err("legacy_history_vault_missing")
    Some(value) -> value
  end
  if U64.compare(balance, bond.principal) < 0 do
    return Err("legacy_history_vault_underfunded")
  end
  let status = List.get(["active", "unbonding", "slashed", "withdrawn"], bond.status - 1)
  Ok("""{"kind":#{q(kind)},"status":#{q(status)},"address":#{q(pubkey_string(bond_address))},"witness_id":#{q(id)},"public_key":#{key},"owner":#{address(bond.owner)},"vault":#{address(bond.vault)},"principal_units":#{units(bond.principal)},"vault_balance_units":#{units(balance)},"donation_surplus_units":#{units(U64.subtract(balance,
    bond.principal)?)},"pending_units":null,"liability_scope":"principal-only-v1-no-v2-pending-interpretation","bonded_at_unix":#{units(bond.bonded_at)},"unbond_at_unix":#{units(bond.unbond_at)},"slashed_at_unix":#{units(bond.slashed_at)}}""")
end

pub fn legacy_bonds(pins :: LegacyHistoryPins,
  records :: List<PublicHistoryRecord>,
  snapshot :: OptionalAccountSlicesAtSlot,
  minimum :: U64) -> (String, Bytes)!String do
  let witnesses = for row in records do
    WitnessKey { witness_id: row.witness_id, public_key: row.public_key }
  end
  let keys = legacy_bond_keys(pins, witnesses)?
  if List.length(keys) != List.length(snapshot.accounts) do
    return Err("legacy_history_batch_length")
  end
  let context = legacy_context(pins, snapshot, minimum)?
  let digest = legacy_digest(keys, snapshot, "morse-public-history-legacy-bonds-v1")?
  let rows = List.concat([bond_row(pins, context, keys, snapshot, 7, None)?],
    for index in 0..List.length(records) do
      bond_row(pins, context, keys, snapshot, 11 + index * 4, Some(List.get(records, index)))?
    end)
  Ok(("{"
      <> legacy_page_header(pins, context, digest)
      <> ",\"rows\":["
      <> String.join(rows, ",")
      <> "]}",
    digest))
end

pub fn legacy_proof_keys(pins :: LegacyHistoryPins,
  records :: List<PublicHistoryRecord>) -> List<Pubkey>!String do
  if List.length(records) > 16 do
    return Err("legacy_history_page_bound")
  end
  let anchor = anchor_addresses(pins.judge, pins.log_name)?
  let receipts = for row in records do
    slash_receipt_address(pins.judge, anchor.log_id, row.proof_hash)?
  end
  Ok(List.concat(legacy_context_keys(pins)?, receipts))
end

fn bit_count(value :: Int) -> Int do
  if value == 0 do
    0
  else
    value % 2 + bit_count(value / 2)
  end
end

pub fn legacy_proofs(pins :: LegacyHistoryPins,
  records :: List<PublicHistoryRecord>,
  snapshot :: OptionalAccountSlicesAtSlot,
  minimum :: U64) -> (String, Bytes)!String do
  let keys = legacy_proof_keys(pins, records)?
  if List.length(keys) != List.length(snapshot.accounts) do
    return Err("legacy_history_batch_length")
  end
  let context = legacy_context(pins, snapshot, minimum)?
  let digest = legacy_digest(keys, snapshot, "morse-public-history-legacy-proofs-v1")?
  let receipts = for index in 0..List.length(records) do
    let expected = List.get(records, index)
    let account = case List.get(snapshot.accounts, 7 + index) do
      None -> return Err("legacy_history_receipt_missing")
      Some(value) -> value
    end
    let raw = collateral_owned(snapshot, 7 + index, pins.judge, Bytes.length(account.info.data))?
    let value = decode_slash_receipt(raw)?
    if expected.address != List.get(keys, 7 + index)
      || expected.version != 1
      || value.proof_hash != expected.proof_hash
      || value.log_id != context.log.log_id
      || value.mint != pins.mint.bytes
      || !context.log.service_slashed
      || context.economics.directory_status != 3
      || U64.compare(value.slashed_at, context.timestamp) > 0 do
      return Err("legacy_history_receipt_identity")
    end
    let rows = for row in value.witnesses do
      """{"witness":#{address(row.witness)},"public_key":#{q(Bytes.to_hex(row.public_key))},"principal_units":#{units(row.principal)},"slashed_units":#{units(row.slashed)},"finder_units":#{units(row.finder_amount)}}"""
    end
    """{"version":1,"status":"settled","address":#{q(pubkey_string(expected.address))},"proof_hash":#{q(Bytes.to_hex(value.proof_hash))},"kind":#{value.kind},"anchored":#{flag(value.anchored)},"finder":#{address(value.finder)},"submitter":#{address(value.submitter)},"slashed_at_unix":#{units(value.slashed_at)},"total_slashed_units":#{units(value.total_slashed)},"finder_units":#{units(value.finder_amount)},"directory_slashed_units":#{units(value.directory_slashed)},"verified_signature_mask":#{units(value.verified_signatures)},"verified_signatures":#{q(Int.to_string(bit_count(U64.to_int(value.verified_signatures)?)))},"row_identity_scope":"recorded-legacy-address-and-key-no-id-seed","rows":[#{String.join(rows,
      ",")}] }"""
  end
  Ok(("{"
      <> legacy_page_header(pins, context, digest)
      <> ",\"proof_scope\":\"onchain-recorded-receipts-not-independent-fork-reverification\",\"receipts\":["
      <> String.join(receipts, ",")
      <> "]}",
    digest))
end
