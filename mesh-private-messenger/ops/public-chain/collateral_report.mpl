from CollateralPins import CollateralSelection, collateral_receipt_keys
from CollateralAccounts import CollateralContext
from CollateralState import PublicBonds, PublicSlashes
from Solana.Read import pubkey, pubkey_string

fn q(value :: String) -> String do
  Json.encode_string(value)
end

fn u(value :: U64) -> String do
  q(U64.to_string(value))
end

fn flag(value :: Bool) -> String do
  if value do
    "true"
  else
    "false"
  end
end

fn address(value :: Bytes) -> String!String do
  Ok(q(pubkey_string(pubkey(Bytes.to_base58(value))?)))
end

fn status(value :: Int) -> String do
  case value do
    1 -> "active"
    2 -> "unbonding"
    3 -> "slashed"
    _ -> "withdrawn"
  end
end

fn header(selection :: CollateralSelection,
  context :: CollateralContext,
  digest :: Bytes) -> String do
  let p = selection.pins
  """"schema_version":2,"availability":"available","selection_scope":"explicit-indexed-records-only","bank_scope":"this-section-only","context_slot":#{u(context.slot)},"source_time_unix":#{u(context.timestamp)},"snapshot_digest":#{q(Bytes.to_hex(digest))},"code_current":#{flag(context.code_current)},"judge":#{q(pubkey_string(p.judge))},"token":#{q(pubkey_string(p.token))},"rewards":#{q(pubkey_string(p.rewards))},"log_name":#{q(p.log_name)},"log_id":#{q(Bytes.to_hex(context.log.log_id))},"service_public_key":#{q(Bytes.to_hex(p.service_key))},"usdc_mint":#{q(pubkey_string(p.usdc))},"morse_mint":#{q(pubkey_string(p.morse))},"decimals":6"""
end

pub fn unavailable_collateral(status :: String) -> String do
  """{"schema_version":2,"availability":#{q(status)},"reason":"no-agreeing-finalized-selected-snapshot"}"""
end

pub fn public_bonds_report(selection :: CollateralSelection,
  state :: PublicBonds) -> String!String do
  let rows = for row in state.rows do
    let b = row.bond
    let other = case row.opposite_balance do
      None -> """{"availability":"absent","balance_units":null}"""
      Some(value) -> """{"availability":"present","balance_units":#{u(value)}}"""
    end
    """{"kind":#{q(row.kind)},"witness_id":#{q(row.witness_id)},"public_key":#{q(Bytes.to_hex(row.public_key))},"address":#{q(pubkey_string(row.address))},"owner":#{address(b.owner)?},"asset":#{q(if b.asset == 0 do
      "USDC"
    else
      "MORSE"
    end)},"mint":#{address(b.mint)?},"vault":#{address(b.vault)?},"status":#{q(status(b.status))},"principal_units":#{u(b.principal)},"pending_recorded_units":#{u(row.pending_recorded)},"pending_liability_units":#{u(row.pending_liability)},"vault_balance_units":#{u(row.balance)},"donation_surplus_units":#{u(row.donation)},"opposite_asset_vault":#{other},"bonded_at_unix":#{u(b.bonded_at)},"unbond_at_unix":#{u(b.unbond_at)},"slashed_at_unix":#{u(b.slashed_at)},"underwater_since_unix":#{u(b.underwater_since)},"pending_target_usd_micros":#{u(row.pending_target_usd)}}"""
  end
  Ok("""{#{header(selection,
    state.context,
    state.digest)},"valuation":{"availability":"unavailable","reason":"no-oracle-authentication-or-USD-valuation"},"rows":[#{String.join(rows,
    ",")}] }""")
end

pub fn public_slashes_report(selection :: CollateralSelection,
  state :: PublicSlashes) -> String!String do
  let keys = collateral_receipt_keys(selection)?
  let receipts = for index in 0..List.length(state.receipts) do
    let r = List.get(state.receipts, index)
    let rows = for row in r.rows do
      let amount = if r.settled do
        u(row.slashed)
      else
        "null"
      end
      let principal = if r.settled do
        u(row.principal)
      else
        "null"
      end
      let finder = if r.settled do
        u(row.finder)
      else
        "null"
      end
      """{"identity":#{q(Bytes.to_hex(row.identity))},"witness":#{address(row.witness)?},"public_key":#{q(Bytes.to_hex(row.public_key))},"asset":#{q(if row.asset == 0 do
        "USDC"
      else
        "MORSE"
      end)},"bonded_at_unix":#{u(row.bonded_at)},"principal_units":#{principal},"slashed_units":#{amount},"finder_units":#{finder}}"""
    end
    let assets = for asset in 0..2 do
      let amount = if !r.settled do
        "null"
      else
        u(if asset == 0 do
          r.usdc_slashed
        else
          r.morse_slashed
        end)
      end
      let finder = if !r.settled do
        "null"
      else
        u(if asset == 0 do
          r.usdc_finder
        else
          r.morse_finder
        end)
      end
      let directory = if !r.settled do
        "null"
      else
        u(if asset == 0 do
          r.directory_usdc
        else
          r.directory_morse
        end)
      end
      """{"asset":#{q(if asset == 0 do
        "USDC"
      else
        "MORSE"
      end)},"slashed_units":#{amount},"finder_units":#{finder},"directory_slashed_units":#{directory}}"""
    end
    """{"address":#{q(pubkey_string(List.get(keys,
      14
        + index)))},"proof_hash":#{q(Bytes.to_hex(r.proof_hash))},"kind":#{r.kind},"anchored":#{flag(r.anchored)},"status":#{q(if r.settled do
      "settled"
    else
      "prepared"
    end)},"prepared_at_unix":#{u(r.prepared_at)},"settled_at_unix":#{u(r.settled_at)},"deadline_ms":#{u(r.deadline_ms)},"verified_signature_mask":#{u(r.verified_signature_mask)},"verified_signatures":#{u(r.verified_signatures)},"finder":#{address(r.finder)?},"submitter":#{address(r.submitter)?},"stage":#{address(r.stage)?},"assets":[#{String.join(assets,
      ",")}],"rows":[#{String.join(rows, ",")}] }"""
  end
  Ok("""{#{header(selection,
    state.context,
    state.digest)},"proof_scope":"onchain-recorded-receipts-not-independent-fork-reverification","receipts":[#{String.join(receipts,
    ",")}] }""")
end
