from Input import RelayConfig, LookupRequest
from Request import CollateralOperatorConfig
from Tests.RelayMpr2Fixture import fixture_receipt
from Lookup import choose_lookup, retained_lookup
from Transparency.RelayLookupRead import RelayLookupState
from Solana.Read import pubkey

fn revision() -> Bool!String do
  let (pins, _, _) = fixture_receipt("mixed-proof-prepared")?
  let payer = pubkey("E6Lu6twRJzX5iXouS9o23fBHX9upgXbApcZyRY3cLYVL")?
  let config = RelayConfig {
    operator: CollateralOperatorConfig { pins: pins, sources: [] },
    submitter: payer,
    fee_payer: payer,
    witnesses: []
  }
  let old = LookupRequest {
    creation_slot: U64.parse("99998")?,
    addresses: [pins.context.usdc_mint, pins.context.token, pins.context.rewards]
  }
  let previous = retained_lookup(config, old)?
  let candidate = retained_lookup(config,
    LookupRequest {
      creation_slot: U64.parse("100000")?,
      addresses: [pins.context.usdc_mint, pins.context.token]
    })?
  let observed = RelayLookupState {
    status: "ready",
    address: previous.table,
    authority: payer,
    creation_slot: old.creation_slot,
    context_slot: U64.parse("100000")?,
    last_extended_slot: U64.parse("99999")?,
    deactivation_slot: U64.parse("18446744073709551615")?,
    addresses: old.addresses
  }
  let retained = choose_lookup(config, candidate, old, observed)?
  assert(retained.table == previous.table && retained.addresses == old.addresses)
  assert(choose_lookup(config,
    candidate,
    old,
    %{observed | status: "missing", addresses: []})?.table == previous.table)
  assert(choose_lookup(config,
    candidate,
    old,
    %{observed |
      status: "missing",
      context_slot: U64.parse("100511")?,
      addresses: []
    })?.table == candidate.table)
  let changed = retained_lookup(config,
    LookupRequest {
      creation_slot: U64.parse("100000")?,
      addresses: [pins.context.usdc_mint, pins.context.judge]
    })?
  assert(choose_lookup(config, changed, old, observed)?.addresses == changed.addresses)
  assert(Result.is_err(choose_lookup(config,
    candidate,
    old,
    %{observed | authority: pins.context.token})))
  Ok(true)
end

test("lookup revisions retain compatible tables and propose replacements without stranding old rent") do
  case revision() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
