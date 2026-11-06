# Test-only harness: caller-owned loopback RPC banks replace public providers.
# Every protocol decision uses the same public Mesh functions as fork-verifier.
# This executable is not a deployable admission boundary and has no wallet.
from Transparency.AnchorChain import (
  AnchorPins,
  AnchorAddresses,
  anchor_addresses,
  sample_anchor_sources
)
from Transparency.RpcTransport import webpki_rpc_transport
from Transparency.RelayAdmission import admit_relay_fork
from Transparency.RelayReport import relay_admission_report
from Transparency.RelayStageRead import read_relay_stage, relay_stage_report
from Transparency.RelayDestinations import read_relay_destinations, relay_destinations_report
from Transparency.RelayLookupRead import (
  read_relay_lookup,
  read_relay_lookup_cooldown,
  relay_lookup_report,
  relay_lookup_cooldown_report
)
from Transparency.SlashReceiptRead import read_slash_receipt_state, slash_receipt_state_report
from Transparency.Relay import validate_relay_submission
from Transparency.Fork import fork_hash
from Solana.Read import Pubkey, pubkey

fn text(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn run() -> String!String do
  let args = Env.args()
  if List.length(args) != 2 do
    return Err("expected local fixture request file")
  end
  let request = Json.parse(File.read(List.get(args, 1))?)?
  let config = Json.object_get(request, "configuration")?
  let program = pubkey(text(config, "program")?)?
  let log_name = text(config, "log_name")?
  let addresses = anchor_addresses(program, log_name)?
  let endpoints = Json.object_get(config, "endpoints")?
  let rpc = webpki_rpc_transport(for index in 0..Json.array_length(endpoints)? do
    Json.as_string(Json.array_get(endpoints, index)?)?
  end)?
  let pins = AnchorPins {
    program: program,
    log_name: log_name,
    log_id: addresses.log_id,
    ring: addresses.ring,
    rpc: rpc
  }
  let key = Bytes.from_hex(text(config, "service_key")?)?
  let version = Json.as_int(Json.object_get(config, "version")?)?
  let submitter = pubkey(text(config, "submitter")?)?
  let mint = pubkey(text(config, "mint")?)?
  let floor = U64.parse(text(request, "minimum_slot")?)?
  let wire = Bytes.from_hex(text(request, "proof_hex")?)?
  let mode = text(request, "mode")?
  case mode do
    "admit" -> Ok(relay_admission_report(admit_relay_fork(pins,
      key,
      version,
      mint,
      submitter,
      wire,
      floor)?))
    "stage" -> Ok(relay_stage_report(read_relay_stage(pins, key, version, submitter, wire, floor)?))
    "destinations" -> Ok(relay_destinations_report(read_relay_destinations(pins,
      key,
      version,
      mint,
      submitter,
      wire,
      floor)?))
    "receipt" -> do
      let proof = validate_relay_submission(key, version, wire)?
      Ok(slash_receipt_state_report(read_slash_receipt_state(sample_anchor_sources(pins)?,
        key,
        version,
        mint,
        fork_hash(proof)?,
        floor)?))
    end
    "lookup" -> do
      let slot = U64.parse(text(request, "creation_slot")?)?
      let values = Json.object_get(request, "addresses")?
      let expected = for index in 0..Json.array_length(values)? do
        pubkey(Json.as_string(Json.array_get(values, index)?)?)?
      end
      if Json.as_bool(Json.object_get(request, "closing")?)? do
        Ok(relay_lookup_cooldown_report(read_relay_lookup_cooldown(pins.rpc,
          submitter,
          slot,
          expected,
          floor)?))
      else
        Ok(relay_lookup_report(read_relay_lookup(pins.rpc, submitter, slot, expected, floor)?))
      end
    end
    _ -> Err("unknown fixture reader")
  end
end

fn main() do
  case run() do
    Ok(report) -> println(report)
    Err(error) -> do
      io_eprintln(error)
      Process.exit(1)
    end
  end
end
