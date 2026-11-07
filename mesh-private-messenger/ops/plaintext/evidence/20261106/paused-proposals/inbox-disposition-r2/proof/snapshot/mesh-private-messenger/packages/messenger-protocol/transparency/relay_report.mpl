from Solana.Read import Pubkey, pubkey_string
from Solana.Tx import Instruction, AccountMeta, instruction_report_json
from Transparency.RelayAdmission import RelayAdmission, RelaySettlementPlan
from Transparency.RelayStage import RelayStagePlan, RelayStageSignature, RelayStageWitness
from Transparency.RelayClock import RelayClock
from Transparency.RelayLookup import RelayLookupPlan
from Transparency.AnchorWrite import AnchorInstructionPair
from Transparency.Merkle import WitnessKey
from Transparency.SlashReceiptRead import ConfirmedSlashReceipt, slash_receipt_report

fn address(value :: Pubkey) -> String do
  Json.encode_string(pubkey_string(value))
end

fn hex(value :: Bytes) -> String do
  Json.encode_string(Bytes.to_hex(value))
end

fn units(value :: U64) -> String do
  Json.encode_string(U64.to_string(value))
end

fn stage_json(stage :: RelayStagePlan) -> String do
  let append = String.join(for chunk in stage.append do
      hex(chunk)
    end,
    ",")
  let signatures = String.join(for step in stage.signatures do
      let witness = case step.witness do
        None -> "null"
        Some(value) -> address(value)
      end
      """{"ordinal":#{step.ordinal},"witness":#{witness},"ed25519_hex":#{hex(step.pair.ed25519)},"judge_hex":#{hex(step.pair.judge)}}"""
    end,
    ",")
  let witnesses = String.join(for subject in stage.witnesses do
      """{"witness_id":#{Json.encode_string(subject.key.witness_id)},"public_key":#{hex(subject.key.public_key)},"address":#{address(subject.address)}}"""
    end,
    ",")
  """{"address":#{address(stage.stage)},"full_hash":#{hex(stage.full_hash)},"initialize_hex":#{hex(stage.initialize)},"append_hex":[#{append}],"seal_hex":#{hex(stage.seal)},"close_hex":#{hex(stage.close)},"signatures":[#{signatures}],"witnesses":[#{witnesses}]}"""
end

# The writer consumes instructions generated locally by Mesh, never account
# lists supplied by an HTTP client. Decimal strings retain exact token units.
fn lookup_json(value :: RelayLookupPlan) -> String do
  let addresses = String.join(for key in value.addresses do
      address(key)
    end,
    ",")
  let extensions = String.join(for instruction in value.extend do
      instruction_report_json(instruction)
    end,
    ",")
  """{"address":#{address(value.table)},"recent_slot":#{units(value.recent_slot)},"addresses":[#{addresses}],"create":#{instruction_report_json(value.create)},"extend":[#{extensions}],"deactivate":#{instruction_report_json(value.deactivate)},"close":#{instruction_report_json(value.close)}}"""
end

fn allocation(step :: String, target :: Pubkey, space :: Int) -> String do
  """{"step":#{Json.encode_string(step)},"address":#{address(target)},"space":#{space}}"""
end

# Full allocation sizes are conservative rent upper bounds, even when a
# destination is prefunded or an idempotent instruction finds it initialized.
# The chain writer obtains rent prices from independent finalized providers.
# It never subtracts anticipated refunds or invents protocol account layouts.
fn rent_json(value :: RelaySettlementPlan) -> String do
  let setup = for index in 0..List.length(value.setup) do
    let instruction = List.get(value.setup, index)
    allocation("setup/#{index}", List.get(instruction.accounts, 1).pubkey, 165)
  end
  let initial = [allocation("initialize", value.stage.stage, 1152 + Bytes.length(value.proof))]
    ++ setup
    ++ [
      allocation("settle", value.receipt, 288 + 96 * List.length(value.stage.witnesses)),
      allocation("create-table", value.lookup.table, 56)
    ]
  let extensions = for index in 0..List.length(value.lookup.extend) do
    # Each instruction's payload has its own 12-byte header. Summing its
    # address bytes also handles a short final extension without a chunk rule.
    let bytes = List.reduce(for earlier in 0..(index + 1) do
        Bytes.length(List.get(value.lookup.extend, earlier).data) - 12
      end,
      0,
      fn(total, size) -> total + size end)
    allocation("extend-table/#{index}", value.lookup.table, 56 + bytes)
  end
  "[#{String.join(initial ++ extensions, ",")}]"
end

pub fn relay_admission_report(result :: RelayAdmission) -> String do
  case result do
    AlreadySettled(value) -> """{"schema_version":1,"status":"settled","receipt":#{slash_receipt_report(value)}}"""
    ReadyToSubmit(value) -> do
      let setup = String.join(for instruction in value.setup do
          instruction_report_json(instruction)
        end,
        ",")
      """{"schema_version":1,"status":"ready","program":#{address(value.program)},"log":#{address(value.log)},"submitter":#{address(value.submitter)},"mint":#{address(value.mint)},"receipt":#{address(value.receipt)},"proof_hex":#{hex(value.proof)},"proof_hash":#{hex(value.stage.proof_hash)},"finder":#{Json.encode_string(Bytes.to_base58(value.stage.finder))},"stage":#{stage_json(value.stage)},"setup":[#{setup}],"settlement":#{instruction_report_json(value.settlement)},"compute_budget":#{instruction_report_json(value.compute_budget)},"lookup":#{lookup_json(value.lookup)},"rent_allocations":#{rent_json(value)},"estimate":{"total_slashed_units":#{units(value.total_slashed)},"finder_units":#{units(value.finder_amount)},"directory_slashed_units":#{units(value.directory_slashed)}},"clock":{"earliest_seconds":"#{value.clock.earliest_seconds}","latest_seconds":"#{value.clock.latest_seconds}"},"context_slot":#{units(value.context_slot)}}"""
    end
  end
end
