from Solana.Read import Pubkey, AccountInfo, OptionalAccountsAtSlot, pubkey_equal, pubkey_string
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.AnchorChain import (
  AnchorPins,
  AnchorAddresses,
  anchor_addresses,
  sample_anchor_sources
)
from Transparency.AnchorBatch import read_anchor_accounts_bounded
from Transparency.AnchorLog import AnchorLog, decode_anchor_log
from Transparency.AnchorRing import anchor_bitmap_contains
from Transparency.Relay import validate_relay_submission
from Transparency.Fork import ForkProof, ForkTarget, decode_fork
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  checkpoint_hash,
  verify_witnesses
)

pub struct RelayStageVerified do
  ordinal :: Int
  public_key :: Bytes
end

pub struct RelayStageState do
  status :: String
  address :: Pubkey
  context_slot :: U64
  total_bytes :: Int
  received_bytes :: Int
  sealed :: Bool
  verified :: List<RelayStageVerified>
end

fn zeroes(bytes :: Bytes, offset :: Int, count :: Int) -> Bool!String do
  Ok(Bytes.to_hex(Bytes.slice(bytes, offset, count)?) == String.repeat("00", count))
end

fn short(bytes :: Bytes, offset :: Int) -> Int!String do
  U64.to_int(U64.parse(Bytes.read_uint_le(bytes, offset, 2)?)?)
end

fn earned(bytes :: Bytes, ordinal :: Int) -> Bool!String do
  Ok(anchor_bitmap_contains(Bytes.get(bytes, 112 + ordinal / 8)?, ordinal % 8))
end

fn verified_key(proof :: ForkProof, ordinal :: Int, key :: Bytes) -> Result<(), String> do
  let attestation = List.get(proof.attestations, ordinal - 2)
  if proof.kind == 3 && Bytes.length(attestation.signature) != 64 do
    return Err("relay_stage_invalid_verification")
  end
  let checkpoint = if Bytes.secure_equals(attestation.checkpoint_hash,
    checkpoint_hash(proof.first)?) do
    proof.first
  else
    case proof.second do
      AnchorReference(_) -> return Err("relay_stage_invalid_verification")
      SignedCheckpoint(value) -> value
    end
  end
  let pin = WitnessKey { witness_id: attestation.witness_id, public_key: key }
  if !verify_witnesses(checkpoint, [attestation], [pin], 1)? do
    return Err("relay_stage_invalid_verification")
  end
  Ok(nil)
end

# The caller validates wire with validate_relay_submission, then binds this
# account to the locally derived address and a finalized whole-batch quorum.
# read_relay_stage performs both steps. An upload is not a payout receipt or fresh custody
# admission. Returned witness keys describe immutable earned bits, not current
# membership; withdrawal/rotation cannot erase an old upload during recovery.
pub fn decode_relay_stage(program :: Pubkey,
  log_id :: Bytes,
  submitter :: Pubkey,
  wire :: Bytes,
  account :: Option<AccountInfo>,
  context_slot :: U64) -> RelayStageState!String do
  if Bytes.length(program.bytes) != 32
    || Bytes.length(log_id) != 32
    || Bytes.length(submitter.bytes) != 32
    || zeroes(submitter.bytes, 0, 32)?
    || Bytes.length(wire) > 8009 do
    return Err("invalid_relay_stage")
  end
  let proof = decode_fork(wire)?
  let digest = Crypto.sha256(wire)
  let address = find_program_address(program,
    [Bytes.from_utf8("stage"), submitter.bytes, digest])?.address
  let state = RelayStageState {
    status: "missing",
    address: address,
    context_slot: context_slot,
    total_bytes: Bytes.length(wire),
    received_bytes: 0,
    sealed: false,
    verified: []
  }
  let account = case account do
    None -> return Ok(state)
    Some(value) -> value
  end
  if !account.executable
    && Bytes.length(account.data) == 0
    && zeroes(account.owner.bytes, 0, 32)? do
    return Ok(state)
  end
  let bytes = account.data
  if !pubkey_equal(account.owner, program)
    || account.executable
    || account.lamports == U64.parse("0")?
    || Bytes.length(bytes) != 1152 + Bytes.length(wire)
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d535401"
    || Bytes.get(bytes, 4)? > 1
    || !zeroes(bytes, 5, 3)?
    || !zeroes(bytes, 12, 4)?
    || !zeroes(bytes, 1144, 8)?
    || short(bytes, 8)? != Bytes.length(wire)
    || !Bytes.secure_equals(Bytes.slice(bytes, 16, 32)?, submitter.bytes)
    || !Bytes.secure_equals(Bytes.slice(bytes, 48, 32)?, log_id)
    || !Bytes.secure_equals(Bytes.slice(bytes, 80, 32)?, digest) do
    return Err("relay_stage_changed")
  end
  let received = short(bytes, 10)?
  let sealed = Bytes.get(bytes, 4)? == 1
  if received > Bytes.length(wire) || (sealed && received != Bytes.length(wire)) do
    return Err("relay_stage_changed")
  end
  if !Bytes.secure_equals(Bytes.slice(bytes, 1152, received)?, Bytes.slice(wire, 0, received)?)
    || !zeroes(bytes, 1152 + received, Bytes.length(wire) - received)? do
    return Err("relay_stage_changed")
  end
  for ordinal in 0..64 do
    let bit = earned(bytes, ordinal)?
    if bit && (!sealed || ordinal >= 2 + List.length(proof.attestations)) do
      return Err("relay_stage_invalid_verification")
    end
    if bit && ordinal == 1 do
      case proof.second do
        AnchorReference(_) -> return Err("relay_stage_invalid_verification")
        SignedCheckpoint(_) -> nil
      end
    end
    if ordinal >= 2 && ordinal < 34 && !bit && !zeroes(bytes, 120 + (ordinal - 2) * 32, 32)? do
      return Err("relay_stage_invalid_verification")
    end
  end
  let verified = for ordinal in 0..(2 + List.length(proof.attestations)) when earned(bytes,
    ordinal)? do
    let key = if ordinal < 2 do
      proof.service_public_key
    else
      let key = Bytes.slice(bytes, 120 + (ordinal - 2) * 32, 32)?
      verified_key(proof, ordinal, key)?
      key
    end
    RelayStageVerified { ordinal: ordinal, public_key: key }
  end
  Ok(%{state |
    status: if sealed do
      "sealed"
    else if received == Bytes.length(wire) do
      "uploaded"
    else
      "uploading"
    end,
    received_bytes: received,
    sealed: sealed,
    verified: verified
  })
end

pub fn read_relay_stage(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  submitter :: Pubkey,
  wire :: Bytes,
  minimum_slot :: U64) -> RelayStageState!String do
  validate_relay_submission(service_key, version, wire)?
  let pins = sample_anchor_sources(pins)?
  let initial = decode_relay_stage(pins.program, pins.log_id, submitter, wire, None, minimum_slot)?
  let addresses = anchor_addresses(pins.program, pins.log_name)?
  let snapshot = read_anchor_accounts_bounded(pins.rpc,
    [addresses.log, initial.address],
    minimum_slot,
    9161)?
  let account = case List.head(snapshot.accounts) do
    None -> return Err("relay_stage_log_missing")
    Some(value) -> value
  end
  if account.executable
    || !pubkey_equal(account.owner, pins.program)
    || account.lamports == U64.parse("0")? do
    return Err("relay_stage_log_mismatch")
  end
  let log = decode_anchor_log(account.data)?
  if log.version != version
    || !Bytes.secure_equals(log.log_id, pins.log_id)
    || !Bytes.secure_equals(log.service_public_key, service_key)
    || !Bytes.secure_equals(log.ring_address, pins.ring.bytes) do
    return Err("relay_stage_log_mismatch")
  end
  decode_relay_stage(pins.program,
    pins.log_id,
    submitter,
    wire,
    List.get(snapshot.accounts, 1),
    snapshot.slot)
end

pub fn relay_stage_report(value :: RelayStageState) -> String do
  let verified = String.join(for item in value.verified do
      """{"ordinal":#{item.ordinal},"public_key":"#{Bytes.to_hex(item.public_key)}"}"""
    end,
    ",")
  """{"schema_version":1,"status":#{Json.encode_string(value.status)},"address":#{Json.encode_string(pubkey_string(value.address))},"context_slot":"#{U64.to_string(value.context_slot)}","total_bytes":#{value.total_bytes},"received_bytes":#{value.received_bytes},"sealed":#{value.sealed},"verified":[#{verified}]}"""
end
