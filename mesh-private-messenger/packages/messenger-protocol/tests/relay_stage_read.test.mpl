from Transparency.RelayStageRead import (
  RelayStageState,
  RelayStageVerified,
  decode_relay_stage,
  relay_stage_report
)
from Transparency.Fork import ForkProof, ForkTarget, encode_fork
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  sign_tree_checkpoint_for,
  sign_witness,
  checkpoint_hash
)
from Solana.Read import Pubkey, AccountInfo

fn signing() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Ok(value)
    Err(_) -> Err("test signing")
  end
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

fn patch(bytes :: Bytes, offset :: Int, replacement :: Bytes) -> Bytes!String do
  cat([
    Bytes.slice(bytes, 0, offset)?,
    replacement,
    Bytes.slice(bytes,
      offset + Bytes.length(replacement),
      Bytes.length(bytes) - offset - Bytes.length(replacement))?
  ])
end

fn raw(wire :: Bytes,
  log_id :: Bytes,
  submitter :: Pubkey,
  received :: Int,
  sealed :: Bool) -> Bytes!String do
  cat([
    Bytes.from_hex(if sealed do
      "4d53540101000000"
    else
      "4d53540100000000"
    end)?,
    Bytes.write_uint_le(Int.to_string(Bytes.length(wire)), 2)?,
    Bytes.write_uint_le(Int.to_string(received), 2)?,
    Bytes.from_hex("00000000")?,
    submitter.bytes,
    log_id,
    Crypto.sha256(wire),
    Bytes.from_hex(String.repeat("00", 1040))?,
    Bytes.slice(wire, 0, received)?,
    Bytes.from_hex(String.repeat("00", Bytes.length(wire) - received))?
  ])
end

fn proof() -> Bool!String do
  let signer = signing()?
  let witness = signing()?
  let program = Pubkey { bytes: Bytes.from_hex(String.repeat("2a", 32))? }
  let submitter = Pubkey { bytes: Bytes.from_hex(String.repeat("3b", 32))? }
  let log_id = Crypto.sha256(Bytes.from_utf8("recovery-test"))
  let zero = Bytes.from_hex(String.repeat("00", 32))?
  let first = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    U64.parse("1")?,
    U64.parse("5")?,
    Crypto.sha256(Bytes.from_utf8("first")),
    zero,
    U64.parse("1000")?)?
  let second = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    U64.parse("2")?,
    U64.parse("5")?,
    Crypto.sha256(Bytes.from_utf8("second")),
    checkpoint_hash(first)?,
    U64.parse("2000")?)?
  let attestation = sign_witness("recovery-witness", witness.private_key, first)?
  let evidence = ForkProof {
    kind: 1,
    finder: submitter.bytes,
    service_public_key: signer.public_key.bytes,
    first: first,
    second: SignedCheckpoint(second),
    attestations: [attestation],
    contradiction: None
  }
  let wire = encode_fork(evidence)?
  let slot = U64.parse("9007199254740993")?
  let base = AccountInfo {
    owner: program,
    data: raw(wire, log_id, submitter, 0, false)?,
    lamports: U64.parse("1000")?,
    executable: false,
    rent_epoch: U64.parse("0")?
  }
  for received in [0, 17, Bytes.length(wire)] do
    let account = %{base | data: raw(wire, log_id, submitter, received, false)?}
    let value = decode_relay_stage(program, log_id, submitter, wire, Some(account), slot)?
    assert(value.received_bytes == received && !value.sealed && List.length(value.verified) == 0)
    assert(value.status == if received == Bytes.length(wire) do
        "uploaded"
      else
        "uploading"
      end)
    assert(Json.as_string(Json.object_get(Json.parse(relay_stage_report(value))?,
      "context_slot")?)? == "9007199254740993")
  end
  let sealed = raw(wire, log_id, submitter, Bytes.length(wire), true)?
  let verified = patch(patch(sealed, 112, Bytes.from_hex("0700000000000000")?)?,
    120,
    witness.public_key.bytes)?
  let value = decode_relay_stage(program,
    log_id,
    submitter,
    wire,
    Some(%{base | data: verified}),
    slot)?
  assert(value.status == "sealed" && value.sealed && List.length(value.verified) == 3)
  assert(List.get(value.verified, 2).ordinal == 2
    && List.get(value.verified, 2).public_key == witness.public_key.bytes)
  assert(decode_relay_stage(program, log_id, submitter, wire, None, slot)?.status == "missing")
  let prefunded = %{base | owner: Pubkey { bytes: zero }, data: Bytes.empty()}
  assert(decode_relay_stage(program,
    log_id,
    submitter,
    wire,
    Some(prefunded),
    slot)?.status == "missing")
  let mutations = [
    %{base | owner: submitter},
    %{base | executable: true},
    %{base | lamports: U64.parse("0")?},
    %{base | data: Bytes.slice(base.data, 0, Bytes.length(base.data) - 1)?},
    %{base | data: patch(base.data, 5, Bytes.from_hex("01")?)?},
    %{base | data: patch(base.data, 12, Bytes.from_hex("01")?)?},
    %{base | data: patch(base.data, 1144, Bytes.from_hex("01")?)?},
    %{base | data: patch(base.data, 16, zero)?},
    %{base | data: patch(base.data, 48, zero)?},
    %{base | data: patch(base.data, 80, zero)?},
    %{base | data: patch(base.data, 1152, Bytes.from_hex("01")?)?},
    %{base | data: patch(base.data, 4, Bytes.from_hex("01")?)?},
    %{base | data: patch(base.data, 112, Bytes.from_hex("01")?)?},
    %{base | data: patch(sealed, 112, Bytes.from_hex("0800000000000000")?)?},
    %{base | data: patch(sealed, 119, Bytes.from_hex("80")?)?},
    %{base | data: patch(sealed, 120, witness.public_key.bytes)?},
    %{base | data: patch(verified, 120, signer.public_key.bytes)?},
    %{base | data: patch(verified, 1152, Bytes.from_hex("00")?)?},
    %{base | data: patch(verified, 10, Bytes.from_hex("ffff")?)?}
  ]
  for account in mutations do
    case decode_relay_stage(program, log_id, submitter, wire, Some(account), slot) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  let anchor_wire = encode_fork(%{evidence | second: AnchorReference(0)})?
  let anchor_data = patch(raw(anchor_wire, log_id, submitter, Bytes.length(anchor_wire), true)?,
    112,
    Bytes.from_hex("0200000000000000")?)?
  case decode_relay_stage(program,
    log_id,
    submitter,
    anchor_wire,
    Some(%{base | data: anchor_data}),
    slot) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  Ok(true)
end

test("Stage recovery binds the upload and verification bits before a relay may resume") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
