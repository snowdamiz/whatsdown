##! MPR2 raw decoding plus canonical judge41–44 and stage instructions.
##! Raw records and pure builders confer no RPC, ownership or economic authority.
from Transparency.TokenCollateralWrite import (
  TokenCollateralContext,
  token_collateral_addresses,
  token_collateral_subject,
  TokenCollateralSubject,
  collateral_meta,
  collateral_derived,
  collateral_public_key
)
from Transparency.TokenChain import token_payout_address
from Transparency.AnchorBond import bond_witness_identity
from Transparency.AnchorWrite import anchor_post_instructions, anchor_cosign_instructions
from Transparency.Fork import ForkProof, ForkTarget, decode_fork, encode_fork, fork_hash
from Transparency.RelayStage import RelayStagePlan
from Transparency.Merkle import WitnessKey, checkpoint_hash
from Solana.Read import Pubkey, pubkey
from Solana.Tx import Instruction, create_associated_token_idempotent_instruction

pub struct TokenPreparedProofRow do
  identity :: Bytes
  witness :: Bytes
  public_key :: Bytes
  asset :: Int
  bonded_at :: U64
  principal :: U64
  slashed :: U64
  finder :: U64
end

pub struct TokenPreparedProof do
  kind :: Int
  anchored :: Bool
  settled :: Bool
  log_id :: Bytes
  proof_hash :: Bytes
  finder :: Bytes
  submitter :: Bytes
  usdc_mint :: Bytes
  morse_mint :: Bytes
  first_hash :: Bytes
  second_hash :: Bytes
  prepared_at :: U64
  usdc_slashed :: U64
  usdc_finder :: U64
  directory_usdc :: U64
  morse_slashed :: U64
  morse_finder :: U64
  directory_morse :: U64
  verified_signature_mask :: U64
  stage :: Bytes
  deadline_ms :: U64
  directory_bonded_at :: U64
  directory_asset :: Int
  settled_at :: U64
  rows :: List<TokenPreparedProofRow>
end

fn part(value :: Bytes, at :: Int, count :: Int) -> Bytes!String do
  Bytes.slice(value, at, count)
end

fn number(value :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(value, at, 8)?)
end

fn zeroes(value :: Bytes, at :: Int, count :: Int) -> Bool!String do
  Ok(Bytes.to_hex(part(value, at, count)?) == String.repeat("00", count))
end

fn time(value :: Bytes, at :: Int) -> U64!String do
  let result = number(value, at)?
  if U64.compare(result, U64.parse("9223372036854775807")?) > 0 do
    Err("invalid_token_prepared_proof")
  else
    Ok(result)
  end
end

pub fn decode_token_prepared_proof(value :: Bytes) -> TokenPreparedProof!String do
  if Bytes.length(value) < 400 || Bytes.length(value) > 2704 do
    return Err("invalid_token_prepared_proof")
  end
  let kind = Bytes.get(value, 4)?
  let anchored = Bytes.get(value, 5)?
  let count = Bytes.get(value, 6)?
  let settled = Bytes.get(value, 7)?
  if Bytes.to_hex(part(value, 0, 4)?) != "4d505202"
    || kind < 1
    || kind > 3
    || anchored > 1
    || count > 16
    || settled > 1
    || Bytes.length(value) != 400 + count * 144
    || Bytes.get(value, 376)? > 1
    || !zeroes(value, 377, 7)?
    || !zeroes(value, 392, 8)? do
    return Err("invalid_token_prepared_proof")
  end
  for at in [8, 40, 72, 104, 136, 168, 200, 232, 328] do
    if zeroes(value, at, 32)? do
      return Err("invalid_token_prepared_proof")
    end
  end
  let zero = U64.parse("0")?
  let prepared_at = time(value, 264)?
  let bonded_at = time(value, 368)?
  let settled_at = time(value, 384)?
  let deadline = number(value, 360)?
  if part(value, 136, 32)? == part(value, 168, 32)?
    || prepared_at == zero
    || bonded_at == zero
    || U64.compare(bonded_at, prepared_at) > 0
    || U64.compare(U64.multiply(prepared_at, U64.parse("1000")?)?, deadline) > 0
    || (settled == 0 && (!zeroes(value, 272, 48)? || settled_at != zero))
    || (settled == 1
      && (U64.compare(settled_at, prepared_at) < 0
        || U64.compare(U64.multiply(settled_at, U64.parse("1000")?)?, deadline) > 0)) do
    return Err("invalid_token_prepared_proof")
  end
  let rows = for index in 0..count do
    let at = 400 + index * 144
    let asset = Bytes.get(value, at + 96)?
    let bonded = time(value, at + 104)?
    let principal = number(value, at + 112)?
    let slashed = number(value, at + 120)?
    let finder = number(value, at + 128)?
    if zeroes(value, at, 32)?
      || zeroes(value, at + 32, 32)?
      || zeroes(value, at + 64, 32)?
      || asset > 1
      || !zeroes(value, at + 97, 7)?
      || !zeroes(value, at + 136, 8)?
      || bonded == zero
      || U64.compare(bonded, prepared_at) > 0
      || (settled == 0 && !zeroes(value, at + 112, 24)?)
      || U64.compare(slashed, principal) < 0
      || finder != U64.divide(slashed, U64.parse("10")?)? do
      return Err("invalid_token_prepared_proof")
    end
    for previous in 0..index do
      if part(value, 400 + previous * 144, 32)? == part(value, at, 32)? do
        return Err("invalid_token_prepared_proof")
      end
    end
    TokenPreparedProofRow {
      identity: part(value, at, 32)?,
      witness: part(value, at + 32, 32)?,
      public_key: part(value, at + 64, 32)?,
      asset: asset,
      bonded_at: bonded,
      principal: principal,
      slashed: slashed,
      finder: finder
    }
  end
  let directory_asset = Bytes.get(value, 376)?
  let directory_usdc = number(value, 288)?
  let directory_morse = number(value, 312)?
  if (directory_asset == 0 && directory_morse != zero)
    || (directory_asset == 1 && directory_usdc != zero) do
    return Err("invalid_token_prepared_proof")
  end
  let totals = for asset in 0..2 do
    let directory = if asset == 0 do
      directory_usdc
    else
      directory_morse
    end
    let slashed = List.reduce(rows,
      Ok(directory),
      fn(total, row) do
        if row.asset == asset do
          U64.add(total?, row.slashed)
        else
          total
        end
      end)?
    let finder = List.reduce(rows,
      Ok(U64.divide(directory, U64.parse("10")?)?),
      fn(total, row) do
        if row.asset == asset do
          U64.add(total?, row.finder)
        else
          total
        end
      end)?
    (slashed, finder)
  end
  let (usdc_slashed, usdc_finder) = List.get(totals, 0)
  let (morse_slashed, morse_finder) = List.get(totals, 1)
  if settled == 1
    && (usdc_slashed != number(value, 272)?
      || usdc_finder != number(value, 280)?
      || morse_slashed != number(value, 296)?
      || morse_finder != number(value, 304)?
      || (usdc_slashed == zero && morse_slashed == zero)) do
    return Err("invalid_token_prepared_proof")
  end
  Ok(TokenPreparedProof {
    kind: kind,
    anchored: anchored == 1,
    settled: settled == 1,
    log_id: part(value, 8, 32)?,
    proof_hash: part(value, 40, 32)?,
    finder: part(value, 72, 32)?,
    submitter: part(value, 104, 32)?,
    usdc_mint: part(value, 136, 32)?,
    morse_mint: part(value, 168, 32)?,
    first_hash: part(value, 200, 32)?,
    second_hash: part(value, 232, 32)?,
    prepared_at: prepared_at,
    usdc_slashed: usdc_slashed,
    usdc_finder: usdc_finder,
    directory_usdc: directory_usdc,
    morse_slashed: morse_slashed,
    morse_finder: morse_finder,
    directory_morse: directory_morse,
    verified_signature_mask: number(value, 320)?,
    stage: part(value, 328, 32)?,
    deadline_ms: deadline,
    directory_bonded_at: bonded_at,
    directory_asset: directory_asset,
    settled_at: settled_at,
    rows: rows
  })
end

pub fn token_proof_stage_address(context :: TokenCollateralContext,
  submitter :: Pubkey,
  wire :: Bytes) -> Pubkey!String do
  token_collateral_addresses(context)?
  if !collateral_public_key(submitter) || Bytes.length(wire) == 0 || Bytes.length(wire) > 8009 do
    return Err("invalid_token_proof_stage")
  end
  decode_fork(wire)?
  collateral_derived(context.judge,
    [Bytes.from_utf8("stage"), submitter.bytes, Crypto.sha256(wire)])
end

pub fn token_proof_initialize_instruction(context :: TokenCollateralContext,
  submitter :: Pubkey,
  wire :: Bytes) -> Instruction!String do
  let a = token_collateral_addresses(context)?
  let stage = token_proof_stage_address(context, submitter, wire)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: [
      collateral_meta(submitter, true, true),
      collateral_meta(a.log, false, false),
      collateral_meta(stage, false, true),
      collateral_meta(pubkey("11111111111111111111111111111111")?, false, false)
    ],
    data: Bytes.concat(Bytes.from_hex("0a")?,
      Bytes.concat(Bytes.write_uint_le(Int.to_string(Bytes.length(wire)), 2)?,
        Crypto.sha256(wire))?)?
  })
end

pub fn token_proof_append_instruction(context :: TokenCollateralContext,
  submitter :: Pubkey,
  wire :: Bytes,
  offset :: Int) -> Instruction!String do
  let stage = token_proof_stage_address(context, submitter, wire)?
  if offset < 0 || offset >= Bytes.length(wire) do
    return Err("invalid_token_proof_offset")
  end
  let count = if Bytes.length(wire) - offset < 900 do
    Bytes.length(wire) - offset
  else
    900
  end
  Ok(Instruction {
    program_id: context.judge,
    accounts: [collateral_meta(submitter, true, true), collateral_meta(stage, false, true)],
    data: Bytes.concat(Bytes.from_hex("0b")?,
      Bytes.concat(Bytes.write_uint_le(Int.to_string(offset), 2)?,
        Bytes.slice(wire, offset, count)?)?)?
  })
end

pub fn token_proof_seal_instruction(context :: TokenCollateralContext,
  submitter :: Pubkey,
  wire :: Bytes) -> Instruction!String do
  let a = token_collateral_addresses(context)?
  let stage = token_proof_stage_address(context, submitter, wire)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: [
      collateral_meta(submitter, true, true),
      collateral_meta(a.log, false, false),
      collateral_meta(stage, false, true)
    ],
    data: Bytes.from_hex("0c")?
  })
end

pub fn token_proof_close_instruction(context :: TokenCollateralContext,
  submitter :: Pubkey,
  wire :: Bytes) -> Instruction!String do
  let stage = token_proof_stage_address(context, submitter, wire)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: [collateral_meta(submitter, true, true), collateral_meta(stage, false, true)],
    data: Bytes.from_hex("0e")?
  })
end

# The precompile must precede judge verification at its actual packet index.
# One pair only; transaction assembly may not move it without rebuilding indices.
pub fn token_proof_signature_instructions(context :: TokenCollateralContext,
  submitter :: Pubkey,
  wire :: Bytes,
  ordinal :: Int,
  witness :: Option<WitnessKey>,
  ed_index :: Int) -> List<Instruction>!String do
  if ed_index < 0 || ed_index >= 65535 || ordinal < 0 || ordinal >= 34 do
    return Err("invalid_token_proof_signature")
  end
  let a = token_collateral_addresses(context)?
  let stage = token_proof_stage_address(context, submitter, wire)?
  let proof = decode_fork(wire)?
  let checkpoint = if ordinal == 0 do
    proof.first
  else if ordinal == 1 do
    case proof.second do
      SignedCheckpoint(value) -> value
      AnchorReference(_) -> return Err("invalid_token_proof_signature")
    end
  else
    if ordinal - 2 >= List.length(proof.attestations) do
      return Err("invalid_token_proof_signature")
    end
    let att = List.get(proof.attestations, ordinal - 2)
    if att.checkpoint_hash == checkpoint_hash(proof.first)? do
      proof.first
    else
      case proof.second do
        AnchorReference(_) -> return Err("invalid_token_proof_signature")
        SignedCheckpoint(value) ->
          if att.checkpoint_hash != checkpoint_hash(value)? do
            return Err("invalid_token_proof_signature")
          end
          value
      end
    end
  end
  let pair = if ordinal < 2 do
    if witness != None do
      return Err("invalid_token_proof_signature")
    end
    anchor_post_instructions(checkpoint, proof.service_public_key, ed_index)?
  else
    let key = case witness do
      None -> return Err("invalid_token_proof_signature")
      Some(value) -> value
    end
    let att = List.get(proof.attestations, ordinal - 2)
    if att.witness_id != key.witness_id || (proof.kind == 3 && Bytes.length(att.signature) != 64) do
      return Err("invalid_token_proof_signature")
    end
    anchor_cosign_instructions(checkpoint, att, key, 0, 0, ed_index)?
  end
  let extra = case witness do
    None -> []
    Some(key) -> [
      collateral_meta(collateral_derived(context.judge,
          [
            Bytes.from_utf8("witness"),
            a.log_id,
            bond_witness_identity(key.witness_id, key.public_key)?
          ])?,
        false,
        false),
      collateral_meta(submitter, true, true)
    ]
  end
  Ok([
    Instruction {
      program_id: pubkey("Ed25519SigVerify111111111111111111111111111")?,
      accounts: [],
      data: pair.ed25519
    },
    Instruction {
      program_id: context.judge,
      accounts: [
        collateral_meta(a.log, false, false),
        collateral_meta(stage, false, true),
        collateral_meta(pubkey("Sysvar1nstructions1111111111111111111111111")?, false, false)
      ]
        ++ extra,
      data: Bytes.concat(Bytes.from_hex("0d")?,
        Bytes.concat(Bytes.write_uint_le(Int.to_string(ordinal), 1)?,
          Bytes.write_uint_le(Int.to_string(ed_index), 2)?)?)?
    }
  ])
end

pub fn token_proof_prepare_instruction(context :: TokenCollateralContext,
  payer :: Pubkey,
  submitter :: Pubkey,
  wire :: Bytes,
  stage :: RelayStagePlan,
  second_hash :: Bytes,
  anchor_generation :: Option<Int>) -> Instruction!String do
  let a = token_collateral_addresses(context)?
  let proof = decode_fork(wire)?
  let expected_stage = token_proof_stage_address(context, submitter, wire)?
  if !collateral_public_key(payer)
    || Bytes.length(second_hash) != 32
    || zeroes(second_hash, 0, 32)?
    || stage.stage != expected_stage
    || stage.full_hash != Crypto.sha256(wire)
    || stage.proof_hash != fork_hash(proof)?
    || List.length(stage.witnesses) > 16 do
    return Err("invalid_token_proof_preparation")
  end
  let anchored = case proof.second do
    SignedCheckpoint(value) ->
      if second_hash != checkpoint_hash(value)? || anchor_generation != None do
        return Err("invalid_token_proof_preparation")
      end
      []
    AnchorReference(_) ->
      let generation = case anchor_generation do
        None -> return Err("invalid_token_proof_preparation")
        Some(value) -> value
      end
      if generation < 0 || generation > 65535 do
        return Err("invalid_token_proof_preparation")
      end
      [
        collateral_meta(a.ring, false, false),
        collateral_meta(collateral_derived(context.judge,
            [
              Bytes.from_utf8("witness-set"),
              a.log_id,
              Bytes.write_uint_le(Int.to_string(generation), 2)?
            ])?,
          false,
          false)
      ]
  end
  let targets = for index in 0..List.length(stage.witnesses) do
    let subject = List.get(stage.witnesses, index)
    let s = token_collateral_subject(context, CollateralWitness(subject.key), 0)?
    if s.witness != Some(subject.address) do
      return Err("invalid_token_proof_preparation")
    end
    for prior in 0..index do
      if List.get(stage.witnesses, prior).address == subject.address do
        return Err("invalid_token_proof_preparation")
      end
    end
    [collateral_meta(subject.address, false, false), collateral_meta(s.bond, false, false)]
  end
  let receipt = collateral_derived(context.judge,
    [Bytes.from_utf8("proof"), a.log_id, stage.proof_hash])?
  let directory = token_collateral_subject(context, CollateralDirectory, 0)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: [
      collateral_meta(payer, true, true),
      collateral_meta(a.log, false, false),
      collateral_meta(stage.stage, false, false),
      collateral_meta(a.economics, false, false),
      collateral_meta(a.binding, false, false),
      collateral_meta(receipt, false, true),
      collateral_meta(pubkey("11111111111111111111111111111111")?, false, false),
      collateral_meta(directory.bond, false, false)
    ]
      ++ anchored
      ++ List.flatten(targets),
    data: Bytes.concat(Bytes.write_uint_le(Int.to_string(proof.kind + 40), 1)?, second_hash)?
  })
end

pub fn token_proof_settle_instruction(context :: TokenCollateralContext,
  receipt :: TokenPreparedProof) -> Instruction!String do
  let a = token_collateral_addresses(context)?
  if receipt.settled
    || receipt.log_id != a.log_id
    || receipt.usdc_mint != context.usdc_mint.bytes
    || receipt.morse_mint != a.morse_mint.bytes
    || List.length(receipt.rows) > 16 do
    return Err("invalid_token_proof_settlement")
  end
  let account = collateral_derived(context.judge,
    [Bytes.from_utf8("proof"), a.log_id, receipt.proof_hash])?
  let directory = token_collateral_subject(context, CollateralDirectory, receipt.directory_asset)?
  let finder = pubkey(Bytes.to_base58(receipt.finder))?
  let locked = collateral_derived(context.judge, [Bytes.from_utf8("locked"), a.log_id])?
  let targets = for index in 0..List.length(receipt.rows) do
    let row = List.get(receipt.rows, index)
    if row.asset != 0 && row.asset != 1 do
      return Err("invalid_token_proof_settlement")
    end
    let witness = collateral_derived(context.judge,
      [Bytes.from_utf8("witness"), a.log_id, row.identity])?
    if row.witness != witness.bytes do
      return Err("invalid_token_proof_settlement")
    end
    for prior in 0..index do
      if List.get(receipt.rows, prior).identity == row.identity do
        return Err("invalid_token_proof_settlement")
      end
    end
    let bond = collateral_derived(context.judge, [Bytes.from_utf8("bond"), a.log_id, row.identity])?
    [
      collateral_meta(witness, false, true),
      collateral_meta(bond, false, true),
      collateral_meta(token_payout_address(bond,
          if row.asset == 0 do
            context.usdc_mint
          else
            a.morse_mint
          end)?,
        false,
        true)
    ]
  end
  Ok(Instruction {
    program_id: context.judge,
    accounts: [
      collateral_meta(a.log, false, true),
      collateral_meta(a.economics, false, true),
      collateral_meta(a.binding, false, false),
      collateral_meta(account, false, true),
      collateral_meta(directory.bond, false, true),
      collateral_meta(directory.vault, false, true),
      collateral_meta(context.usdc_mint, false, false),
      collateral_meta(token_payout_address(finder, context.usdc_mint)?, false, true),
      collateral_meta(token_payout_address(locked, context.usdc_mint)?, false, true),
      collateral_meta(a.morse_mint, false, false),
      collateral_meta(token_payout_address(finder, a.morse_mint)?, false, true),
      collateral_meta(token_payout_address(locked, a.morse_mint)?, false, true),
      collateral_meta(pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?, false, false)
    ]
      ++ List.flatten(targets),
    data: Bytes.from_hex("2c")?
  })
end

pub fn token_proof_payout_setup_instructions(context :: TokenCollateralContext,
  payer :: Pubkey,
  receipt :: TokenPreparedProof) -> List<Instruction>!String do
  let a = token_collateral_addresses(context)?
  if !collateral_public_key(payer)
    || receipt.log_id != a.log_id
    || receipt.usdc_mint != context.usdc_mint.bytes
    || receipt.morse_mint != a.morse_mint.bytes do
    return Err("invalid_token_proof_settlement")
  end
  let finder = pubkey(Bytes.to_base58(receipt.finder))?
  let locked = collateral_derived(context.judge, [Bytes.from_utf8("locked"), a.log_id])?
  let groups = for mint in [context.usdc_mint, a.morse_mint] do
    [
      create_associated_token_idempotent_instruction(payer,
        token_payout_address(finder, mint)?,
        finder,
        mint)?,
      create_associated_token_idempotent_instruction(payer,
        token_payout_address(locked, mint)?,
        locked,
        mint)?
    ]
  end
  Ok(List.flatten(groups))
end

# Cleanup needs no fork parser, current witness eligibility or live oracle.
# The onchain header still authenticates owner and exact stage digest PDA.
pub fn token_proof_owner_stage_address(judge :: Pubkey,
  submitter :: Pubkey,
  full_hash :: Bytes) -> Pubkey!String do
  if !collateral_public_key(judge)
    || !collateral_public_key(submitter)
    || Bytes.length(full_hash) != 32 do
    return Err("invalid_token_proof_owner_stage")
  end
  collateral_derived(judge, [Bytes.from_utf8("stage"), submitter.bytes, full_hash])
end

pub fn token_proof_owner_close_instruction(judge :: Pubkey,
  submitter :: Pubkey,
  full_hash :: Bytes) -> Instruction!String do
  let stage = token_proof_owner_stage_address(judge, submitter, full_hash)?
  Ok(Instruction {
    program_id: judge,
    accounts: [collateral_meta(submitter, true, true), collateral_meta(stage, false, true)],
    data: Bytes.from_hex("0e")?
  })
end
