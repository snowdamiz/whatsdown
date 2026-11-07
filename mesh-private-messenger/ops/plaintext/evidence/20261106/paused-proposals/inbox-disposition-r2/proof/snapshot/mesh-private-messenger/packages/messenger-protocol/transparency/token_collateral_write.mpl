##! Pure canonical judge31–40/45 instructions. These functions do not authenticate
##! RPC state, authorize a signer, choose a price, or submit a transaction.
from Solana.Read import Pubkey, pubkey
from Solana.Address import find_program_address
from Solana.Tx import Instruction, AccountMeta
from Transparency.AnchorChain import anchor_addresses
from Transparency.AnchorBond import bond_witness_identity
from Transparency.Config import valid_witness_id
from Transparency.Merkle import WitnessKey
from Transparency.TokenChain import token_addresses, token_payout_address
from Transparency.TokenCustody import token_binding_address, token_pending_address

pub struct TokenCollateralContext do
  judge :: Pubkey
  token :: Pubkey
  rewards :: Pubkey
  log_name :: String
  usdc_mint :: Pubkey
end

pub type TokenCollateralSubject do
  CollateralDirectory
  CollateralWitness(WitnessKey)
end

pub struct TokenCollateralAddresses do
  log :: Pubkey
  log_id :: Bytes
  ring :: Pubkey
  judge_config :: Pubkey
  economics :: Pubkey
  binding :: Pubkey
  token_config :: Pubkey
  morse_mint :: Pubkey
  oracle :: Pubkey
  pool :: Pubkey
  judge_data :: Pubkey
  token_data :: Pubkey
  rewards_data :: Pubkey
end

pub struct TokenCollateralSubjectAddresses do
  witness :: Option<Pubkey>
  bond :: Pubkey
  pending :: Pubkey
  mint :: Pubkey
  vault :: Pubkey
end

pub fn collateral_meta(key :: Pubkey, signer :: Bool, writable :: Bool) -> AccountMeta do
  AccountMeta { pubkey: key, signer: signer, writable: writable }
end

pub fn collateral_public_key(value :: Pubkey) -> Bool do
  Bytes.length(value.bytes) == 32 && Bytes.to_hex(value.bytes) != String.repeat("00", 32)
end

pub fn collateral_derived(program :: Pubkey, seeds :: List<Bytes>) -> Pubkey!String do
  Ok(find_program_address(program, seeds)?.address)
end

pub fn token_collateral_addresses(context :: TokenCollateralContext) -> TokenCollateralAddresses!String do
  if !collateral_public_key(context.judge)
    || !collateral_public_key(context.token)
    || !collateral_public_key(context.rewards)
    || !collateral_public_key(context.usdc_mint)
    || context.judge == context.token
    || context.judge == context.rewards
    || context.token == context.rewards
    || !valid_witness_id(context.log_name)
    || String.length(context.log_name) > 32 do
    return Err("invalid_token_collateral_context")
  end
  let anchor = anchor_addresses(context.judge, context.log_name)?
  let token = token_addresses(context.token)?
  if token.mint == context.usdc_mint do
    return Err("invalid_token_collateral_context")
  end
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  Ok(TokenCollateralAddresses {
    log: anchor.log,
    log_id: anchor.log_id,
    ring: anchor.ring,
    judge_config: collateral_derived(context.judge, [Bytes.from_utf8("config")])?,
    economics: collateral_derived(context.judge, [Bytes.from_utf8("economics"), anchor.log_id])?,
    binding: token_binding_address(context.judge, anchor.log_id)?,
    token_config: token.config,
    morse_mint: token.mint,
    oracle: token.oracle,
    pool: collateral_derived(context.rewards, [Bytes.from_utf8("pool")])?,
    judge_data: collateral_derived(loader, [context.judge.bytes])?,
    token_data: collateral_derived(loader, [context.token.bytes])?,
    rewards_data: collateral_derived(loader, [context.rewards.bytes])?
  })
end

pub fn token_collateral_subject(context :: TokenCollateralContext,
  subject :: TokenCollateralSubject,
  asset :: Int) -> TokenCollateralSubjectAddresses!String do
  if asset != 0 && asset != 1 do
    return Err("invalid_token_collateral_asset")
  end
  let a = token_collateral_addresses(context)?
  let identity = case subject do
    CollateralDirectory -> Bytes.from_utf8("directory")
    CollateralWitness(key) -> bond_witness_identity(key.witness_id, key.public_key)?
  end
  let witness = case subject do
    CollateralDirectory -> None
    CollateralWitness(_) -> Some(collateral_derived(context.judge,
      [Bytes.from_utf8("witness"), a.log_id, identity])?)
  end
  let bond = collateral_derived(context.judge, [Bytes.from_utf8("bond"), a.log_id, identity])?
  let mint = if asset == 0 do
    context.usdc_mint
  else
    a.morse_mint
  end
  Ok(TokenCollateralSubjectAddresses {
    witness: witness,
    bond: bond,
    pending: token_pending_address(context.judge, bond)?,
    mint: mint,
    vault: token_payout_address(bond, mint)?
  })
end

fn bytes(tag :: Int, suffix :: Bytes) -> Bytes!String do
  Bytes.concat(Bytes.write_uint_le(Int.to_string(tag), 1)?, suffix)
end

fn selected(tag :: Int, subject :: TokenCollateralSubject) -> Bytes!String do
  bytes(tag,
    Bytes.write_uint_le(case subject do
        CollateralDirectory -> "0"
        CollateralWitness(_) -> "1"
      end,
      1)?)
end

fn witness_meta(value :: TokenCollateralSubjectAddresses, writable :: Bool) -> List<AccountMeta> do
  case value.witness do
    None -> []
    Some(key) -> [collateral_meta(key, false, writable)]
  end
end

fn binding(context :: TokenCollateralContext,
  governance :: Pubkey,
  payer :: Pubkey,
  tag :: Int) -> Instruction!String do
  if !collateral_public_key(governance) || !collateral_public_key(payer) do
    return Err("invalid_token_collateral_signer")
  end
  let a = token_collateral_addresses(context)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: [
      collateral_meta(governance, true, true),
      collateral_meta(payer, true, true),
      collateral_meta(a.judge_config, false, false),
      collateral_meta(a.log, false, false),
      collateral_meta(a.economics, false, true),
      collateral_meta(a.binding, false, true),
      collateral_meta(context.token, false, false),
      collateral_meta(a.token_data, false, false),
      collateral_meta(a.token_config, false, false),
      collateral_meta(a.morse_mint, false, false),
      collateral_meta(a.oracle, false, false),
      collateral_meta(context.rewards, false, false),
      collateral_meta(a.rewards_data, false, false),
      collateral_meta(a.pool, false, false),
      collateral_meta(pubkey("11111111111111111111111111111111")?, false, false)
    ],
    data: bytes(tag, Bytes.empty())?
  })
end

pub fn token_binding_propose_instruction(context :: TokenCollateralContext,
  governance :: Pubkey,
  payer :: Pubkey) -> Instruction!String do
  binding(context, governance, payer, 31)
end

pub fn token_binding_activate_instruction(context :: TokenCollateralContext,
  governance :: Pubkey,
  payer :: Pubkey) -> Instruction!String do
  binding(context, governance, payer, 32)
end

pub fn token_collateral_migrate_instruction(context :: TokenCollateralContext,
  subject :: TokenCollateralSubject) -> Instruction!String do
  let a = token_collateral_addresses(context)?
  let s = token_collateral_subject(context, subject, 0)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: [
      collateral_meta(a.log, false, false),
      collateral_meta(a.economics, false, true),
      collateral_meta(a.binding, false, false),
      collateral_meta(s.bond, false, true)
    ]
      ++ witness_meta(s, false),
    data: selected(33, subject)?
  })
end

fn price_context(context :: TokenCollateralContext,
  a :: TokenCollateralAddresses) -> List<AccountMeta> do
  [
    collateral_meta(context.token, false, false),
    collateral_meta(a.token_data, false, false),
    collateral_meta(a.token_config, false, false),
    collateral_meta(a.morse_mint, false, false),
    collateral_meta(a.oracle, false, false),
    collateral_meta(context.rewards, false, false),
    collateral_meta(a.rewards_data, false, false),
    collateral_meta(a.pool, false, false)
  ]
end

pub fn token_collateral_deposit_instruction(context :: TokenCollateralContext,
  governance :: Pubkey,
  operator :: Pubkey,
  subject :: TokenCollateralSubject,
  asset :: Int,
  amount :: U64) -> Instruction!String do
  if !collateral_public_key(operator)
    || amount == U64.parse("0")?
    || (asset == 1 && U64.compare(amount, U64.parse("1000000000000000")?) > 0) do
    return Err("invalid_token_collateral_deposit")
  end
  let a = token_collateral_addresses(context)?
  let s = token_collateral_subject(context, subject, asset)?
  let prefix = case subject do
    CollateralDirectory ->
      if !collateral_public_key(governance) do
        return Err("invalid_token_collateral_signer")
      end
      [collateral_meta(governance, true, true), collateral_meta(a.judge_config, false, false)]
    CollateralWitness(_) -> []
  end
  let source = token_payout_address(operator, s.mint)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: prefix
      ++ [
        collateral_meta(operator, true, true),
        collateral_meta(a.log,
          false,
          case subject do
            CollateralDirectory -> true
            _ -> false
          end),
        collateral_meta(a.economics, false, true),
        collateral_meta(a.binding, false, false)
      ]
      ++ witness_meta(s, true)
      ++ [
        collateral_meta(s.bond, false, true),
        collateral_meta(s.pending, false, true),
        collateral_meta(s.vault, false, true),
        collateral_meta(source, false, true),
        collateral_meta(s.mint, false, false)
      ]
      ++ price_context(context, a)
      ++ [
        collateral_meta(pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?, false, false),
        collateral_meta(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?, false, false),
        collateral_meta(pubkey("11111111111111111111111111111111")?, false, false)
      ],
    data: bytes(case subject do
        CollateralDirectory -> 35
        CollateralWitness(_) -> 34
      end,
      Bytes.concat(Bytes.write_uint_le(Int.to_string(asset), 1)?,
        Bytes.write_uint_le(U64.to_string(amount), 8)?)?)?
  })
end

fn update(context :: TokenCollateralContext,
  subject :: TokenCollateralSubject,
  asset :: Int,
  activate :: Bool) -> Instruction!String do
  let a = token_collateral_addresses(context)?
  let s = token_collateral_subject(context, subject, asset)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: [
      collateral_meta(a.log, false, false),
      collateral_meta(a.economics, false, true),
      collateral_meta(a.binding, false, false),
      collateral_meta(s.bond, false, true),
      collateral_meta(s.pending, false, activate),
      collateral_meta(s.vault, false, true)
    ]
      ++ price_context(context, a)
      ++ witness_meta(s, false),
    data: selected(if activate do
        36
      else
        45
      end,
      subject)?
  })
end

pub fn token_collateral_activate_pending_instruction(context :: TokenCollateralContext,
  subject :: TokenCollateralSubject,
  asset :: Int) -> Instruction!String do
  update(context, subject, asset, true)
end

pub fn token_collateral_assess_instruction(context :: TokenCollateralContext,
  subject :: TokenCollateralSubject,
  asset :: Int) -> Instruction!String do
  update(context, subject, asset, false)
end

pub fn token_collateral_request_unbond_instruction(context :: TokenCollateralContext,
  operator :: Pubkey,
  subject :: TokenCollateralSubject) -> Instruction!String do
  if !collateral_public_key(operator) do
    return Err("invalid_token_collateral_signer")
  end
  let a = token_collateral_addresses(context)?
  let s = token_collateral_subject(context, subject, 0)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: [
      collateral_meta(operator, true, true),
      collateral_meta(a.log, false, false),
      collateral_meta(a.economics, false, true),
      collateral_meta(a.binding, false, false),
      collateral_meta(s.bond, false, true),
      collateral_meta(s.pending, false, false)
    ]
      ++ witness_meta(s, true),
    data: selected(37, subject)?
  })
end

pub fn token_collateral_withdraw_instruction(context :: TokenCollateralContext,
  operator :: Pubkey,
  subject :: TokenCollateralSubject,
  asset :: Int) -> Instruction!String do
  if !collateral_public_key(operator) do
    return Err("invalid_token_collateral_signer")
  end
  let a = token_collateral_addresses(context)?
  let s = token_collateral_subject(context, subject, asset)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: [
      collateral_meta(operator, true, true),
      collateral_meta(a.log, false, false),
      collateral_meta(a.economics, false, true),
      collateral_meta(a.binding, false, false),
      collateral_meta(s.bond, false, true),
      collateral_meta(s.pending, false, true),
      collateral_meta(s.vault, false, true),
      collateral_meta(token_payout_address(operator, s.mint)?, false, true),
      collateral_meta(s.mint, false, false),
      collateral_meta(pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?, false, false)
    ]
      ++ witness_meta(s, true),
    data: selected(38, subject)?
  })
end

pub fn token_collateral_propose_minimums_instruction(context :: TokenCollateralContext,
  governance :: Pubkey,
  witness_usd :: U64,
  directory_usd :: U64) -> Instruction!String do
  if !collateral_public_key(governance)
    || witness_usd == U64.parse("0")?
    || U64.compare(directory_usd, witness_usd) < 0 do
    return Err("invalid_token_collateral_minimums")
  end
  let a = token_collateral_addresses(context)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: [
      collateral_meta(governance, true, true),
      collateral_meta(a.judge_config, false, false),
      collateral_meta(a.log, false, false),
      collateral_meta(a.economics, false, true),
      collateral_meta(a.binding, false, false)
    ],
    data: bytes(39,
      Bytes.concat(Bytes.write_uint_le(U64.to_string(witness_usd), 8)?,
        Bytes.write_uint_le(U64.to_string(directory_usd), 8)?)?)?
  })
end

pub fn token_collateral_activate_minimums_instruction(context :: TokenCollateralContext) -> Instruction!String do
  let a = token_collateral_addresses(context)?
  Ok(Instruction {
    program_id: context.judge,
    accounts: [
      collateral_meta(a.log, false, false),
      collateral_meta(a.economics, false, true),
      collateral_meta(a.binding, false, false)
    ],
    data: bytes(40, Bytes.empty())?
  })
end

# Tag32 authenticates its committed binding/timelock, not these unused legacy
# authority positions. The transaction's chosen fee payer remains a signer.
pub fn token_binding_activate_permissionless_instruction(context :: TokenCollateralContext,
  governance :: Pubkey,
  fee_payer :: Pubkey) -> Instruction!String do
  let signed = token_binding_activate_instruction(context, governance, fee_payer)?
  let accounts = for index in 0..List.length(signed.accounts) do
    let value = List.get(signed.accounts, index)
    if index < 2 do
      collateral_meta(value.pubkey, false, false)
    else
      value
    end
  end
  Ok(%{signed | accounts: accounts})
end
