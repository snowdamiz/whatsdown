##! Derived from qualified ops/public-chain/collateral_pins.mpl; raw snapshot authentication only.
from Solana.Read import Pubkey, pubkey
from Solana.Address import find_program_address
from Transparency.Merkle import WitnessKey
from Transparency.AnchorChain import anchor_addresses
from Transparency.AnchorBond import bond_witness_identity
from Transparency.TokenChain import token_addresses, token_payout_address
from Transparency.TokenCustody import token_pending_address

pub struct CollateralPins do
  token :: Pubkey
  token_governance :: Pubkey
  token_slot :: U64
  usdc :: Pubkey
  morse :: Pubkey
  judge :: Pubkey
  judge_slot :: U64
  rewards :: Pubkey
  rewards_slot :: U64
  rewards_governance :: Pubkey
  log_name :: String
  log_version :: Int
  service_key :: Bytes
  network_started :: U64
end

pub struct CollateralSelection do
  pins :: CollateralPins
  witnesses :: List<WitnessKey>
  proofs :: List<Bytes>
end

pub fn collateral_pda(program :: Pubkey, seeds :: List<Bytes>) -> Pubkey!String do
  Ok(find_program_address(program, seeds)?.address)
end

pub fn collateral_context_keys(pins :: CollateralPins) -> List<Pubkey>!String do
  let anchor = anchor_addresses(pins.judge, pins.log_name)?
  let token = token_addresses(pins.token)?
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  Ok([
    anchor.log,
    collateral_pda(pins.judge, [Bytes.from_utf8("economics"), anchor.log_id])?,
    collateral_pda(pins.judge, [Bytes.from_utf8("token-binding"), anchor.log_id])?,
    token.config,
    pins.usdc,
    pins.morse,
    collateral_pda(pins.rewards, [Bytes.from_utf8("pool")])?,
    pubkey("SysvarC1ock11111111111111111111111111111111")?,
    pins.judge,
    collateral_pda(loader, [pins.judge.bytes])?,
    pins.token,
    collateral_pda(loader, [pins.token.bytes])?,
    pins.rewards,
    collateral_pda(loader, [pins.rewards.bytes])?
  ])
end

fn bond_keys(pins :: CollateralPins, identity :: Bytes) -> List<Pubkey>!String do
  let anchor = anchor_addresses(pins.judge, pins.log_name)?
  let bond = collateral_pda(pins.judge, [Bytes.from_utf8("bond"), anchor.log_id, identity])?
  Ok([
    bond,
    token_pending_address(pins.judge, bond)?,
    token_payout_address(bond, pins.usdc)?,
    token_payout_address(bond, pins.morse)?
  ])
end

pub fn collateral_bond_keys(selection :: CollateralSelection) -> List<Pubkey>!String do
  let p = selection.pins
  let anchor = anchor_addresses(p.judge, p.log_name)?
  let directory = bond_keys(p, Bytes.from_utf8("directory"))?
  let rows = for key in selection.witnesses do
    let identity = bond_witness_identity(key.witness_id, key.public_key)?
    let witness = collateral_pda(p.judge, [Bytes.from_utf8("witness"), anchor.log_id, identity])?
    [witness] ++ bond_keys(p, identity)?
  end
  Ok(collateral_context_keys(p)? ++ directory ++ List.flatten(rows))
end
