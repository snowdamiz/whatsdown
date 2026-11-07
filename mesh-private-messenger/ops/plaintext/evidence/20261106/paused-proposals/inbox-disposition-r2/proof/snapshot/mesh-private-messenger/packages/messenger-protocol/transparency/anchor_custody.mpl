from Solana.Read import (
  Pubkey,
  AccountInfo,
  OptionalAccountsAtSlot,
  TokenAccount,
  Mint,
  pubkey,
  pubkey_equal,
  mint,
  token_account
)
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.AnchorBatch import read_anchor_accounts
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.AnchorLog import AnchorLog, decode_anchor_log
from Transparency.AnchorBond import (
  AnchorBond,
  AnchorEconomics,
  AnchorBondAddresses,
  decode_anchor_bond,
  decode_anchor_economics,
  bond_witness_identity,
  witness_bond_addresses,
  directory_bond_addresses
)
from Transparency.Merkle import WitnessKey

pub struct AnchorBondBalance do
  bond :: AnchorBond
  vault_amount :: U64
end

pub struct AnchorWitnessBond do
  witness_id :: String
  public_key :: Bytes
  status :: String
  owner :: Bytes
  payout :: Bytes
  escrow :: Option<AnchorBondBalance>
end

pub struct AnchorCustody do
  log :: AnchorLog
  economics :: Option<AnchorEconomics>
  directory :: Option<AnchorBondBalance>
  witnesses :: List<AnchorWitnessBond>
  context_slot :: U64
end

fn zeroes(bytes :: Bytes) -> Bool do
  Bytes.to_hex(bytes) == String.repeat("00", Bytes.length(bytes))
end

fn owned(value :: Option<AccountInfo>, owner :: Pubkey, length :: Int) -> AccountInfo!String do
  let account = case value do
    None -> return Err("anchor_custody_account_missing")
    Some(value) -> value
  end
  if account.executable
    || !pubkey_equal(account.owner, owner)
    || Bytes.length(account.data) != length
    || account.lamports == U64.parse("0")? do
    return Err("invalid_anchor_custody_account")
  end
  Ok(account)
end

# Prefunding an uninitialized PDA must not turn a not-yet-bonded key into a
# bonded key or make that key disappear. Any other ownership or data is invalid.
fn absent(value :: Option<AccountInfo>) -> Bool do
  case value do
    None -> true
    Some(account) -> !account.executable
      && zeroes(account.owner.bytes)
      && Bytes.length(account.data) == 0
  end
end

fn log_record(pins :: AnchorPins,
  key :: Bytes,
  version :: Int,
  value :: Option<AccountInfo>) -> AnchorLog!String do
  let log = decode_anchor_log(owned(value, pins.program, 352)?.data)?
  if log.name != pins.log_name
    || log.version != version
    || !Bytes.secure_equals(log.log_id, pins.log_id)
    || !Bytes.secure_equals(log.service_public_key, key)
    || !Bytes.secure_equals(log.ring_address, pins.ring.bytes) do
    return Err("anchor_log_mismatch")
  end
  Ok(log)
end

fn policy_record(pins :: AnchorPins,
  expected_mint :: Pubkey,
  value :: Option<AccountInfo>) -> AnchorEconomics!String do
  let policy = decode_anchor_economics(owned(value, pins.program, 192)?.data)?
  if !Bytes.secure_equals(policy.log_id, pins.log_id)
    || !Bytes.secure_equals(policy.mint, expected_mint.bytes) do
    return Err("anchor_custody_identity_mismatch")
  end
  Ok(policy)
end

fn balance(pins :: AnchorPins,
  expected_mint :: Pubkey,
  addresses :: AnchorBondAddresses,
  record :: Option<AccountInfo>,
  vault :: Option<AccountInfo>) -> Option<AnchorBondBalance>!String do
  if absent(record) do
    return Ok(None)
  end
  let bond = decode_anchor_bond(owned(record, pins.program, 208)?.data)?
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let vault = token_account(owned(vault, token, 165)?)?
  if !Bytes.secure_equals(bond.log_id, pins.log_id)
    || !Bytes.secure_equals(bond.mint, expected_mint.bytes)
    || !Bytes.secure_equals(bond.vault, addresses.vault.bytes)
    || !pubkey_equal(vault.mint, expected_mint)
    || !pubkey_equal(vault.owner, addresses.bond)
    || vault.state != 1
    || U64.compare(vault.amount, bond.principal) < 0 do
    return Err("anchor_custody_identity_mismatch")
  end
  case vault.delegate do
    Some(_) -> return Err("invalid_anchor_custody_vault")
    None -> nil
  end
  case vault.native_reserve do
    Some(_) -> return Err("invalid_anchor_custody_vault")
    None -> nil
  end
  case vault.close_authority do
    Some(_) -> return Err("invalid_anchor_custody_vault")
    None -> nil
  end
  Ok(Some(AnchorBondBalance { bond: bond, vault_amount: vault.amount }))
end

fn directory_balance(pins :: AnchorPins,
  expected_mint :: Pubkey,
  addresses :: AnchorBondAddresses,
  log :: AnchorLog,
  policy :: AnchorEconomics,
  accounts :: List<Option<AccountInfo>>) -> Option<AnchorBondBalance>!String do
  let value = balance(pins, expected_mint, addresses, List.get(accounts, 3), List.get(accounts, 4))?
  case value do
    None -> if policy.directory_status != 0 || !zeroes(log.directory_bond_vault) do
      return Err("anchor_custody_state_mismatch")
    end
    Some(escrow) -> if escrow.bond.kind != 0
      || escrow.bond.status != policy.directory_status
      || escrow.bond.principal != policy.directory_principal
      || !Bytes.secure_equals(escrow.bond.owner, policy.directory_owner)
      || !Bytes.secure_equals(log.directory_bond_vault, addresses.vault.bytes)
      || log.service_slashed != (escrow.bond.status == 3) do
      return Err("anchor_custody_state_mismatch")
    end
  end
  Ok(value)
end

fn witness_address(pins :: AnchorPins, key :: WitnessKey) -> Pubkey!String do
  Ok(find_program_address(pins.program,
    [
      Bytes.from_utf8("witness"),
      pins.log_id,
      bond_witness_identity(key.witness_id, key.public_key)?
    ])?.address)
end

fn witness_balance(pins :: AnchorPins,
  expected_mint :: Pubkey,
  key :: WitnessKey,
  accounts :: List<Option<AccountInfo>>,
  offset :: Int) -> AnchorWitnessBond!String do
  let addresses = witness_bond_addresses(pins.program,
    pins.log_id,
    expected_mint,
    key.witness_id,
    key.public_key)?
  let record = List.get(accounts, offset)
  let escrow = balance(pins,
    expected_mint,
    addresses,
    List.get(accounts, offset + 1),
    List.get(accounts, offset + 2))?
  let blank = AnchorWitnessBond {
    witness_id: key.witness_id,
    public_key: key.public_key,
    status: "unregistered",
    owner: Bytes.empty(),
    payout: Bytes.empty(),
    escrow: escrow
  }
  if absent(record) do
    case escrow do
      Some(_) -> return Err("anchor_custody_state_mismatch")
      None -> return Ok(blank)
    end
  end
  let bytes = owned(record, pins.program, 320)?.data
  let length = Bytes.get(bytes, 4)?
  let status = Bytes.get(bytes, 5)?
  if Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d574901"
    || length != String.length(key.witness_id)
    || status > 4
    || Bytes.get(bytes, 6)? > 1
    || Bytes.get(bytes, 7)? != 0
    || !Bytes.secure_equals(Bytes.slice(bytes, 8, length)?, Bytes.from_utf8(key.witness_id))
    || !zeroes(Bytes.slice(bytes, 8 + length, 64 - length)?)
    || !Bytes.secure_equals(Bytes.slice(bytes, 72, 32)?, key.public_key)
    || !Bytes.secure_equals(Bytes.slice(bytes, 200, 32)?, pins.log_id)
    || zeroes(Bytes.slice(bytes, 104, 32)?)
    || zeroes(Bytes.slice(bytes, 136, 32)?)
    || !zeroes(Bytes.slice(bytes, 272, 48)?) do
    return Err("anchor_custody_identity_mismatch")
  end
  let owner = Bytes.slice(bytes, 104, 32)?
  case escrow do
    None -> if status != 0 || !zeroes(Bytes.slice(bytes, 232, 40)?) do
      return Err("anchor_custody_state_mismatch")
    end
    Some(value) -> if value.bond.kind != 1
      || value.bond.status != status
      || !Bytes.secure_equals(owner, value.bond.owner)
      || !Bytes.secure_equals(value.bond.witness, witness_address(pins, key)?.bytes)
      || !Bytes.secure_equals(Bytes.slice(bytes, 232, 32)?, value.bond.vault)
      || Bytes.read_uint_le(bytes, 264, 8)? != U64.to_string(value.bond.unbond_at) do
      return Err("anchor_custody_state_mismatch")
    end
  end
  Ok(%{blank |
    status: List.get(["registered", "active", "unbonding", "slashed", "withdrawn"], status),
    owner: owner,
    payout: Bytes.slice(bytes, 136, 32)?
  })
end

# expected_mint comes from release/operator pins, not an RPC response. A
# different six-decimal mint must never be presented as USDC. The first read
# discovers optional configuration; the complete second batch must retain it.
pub fn read_anchor_custody(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  expected_mint :: Pubkey,
  witnesses :: List<WitnessKey>,
  minimum_slot :: U64) -> AnchorCustody!String do
  let derived = anchor_addresses(pins.program, pins.log_name)?
  if !Bytes.secure_equals(derived.log_id, pins.log_id)
    || !pubkey_equal(derived.ring, pins.ring)
    || Bytes.length(service_key) != 32
    || (version != 1 && version != 2)
    || List.length(witnesses) > 16 do
    return Err("invalid_anchor_pins")
  end
  for index in 0..List.length(witnesses) do
    let key = List.get(witnesses, index)
    bond_witness_identity(key.witness_id, key.public_key)?
    for earlier in 0..index do
      let previous = List.get(witnesses, earlier)
      # Custody belongs to the immutable (ID, key) identity, not the current
      # membership list. Rotated keys can remain funded at the same time.
      if previous.witness_id == key.witness_id
        && Bytes.secure_equals(previous.public_key, key.public_key) do
        return Err("invalid_anchor_pins")
      end
    end
  end
  let directory = directory_bond_addresses(pins.program, pins.log_id, expected_mint)?
  let initial = read_anchor_accounts(pins.rpc,
    [derived.log, directory.economics],
    minimum_slot)?
  let log = log_record(pins, service_key, version, List.get(initial.accounts, 0))?
  if absent(List.get(initial.accounts, 1)) do
    if !zeroes(log.directory_bond_vault) do
      return Err("anchor_custody_state_mismatch")
    end
    return Ok(AnchorCustody {
      log: log,
      economics: None,
      directory: None,
      witnesses: [],
      context_slot: initial.slot
    })
  end
  policy_record(pins, expected_mint, List.get(initial.accounts, 1))?
  let base = [derived.log, directory.economics, expected_mint, directory.bond, directory.vault]
  let addresses = witness_addresses(pins, expected_mint, witnesses, base)?
  let snapshot = read_anchor_accounts(pins.rpc, addresses, initial.slot)?
  for index in 0..2 do
    let before = owned(List.get(initial.accounts, index),
      pins.program,
      if index == 0 do
        352
      else
        192
      end)?
    let current = owned(List.get(snapshot.accounts, index),
      pins.program,
      if index == 0 do
        352
      else
        192
      end)?
    if !Bytes.secure_equals(before.data, current.data) do
      return Err("anchor_snapshot_changed")
    end
  end
  let policy = policy_record(pins, expected_mint, List.get(snapshot.accounts, 1))?
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let mint = mint(owned(List.get(snapshot.accounts, 2), token, 82)?)?
  if !mint.initialized || mint.decimals != 6 do
    return Err("invalid_anchor_custody_mint")
  end
  let directory = directory_balance(pins, expected_mint, directory, log, policy, snapshot.accounts)?
  let balances = for index in 0..List.length(witnesses) do
    witness_balance(pins,
      expected_mint,
      List.get(witnesses, index),
      snapshot.accounts,
      5 + index * 3)?
  end
  let principal = total_principal(balances, U64.parse("0")?)?
  if U64.compare(principal, policy.witness_principal) > 0 do
    return Err("anchor_custody_state_mismatch")
  end
  Ok(AnchorCustody {
    log: log,
    economics: Some(policy),
    directory: directory,
    witnesses: balances,
    context_slot: snapshot.slot
  })
end

fn witness_addresses(pins :: AnchorPins,
  mint :: Pubkey,
  witnesses :: List<WitnessKey>,
  addresses :: List<Pubkey>) -> List<Pubkey>!String do
  if List.length(witnesses) == 0 do
    return Ok(addresses)
  end
  let key = List.head(witnesses)
  let bond = witness_bond_addresses(pins.program,
    pins.log_id,
    mint,
    key.witness_id,
    key.public_key)?
  witness_addresses(pins,
    mint,
    List.tail(witnesses),
    addresses ++ [witness_address(pins, key)?, bond.bond, bond.vault])
end

fn total_principal(witnesses :: List<AnchorWitnessBond>, total :: U64) -> U64!String do
  if List.length(witnesses) == 0 do
    return Ok(total)
  end
  let amount = case List.head(witnesses).escrow do
    None -> U64.parse("0")?
    Some(value) -> value.bond.principal
  end
  total_principal(List.tail(witnesses), U64.add(total, amount)?)
end
