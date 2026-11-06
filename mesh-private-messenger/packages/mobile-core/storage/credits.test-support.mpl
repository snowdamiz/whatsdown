# Test-only access to the exact production load transaction. The two independent
# SQLite connections contend over the same authenticated original generation.
pub fn test_competing_attachment_loaders(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> Bool!String do
  let first = open_database(path)?
  Sqlite.begin(first)?
  let uncommitted = read_wallet(first, wrapping, who)?
  let loser = load_credit_wallet(path, wrapping, who)
  Sqlite.rollback(first)?
  Sqlite.close(first)
  if Result.is_ok(loser) do
    return Err("competing loader exposed an uncommitted migration")
  end
  let committed = load_credit_wallet(path, wrapping, who)?
  let next = %{uncommitted.wallet | revision: U64.add(uncommitted.wallet.revision, U64.parse("1")?)?}
  if commit_credit_wallet(path, wrapping, who, uncommitted, next) != Err("credit_wallet_changed") do
    return Err("uncommitted loader snapshot won the migration CAS")
  end
  commit_credit_wallet(path, wrapping, who, committed,
    %{committed.wallet | revision: U64.add(committed.wallet.revision, U64.parse("1")?)?})?
  let reopened = load_credit_wallet(path, wrapping, who)?
  Ok(reopened.wallet.revision == next.revision)
end

# Manifest framing only; real authenticated full-wallet migration has its own fixture.
pub fn test_credit_wallet_manifest_bound(manifest :: Bytes) -> Int!String do
  Ok(read_wallet_manifest(manifest)?.count)
end
