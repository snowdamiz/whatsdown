# Test-only structural accounting; does not claim serialized-wallet or AEAD validity.
pub fn test_credit_wallet_logical_size(records :: List<CreditRecord>, physical :: Int) -> Int!String do
  credit_wallet_logical_size(records, physical)
end
