# The independent fixture binds loopback HTTP. Production always uses the
# operator's validated HTTPS URL; this substitution is compiled only in tests.
pub fn push_c2sp_with_test_transport(pool :: PoolHandle,
  id :: String,
  endpoint :: String) -> Result<(), String> do
  registered(pool, id)?
  push_to(pool, id, endpoint)
end

pub fn retry_size_for_test(body :: Bytes, maximum :: Int) -> Int!String do
  retry_size(body, maximum)
end
