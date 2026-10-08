struct IssuerRegistryState do
  pool :: PoolHandle
end

service IssuerRegistry do
  fn init(pool :: PoolHandle) -> IssuerRegistryState do
    IssuerRegistryState { pool: pool }
  end

  call GetPool() :: PoolHandle do |state|
    (state, state.pool)
  end
end

pub fn issuer_start_registry(pool :: PoolHandle) do
  let pid = IssuerRegistry.start(pool)
  Process.register("credit_issuer_registry", pid)
  pid
end

pub fn issuer_pool() -> PoolHandle do
  IssuerRegistry.get_pool(Process.whereis("credit_issuer_registry"))
end
