from Runtime.Config import IssuerServerConfig

pub struct IssuerState do
  pool :: PoolHandle
  config :: IssuerServerConfig
end

service CreditIssuerRegistry do
  fn init(pool :: PoolHandle, config :: IssuerServerConfig) -> IssuerState do
    IssuerState { pool: pool, config: config }
  end

  call Get() :: IssuerState do |state|
    (state, state)
  end
end

pub fn start_registry(pool :: PoolHandle, config :: IssuerServerConfig) do
  Process.register("credit_issuer_registry", CreditIssuerRegistry.start(pool, config))
end

pub fn issuer_state() -> IssuerState do
  CreditIssuerRegistry.get(Process.whereis("credit_issuer_registry"))
end
