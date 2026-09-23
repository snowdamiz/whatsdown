struct RegistryState do
  pool :: PoolHandle
end

service MessengerRegistry do
  fn init(pool :: PoolHandle) -> RegistryState do
    RegistryState { pool: pool }
  end

  call GetPool() :: PoolHandle do|state|
    (state, state.pool)
  end
end

pub fn start_registry(pool :: PoolHandle) do
  let pid = MessengerRegistry.start(pool)
  Process.register("messenger_registry", pid)
  pid
end

pub fn get_pool() -> PoolHandle do
  MessengerRegistry.get_pool(Process.whereis("messenger_registry"))
end
