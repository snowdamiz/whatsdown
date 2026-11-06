from Storage.LightningRevenue import freeze_lightning_revenue_week, lightning_revenue_versions
from Storage.Lightning import lightning_backend_hash
from Api.Lightning import resume_lightning_settlement
from Runtime.Config import IssuerServerConfig, open_storage_key
from Runtime.KeySync import issuer_now
from Storage.Lightning import claim_lightning_settlements

pub fn run_lightning_cycle(pool :: PoolHandle,
  config :: IssuerServerConfig,
  now :: U64) -> Int!String do
  let policy = case config.lightning do
    None -> return Ok(0)
    Some(value) -> value
  end
  let jobs = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do claim_lightning_settlements(conn,
      policy.backend,
      policy.service_key,
      now) end)?
  let statuses = for id in jobs do
    case resume_lightning_settlement(pool,
      policy,
      id,
      fn() do open_storage_key(config.key_directory) end,
      now) do
      Ok(value) -> value.status
      Err(_) -> 503
    end
  end
  let current = U64.divide(now, U64.parse("604800")?)?
  let revenue_errors = if current == U64.parse("0")? do
    []
  else
    let versions = Repo.transaction(pool,
      fn(conn :: borrow PgConn) do lightning_revenue_versions(conn,
        lightning_backend_hash(policy.backend)?) end)?
    for version in versions do
      case Repo.transaction(pool,
        fn(conn :: borrow PgConn) do freeze_lightning_revenue_week(conn,
          U64.subtract(current, U64.parse("1")?)?,
          lightning_backend_hash(policy.backend)?,
          version,
          now) end) do
        Ok(_) -> 0
        Err(_) -> 1
      end
    end
  end
  Ok(List.length(List.filter(statuses, fn(status) do status != 200 end))
    + List.length(List.filter(revenue_errors, fn(error) do error == 1 end)))
end

fn worker_loop(pool :: PoolHandle, config :: IssuerServerConfig) do
  if Process.shutdown_requested() do
    return
  end
  case issuer_now() do
    Err(_) -> io_eprintln("credit Lightning clock unavailable")
    Ok(now) -> case run_lightning_cycle(pool, config, now) do
      Err(_) -> io_eprintln("credit Lightning recovery cycle failed")
      Ok(errors) -> if errors > 0 do
        io_eprintln("credit Lightning recovery requires another attempt")
      end
    end
  end
  Timer.sleep(30000)
  worker_loop(pool, config)
end

actor lightning_worker(pool :: PoolHandle, config :: IssuerServerConfig) do
  worker_loop(pool, config)
end

pub fn start_lightning_worker(pool :: PoolHandle, config :: IssuerServerConfig) do
  case config.lightning do
    None -> nil
    Some(_) -> do
      spawn(lightning_worker, pool, config)
      nil
    end
  end
end
