##! Redemption signals for alerting (plan §12, "Credits"): how many redemptions
##! this process answered, how many failed because the spent set could not be
##! read or written, and the p95 time of the last 256. Counts and durations
##! only: never a token, a nullifier or an action.

struct CreditStatsState do
  durations :: List<Int>
  redemptions :: Int
  failures :: Int
end

service CreditStats do
  fn init() -> CreditStatsState do
    CreditStatsState { durations: List.new(), redemptions: 0, failures: 0 }
  end

  cast Record(duration_ms :: Int, failed :: Bool) do |state|
    let kept = if List.length(state.durations) >= 256 do
      List.drop(state.durations, 1)
    else
      state.durations
    end
    CreditStatsState {
      durations: List.append(kept, duration_ms),
      redemptions: state.redemptions + 1,
      failures: state.failures
        + if failed do
          1
        else
          0
        end
    }
  end

  call Snapshot() :: (Int, Int, Int) do |state|
    let sorted = List.sort(state.durations, fn a, b -> a - b end)
    let p95 = if List.length(sorted) == 0 do
      0
    else
      List.get(sorted, (List.length(sorted) - 1) * 95 / 100)
    end
    (state, (state.redemptions, state.failures, p95))
  end
end

pub fn credits_stats_start() do
  Process.register("credit_stats", CreditStats.start())
end

pub fn credits_stats_record(duration_ms :: Int, failed :: Bool) do
  CreditStats.record(Process.whereis("credit_stats"), duration_ms, failed)
end

## (redemptions, spent-set failures, p95 milliseconds) since the process
## started. Only after credits_stats_start.

pub fn credits_stats_snapshot() -> (Int, Int, Int) do
  CreditStats.snapshot(Process.whereis("credit_stats"))
end
