##! The OHTTP gateway's strike register (RFC 9458 section 6.5.1): the `enc`
##! of every request it opened in the last ten to twenty minutes, so a relay
##! that replays an encapsulated request gets it refused. A signed mailbox
##! fetch stays valid six minutes, well inside the window.
##!
##! ponytail: one process's memory, lost on restart and not shared; move it to
##! Postgres if the gateway ever runs as more than one instance.

struct StrikeState do
  current :: Map<String, Int>
  previous :: Map<String, Int>
  started_ms :: Int
end

fn window_ms() -> Int do
  600000
end

# At most this many requests in a window; past it the gateway refuses, so a
# flood can't grow the register without bound.
fn capacity() -> Int do
  200000
end

fn rotated(state :: StrikeState, now_ms :: Int) -> StrikeState do
  if now_ms - state.started_ms >= window_ms() do
    StrikeState { current: Map.new(), previous: state.current, started_ms: now_ms }
  else
    state
  end
end

service OhttpStrikes do
  fn init() -> StrikeState do
    StrikeState { current: Map.new(), previous: Map.new(), started_ms: 0 }
  end

  call Claim(key :: String, now_ms :: Int) :: Bool do |state|
    let fresh = rotated(state, now_ms)
    if Map.has_key(fresh.current, key)
      || Map.has_key(fresh.previous, key)
      || Map.size(fresh.current) >= capacity() do
      (fresh, false)
    else
      (%{fresh | current: Map.put(fresh.current, key, 1)}, true)
    end
  end
end

pub fn ohttp_strikes_start() do
  Process.register("ohttp_strikes", OhttpStrikes.start())
end

## True the first time `enc` is seen in the window; false for a replay, or
## when the register is full.

pub fn ohttp_strike_claim(enc :: Bytes, now_ms :: Int) -> Bool do
  OhttpStrikes.claim(Process.whereis("ohttp_strikes"), Bytes.to_hex(enc), now_ms)
end
