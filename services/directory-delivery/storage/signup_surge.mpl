##! Priority sign-up (plan §6.10): registration work rises with load. The
##! signal is devices registered in the last 10 minutes against
##! MORSE_SIGNUP_SURGE_TARGET (default 300; 0 turns the surge off). Each
##! doubling above the target adds one bit, up to 8 bits and never past 24;
##! nothing ever goes below the pinned base. 20 credits skip the raise.

fn bits_over(load :: Int, target :: Int, bits :: Int) -> Int do
  if load <= target || bits >= 8 do
    bits
  else
    bits_over(load, target * 2, bits + 1)
  end
end

## The difficulty a registration's stamp must meet now, from the pinned base.

pub fn signup_difficulty(pool :: PoolHandle, base :: Int, target :: Int) -> Int!String do
  if target <= 0 do
    Ok(base)
  else
    let rows = Pool.query_values(pool,
      "SELECT count(*)::text AS load FROM messenger_devices WHERE registered_at > now() - interval '10 minutes'",
      [])?
    let load = case rows do
      [row] -> case Map.get(row, "load") do
        Text(text) -> case String.to_int(text) do
          Some(value) -> value
          None -> 0
        end
        _ -> 0
      end
      _ -> 0
    end
    Ok(Math.min(24, base + bits_over(load, target, 0)))
  end
end

pub fn signup_surge_target() -> Int do
  Env.get_int("MORSE_SIGNUP_SURGE_TARGET", 300)
end

pub fn signup_price() -> Int do
  20
end
