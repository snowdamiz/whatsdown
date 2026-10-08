##! Proof-of-work mining cost, measured with `mint_request_stamp`, the function
##! the mobile core mints stamps with (sealed-delivery-v1.md, "Per-endpoint
##! difficulty"). Build it the way release builds build the core, against the
##! release runtime (`cargo build --release -p mesh-rt --lib` in mesh-lang) at
##! optimization level 2, and run it:
##!
##!   MESH_RT_LIB_PATH=<mesh-lang>/target/release/libmesh_rt.a \
##!     meshc build tools/pow-bench --opt-level 2 -o pow-bench && ./pow-bench
##!
##! Without the runtime and the level it measures a development build.
##! POW_LOW and POW_HIGH pick the difficulties (default 8 to 20). For the iOS
##! simulator, build with `--target aarch64-apple-ios-sim`, link the object
##! against that target's runtime, and run it with `xcrun simctl spawn`.

from Privacy.Edge import mint_request_stamp

fn power(exponent :: Int, value :: Int) -> Int do
  if exponent <= 0 do
    value
  else
    power(exponent - 1, value * 2)
  end
end

# Minting at the base of an endpoint with no step mines exactly these bits.

fn attempts(difficulty :: Int, remaining :: Int, total :: Int) -> Int!String do
  if remaining <= 0 do
    Ok(total)
  else
    let payload = case Crypto.random_bytes(80) do
      Err(_) -> Err("random payload failed")
      Ok(value)
    end?
    let stamp = mint_request_stamp("mesh-msg/v1/work/register",
      payload,
      U64.parse("1900000000000")?,
      difficulty)?
    attempts(difficulty, remaining - 1, total + stamp.nonce + 1)
  end
end

fn stamps_for(difficulty :: Int) -> Int do
  if difficulty <= 12 do
    64
  else if difficulty <= 16 do
    16
  else
    4
  end
end

fn measure(difficulty :: Int) -> Result<(), String> do
  let stamps = stamps_for(difficulty)
  let started = Monotonic.now_nanos()
  let total = attempts(difficulty, stamps, 0)?
  let elapsed = Monotonic.elapsed(started, Monotonic.now_nanos())?
  let rate = total * 1000000000 / elapsed
  println("difficulty=#{difficulty} stamps=#{stamps} attempts=#{total} hashes_per_second=#{rate} measured_ms_per_stamp=#{elapsed
    / stamps
    / 1000000} expected_ms_per_stamp=#{1000 * power(difficulty, 1) / rate}")
  Ok(nil)
end

fn main() do
  for difficulty in Env.get_int("POW_LOW", 8)..Env.get_int("POW_HIGH", 20) + 1 do
    case measure(difficulty) do
      Err(error) -> println("difficulty=#{difficulty} error=#{error}")
      Ok(_) -> nil
    end
  end
end
