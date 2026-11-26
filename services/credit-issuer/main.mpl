from Api.IssuerApi import (
  IssuerResult,
  issuer_health_request,
  issuer_issue_request,
  issuer_quote_request
)
from Issuer.KeyStore import (
  issuer_announce_keys,
  issuer_provision_key,
  issuer_revoke_key,
  issuer_wrapping_key
)
from Issuer.Refunds import issuer_refund, issuer_refund_plan, issuer_refund_plan_json
from Issuer.Reissues import issuer_reissue, issuer_reissue_plan, issuer_reissue_plan_json
from Issuer.Registry import issuer_pool, issuer_start_registry
from Issuer.Settings import IssuerSettings, issuer_settings_from_env
from Issuer.Settlement import issuer_settlement
from Issuer.Sweeper import issuer_sweep

fn now_ms() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn respond(result :: IssuerResult) -> Response do
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.put(Map.new(), "Cache-Control", "no-store"))
end

fn handle_quote(request :: Request) -> Response do
  case issuer_settings_from_env() do
    Err(_) -> HTTP.response(503, "")
    Ok(settings) -> respond(issuer_quote_request(issuer_pool(),
      settings,
      Request.body_bytes(request),
      now_ms()))
  end
end

fn handle_issue(request :: Request) -> Response do
  case issuer_settings_from_env() do
    Err(_) -> HTTP.response(503, "")
    Ok(settings) -> case issuer_wrapping_key() do
      Err(_) -> HTTP.response(503, "")
      Ok(wrapping) -> respond(issuer_issue_request(issuer_pool(),
        settings,
        Request.body_bytes(request),
        wrapping,
        now_ms()))
    end
  end
end

fn handle_health(_request :: Request) -> Response do
  case issuer_settings_from_env() do
    Err(_) -> HTTP.response(503, "")
    Ok(settings) -> HTTP.response_bytes_with_headers(issuer_health_request(issuer_pool(),
        settings,
        now_ms()).status,
      issuer_health_request(issuer_pool(), settings, now_ms()).body,
      Map.put(Map.new(), "Content-Type", "application/json"))
  end
end

# Every minute: announce this epoch's (and the next epoch's) key, then one
# sweeper pass unless MORSE_CREDIT_SWEEP is off. Failures are logged by kind
# only, never with amounts, addresses or keys.

fn background_pass() do
  case issuer_settings_from_env() do
    Err(_) -> println("credit issuer: configuration invalid")
    Ok(settings) -> if settings.mode != "off" do
      case issuer_announce_keys(issuer_pool(), settings, now_ms()) do
        Err(_) -> println("credit issuer: key announcement failed")
        Ok(_) -> nil
      end
      if Env.get("MORSE_CREDIT_SWEEP", "on") != "off" do
        case issuer_sweep(issuer_pool(), settings) do
          Err(_) -> println("credit issuer: sweep failed")
          Ok(_) -> nil
        end
      end
    end
  end
end

fn background_loop(elapsed_ms :: Int) do
  if Process.shutdown_requested() do
    nil
  else
    let next = if elapsed_ms >= 60000 do
      background_pass()
      0
    else
      elapsed_ms
    end
    Timer.sleep(250)
    background_loop(next + 250)
  end
end

actor issuer_background() do
  background_loop(60000)
end

fn open_pool() -> PoolHandle!String do
  Pool.open(Env.get("MORSE_CREDIT_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/credit_issuer?sslmode=disable"),
    1,
    4,
    5000)
end

fn serve() -> Int!String do
  let settings = issuer_settings_from_env()?
  if settings.mode != "off" do
    issuer_wrapping_key()?
  end
  let port = Env.get_int("MORSE_CREDIT_PORT", 18092)
  if port <= 0 || port > 65535 do
    return Err("MORSE_CREDIT_PORT must be between 1 and 65535")
  end
  let pool = open_pool()?
  issuer_start_registry(pool)
  spawn(issuer_background)
  println("credit-issuer (#{settings.mode}) listening on :#{port}")
  HTTP.serve(HTTP.router()
      |> HTTP.on_get("/health", handle_health)
      |> HTTP.on_post("/v1/credits/quote", handle_quote)
      |> HTTP.on_post("/v1/credits/issue", handle_issue),
    port)
  Pool.close(pool)
  if Process.shutdown_requested() do
    Ok(0)
  else
    Err("HTTP server failed")
  end
end

fn epoch_argument(text :: String) -> Int!String do
  case String.to_int(text) do
    Some(value) -> Ok(value)
    None -> Err("the epoch is a number (Unix time / 30 days)")
  end
end

fn provision(purpose :: String, epoch :: String) -> Int!String do
  let wrapping_public = Bytes.from_hex(Env.get("MORSE_CREDIT_KEY_WRAPPING_PUBLIC_KEY_HEX", ""))?
  let pkcs8 = case Env.get_secret_hex("MORSE_CREDIT_PROVISION_KEY_HEX") do
    Err(_) -> Err("MORSE_CREDIT_PROVISION_KEY_HEX (PKCS#8 DER, hex) is required")
    Ok(value)
  end?
  let key_id = issuer_provision_key(open_pool()?,
    wrapping_public,
    pkcs8,
    purpose,
    epoch_argument(epoch)?)?
  println("provisioned #{purpose} key for epoch #{epoch}: token_key_id #{Bytes.to_hex(key_id)}")
  Ok(0)
end

fn wrapping_public() -> Int!String do
  let wrapping = issuer_wrapping_key()?
  case Crypto.x25519_public(wrapping) do
    Err(_) -> Err("invalid key-wrapping key")
    Ok(public) -> do
      println(Bytes.to_hex(public.bytes))
      Ok(0)
    end
  end
end

fn announce() -> Int!String do
  let count = issuer_announce_keys(open_pool()?, issuer_settings_from_env()?, now_ms())?
  println("announced #{count} key(s)")
  Ok(0)
end

fn revoke(purpose :: String, epoch :: String) -> Int!String do
  let key_id = issuer_revoke_key(open_pool()?,
    issuer_settings_from_env()?,
    purpose,
    epoch_argument(epoch)?,
    now_ms())?
  println("revoked #{purpose} key of epoch #{epoch}: token_key_id #{Bytes.to_hex(key_id)}")
  Ok(0)
end

fn refund(arguments :: List<String>) -> Int!String do
  let quote_id = Bytes.from_hex(List.get(arguments, 0))?
  let settings = issuer_settings_from_env()?
  let pool = open_pool()?
  case arguments do
    [_quote, "--confirm", confirmation] -> do
      let signature = issuer_refund(pool, settings, quote_id, confirmation)?
      println("refund sent: #{signature}")
      Ok(0)
    end
    _ -> do
      println(issuer_refund_plan_json(issuer_refund_plan(pool, settings, quote_id)?))
      println("to send it: credit-issuer refund #{Bytes.to_hex(quote_id)} --confirm #{Bytes.to_hex(quote_id)}")
      Ok(0)
    end
  end
end

fn reissue_now(quote :: String, confirmation :: String, note :: String) -> Int!String do
  let quote_id = Bytes.from_hex(quote)?
  issuer_reissue(open_pool()?, quote_id, confirmation, note)?
  println("re-issue open for #{quote}: the next batch for this quote is signed, once")
  Ok(0)
end

fn reissue(arguments :: List<String>) -> Int!String do
  case arguments do
    [quote] -> do
      println(issuer_reissue_plan_json(issuer_reissue_plan(open_pool()?, Bytes.from_hex(quote)?)?))
      println("to re-open it: credit-issuer reissue #{quote} --confirm #{quote} --note <text>")
      Ok(0)
    end
    [quote, "--confirm", confirmation] -> reissue_now(quote, confirmation, "")
    [quote, "--confirm", confirmation, "--note", note] -> reissue_now(quote, confirmation, note)
    _ -> usage()
  end
end

fn settlement(week_start :: String) -> Int!String do
  println(issuer_settlement(open_pool()?, issuer_settings_from_env()?.split, week_start)?)
  Ok(0)
end

# `sweep --now` first brings every issued deposit's random delay forward (an
# exposed deposit seed: empty everything at once).

fn sweep_once(now :: Bool) -> Int!String do
  let pool = open_pool()?
  if now do
    Pool.execute(pool,
      "UPDATE quotes SET sweep_after = now() WHERE state = 'issued' AND swept_at IS NULL AND sweep_after IS NOT NULL",
      [])?
  end
  let run = issuer_sweep(pool, issuer_settings_from_env()?)?
  println("sweep: #{run.sent} sent, #{run.finalized} finalized, #{run.retried} released")
  Ok(0)
end

fn usage() -> Int!String do
  Err("usage: credit-issuer [serve | wrapping-public-key | provision-key <live|test> <epoch> | announce | revoke-key <live|test> <epoch> | refund <quote-id> [--confirm <quote-id>] | reissue <quote-id> [--confirm <quote-id> [--note <text>]] | settlement <YYYY-MM-DD Monday> | sweep [--now]]")
end

fn run() -> Int!String do
  case List.drop(Env.args(), 1) do
    [] -> serve()
    ["serve"] -> serve()
    ["wrapping-public-key"] -> wrapping_public()
    ["provision-key", purpose, epoch] -> provision(purpose, epoch)
    ["announce"] -> announce()
    ["revoke-key", purpose, epoch] -> revoke(purpose, epoch)
    ["settlement", week] -> settlement(week)
    ["sweep"] -> sweep_once(false)
    ["sweep", "--now"] -> sweep_once(true)
    "reissue" :: rest -> reissue(rest)
    "refund" :: rest -> if List.length(rest) == 1 || List.length(rest) == 3 do
      refund(rest)
    else
      usage()
    end
    _ -> usage()
  end
end

fn main() do
  Process.install_shutdown_signals()
  case run() do
    Err(error) -> do
      io_eprintln("credit-issuer: #{error}")
      Process.exit(1)
    end
    Ok(_) -> nil
  end
end
