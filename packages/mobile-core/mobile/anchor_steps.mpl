from Security.Config import SecurityConfig
from Binary.Reader import BinaryReader, reader
from Mobile.Platform import native_security_config
from Mobile.Types import MobileSecurityConfig
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_take_u16,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u16,
  tcodec_u8,
  tcodec_vector
)

##! Mobile.AnchorSteps: how the anchor check (Mobile.Anchor) asks the app for
##! network reads. The core does no networking of its own: each call returns
##! the requests it still needs, the app performs them and calls again with
##! every exchange of the run so far, and the core decides from those bytes.
##!
##! Request: u8 kind || vector32(tag) || vector32(target) || vector32(body).
##!   kind 1 rpc: POST body (JSON) to target, a pinned RPC URL, as
##!     application/json.
##!   kind 2 directory: POST body to target, a path on the messenger
##!     directory, as application/octet-stream.
##!   kind 3 relay: POST body (an FRK) to target, a pinned relay's
##!     /v1/fork-evidence.
##!   kind 4 finder: answer a fresh one-time finder address (32 bytes) when
##!     the person collects fork bounties, or nothing.
##! Exchange: vector32(request) || u16 status (0: no answer) || vector32(body).
##! Call: vector32(database path) || vector32(u16 count || count x exchange).
##! Step: u8 1 || "ACS" || u8 done || u16 count || count x vector32(request).
##!
##! An RPC read counts only when two providers return the same projection
##! (Mobile.Chain). The first two providers are picked at random from the
##! pinned list; after a disagreement one more is asked, and if it agrees with
##! neither the read fails as `rpc_disagree`, never as a pass.

pub struct AnchorExchange do
  kind :: Int
  tag :: String
  target :: String
  body :: Bytes
  status :: Int
  answer :: Bytes
end

# asks: requests still needed (the step is not over). With no asks, outcome
# names why the read failed.

pub struct AnchorStop do
  asks :: List<Bytes>
  outcome :: String
end

pub struct AnchorContext do
  database_path :: String
  config :: MobileSecurityConfig
  exchanges :: List<AnchorExchange>
  preferred :: List<String>
  now :: Int
end

struct AnchorProjection do
  target :: String
  value :: Bytes
end

struct ReadExchanges do
  state :: BinaryReader
  value :: List<AnchorExchange>
end

pub fn anchor_kind_rpc() -> Int do
  1
end

pub fn anchor_kind_directory() -> Int do
  2
end

pub fn anchor_kind_relay() -> Int do
  3
end

pub fn anchor_kind_finder() -> Int do
  4
end

pub fn anchor_fail(outcome :: String) -> AnchorStop do
  AnchorStop { asks: List.new(), outcome: outcome }
end

pub fn anchor_ask(asks :: List<Bytes>) -> AnchorStop do
  AnchorStop { asks: asks, outcome: "" }
end

# A plain error becomes a failed read named outcome.

pub fn anchor_lift<T>(value :: Result<T, String>, outcome :: String) -> Result<T, AnchorStop> do
  case value do
    Ok(inner)
    Err(_) -> Err(anchor_fail(outcome))
  end
end

# A plain error that is not about the chain keeps its own name.

pub fn anchor_local<T>(value :: Result<T, String>) -> Result<T, AnchorStop> do
  case value do
    Ok(inner)
    Err(error) -> Err(anchor_fail(error))
  end
end

pub fn anchor_asks<T>(value :: Result<T, AnchorStop>) -> List<Bytes> do
  case value do
    Ok(_) -> List.new()
    Err(stop) -> stop.asks
  end
end

pub fn anchor_waiting(asks :: List<Bytes>) -> Result<(), AnchorStop> do
  if List.length(asks) > 0 do
    Err(anchor_ask(asks))
  else
    Ok(nil)
  end
end

# Requests still needed pass through; a failed read becomes None.

pub fn anchor_soft<T>(value :: Result<T, AnchorStop>) -> Result<Option<T>, AnchorStop> do
  case value do
    Ok(inner) -> Ok(Some(inner))
    Err(stop) -> if List.length(stop.asks) > 0 do
      Err(stop)
    else
      Ok(None)
    end
  end
end

pub fn anchor_request(kind :: Int,
  tag :: String,
  target :: String,
  body :: Bytes) -> Bytes!String do
  tcodec_join([
    tcodec_u8(kind)?,
    tcodec_vector(Bytes.from_utf8(tag))?,
    tcodec_vector(Bytes.from_utf8(target))?,
    tcodec_vector(body)?
  ])
end

fn text(value :: Bytes) -> String!String do
  case Bytes.to_utf8(value) do
    Err(_) -> Err("invalid_anchor_request")
    Ok(decoded)
  end
end

fn take_exchanges(state :: BinaryReader,
  count :: Int,
  output :: List<AnchorExchange>) -> ReadExchanges!String do
  if List.length(output) >= count do
    Ok(ReadExchanges { state: state, value: output })
  else
    let request = tcodec_take_vector(state, 65536)?
    let status = tcodec_take_u16(request.state)?
    let answer = tcodec_take_vector(status.state, 1048576)?
    let inner = case reader(request.value, 65536) do
      Err(_) -> Err("invalid_anchor_request")
      Ok(value)
    end?
    let kind = tcodec_take_u8(inner)?
    let tag = tcodec_take_vector(kind.state, 1024)?
    let target = tcodec_take_vector(tag.state, 2048)?
    let body = tcodec_take_vector(target.state, 65536)?
    tcodec_done(body.state)?
    take_exchanges(answer.state,
      count,
      List.append(output,
        AnchorExchange {
          kind: kind.value,
          tag: text(tag.value)?,
          target: text(target.value)?,
          body: body.value,
          status: status.value,
          answer: answer.value
        }))
  end
end

pub fn anchor_parse_input(input :: Bytes) -> (String, List<AnchorExchange>)!String do
  let state = case reader(input, 16777216) do
    Err(_) -> Err("invalid_anchor_request")
    Ok(value)
  end?
  let path = tcodec_take_vector(state, 4096)?
  let frame = tcodec_take_vector(path.state, 16777216)?
  tcodec_done(frame.state)?
  let inner = case reader(frame.value, 16777216) do
    Err(_) -> Err("invalid_anchor_request")
    Ok(value)
  end?
  let count = tcodec_take_u16(inner)?
  let exchanges = take_exchanges(count.state, count.value, List.new())?
  tcodec_done(exchanges.state)?
  let database_path = text(path.value)?
  if String.length(database_path) == 0 do
    Err("invalid_database_path")
  else
    Ok((database_path, exchanges.value))
  end
end

pub fn anchor_step(done :: Bool, asks :: List<Bytes>) -> Bytes!String do
  let requests = for ask in asks do
    tcodec_vector(ask)?
  end
  tcodec_join([
    tcodec_u8(1)?,
    Bytes.from_utf8("ACS"),
    tcodec_u8(if done do
      1
    else
      0
    end)?,
    tcodec_u16(List.length(asks))?
  ]
    ++ requests)
end

fn random_index(count :: Int) -> Int!String do
  let bytes = case Crypto.random_bytes(2) do
    Err(_) -> Err("random_generation_failed")
    Ok(value) -> Ok(Bytes.to_list(value))
  end?
  Ok((List.get(bytes, 0) * 256 + List.get(bytes, 1)) % count)
end

pub fn anchor_shuffled(values :: List<String>) -> List<String>!String do
  shuffle_from(values, List.new())
end

fn shuffle_from(values :: List<String>, output :: List<String>) -> List<String>!String do
  if List.length(values) == 0 do
    Ok(output)
  else
    let index = random_index(List.length(values))?
    let chosen = List.get(values, index)
    shuffle_from(List.filter(values, fn value -> value != chosen end), List.append(output, chosen))
  end
end

fn distinct_targets(values :: List<AnchorExchange>, output :: List<String>) -> List<String> do
  case values do
    [] -> output
    value :: rest -> if List.contains(output, value.target) do
      distinct_targets(rest, output)
    else
      distinct_targets(rest, List.append(output, value.target))
    end
  end
end

# The two providers this run reads first: the first two asked for the Log
# account, or a fresh random pair when the run starts.

pub fn anchor_context(database_path :: String,
  exchanges :: List<AnchorExchange>) -> AnchorContext!String do
  let config = native_security_config()?
  let asked = distinct_targets(List.filter(exchanges,
      fn value -> value.kind == anchor_kind_rpc() && value.tag == "log" end),
    List.new())
  let preferred = if List.length(asked) >= 2 do
    List.take(asked, 2)
  else
    List.take(anchor_shuffled(config.config.rpc_urls)?, 2)
  end
  Ok(AnchorContext {
    database_path: database_path,
    config: config,
    exchanges: exchanges,
    preferred: preferred,
    now: DateTime.to_unix_ms(DateTime.utc_now())
  })
end

pub fn anchor_answered(ctx :: AnchorContext, tag :: String) -> Option<AnchorExchange> do
  List.find(ctx.exchanges, fn value -> value.kind != anchor_kind_rpc() && value.tag == tag end)
end

# A directory, relay or finder request: its answer once made, else a request.

pub fn anchor_call(ctx :: AnchorContext,
  kind :: Int,
  tag :: String,
  target :: String,
  body :: Bytes) -> Result<AnchorExchange, AnchorStop> do
  case anchor_answered(ctx, tag) do
    Some(value) -> Ok(value)
    None -> Err(anchor_ask([
      anchor_lift(anchor_request(kind, tag, target, body), "invalid_anchor_request")?
    ]))
  end
end

fn projections(values :: List<AnchorExchange>,
  project :: Fun(Bytes) -> Result<Bytes, String>,
  output :: List<AnchorProjection>) -> List<AnchorProjection> do
  case values do
    [] -> output
    value :: rest -> if value.status != 200 do
      projections(rest, project, output)
    else
      case project(value.answer) do
        Err(_) -> projections(rest, project, output)
        Ok(projection) -> projections(rest,
          project,
          List.append(output, AnchorProjection { target: value.target, value: projection }))
      end
    end
  end
end

fn agreement(values :: List<AnchorProjection>) -> Option<Bytes> do
  case values do
    [] -> None
    first :: rest -> if List.any(rest,
      fn other -> other.target != first.target
        && Bytes.secure_equals(other.value, first.value) end) do
      Some(first.value)
    else
      agreement(rest)
    end
  end
end

fn rpc_asks(ctx :: AnchorContext,
  tag :: String,
  body :: String,
  urls :: List<String>) -> Result<Bytes, AnchorStop> do
  let asks = for url in urls do
    anchor_lift(anchor_request(anchor_kind_rpc(), tag, url, Bytes.from_utf8(body)),
      "invalid_anchor_request")?
  end
  Err(anchor_ask(asks))
end

# The agreed projection of one RPC read (tag names it within the run).

pub fn anchor_rpc(ctx :: AnchorContext,
  tag :: String,
  body :: String,
  project :: Fun(Bytes) -> Result<Bytes, String>) -> Result<Bytes, AnchorStop> do
  let answers = List.filter(ctx.exchanges,
    fn value -> value.kind == anchor_kind_rpc() && value.tag == tag end)
  let tried = distinct_targets(answers, List.new())
  let valid = projections(answers, project, List.new())
  let rest = List.filter(ctx.config.config.rpc_urls,
    fn url -> !List.contains(ctx.preferred, url) && !List.contains(tried, url) end)
  let untried = List.filter(ctx.preferred, fn url -> !List.contains(tried, url) end)
    ++ anchor_lift(anchor_shuffled(rest), "invalid_anchor_request")?
  case agreement(valid) do
    Some(projection) -> Ok(projection)
    None -> if List.length(tried) == 0 do
      rpc_asks(ctx, tag, body, List.take(untried, 2))
    else if List.length(valid) >= 2 do
      if List.length(tried) < 3 && List.length(untried) > 0 do
        rpc_asks(ctx, tag, body, List.take(untried, 1))
      else
        Err(anchor_fail("rpc_disagree"))
      end
    else if List.length(untried) > 0 do
      rpc_asks(ctx, tag, body, List.take(untried, 2 - List.length(valid)))
    else
      Err(anchor_fail("rpc_unavailable"))
    end
  end
end
