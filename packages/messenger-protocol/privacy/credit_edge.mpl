##! The privacy edge's credit path (protocol/credits-v1.md "Privacy edge").
##!
##! An envelope submission is `PRV` (proof of work, the free path, unchanged),
##! `CRD ‖ PRV` (credits beside the work) or `CRD ‖ SED` (credits instead of
##! it). The edge checks the frame's binding and any work, sends the frame to
##! the core's redeem route, and forwards `HLD(redemption id, SED)` only after a
##! redemption. It never keeps, logs or forwards anything else of a token.
##!
##! The two calls to the core are parameters, so the same path runs over HTTP
##! in the edge and against the core itself in the end-to-end test.

from Credits.CreditFrames import (
  credits_action_envelope,
  credits_decode_redemption,
  credits_detach,
  credits_encode_frame,
  credits_encode_held,
  credits_encode_redeem
)
from Privacy.Edge import decode_sealed_delivery, sealed_delivery_bytes, verify_submission

pub struct CreditEdgeResult do
  status :: Int
  body :: Bytes
end

pub type EdgeSubmission do
  EdgeByWork(sealed :: Bytes)
  EdgeByCredits(frame :: Bytes, sealed :: Bytes)
  EdgeRefused(status :: Int)
end

fn refused(status :: Int) -> CreditEdgeResult do
  CreditEdgeResult { status: status, body: Bytes.empty() }
end

# A PRV frame: 400 when malformed, 429 when its work is missing, stale or
# short, else its sealed delivery.

fn by_work(body :: Bytes, now :: U64, maximum_future :: U64, difficulty :: Int) -> EdgeSubmission do
  case verify_submission(body, now, maximum_future, difficulty) do
    Err(_) -> EdgeRefused(400)
    Ok(false) -> EdgeRefused(429)
    Ok(true) -> case sealed_delivery_bytes(body) do
      Err(_) -> EdgeRefused(400)
      Ok(sealed) -> EdgeByWork(sealed)
    end
  end
end

fn credited(frame :: Bytes,
  rest :: Bytes,
  now :: U64,
  maximum_future :: U64,
  difficulty :: Int) -> EdgeSubmission do
  case decode_sealed_delivery(rest) do
    Ok(_) -> EdgeByCredits(frame, rest)
    Err(_) -> case by_work(rest, now, maximum_future, difficulty) do
      EdgeByWork(sealed) -> EdgeByCredits(frame, sealed)
      other
    end
  end
end

## What an envelope submission asks for, before anything reaches the core.

pub fn credit_edge_classify(body :: Bytes,
  now :: U64,
  maximum_future :: U64,
  difficulty :: Int) -> EdgeSubmission do
  case credits_detach(body) do
    Err(_) -> EdgeRefused(400)
    Ok((None, _)) -> by_work(body, now, maximum_future, difficulty)
    Ok((Some(frame), rest)) -> case credits_encode_frame(frame.binding, frame.tokens) do
      Err(_) -> EdgeRefused(400)
      Ok(encoded) -> credited(encoded, rest, now, maximum_future, difficulty)
    end
  end
end

fn deliver_held(redemption :: Bytes,
  sealed :: Bytes,
  deliver :: Fun(Bytes) -> CreditEdgeResult!String) -> CreditEdgeResult do
  let held = case credits_decode_redemption(redemption) do
    Err(_) -> return refused(503)
    Ok(value) -> credits_encode_held(value.redemption_id, sealed)
  end
  case held do
    Err(_) -> refused(500)
    Ok(request) -> case deliver(request) do
      Err(_) -> refused(503)
      Ok(delivered) -> delivered
    end
  end
end

# The core's redeem answer, as the edge passes it on: its refusals (422 not a
# credit, 403 credits off, 409 already spent) as they are, and 503 for
# anything else, so a core that cannot reach its spent set never delivers.

fn after_redeem(answer :: CreditEdgeResult!String,
  sealed :: Bytes,
  deliver :: Fun(Bytes) -> CreditEdgeResult!String) -> CreditEdgeResult do
  case answer do
    Err(_) -> refused(503)
    Ok(result) -> if result.status == 201 do
      deliver_held(result.body, sealed, deliver)
    else if result.status == 400
      || result.status == 422
      || result.status == 403
      || result.status == 409 do
      refused(result.status)
    else
      refused(503)
    end
  end
end

## One envelope submission through the edge. `redeem` posts an RDQ frame to
## the core's redeem route; `deliver` posts the bytes to its sealed route.

pub fn credit_edge_submit(body :: Bytes,
  now :: U64,
  maximum_future :: U64,
  difficulty :: Int,
  redeem :: Fun(Bytes) -> CreditEdgeResult!String,
  deliver :: Fun(Bytes) -> CreditEdgeResult!String) -> CreditEdgeResult do
  case credit_edge_classify(body, now, maximum_future, difficulty) do
    EdgeRefused(status) -> refused(status)
    EdgeByWork(sealed) -> case deliver(sealed) do
      Err(_) -> refused(502)
      Ok(delivered) -> delivered
    end
    EdgeByCredits(frame, sealed) -> case credits_encode_redeem(credits_action_envelope(), frame) do
      Err(_) -> refused(400)
      Ok(request) -> after_redeem(redeem(request), sealed, deliver)
    end
  end
end

## A request that only credits pay for (longer storage): the body must start
## with a CRD frame (402 without one, 400 malformed). The frame is redeemed for
## `action` and the rest goes on as HLD, exactly as an envelope's does.

pub fn credit_edge_paid(body :: Bytes,
  action :: Int,
  redeem :: Fun(Bytes) -> CreditEdgeResult!String,
  deliver :: Fun(Bytes) -> CreditEdgeResult!String) -> CreditEdgeResult do
  case credits_detach(body) do
    Err(_) -> refused(400)
    Ok((None, _)) -> refused(402)
    Ok((Some(frame), rest)) -> case credits_encode_frame(frame.binding, frame.tokens) do
      Err(_) -> refused(400)
      Ok(encoded) -> case credits_encode_redeem(action, encoded) do
        Err(_) -> refused(400)
        Ok(request) -> after_redeem(redeem(request), rest, deliver)
      end
    end
  end
end
