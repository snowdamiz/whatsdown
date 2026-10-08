##! Credits for large objects (opaque-object-wire-v1.md "Large objects",
##! credits-v1.md "Large files").
##!
##! A grant of up to 257 parts is free, as it always was. A larger one is a
##! padded attachment bucket above 16 MiB, and its request is `CRD ‖ OGR`: the
##! object store redeems the frame with the core (action 4) before it grants
##! anything. The core call is a parameter, so the same path runs over HTTP in
##! the store and against the core itself in the directory's tests.

from Attachments.Protocol import attachment_credit_cost, attachment_padded_size
from Credits.CreditFrames import (
  CreditFrame,
  credits_action_file,
  credits_decode_redemption,
  credits_detach,
  credits_encode_frame,
  credits_encode_redeem
)
from Privacy.CreditEdge import CreditEdgeResult

## The credits a grant of `part_count` parts costs: nothing up to 257 parts;
## above that the object must be a bucket of (part_count - 1) full chunks, and
## costs what the bucket costs.

pub fn object_grant_price(part_count :: Int) -> Int!String do
  if part_count >= 1 && part_count <= 257 do
    Ok(0)
  else if part_count < 1 || part_count > 8193 do
    Err("invalid object part count")
  else
    let size = (part_count - 1) * 65536
    if attachment_padded_size(size) != size do
      Err("a large object must be an attachment bucket")
    else
      Ok(attachment_credit_cost(size))
    end
  end
end

## Splits a grant request into its CRD frame, if any, and the OGR it is bound
## to; a frame bound to other bytes is refused.

pub fn object_grant_split(request :: Bytes) -> (Option<CreditFrame>, Bytes)!String do
  credits_detach(request)
end

fn redeemed(answer :: CreditEdgeResult!String, price :: Int) -> Int do
  case answer do
    Err(_) -> 503
    Ok(result) -> if result.status == 201 do
      case credits_decode_redemption(result.body) do
        Err(_) -> 503
        Ok(redemption) -> if redemption.credits >= price do
          0
        else
          402
        end
      end
    else if result.status == 422 || result.status == 403 || result.status == 409 do
      result.status
    else
      503
    end
  end
end

## 0 when a grant of `part_count` parts may be stored, else the status to
## answer: 402 no frame or fewer tokens than the price (nothing is redeemed),
## 400 a part count off the ladder, the core's 422 (not credits), 403 (credits
## off) or 409 (a token already spent), and 503 for anything else. A frame on a
## free grant is ignored, never spent.

fn redeem_request(value :: CreditFrame) -> Bytes!String do
  credits_encode_redeem(credits_action_file(), credits_encode_frame(value.binding, value.tokens)?)
end

fn redeem_frame(value :: CreditFrame,
  price :: Int,
  redeem :: Fun(Bytes) -> CreditEdgeResult!String) -> Int do
  case redeem_request(value) do
    Err(_) -> 400
    Ok(request) -> redeemed(redeem(request), price)
  end
end

pub fn object_grant_entitle(frame :: Option<CreditFrame>,
  part_count :: Int,
  redeem :: Fun(Bytes) -> CreditEdgeResult!String) -> Int do
  case object_grant_price(part_count) do
    Err(_) -> 400
    Ok(0) -> 0
    Ok(price) -> case frame do
      None -> 402
      Some(value) -> if List.length(value.tokens) < price do
        402
      else
        redeem_frame(value, price, redeem)
      end
    end
  end
end
