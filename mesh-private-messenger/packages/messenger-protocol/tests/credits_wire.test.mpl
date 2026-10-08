from Credits.CreditToken import CreditToken, credits_encode_token
from Credits.CreditFrames import (
  CreditIssueRequest,
  CreditIssueResponse,
  CreditQuote,
  CreditQuoteRequest,
  CreditRedemption,
  credits_attach,
  credits_blinded_hash,
  credits_decode_issue_request,
  credits_decode_held,
  credits_decode_issue_response,
  credits_decode_quote,
  credits_decode_quote_request,
  credits_decode_redeem,
  credits_decode_redemption,
  credits_decode_work,
  credits_detach,
  credits_encode_frame,
  credits_encode_held,
  credits_encode_issue_request,
  credits_encode_issue_response,
  credits_encode_quote,
  credits_encode_quote_request,
  credits_encode_redeem,
  credits_encode_redemption,
  credits_encode_work,
  credits_frame_nullifiers,
  credits_pack_price,
  credits_pack_size
)

fn repeated(value :: Int, count :: Int) -> Bytes do
  case Bytes.repeat(value, count) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn token(seed :: Int) -> Bytes!String do
  credits_encode_token(CreditToken {
    nonce: repeated(seed, 32),
    challenge_digest: repeated(2, 32),
    token_key_id: repeated(3, 32),
    authenticator: repeated(4, 256)
  })
end

fn refused<T>(value :: Result<T, String>) -> Bool do
  case value do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn attached() -> Bool!String do
  let body = Bytes.from_utf8("the request body")
  let tokens = [token(10)?, token(11)?, token(12)?]
  let request = credits_attach(tokens, body)?
  let (frame, rest) = credits_detach(request)?
  case frame do
    None -> Ok(false)
    Some(found) -> Ok(Bytes.secure_equals(rest, body)
      && Bytes.secure_equals(found.binding, Crypto.sha256(body))
      && List.length(found.tokens) == 3
      && Bytes.secure_equals(List.get(found.tokens, 1), token(11)?)
      && Bytes.length(request) == 4 + 32 + 1 + 3 * 354 + Bytes.length(body)
      && List.length(credits_frame_nullifiers(found)?) == 3)
  end
end

test("a CRD frame travels in front of the body it binds") do
  case attached() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn passthrough() -> Bool!String do
  let body = Bytes.from_hex("01505256")?
  let (frame, rest) = credits_detach(body)?
  Ok(frame == None && Bytes.secure_equals(rest, body))
end

test("a body without a CRD frame passes through untouched") do
  assert(passthrough() == Ok(true))
end

# A frame with no tokens, built by hand since the encoder refuses one.

fn empty_frame(body :: Bytes) -> Bytes!String do
  let head = Bytes.concat(Bytes.from_hex("01435244")?, Crypto.sha256(body))?
  Bytes.concat(Bytes.concat(head, Bytes.from_hex("00")?)?, body)
end

fn frames_refused() -> Bool!String do
  let body = Bytes.from_utf8("body")
  let request = credits_attach([token(10)?], body)?
  let tampered = Bytes.concat(request, Bytes.from_utf8("!"))?
  let many = for seed in 0..65 do
    token(seed)?
  end
  Ok(refused(credits_detach(tampered))
    && refused(credits_attach([token(10)?, token(10)?], body))
    && refused(credits_detach(empty_frame(body)?))
    && refused(credits_attach(many, body))
    && refused(credits_detach(Bytes.slice(request, 0, 100)?))
    && refused(credits_encode_frame(Crypto.sha256(body), [repeated(1, 354)])))
end

test("CRD frames refuse a wrong binding, repeated or missing tokens and more than 64") do
  case frames_refused() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn redeem_round_trip() -> Bool!String do
  let frame = credits_encode_frame(Crypto.sha256(Bytes.from_utf8("b")), [token(1)?, token(2)?])?
  let request = credits_encode_redeem(1, frame)?
  let (action, decoded) = credits_decode_redeem(request)?
  let response = credits_encode_redemption(CreditRedemption {
    redemption_id: repeated(9, 16),
    credits: 2
  })?
  let redemption = credits_decode_redemption(response)?
  Ok(action == 1
    && List.length(decoded.tokens) == 2
    && Bytes.secure_equals(redemption.redemption_id, repeated(9, 16))
    && redemption.credits == 2
    && refused(credits_encode_redeem(9, frame))
    && refused(credits_decode_redeem(Bytes.concat(request, Bytes.from_hex("00")?)?)))
end

test("redeem requests name an action and carry one frame; answers carry the hold") do
  case redeem_round_trip() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn quote_round_trip() -> Bool!String do
  let request = credits_decode_quote_request(credits_encode_quote_request(CreditQuoteRequest {
    pack: 2,
    asset: 1
  })?)?
  let quote = CreditQuote {
    quote_id: repeated(5, 32),
    pack: 2,
    asset: 1,
    batch: 500,
    amount: 25000000,
    expires_at: 1790000000000,
    token_key_id: repeated(6, 32),
    payment_request: "solana:Deposit111?amount=25"
  }
  let decoded = credits_decode_quote(credits_encode_quote(quote)?)?
  Ok(request.pack == 2
    && request.asset == 1
    && decoded == quote
    && credits_pack_size(1) == Ok(100)
    && credits_pack_size(3) == Ok(2000)
    && credits_pack_price(2) == Ok(25000000)
    && refused(credits_encode_quote_request(CreditQuoteRequest { pack: 4, asset: 1 }))
    && refused(credits_encode_quote_request(CreditQuoteRequest { pack: 1, asset: 4 }))
    && refused(credits_encode_quote(%{quote | batch: 100})))
end

test("quotes come in the fixed packs, and the batch is the pack") do
  case quote_round_trip() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn blinded(count :: Int) -> List<Bytes> do
  for index in 0..count do
    repeated(index % 256, 256)
  end
end

fn issue_round_trip() -> Bool!String do
  let request = CreditIssueRequest {
    quote_id: repeated(5, 32),
    payment: "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW",
    token_key_id: repeated(6, 32),
    blinded: blinded(100)
  }
  let decoded = credits_decode_issue_request(credits_encode_issue_request(request)?)?
  let response = CreditIssueResponse {
    quote_id: repeated(5, 32),
    token_key_id: repeated(6, 32),
    signatures: blinded(100)
  }
  let answer = credits_decode_issue_response(credits_encode_issue_response(response)?)?
  let reordered = %{request | blinded: List.reverse(request.blinded)}
  Ok(decoded == request
    && answer == response
    && credits_blinded_hash(request)? != credits_blinded_hash(reordered)?
    && credits_blinded_hash(request)? == credits_blinded_hash(%{request | payment: ""})?
    && refused(credits_encode_issue_request(%{request | blinded: blinded(99)}))
    && refused(credits_encode_issue_request(%{request | blinded: [repeated(1, 255)]})))
end

test("issue requests carry a whole pack of 256-byte blinded messages") do
  case issue_round_trip() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn held_round_trip() -> Bool!String do
  let sealed = Bytes.from_hex("01534544aabb")?
  let held = credits_encode_held(repeated(7, 16), sealed)?
  let (id, body) = credits_decode_held(held)?
  let (none, plain) = credits_decode_held(sealed)?
  Ok(id == Some(repeated(7, 16))
    && Bytes.secure_equals(body, sealed)
    && none == None
    && Bytes.secure_equals(plain, sealed)
    && refused(credits_encode_held(repeated(7, 15), sealed))
    && refused(credits_decode_held(Bytes.slice(held, 0, 22)?)))
end

test("a held delivery names its redemption in front of the sealed bytes") do
  case held_round_trip() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("the registration work answer names the difficulty and the sign-up price") do
  assert(case credits_encode_work(18, 20) do
    Ok(encoded) -> credits_decode_work(encoded) == Ok((18, 20)) && Bytes.length(encoded) == 6
    Err(_) -> false
  end)
  assert(refused(credits_encode_work(25, 20)))
end
