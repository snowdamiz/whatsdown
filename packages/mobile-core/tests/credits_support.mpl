from Credits.CreditFrames import (
  CreditIssueRequest,
  CreditIssueResponse,
  CreditQuote,
  CreditQuoteRequest,
  credits_blinded_hash,
  credits_decode_issue_request,
  credits_decode_quote_request,
  credits_encode_issue_response,
  credits_encode_quote,
  credits_pack_price,
  credits_pack_size
)
from Credits.IssuerKey import (
  IssuerKey,
  credits_encode_issuer_key,
  credits_encode_issuer_keys,
  credits_issuer_key
)
from Privacy.Edge import RequestStamp, decode_stamped_request
from Security.Config import SecurityConfig, SecurityWitness, security_config_encode
from Tests.AnchorSupport import (
  attestations,
  seeded,
  service_public_key,
  signed_checkpoint,
  witness_ids
)
from Tests.Support import evidence_v2, repeated
from Transparency.Merkle import TransparencyCheckpoint, WitnessAttestation, leaf_hash

##! A fake credit issuer behind a fake privacy edge, and a fake directory
##! listing issuer keys, on one port, for the credits tests. The issuer signs
##! real blind signatures with keys the test generates (sealed to files under
##! the test's secure store, since a request handler holds no state).
##!
##! Files "/tmp/mesh_mobile_credits_<name>": `current` (hex key ID the issuer
##! signs with), `key-<id>` (the sealed key), `listing` (the CIK the directory
##! serves), `issue-mode` ("", "pending:N", "lose:N", "stale", "expired",
##! "unpaid", "reissue", "down"), `quote-<id>` (batch), `batch-<id>` (the
##! stored batch hash), `hits-<id>` (one line per issue request seen).

pub fn credits_fake_port() -> Int do
  18983
end

pub fn credits_fake_url() -> String do
  "http://127.0.0.1:18983"
end

fn file(name :: String) -> String do
  "/tmp/mesh_mobile_credits_" <> name
end

fn must<T, E>(value :: Result<T, E>, error :: String) -> T!String do
  case value do
    Err(_) -> Err(error)
    Ok(output)
  end
end

pub fn credits_fake_write(name :: String, value :: Bytes) -> Result<(), String> do
  if Bytes.length(value) == 0 do
    must(File.write(file(name), ""), "fake write failed")?
  else
    must(File.write_bytes(file(name), 0, value, true), "fake write failed")?
  end
  Ok(nil)
end

pub fn credits_fake_read(name :: String) -> Bytes do
  let path = file(name)
  if !File.exists(path) do
    Bytes.empty()
  else
    case File.size(path) do
      Err(_) -> Bytes.empty()
      Ok(0) -> Bytes.empty()
      Ok(size) -> case File.read_bytes(path, 0, size) do
        Err(_) -> Bytes.empty()
        Ok(value) -> value
      end
    end
  end
end

fn text(name :: String) -> String do
  case Bytes.to_utf8(credits_fake_read(name)) do
    Err(_) -> ""
    Ok(value) -> value
  end
end

pub fn credits_fake_mode(value :: String) -> Result<(), String> do
  credits_fake_write("issue-mode", Bytes.from_utf8(value))
end

## How many issue requests the issuer saw for a quote, and how many distinct
## batches among them.

pub fn credits_fake_hits(quote_id :: Bytes) -> (Int, Int) do
  let lines = List.filter(String.split(text("hits-" <> Bytes.to_hex(quote_id)), "\n"),
    fn line -> line != "" end)
  let distinct = List.reduce(lines,
    List.new(),
    fn found, line -> if List.any(found, fn known -> known == line end) do
      found
    else
      List.append(found, line)
    end end)
  (List.length(lines), List.length(distinct))
end

# A version 2 config pinning witness-a..c (2 of 3) and `issuer` as the credit
# issuer origin ("" for none).

pub fn credits_install_config(issuer :: String) -> Bool!String do
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> Err("test delivery key generation failed")
    Ok(value)
  end?
  let witnesses = for index in 0..3 do
    SecurityWitness {
      witness_id: List.get(witness_ids(), index),
      public_key: seeded(92 + index)?.public_key.bytes,
      label: "Morse"
    }
  end
  let frame = security_config_encode(SecurityConfig {
    version: 2,
    service_public_key: service_public_key()?,
    delivery_public_key: delivery.public_key.bytes,
    abuse_difficulty: 4,
    threshold: 2,
    witnesses: witnesses,
    judge_program_id: "",
    log_account: "",
    rpc_urls: List.new(),
    relays: List.new(),
    issuer_origin: issuer,
    c2sp_origin: "",
    minimum_suite: 1,
    ohttp_key_config: Bytes.empty(),
    ohttp_relay: "",
    set_id: Bytes.empty()
  })?
  Ok(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame))
end

# A storage context of purpose 18 (a blind RSA issuer key), whose session
# field must be zero.

fn key_context(id :: String) -> Bytes!String do
  let head = must(Bytes.from_list([1]), "context failed")?
  let purpose = must(Bytes.from_list([0, 18, 0, 0, 0, 0, 0, 0, 0, 1]), "context failed")?
  must(Bytes.concat(must(Bytes.concat(must(Bytes.concat(head, repeated(0, 80)?), "context failed")?,
          Crypto.sha256(Bytes.from_utf8("credits-test-issuer/" <> id))),
        "context failed")?,
      purpose),
    "context failed")
end

## A new issuer key for `purpose` (1 live, 2 test) and `epoch` of `issuer`,
## kept for the fake issuer to sign with. `current` makes it the one it signs
## with now.

pub fn credits_fake_key(issuer :: String,
  purpose :: Int,
  epoch :: Int,
  current :: Bool) -> IssuerKey!String do
  let secret = case Crypto.blind_rsa_generate() do
    Err(_) -> Err("issuer key generation failed")
    Ok(value)
  end?
  let public = must(Crypto.blind_rsa_public(secret), "issuer public key failed")?
  let key = credits_issuer_key(purpose, issuer, epoch, public.bytes)?
  let id = Bytes.to_hex(Crypto.sha256(public.bytes))
  let storage = case StorageKey.platform() do
    Err(_) -> Err("test storage key unavailable")
    Ok(value)
  end?
  let sealed = must(BlindRsaSecretKey.seal_for_storage(secret, storage, key_context(id)?),
    "issuer key sealing failed")?
  credits_fake_write("key-" <> id, sealed)?
  if current do
    credits_fake_write("current", Bytes.from_utf8(id))?
  end
  Ok(key)
end

fn signing_key(id :: String) -> BlindRsaSecretKey!String do
  let storage = case StorageKey.platform() do
    Err(_) -> Err("test storage key unavailable")
    Ok(value)
  end?
  case BlindRsaSecretKey.unseal_from_storage(credits_fake_read("key-" <> id),
    storage,
    key_context(id)?) do
    Err(_) -> Err("issuer key unavailable")
    Ok(value)
  end
end

## One log holding `entries` (issuer-key leaves and others) and a listing of
## KTE v2 evidence for those at `listed` indexes, consistent from `old_size`.

pub fn credits_fake_listing(entries :: List<Bytes>,
  listed :: List<Int>,
  old_size :: Int) -> Bytes!String do
  let leaves = for entry in entries do
    leaf_hash(entry)?
  end
  let checkpoint = signed_checkpoint(1, leaves)?
  let witnessed = attestations(checkpoint)?
  let evidence = for index in listed do
    evidence_v2(List.get(entries, index), leaves, index, old_size, checkpoint, witnessed)?
  end
  credits_encode_issuer_keys(evidence)
end

## The listing as a directory whose witnesses did not sign serves it.

pub fn credits_unwitnessed_listing(entries :: List<Bytes>) -> Bytes!String do
  let leaves = for entry in entries do
    leaf_hash(entry)?
  end
  let checkpoint = signed_checkpoint(1, leaves)?
  let evidence = for index in 0..List.length(entries) do
    evidence_v2(List.get(entries, index), leaves, index, 0, checkpoint, List.new())?
  end
  credits_encode_issuer_keys(evidence)
end

pub fn credits_key_entry(key :: IssuerKey) -> Bytes!String do
  credits_encode_issuer_key(key)
end

# The issuer.

fn respond(status :: Int, body :: Bytes) -> Response do
  HTTP.response_bytes_with_headers(status, body, Map.put(Map.new(), "Cache-Control", "no-store"))
end

fn quote_for(request :: CreditQuoteRequest) -> Bytes!String do
  let quote_id = must(Crypto.random_bytes(32), "random failed")?
  let key_id = must(Bytes.from_hex(text("current")), "no current key")?
  let batch = credits_pack_size(request.pack)?
  credits_fake_write("quote-" <> Bytes.to_hex(quote_id), Bytes.from_utf8(Int.to_string(batch)))?
  credits_encode_quote(CreditQuote {
    quote_id: quote_id,
    pack: request.pack,
    asset: request.asset,
    batch: batch,
    amount: credits_pack_price(request.pack)?,
    expires_at: DateTime.to_unix_ms(DateTime.utc_now()) + 900000,
    token_key_id: key_id,
    payment_request: "solana:"
      <> Bytes.to_base58(repeated(9, 32)?)
      <> "?amount="
      <> Int.to_string(credits_pack_price(request.pack)? / 1000000)
      <> "&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&reference="
      <> Bytes.to_base58(Crypto.sha256(quote_id))
      <> "&label=Morse&message="
      <> Int.to_string(batch)
      <> "%20Morse%20credits"
  })
end

fn handle_quote(request :: Request) -> Response do
  let answered = case decode_stamped_request(Request.body_bytes(request), 64) do
    Err(_) -> Err("400")
    Ok((_, payload)) -> case credits_decode_quote_request(payload) do
      Err(_) -> Err("400")
      Ok(value) -> quote_for(value)
    end
  end
  case answered do
    Err(_) -> respond(400, Bytes.empty())
    Ok(body) -> respond(201, body)
  end
end

fn sign_all(key :: borrow BlindRsaSecretKey,
  blinded :: List<Bytes>,
  output :: List<Bytes>) -> List<Bytes>!String do
  case blinded do
    [] -> Ok(output)
    head :: rest -> sign_all(key,
      rest,
      List.append(output, must(Crypto.blind_rsa_sign(key, head), "signing failed")?))
  end
end

fn countdown(prefix :: String) -> Bool do
  let mode = text("issue-mode")
  if !String.starts_with(mode, prefix) do
    false
  else
    case String.to_int(String.slice(mode, String.length(prefix), String.length(mode))) do
      Some(left) -> if left > 0 do
        case credits_fake_mode(prefix <> Int.to_string(left - 1)) do
          _ -> true
        end
      else
        false
      end
      None -> false
    end
  end
end

fn signed(value :: CreditIssueRequest) -> Bytes!String do
  let quote = Bytes.to_hex(value.quote_id)
  let hash = Bytes.to_hex(credits_blinded_hash(value)?)
  must(File.append(file("hits-" <> quote), hash <> "\n"), "fake append failed")?
  let stored = text("batch-" <> quote)
  if stored != "" && stored != hash && text("issue-mode") != "reissue" do
    return Err("409")
  end
  let current = text("current")
  if Bytes.to_hex(value.token_key_id) != current do
    return Err("412")
  end
  let key = signing_key(current)?
  let signatures = sign_all(key, value.blinded, List.new())?
  credits_fake_write("batch-" <> quote, Bytes.from_utf8(hash))?
  if countdown("lose:") do
    return Err("500")
  end
  credits_encode_issue_response(CreditIssueResponse {
    quote_id: value.quote_id,
    token_key_id: value.token_key_id,
    signatures: signatures
  })
end

fn status_of(error :: String) -> Int do
  case String.to_int(error) do
    Some(status) -> status
    None -> 500
  end
end

fn issue_answer(value :: CreditIssueRequest) -> Response do
  let mode = text("issue-mode")
  if text("quote-" <> Bytes.to_hex(value.quote_id)) == "" do
    respond(404, Bytes.empty())
  else if countdown("pending:") do
    respond(202, Bytes.empty())
  else if mode == "expired" do
    respond(410, Bytes.empty())
  else if mode == "unpaid" do
    respond(402, Bytes.empty())
  else if mode == "down" do
    respond(503, Bytes.empty())
  else
    case signed(value) do
      Err(error) -> respond(status_of(error), Bytes.empty())
      Ok(body) -> respond(200, body)
    end
  end
end

fn handle_issue(request :: Request) -> Response do
  case credits_decode_issue_request(Request.body_bytes(request)) do
    Err(_) -> respond(400, Bytes.empty())
    Ok(value) -> issue_answer(value)
  end
end

fn handle_listing(_request :: Request) -> Response do
  respond(200, credits_fake_read("listing"))
end

actor credits_world() do
  HTTP.router()
    |> HTTP.on_post("/v1/credits/quote", handle_quote)
    |> HTTP.on_post("/v1/credits/issue", handle_issue)
    |> HTTP.on_get("/v1/credits/issuer-keys", handle_listing)
    |> HTTP.serve(credits_fake_port())
end

## Starts the fake world unless an earlier test in this run did.

pub fn credits_fake_start() do
  case Http.build(:get, credits_fake_url() <> "/v1/credits/issuer-keys")
    |> Http.timeout(500)
    |> Http.send() do
    Ok(_) -> nil
    Err(_) -> do
      spawn(credits_world)
      Timer.sleep(150)
    end
  end
end
