from Tests.LegacyAttachmentFixture import (
  LegacyAttachmentManifest,
  copy_legacy_fixture_manifest,
  legacy_fixture_chunk
)
import File
from Attachments.Protocol import (
  AttachmentManifest,
  generate_attachment_key,
  seal_manifest,
  seal_bound_chunk,
  open_bound_chunk
)
from Credits.ActionWire import CreditActionSubmission, encode_credit_action_submission
from Credits.Attachment import (
  CreditAttachmentGrant,
  encode_credit_attachment_grant,
  credit_attachment_action,
  verify_credit_attachment_receipt
)
from Credits.Issuer import CreditIssuerKey, encode_issuer_key
from Credits.Policy import issuer_epoch
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Credits.Wire import CreditToken, CreditFrame
from Objects.Grant import ObjectControl, encode_complete, encode_delete, mint_grant, encode_grant
from Storage.CreditIssuers import announce_credit_issuer, admit_credit_issuer
from Transparency.Merkle import (
  leaf_hash_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence

struct Reply do
  status :: Int
  body :: Bytes
end

fn public_legacy_metadata(value :: AttachmentManifest) -> LegacyAttachmentManifest do
  declassify(copy_legacy_fixture_manifest(value),
    "synthetic public legacy attachment fixture metadata only; no application disclosure")
end

fn exact(value :: Plaintext<Bool>) -> Bool do
  declassify(value, "synthetic public paid object fixture equality only; no application disclosure")
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn pair(name :: String) -> SigningKeyPair!String do
  let seed = case Env.get_secret_hex(name) do
    Err(_) -> return Err("proof signer missing")
    Ok(value) -> value
  end
  case Crypto.signing_from_secret(seed) do
    Err(_) -> Err("proof signer failed")
    Ok(value)
  end
end

fn post(base :: String, route :: String, body :: Bytes) -> Reply!String do
  let value = Http.build(:post, base <> route)
    |> Http.header("Accept-Encoding", "identity")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Authorization", "Bearer " <> Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", ""))
    |> Http.body_bytes(body)
    |> Http.timeout(15000)
    |> Http.max_response_bytes(1024)
    |> Http.send()
  let response = value?
  Ok(Reply { status: response.status, body: response.body_bytes })
end

fn put(base :: String,
  id :: Bytes,
  index :: Int,
  capability :: Bytes,
  body :: Bytes) -> Reply!String do
  let response = Http.build(:put, base <> "/v2/objects/#{Bytes.to_hex(id)}/parts/#{index}")
    |> Http.header("Accept-Encoding", "identity")
    |> Http.header("X-Object-Capability", Bytes.to_hex(capability))
    |> Http.body_bytes(body)
    |> Http.timeout(15000)
    |> Http.max_response_bytes(1024)
    |> Http.send()
  let value = response?
  Ok(Reply { status: value.status, body: value.body_bytes })
end

fn get(base :: String,
  version :: Int,
  id :: Bytes,
  index :: Int,
  capability :: Bytes) -> Reply!String do
  let response = Http.build(:get, base <> "/v#{version}/objects/#{Bytes.to_hex(id)}/parts/#{index}")
    |> Http.header("Accept-Encoding", "identity")
    |> Http.header("X-Object-Capability", Bytes.to_hex(capability))
    |> Http.timeout(15000)
    |> Http.max_response_bytes(65577)
    |> Http.send()
  let value = response?
  Ok(Reply { status: value.status, body: value.body_bytes })
end

# The public File API deliberately caps each operation at64KiB. Padded final
# ciphertext needs the same bounded two-write repair as the actual store.
fn repair_part(path :: String, wire :: Bytes) -> Result<(), String> do
  if Bytes.length(wire) <= 65536 do
    File.write_bytes(path, 0, wire, true)
  else
    File.write_bytes(path, 0, Bytes.slice(wire, 0, 65536)?, true)?
    File.write_bytes(path, 65536, Bytes.slice(wire, 65536, Bytes.length(wire) - 65536)?, false)
  end
end

fn part_path(root :: String, id :: Bytes, index :: Int) -> String do
  root <> "/large-#{Bytes.to_hex(id)}.#{index}"
end

fn scalar(pool :: PoolHandle, query :: String) -> String!String do
  Ok(Map.get(List.head(Pool.query(pool, query, [])?), "value"))
end

fn mint(secret :: borrow BlindRsaSecretKey,
  key :: CreditIssuerKey,
  service_key :: Bytes,
  now :: U64) -> CreditToken!String do
  let pending = blind_credit(key, service_key, now)?
  let signed = sign_credit_request(secret, key, pending.request)?
  finalize_credit(key, pending, signed)
end

fn submission(grant :: CreditAttachmentGrant,
  tokens :: List<CreditToken>) -> CreditActionSubmission!String do
  let body = encode_credit_attachment_grant(grant)?
  Ok(CreditActionSubmission {
    action: credit_attachment_action(grant)?,
    request_body: body,
    frame: CreditFrame { binding: Crypto.sha256(body), tokens: tokens }
  })
end

fn proof() -> Bool!String do
  let padded = Env.get("CREDIT_ATTACHMENT_LAYOUT", "2") == "2"
  let core_url = Env.get("CREDIT_ATTACHMENT_CORE_DATABASE_URL", "")
  let object_url = Env.get("CREDIT_ATTACHMENT_OBJECT_DATABASE_URL", "")
  let root = Env.get("MESSENGER_OBJECT_STORAGE_ROOT", "")
  let base = Env.get("CREDIT_ATTACHMENT_OBJECT_A", "")
  let other = Env.get("CREDIT_ATTACHMENT_OBJECT_B", "")
  let disabled = Env.get("CREDIT_ATTACHMENT_OBJECT_OFF", "")
  if !String.contains(core_url, "/attachments_core_test?")
    || !String.contains(object_url, "/attachments_object_test?")
    || !String.starts_with(base, "http://127.0.0.1:")
    || !String.starts_with(other, "http://127.0.0.1:")
    || !String.starts_with(root, "/") do
    return Err("paid attachment proof requires its disposable local PostgreSQL/HTTP harness")
  end
  let pool = Pool.open(core_url, 1, 4, 5000)?
  let store = Pool.open(object_url, 1, 4, 5000)?
  assert(post(base, "/v1/attachments/paid-grant", Bytes.empty())?.status == 400)
  assert(post(disabled, "/v1/attachments/paid-grant", Bytes.empty())?.status == 503)
  let rsa = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("proof RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(rsa) do
    Err(_) -> return Err("proof RSA public failed")
    Ok(value) -> value
  end
  let now_ms = wide(DateTime.to_unix_ms(DateTime.utc_now()))?
  let now = U64.divide(now_ms, wide(1000)?)?
  let signer = pair("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX")?
  let witness_a = pair("CREDIT_FIXTURE_WITNESS_A_SEED")?
  let witness_b = pair("CREDIT_FIXTURE_WITNESS_B_SEED")?
  let issuer = CreditIssuerKey {
    epoch: issuer_epoch(now)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: signer.public_key.bytes
  }
  let leaf = encode_issuer_key(issuer)?
  let announced = announce_credit_issuer(pool, leaf)?
  let tree = [leaf_hash_for(2, leaf)?]
  admit_credit_issuer(pool,
    TransparencyEvidence {
      entry_bytes: leaf,
      inclusion: compact_inclusion_proof_for(2, tree, 0)?,
      consistency: compact_consistency_proof_for(2, [], tree)?,
      checkpoint: announced.checkpoint,
      witnesses: [
        sign_witness("witness-a", witness_a.private_key, announced.checkpoint)?,
        sign_witness("witness-b", witness_b.private_key, announced.checkpoint)?
      ]
    })?
  let attachment_key = case generate_attachment_key() do
    Err(_) -> return Err("proof attachment key failed")
    Ok(value) -> value
  end
  let id = bytes("61", 32)?
  let expires = U64.add(now_ms, wide(518400000)?)?
  let manifest = AttachmentManifest {
    version: if padded do
      4
    else
      2
    end,
    attachment_id: id,
    chunk_size: 65536,
    chunk_count: 257,
    plaintext_size: 16777217,
    filename: Bytes.from_utf8("secret attachment.bin"),
    mime_type: Bytes.from_utf8("application/octet-stream"),
    expires_at: expires
  }
  let encrypted_manifest = case seal_manifest(attachment_key, manifest) do
    Err(_) -> return Err("proof manifest failed")
    Ok(value) -> value
  end
  let grant = CreditAttachmentGrant {
    layout_version: if padded do
      2
    else
      1
    end,
    operation_nonce: bytes("62", 32)?,
    object_id: id,
    upload_capability: bytes("63", 32)?,
    download_capability: bytes("64", 32)?,
    size_bytes: if padded do
      16842752
    else
      manifest.plaintext_size
    end,
    manifest_size: Bytes.length(encrypted_manifest),
    manifest_sha256: Crypto.sha256(encrypted_manifest),
    expires_at_ms: expires,
    action_expires_at: U64.add(now, wide(600)?)?
  }
  let paid_token = mint(rsa, issuer, signer.public_key.bytes, now)?
  let fresh = mint(rsa, issuer, signer.public_key.bytes, now)?
  let request = submission(grant, [paid_token])?
  let encoded = encode_credit_action_submission(request)?
  # Effect failure rolls back every nullifier and the hold in the same DB tx.
  Pool.execute(pool,
    "CREATE FUNCTION attachment_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'proof atomic grant failure'; END $$",
    [])?
  Pool.execute(pool,
    "CREATE TRIGGER attachment_fail BEFORE INSERT ON credit_attachment_objects FOR EACH ROW EXECUTE FUNCTION attachment_fail()",
    [])?
  assert(post(base, "/v1/attachments/paid-grant", encoded)?.status == 503)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "0")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_holds")? == "0")
  Pool.execute(pool, "DROP TRIGGER attachment_fail ON credit_attachment_objects", [])?
  Pool.execute(pool, "DROP FUNCTION attachment_fail()", [])?
  # A lost local commit leaves a real consumed central effect. Exact recovery
  # must reuse its receipt; another nonce for that object must roll back.
  Pool.execute(store,
    "CREATE FUNCTION attachment_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'proof lost object commit'; END $$",
    [])?
  Pool.execute(store,
    "CREATE TRIGGER attachment_fail BEFORE INSERT ON large_objects FOR EACH ROW EXECUTE FUNCTION attachment_fail()",
    [])?
  assert(post(base, "/v1/attachments/paid-grant", encoded)?.status == 503)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "1")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_action_effects")? == "1")
  assert(scalar(store, "SELECT count(*)::text AS value FROM large_objects")? == "0")
  let changed = encode_credit_action_submission(submission(%{grant |
      operation_nonce: bytes("65", 32)?
    },
    [fresh])?)?
  assert(post(other, "/v1/attachments/paid-grant", changed)?.status == 409)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_holds")? == "1")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "1")
  Pool.execute(store, "DROP TRIGGER attachment_fail ON large_objects", [])?
  Pool.execute(store, "DROP FUNCTION attachment_fail()", [])?
  let raced = Job.map([base, other],
    fn(url) do post(url, "/v1/attachments/paid-grant", encoded) end)
  let replies = for result in raced do
    result??
  end
  assert(List.length(List.filter(replies, fn(value) do value.status == 201 end)) == 1)
  assert(List.length(List.filter(replies, fn(value) do value.status == 200 end)) == 1)
  assert(Bytes.secure_equals(List.head(replies).body, List.get(replies, 1).body))
  verify_credit_attachment_receipt(request, signer.public_key, List.head(replies).body)?
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_attachment_objects")? == "1")
  assert(scalar(pool,
    "SELECT count(*)::text AS value FROM credit_holds WHERE consumed_at IS NOT NULL AND retain_until >= "
      <> U64.to_string(U64.add(U64.divide(expires, wide(1000)?)?, wide(604800)?)?))? == "1")
  assert(post(base, "/v1/attachments/paid-grant", changed)?.status == 409)
  # Mixed spent+fresh frame cannot strand the fresh token or create an object.
  let mixed_grant = %{grant |
    object_id: bytes("66", 32)?,
    operation_nonce: bytes("67", 32)?,
    size_bytes: if padded do
      33619968
    else
      33554433
    end
  }
  assert(post(base,
    "/v1/attachments/paid-grant",
    encode_credit_action_submission(submission(mixed_grant, [paid_token, fresh])?)?)?.status == 409)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "1")
  assert(scalar(store, "SELECT layout_version::text AS value FROM large_objects")? == if padded do
      "2"
    else
      "1"
    end)
  assert(scalar(store,
    "SELECT plaintext_size::text AS value FROM large_objects")? == Int.to_string(grant.size_bytes))
  assert(scalar(store,
    "SELECT manifest_size::text AS value FROM large_objects")? == Int.to_string(Bytes.length(encrypted_manifest)))
  if padded do
    assert(Bytes.length(encrypted_manifest) == 514)
    let old_manifest = case seal_manifest(attachment_key, %{manifest | version: 2}) do
      Ok(value) -> value
      Err(_) -> return Err("proof legacy manifest failed")
    end
    let old_chunk = case seal_bound_chunk(attachment_key, old_manifest, 0, bytes("71", 65536)?) do
      Ok(value) -> value
      Err(_) -> return Err("proof legacy chunk failed")
    end
    assert(put(base, id, 1, grant.upload_capability, old_chunk)?.status == 400)
  else
    let new_manifest = case seal_manifest(attachment_key, %{manifest | version: 4}) do
      Ok(value) -> value
      Err(_) -> return Err("proof padded manifest failed")
    end
    let new_chunk = case seal_bound_chunk(attachment_key, new_manifest, 0, bytes("71", 65536)?) do
      Ok(value) -> value
      Err(_) -> return Err("proof padded chunk failed")
    end
    assert(put(base, id, 1, grant.upload_capability, new_chunk)?.status == 400)
  end
  let control = ObjectControl { object_id: id, capability: grant.upload_capability }
  let completion = encode_complete(control)?
  assert(post(base, "/v2/attachments/complete", completion)?.status == 409)
  assert(get(base, 2, id, 0, grant.download_capability)?.status == 409)
  assert(put(base, id, 0, grant.upload_capability, encrypted_manifest)?.status == 201)
  assert(put(base, id, 0, grant.upload_capability, encrypted_manifest)?.status == 200)
  let last = case seal_bound_chunk(attachment_key, encrypted_manifest, 256, Bytes.from_utf8("x")) do
    Err(_) -> return Err("proof encrypt failed")
    Ok(value) -> value
  end
  let block = bytes("71", 65536)?
  for index in 0..257 do
    let plain = if index == 256 do
      Bytes.from_utf8("x")
    else
      block
    end
    let encrypted = if index == 256 do
      last
    else if padded || index % 2 == 0 do
      case seal_bound_chunk(attachment_key, encrypted_manifest, index, plain) do
        Err(_) -> return Err("proof bound encrypt failed")
        Ok(value) -> value
      end
    else
      case legacy_fixture_chunk(attachment_key, public_legacy_metadata(manifest), index, plain) do
        Err(_) -> return Err("proof encrypt failed")
        Ok(value) -> value
      end
    end
    assert(Bytes.length(encrypted) == if padded do
        65576
      else if index == 256 do
        41
      else
        65576
      end)
    assert(put(if index % 2 == 0 do
        base
      else
        other
      end,
      id,
      index + 1,
      grant.upload_capability,
      encrypted)?.status == 201)
  end
  assert(put(base, id, 257, grant.upload_capability, last)?.status == 200)
  let changed_last = case seal_bound_chunk(attachment_key,
    encrypted_manifest,
    256,
    Bytes.from_utf8("y")) do
    Err(_) -> return Err("proof encrypt failed")
    Ok(value) -> value
  end
  assert(put(base, id, 257, grant.upload_capability, changed_last)?.status == 409)
  assert(put(base, id, 258, grant.upload_capability, last)?.status == 404)
  assert(put(base, id, 257, grant.upload_capability, Bytes.from_utf8("bad"))?.status == 400)
  let last_path = part_path(root, id, 257)
  File.write_bytes(last_path, 0, Bytes.from_utf8("broken"), true)?
  assert(post(base, "/v2/attachments/complete", completion)?.status == 202)
  assert(scalar(store, "SELECT verify_index::text AS value FROM large_objects")? == "128")
  assert(get(base, 2, id, 0, grant.download_capability)?.status == 409)
  assert(post(other, "/v2/attachments/complete", completion)?.status == 202)
  assert(scalar(store, "SELECT verify_index::text AS value FROM large_objects")? == "256")
  assert(post(base, "/v2/attachments/complete", completion)?.status == 409)
  repair_part(last_path, last)?
  assert(post(other, "/v2/attachments/complete", completion)?.status == 200)
  assert(post(base, "/v2/attachments/complete", completion)?.status == 200)
  let downloaded = get(other, 2, id, 257, grant.download_capability)?
  assert(downloaded.status == 200 && Bytes.secure_equals(downloaded.body, last))
  assert(exact(case open_bound_chunk(attachment_key, encrypted_manifest, 256, downloaded.body) do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, Bytes.from_utf8("x"))
  end))
  # Genuine legacy objects retain ACH2/3. New LAG2 objects require ACH4.
  # Neither format is silently converted by the store.
  for index in 0..2 do
    let first = get(other, 2, id, index + 1, grant.download_capability)?
    assert(first.status == 200)
    assert(Bytes.get(first.body, 0) == Ok(if padded do
        4
      else if index == 0 do
        3
      else
        2
      end))
    assert(exact(case open_bound_chunk(attachment_key, encrypted_manifest, index, first.body) do
      Err(_) -> false
      Ok(value) -> Bytes.secure_equals(value, block)
    end))
  end
  assert(get(base, 2, id, 257, grant.upload_capability)?.status == 403)
  assert(get(base, 1, id, 0, grant.download_capability)?.status == 404)
  assert(scalar(store,
    "SELECT total_bytes::text AS value FROM large_objects")? == Int.to_string(Bytes.length(encrypted_manifest)
      + grant.size_bytes
      + 257 * 40))
  println("public paid layout="
    <> Int.to_string(grant.layout_version)
    <> " capacity_or_legacy_size="
    <> Int.to_string(grant.size_bytes)
    <> " manifest="
    <> Int.to_string(Bytes.length(encrypted_manifest))
    <> " actual_total="
    <> scalar(store, "SELECT total_bytes::text AS value FROM large_objects")?)
  let deletion = encode_delete(control)?
  assert(post(base, "/v2/attachments/delete", deletion)?.status == 202)
  assert(get(base, 2, id, 257, grant.download_capability)?.status == 410)
  assert(scalar(store, "SELECT purge_index::text AS value FROM large_objects")? == "128")
  assert(!File.exists(part_path(root, id, 127)))
  assert(File.exists(last_path))
  assert(post(other, "/v2/attachments/delete", deletion)?.status == 202)
  assert(scalar(store, "SELECT purge_index::text AS value FROM large_objects")? == "256")
  assert(!File.exists(part_path(root, id, 255)))
  assert(File.exists(last_path))
  assert(post(base, "/v2/attachments/delete", deletion)?.status == 204)
  assert(scalar(store, "SELECT count(*)::text AS value FROM large_objects")? == "0")
  # A valid retry after local deletion recovers the same authorization and
  # never recharges. Expiry cleanup is likewise bounded and idempotent.
  let recovered = post(base, "/v1/attachments/paid-grant", encoded)?
  assert(recovered.status == 201 && Bytes.secure_equals(recovered.body, List.head(replies).body))
  # Recover an already-queued delete through the real HTTP job endpoint.
  # Do not corrupt the receipt-bound expiry as the old fixture did. A separate
  # Store.Large fixture exercises expiry with an explicit future test clock.
  Pool.execute(store, "UPDATE large_objects SET deleting=1", [])?
  assert(post(base, "/internal/v1/jobs/objects", Bytes.from_utf8("0"))?.status == 200)
  assert(scalar(store, "SELECT purge_index::text AS value FROM large_objects")? == "128")
  assert(post(base, "/internal/v1/jobs/objects", Bytes.from_utf8("0"))?.status == 200)
  assert(scalar(store, "SELECT purge_index::text AS value FROM large_objects")? == "256")
  assert(post(base, "/internal/v1/jobs/objects", Bytes.from_utf8("0"))?.status == 200)
  assert(scalar(store, "SELECT count(*)::text AS value FROM large_objects")? == "0")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "1")
  # Two independent services race distinct actions with the same fresh token.
  # Exactly one entitlement commits; the other action/hold rolls back entirely.
  let race_token = mint(rsa, issuer, signer.public_key.bytes, now)?
  let grants = for marker in ["68", "69"] do
    let race_id = bytes(marker, 32)?
    let race_manifest = case seal_manifest(attachment_key, %{manifest | attachment_id: race_id}) do
      Err(_) -> return Err("proof race manifest failed")
      Ok(value) -> value
    end
    %{grant |
      object_id: race_id,
      operation_nonce: race_id,
      manifest_size: Bytes.length(race_manifest),
      manifest_sha256: Crypto.sha256(race_manifest)
    }
  end
  let races = Job.map([0, 1],
    fn(index) do post(if index == 0 do
        base
      else
        other
      end,
      "/v1/attachments/paid-grant",
      encode_credit_action_submission(submission(List.get(grants, index), [race_token])?)?) end)
  let raced_actions = for value in races do
    value??
  end
  assert(List.length(List.filter(raced_actions, fn(value) do value.status == 201 end)) == 1)
  assert(List.length(List.filter(raced_actions, fn(value) do value.status == 409 end)) == 1)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "2")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_holds")? == "2")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_attachment_objects")? == "2")
  # The maximum entitlement still costs31 despite a one-token request.
  let maximum_grant = %{grant |
    object_id: bytes("70", 32)?,
    operation_nonce: bytes("70", 32)?,
    size_bytes: 536870912
  }
  assert(post(base,
    "/v1/attachments/paid-grant",
    encode_credit_action_submission(submission(maximum_grant, [fresh])?)?)?.status == 400)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "2")
  # Legacy free grants retain their original proof-of-work and independent ID
  # space, even when a paid ID was previously used.
  let free = encode_grant(mint_grant(id,
    2,
    U64.add(now_ms, wide(60000)?)?,
    U64.add(now_ms, wide(30000)?)?,
    grant.upload_capability,
    grant.download_capability,
    4)?)?
  assert(post(base, "/v1/attachments/grant", free)?.status == 201)
  Pool.close(store)
  Pool.close(pool)
  println("PAID_ATTACHMENT_PROOF: streamed 16777217 bytes in 258 bounded parts; cross-process retry, rollback, recovery and 128-part cleanup passed")
  Ok(true)
end

test("paid attachments atomically authorize once and stream through independent object stores") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
