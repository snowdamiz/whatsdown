from Tests.BackupArchiveViewIntegrationFixture import (
  view_request_proof,
  view_chunk_codec_proof,
  view_page_codec_proof,
  view_overview_codec_proof
)

test("content view request tags preserve legacy selectors and strictly admit bounded file chunks") do
  assert(view_request_proof() == Ok(true))
end

test("content native overview preserves distinct policy file counters and exact canonical fields") do
  assert(view_overview_codec_proof() == Ok(true))
end

test("content native message page matches exact slot framing and protected byte extent") do
  assert(view_page_codec_proof() == Ok(true))
end

test("content native chunk binds exact scope ordinal slot token and final byte length") do
  assert(view_chunk_codec_proof() == Ok(true))
end

from Tests.BackupArchiveViewIntegrationFixture import (
  view_guarded_roundtrip_proof,
  view_ciphertext_replacement_proof
)

test("guarded content overview page and exact selected chunks preserve the owned archive and current profile") do
  assert(view_guarded_roundtrip_proof() == Ok(true))
end

test("same content archive ciphertext replacement refuses old token and accepts fresh binding") do
  assert(view_ciphertext_replacement_proof(false) == Ok(true))
end

test("same content index ciphertext replacement refuses old token and accepts fresh binding") do
  assert(view_ciphertext_replacement_proof(true) == Ok(true))
end
