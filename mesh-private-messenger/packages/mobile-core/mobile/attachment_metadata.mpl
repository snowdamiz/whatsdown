# Attachment filename/MIME admission only. No byte, digest or exact length release.
pub fn attachment_input_admitted(filename :: Plaintext<Bytes>,
  mime_type :: Plaintext<Bytes>,
  require_utf8 :: Bool) -> Bool do
  let bounded = Bytes.length(filename) <= 255
    && Bytes.length(mime_type) >= 1
    && Bytes.length(mime_type) <= 127
  let text_valid = if require_utf8 do
    Result.is_ok(Bytes.to_utf8(filename)) && Result.is_ok(Bytes.to_utf8(mime_type))
  else
    true
  end
  declassify(bounded && text_valid,
    "attachment native metadata admission exposes only whether filename is at most 255 bytes and MIME is 1..127 bytes, with valid UTF8 when the free request parser requires it; metadata bytes, exact lengths, derived digests, and unrelated private control remain private")
end
