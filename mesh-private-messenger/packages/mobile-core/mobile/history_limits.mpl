##! One budget for history codecs and sealed storage. The eight-byte count
##! frame plus 256 bounded entry vectors covers every previously valid history.
##! Entries beyond 256 retain the existing rule: discard the oldest entries.

pub fn history_max_entries() -> Int do
  256
end

pub fn history_max_entry_bytes() -> Int do
  65600
end

pub fn history_max_plaintext_bytes() -> Int do
  8 + history_max_entries() * (4 + history_max_entry_bytes())
end

pub fn history_chunk_bytes() -> Int do
  60000
end

pub fn history_max_parts() -> Int do
  1 + (history_max_plaintext_bytes() + history_chunk_bytes() - 1) / history_chunk_bytes()
end

pub fn history_max_blob_bytes() -> Int do
  history_max_plaintext_bytes() + history_max_parts() * 128 + 1024
end
