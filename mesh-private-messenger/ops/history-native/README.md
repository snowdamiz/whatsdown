# Native history response boundary

Run against a compiler and production runtime with bounded native exports:

```sh
python3 ops/history-native/prove.py \
  --compiler /absolute/path/to/meshc \
  --evidence-dir /absolute/path/to/evidence
```

The runner copies hash-pinned compiler, runtime and production source snapshots
into a fresh work folder. It selects the pinned runtime explicitly with
`MESH_RT_LIB_PATH`. It creates two real accounts and an authenticated direct session, then
stores 256 synthetic 32,768-byte messages using the production history codec,
chunked platform wrapping, and SQLite. Its C host calls the production
`load_visible_history` reader through generated exports. A default 1 MiB export
must refuse the response with status 6 and no returned buffer. The explicitly
bounded export must return exactly **8,404,488 bytes**, preserve every row ID,
timestamp, body and delivery state, and produce an identical repeat read.

Only the isolated fixture adds exports. Application exports and host callbacks
remain unchanged by this runner. Callback input/output and total secure-store
state stay bounded at 1 MiB. The host secure store is an in-memory test host;
this proves the native ABI, production cryptographic wrapping and database path,
not OS credential persistence or physical-device execution. Each run writes its
own `evidence.json`, source hashes, generated ABI manifest and log without resetting
an existing database. Default optimization is 2; `--opt-level 0` is also supported.
