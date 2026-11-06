# Inactive Braid fragment encoding

CBF1 is a development encoding for public Braid erasure chunks. Its codec is
implemented in `Session.BraidFragment`; active conversations do not send it.
It allocates no production capability or RAT version. The existing RAT4 format
is unchanged.

Parsing establishes canonical syntax and a matching configuration/session. It
does not authenticate a peer, acknowledge a ciphertext, establish erasure rank,
or authorize an epoch transition. A future coordinator must authenticate the
containing envelope and apply its state and epoch rules before committing any
progress.

All integers are unsigned big-endian. Every record starts with:

| Field | Bytes | Requirement |
|---|---:|---|
| Magic | 4 | ASCII `CBF1` |
| Profile | 1 | 1 |
| Kind | 1 | One of the values below |
| Configuration | 32 | Exact captured session configuration |
| Session | 32 | Exact captured session identifier |
| Negotiated Braid epoch | 8 | 1 through u64 maximum |

Kinds 0 and 4 end here, at exactly 78 bytes. Data kinds append original length
u16, width u16, index u16 and a 64-byte codeword, for exactly 148 bytes.

| Kind | Meaning | Original length | Required distinct indices |
|---|---|---:|---:|
| 0 | No fragment | — | — |
| 1 | Header and authenticator | 96 | 2 |
| 2 | Public vector | 1152 | 18 |
| 3 | Public vector with Ct1 acknowledgement | 1152 | 18 |
| 4 | Ct1 acknowledgement | — | — |
| 5 | First ciphertext | 960 | 15 |
| 6 | Second ciphertext and authenticator | 160 | 3 |

The width is always 64. Original length is fixed by the kind; callers cannot
select it. Every index from 0 through 65535 is syntactically valid, including
repair indices beyond the number of original words. The codec rejects unknown
kinds, other profiles, mismatched scope, epoch zero, truncation, trailing bytes,
wrong lengths and widths, and data appended to control records. The encoder
also rejects out-of-range indices and noncanonical control values: control
records have index zero and an empty word in the in-memory representation.

There is no Boolean acknowledgement field. Kind 4 represents an acknowledgement;
kind 3 couples one to a public-vector word. Their acceptance and emission need
authenticated coordinator state; the parser itself grants no acknowledgement
permission. Maximum epoch is representable, but checking whether a successor
exists belongs to the coordinator.

Words use the public `Binary.Erasure` GF(2^16) codec with polynomial `0x1100b`
and big-endian two-byte symbols. Consistent reconstruction is not authentication:
the recovered header or ciphertext still needs the existing Braid admission
checks. This profile does not claim Signal wire interoperability.

Scoped host tests compare encoding and decoding with seven independent wire
literals. They cover all truncated data lengths, malformed parameters and
controls, substituted scope, zero and maximum epochs, and index boundaries at
optimization levels 0 and 2. A payload mutation intentionally remains valid
syntax. Durable scheduling, composite encrypted headers, same-transaction key
consumption, native qualification and activation remain separate work.

`Session.BraidFragmentWords` connects this format to the public erasure codec.
`emit_braid_fragment` requires the exact carrier length for its kind and emits
one systematic or repair word. Controls require an empty carrier and index
zero. `recover_braid_carrier` takes the expected kind, configuration, session
and epoch, and at most 72 supplied fragments, counting duplicates toward that
input bound. It validates every fragment before reconstruction.

Identical duplicates add no rank; conflicting duplicates and inconsistent
surplus words refuse recovery. Fewer than the required distinct words returns
`None`. Successful reconstruction returns `Some(carrier)` without authenticating
it. The two vector kinds share carrier data, so they can be combined for
reconstruction; the return value supplies no acknowledgement information. The
coordinator must separately authenticate and handle the actual received kind.
Control kinds have no recoverable carrier and are rejected by this function.

Four helper test groups and two actual bilateral Braid carrier groups pass at
both optimization levels. The latter reconstruct all four public carriers from
repair-only CBF1 words before invoking the existing kernel; authenticated output
agreement passes and a reconstructed forged header still fails its MAC check.
