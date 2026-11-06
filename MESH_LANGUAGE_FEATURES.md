# Mesh language inventory and refactoring guide

Inventory date: 2026-09-23. Source: Mesh v0.1.3 (`ab32513`), the first
published release with the fixes the messenger relies on (list patterns,
`return` as an expression, tuple-aware exhaustiveness, the whitespace-preserving
formatter) and with pass-through match arms and callbacks that discard their
result. The messenger builds with the latest published Mesh release: `run.sh`
and CI resolve it on every run (`mesh-private-messenger/scripts/mesh-release.mjs`),
and a release build uses the revision its verification recorded. A compiler
feature can be used here once a release contains it.


Witness-network development (2026-10-08) additionally requires the unpublished
sibling Mesh changes for `Http.url_origin`, `File.sync`, `File.rename`, and five
compiler regressions (actor/helper inference, comprehension result types,
string-keyed map function values, ownership after returning branches, and
full-path import resolution for modules with the same final segment), plus
HTTP handling of empty HEAD and 204/205/304 responses carrying gzip metadata.
The unpublished public `mesh-solana` additions also include context-aware
atomic account batches and bounded keyed program-account discovery. Morse
dogfoods those APIs in custody reads and historical collectible-key resolution.
Rewards development (2026-10-20) additionally uses exact full-intermediate
`U64.multiply_divide` / `U128.multiply_divide` and UTC calendar
`DateTime.add_months`. The reward policy compares both implementations against
the same independent integer/calendar vectors. Attendance reads dogfood
`mesh-solana` sliced account batches, preserving one RPC context and full
allocation sizes while fetching bounded data.
The authenticated rewards reader also exposed a lexical block-scope bug: an
inner conditional or loop binding could overwrite an outer variable's type or
MIR value. Public Mesh now scopes each block in inference and lowering, with
debug/optimized regressions and the original reader shadowing retained as app
dogfood. This compiler fix is also unpublished.
Credit development additionally uses public Mesh BR1: strict RSA-PSS SPKI
parsing, blind/sign/finalize/verify, affine `BlindRsaSecretKey` and
`BlindRsaBlindingState`, and authenticated storage purposes 18 and 19. Pending
blinding state is sealed before issuance so an interrupted paid purchase can
recover the same token. Direct `Secret.destroy` now accepts built-in opaque
secret handles; aggregates and arbitrary resources remain excluded. Morse's
credit protocol tests exercise the public API, published RFC 9578 vectors and
sealed restart recovery. These APIs also remain unpublished.
The issuer additionally dogfoods `StorageKey.file(directory)` on Linux/macOS:
an opaque wrapping key backed by a private directory, process-safe nonce
reservations and durable atomic counter updates. It uses the same authenticated
storage format as native-host keys; it cannot detect an operator rolling back
both key and counter. See Mesh `docs/security/storage-key-file.md`.
Credit batches exposed the old 64 KiB builder ceiling. `BytesBuilder` now accepts
explicit capacities up to 1 MiB, with overflow leaving its content unchanged;
secret storage blobs retain their existing 64 KiB limit. Imported public return
types now carry reachable type-layout context across module boundaries without
re-exporting private fields or constructors. Payment parsing and mobile credit
storage use these fixes without redundant leaf-type imports.
Local proofs use that checkout. Production release verification and the exact
released compiler pin must be updated before these app changes ship.

Local service integration additionally uses the unpublished public Mesh
`HTTP.serve_on` / `HTTP.serve_tls_on` and `Ws.serve_on` / `Ws.serve_tls_on` APIs.
They accept an explicit IPv4 or IPv6 literal and a separate port, reject invalid
values without a wildcard fallback, and retain the existing server lifetime and
diagnostic behavior. The original APIs keep their existing wildcard defaults.
Morse uses the explicit variants in directory HTTP, mailbox WebSockets and the
privacy edge so owned local fixtures can bind to `127.0.0.1`. This does not change
the released compiler requirement for production deployment.

Backup recovery development (2026-10-23) adds public Mesh
`RecoveryCode.generate()` / `RecoveryCode.parse()`. Generation returns a fresh
opaque 256-bit secret and a deliberately disclosed canonical recovery String;
parsing restores an opaque owner. There is no exporter for existing keys.
Morse dogfoods these operations through `Backups.Recovery` and the actual fixed
Argon2id backup manifest/chunk protocol, including restore after original owners
are destroyed. Public compiled/affine tests and all 719 typechecker checks pass.
The displayed String has no prompt-erasure guarantee, and the checksum is not
account authentication. This remains unpublished development source, with UI,
portable export/import and matching native/release qualification still open.

Backup file development (2026-10-29) additionally adopts public Mesh
`File.read_bytes_v2` / `File.write_bytes_v2` with explicit quotas and the same
64-KiB per-call limit. Morse's maximum 16-MiB synthetic archive passes actual
encrypted-file write, readback and full restore with a 16,796,864-byte quota.
The final compiler/runtime candidate also passes namespace and free API calls;
missing interactive-runtime registrations for these APIs and RecoveryCode
were reproduced and fixed. The 11 public compiler/runtime/test/documentation
paths are adopted locally after 1,657 runtime tests, 713 end-to-end tests and
13 Solana test files pass. The stale fuzz lockfile is also repaired without
changing retained dependency versions; all fuzz targets compile with the lock
required, and the documentation site builds locally. Seven mechanical formatting
repairs are adopted and the whole-workspace formatting check passes. Platform-specific
release gaps remain explicit; this is not a published release.
Guarded backup integration, resource bounds and native/UI acceptance remain open.

Backup database development (2026-10-30) adopts public Mesh
`Sqlite.execute_values_v2` / `Sqlite.query_values_v2`, with explicit per-value
quotas from 1 through 33,554,432 bytes and a 64-MiB aggregate parameter budget.
Legacy SQLite and PostgreSQL limits are unchanged. The new calls work through
compiled Mesh and the interactive runtime, and reject private arguments/control.
Morse's canonical synthetic 16-MiB archive passes actual HCB2 sealing, storage
of the resulting 16,797,311 bytes, SQL close/reopen and full plaintext recovery.
A one-byte-smaller quota rejects replacement and preserves the first container.
The 14 public source paths are adopted after core/runtime/end-to-end checks,
public-package and fuzz checks, formatting/lint and a local documentation build.
The whole protected backup operations remain in isolated integration; native,
production and published-release qualification are still open.

Plaintext migration (2026-10-22) additionally dogfoods public Mesh
`Plaintext<T>`, checked encryption/storage exits, reviewed `@display` exports,
and source-hashed disclosure reports. The qualified successor adds
`declassify_discriminant(result, "reason")`: it reviews only the `Result` tag,
preserving payload labels, prior/caller control and affine ownership. It is a
runtime identity, including pipe forms. Application code must review the raw
encryption result before matching it; reviewing a result after branching on
private data cannot erase that control dependency. Morse's adopted development
attachment manifest and initial handshake exercise this boundary. The same compiler fixes
qualified module calls shadowed by local closures and shorthand constructor
arms that falsely retained an unreachable variant's private payload. Exact
qualification and adoption status are in `WITNESS_NETWORK_PLAN.md`; the compiler
and full application migration are not a published release.

Wallet performance qualification (2026-10-22) additionally adds public
`meshc test --opt-level 0..3`, retaining debug `0` as the default and preserving
test-only fixtures and assertion failures at release `2`. The scoped compiler
change passes 73 compiler unit tests, 56 tooling tests and three Morse runtime
tests at explicit optimization `2`. Its frozen executable is
`ca50900d0926acd5c76b50ddd42a1b48712f23f71587c8e386fbe937a42ed6d9`;
the sibling checkout's `.morse/witness-proof/test-optimization/manifest.json`
records the exact sources and results. This option alone does not establish a
maximum-wallet memory bound; the separately qualified workload and development
adoption are recorded below.

The adopted development wallet also dogfoods public
`Bytes.concat_many(parts :: List<Bytes>, maximum :: Int) -> Bytes!BytesError`.
It preflights the full extent, copies parts in order into one output buffer, and
treats the limit as a bound rather than reserved storage. Immutable views,
aliases and private dependencies remain intact; the `BytesBuilder` ceiling is
unchanged. Twenty focused Morse tests and its full host build pass with the same
32 reviewed disclosures and 162 exports. The initial joined-buffer candidate
still exceeded the 512 MiB sampled host RSS bound. A subsequent public runtime
fix enables safe-point collection in native-thread library calls, preserving
coroutine-origin synchronous behavior, child loans and output-copy ordering.
The unchanged actual FFI maximum-wallet workload now passes in 26.892 seconds
at 315,277,312 bytes sampled peak RSS. Fresh five-target libraries, iOS/Android
ACH3 and funded upload proofs, all three development host builds and native
inventory checks pass. The guarded development adoption retains 32 reviewed
sites and the same 162 exports. The current adopted app regression is now
qualified with the documented fixture successors; public Mesh publication and
the exact release dependency pin remain separate gates. Exact scope, source
pins and prior failures are recorded in `WITNESS_NETWORK_PLAN.md`.

BTC conversion development additionally dogfoods public
`Crypto.hmac_sha512_tag(key :: borrow SecretBytes, message :: Bytes)` returning
`Bytes!CryptoError`. It emits the 64-byte public authentication tag without
exporting the opaque key, with 64 KiB input bounds and repeated borrowing.
Morse's isolated Kraken request builders pass the published Spot signature
vector and an independent Funding v1 query/body vector at optimization 0 and 2.
The host qualification passed 4,549 workspace tests with 27 explicitly ignored
environment/timing gates. Its 1,030-record source/tool/evidence manifest is the
sibling checkout's `.morse/witness-proof/hmac-sha512-tag-host/manifest.json`
(SHA-256 `7d0e58bb292990544e0a100161911cbc93e4a115cb3278e9c80b15b4c52980d5`).
Existing unrelated repository formatting findings and public/multiplatform
release gates remain open. This isolated host toolchain does not replace native
app runtime pins. The pure signing proof is complemented by the adopted default-off
BTC adapter's 3,081-record local archive,
`.morse/witness-proof/btc-conversion-adapter/manifest.json` (SHA-256
`f27daaed3626717bec3c8e119ccd492e126352eb767bd7e59bdde4bad8ca53fe`).
It exercises the same opaque-key API through persisted nonce allocation,
authenticated owned Kraken request fixtures and actual regtest Lightning/SPL
outputs. This qualifies local application behavior; live Kraken acceptance,
independent providers and public Mesh publication remain separate gates.

The combined treasury proof exposed a public HTTP persistence defect: a
length-delimited HTTP/1.0 response could return a nonpersistent socket to the
connection pool before its delayed close. Mesh now vendors the narrowly patched
locked `ureq-proto` 0.5.3 dependency, preserving HTTP/1.1 reuse and explicit
HTTP/1.0 keep-alive while giving `Connection: close` precedence. Deterministic
two-POST tests reproduce the old failure and pass at optimization 0 and 2; no
request retry or pooling disable is added. Both root and fuzz workspaces resolve
the same reviewed source. The final 1,120-record host qualification is
`../mesh-lang/.morse/witness-proof/http10-response-persistence-host/manifest.json`
(SHA-256 `a657ec10995268fc602384e03590abe727c310d555649c8f6826d330687bbf77`).
All 66 owned file bodies and eight existing baselines were independently checked.
The workspace passes 4,555 tests with 27 existing ignores, plus two doc tests;
179 protocol, four runtime and seven generated HTTP checks pass. Workspace build,
four fuzz binaries and 13 public Solana test files also pass. Six unchanged
preexisting Rust formatting findings remain outside this change.

Morse dogfoods the fixed host runtime in the 47-outcome common BTC/SOL bank proof
and its current optimized issuer build, recorded respectively in
`.morse/witness-proof/treasury-conversions-common-bank-final/manifest.json`
(`b28b9d5daa4ef358b41ee34f767dbe0c8b6b0045ea32b4792e2695a17043ef25`)
and `.morse/witness-proof/treasury-conversions-http-adopted/manifest.json`
(`5eeb9dd816c0d4f74f7c724c9e6e576217840a4d795f6ec9861c901a680bc2c6`).
This qualification does not change native/default compiler pins or publish a
Mesh release; owned local banks do not establish production finality.

This is an inventory of language constructs, library capabilities, and tools.
The linked references own individual API signatures and limits. Compiler
registrations and executable tests resolve gaps in the prose documentation.

## Refactoring rules for this repository

- Use the simplest supported construct that expresses the behavior. Features
  are options, not a quota: do not add interfaces, actors, generics, or a query
  abstraction just to demonstrate them.
- Prefer `?` for propagation and guard returns for rejection before the main
  path. Preserve the exact error classification and cleanup on every exit.
- Use tuple/constructor patterns to unpack values; use struct updates when
  most fields are unchanged. Keep protocol validation and canonical encoding.
- Use comprehensions, `List` operations, or `Iter` for ordinary collections.
  Keep explicit state threading for resource ownership and binary readers.
- Split modules by responsibility and dependency direction. Export only what
  another module needs; keep mobile ABI entrypoints stable.
- Preserve `borrow`/`consume` contracts. An early return must not skip an
  explicit SQLite close, rollback, file cleanup, or state-preserving rejection.
- Keep typed binary database values. `deriving(Row)` decodes string maps and
  does not replace the `DbValue`/`Bytes` contract of these services.
- Use existing Mesh tooling before writing another formatter or parser.
- Start bug fixes with a failing behavioral regression. Refactor against
  passing tests, then run formatting, compilation, and the affected proofs.

## Features applied in this refactor

- `Mobile.Requests` uses `?` and two shared boundary-error adapters to keep
  binary decoding linear while retaining each API’s error messages.
- Directory device, delivery, and outbox decoding use comprehensions instead
  of recursive index/accumulator builders. Device snapshots use struct updates.
- Object-store handlers and mobile record writes use closures around explicit
  connection and transaction scopes, keeping close/rollback behavior in one place.
- Ratchet transitions use small `consume` helpers to reduce nesting while
  returning the original state on rejection and disposing of candidate secrets.
  Group decryption validates and opens through a `borrow` helper with `?`, then
  updates replay state only after success.
- Result remapping writes the success arm as a pass-through (`Ok(value)`)
  instead of `Ok(value) -> Ok(value)`; callbacks return their value without a
  `let _ =` discard.
- Protocol, group, and mobile code use explicit modules and selective imports.
  `mobile_core.mpl` contains the existing native ABI entrypoints; `mobile/`
  contains domain operations and `storage/` contains persistence.

## Source, values, and expressions

| Feature | Surface and application |
| --- | --- |
| Source modules | `.mpl` files; file paths map to PascalCase module paths. Explicit `module Name do ... end` and `pub module` are supported. |
| Entrypoint | `main.mpl` by default; `[package].entrypoint` can choose another file. |
| Imports | `import Foo.Bar` for qualified use; `from Foo.Bar import name, other` for selected public names. Parenthesize a multiline import list. |
| Visibility | `pub` exports functions, modules, structs, interfaces, supervisors, sum types, and aliases. Ordinary functions/types default to private; actors and services are exported without a `pub` modifier. |
| Comments | `#` line, `##` declaration documentation, `##!` module documentation, and nested `#= ... =#` block comments. |
| Statements | Significant newlines or `;`; delimiters and pipes permit continuation. |
| Identifiers | Unicode alphabetic or `_` first character; subsequent Unicode alphanumeric characters or `_`. Keywords match exact ASCII spelling. |
| Bindings | Immutable `let`, inferred types, optional `:: Type`, `_` for ignored values, shadowing, tuple destructuring. |
| Integers | Decimal, binary `0b`, octal `0o`, hexadecimal `0x`, and `_` digit separators. |
| Other scalars | Decimal/scientific floats, `true`/`false`, `nil`/`()`, atoms such as `:ready`. |
| Text | Escaped strings; interpolation with `#{expression}` (preferred) or `${expression}`; multiline `"""heredocs"""`. |
| Regex literals | `~r/pattern/ims`, including multiline patterns; `i`, `m`, `s` flags. |
| Collections | Lists `[a, b]`, tuples `(a, b)`, maps `%{key => value}`; immutable collection operations. |
| Records | `Type { field: value }`; `%{existing | field: replacement}` for updates. |
| JSON literals | `json { key: expression }` produces structured `Json`; compatible with APIs taking encoded JSON strings. |
| Blocks | The final expression supplies the value; standalone `do ... end` blocks can group statements where an expression is required. |
| Arithmetic | `+`, `-`, `*`, `/`, `%`, unary `-`; checked ordinary integer arithmetic and explicit `Checked`/wide-integer APIs. |
| Comparison | `==`, `!=`, `<`, `>`, `<=`, `>=`; built-in interface dispatch. Tuples, unit, `Option`, `Result`, `Ordering`, lists, maps, and sets compare by contents; tuples, `Option`, `Result`, and `Ordering` also order and print. |
| Logic | `and`/`&&`, `or`/`\|\|`, `not`/`!`; short-circuit boolean expressions. |
| Concatenation | `<>` for strings; `++` for lists. Use `Bytes`/`BytesBuilder` for binary data. |
| Pipes | `value \|> f(args)` inserts the first argument; `\|N>` inserts at position N, starting at 2. Leading/trailing multiline pipes are supported. |
| Chaining | Calls, field access, method calls, and postfix `?` can be chained. |

## Types and ownership

| Feature | Surface and application |
| --- | --- |
| Primitive values | `Int`, `Float`, `Bool`, `String`, `Bytes`, `Json`, `Atom`, `Regex`, Unit. |
| Wide integers | `U64`, `U128`, `I128`; construct, compare, convert, and calculate through checked module functions. |
| Product types | Named-field structs, generic structs, and tuples. |
| Sum types | `type Name do Variant ... end`; nullary, positional, or named payloads; qualified constructors are supported. |
| Optional/result types | `Option<T>` or `T?`; `Result<T, E>` or `T!E`. Constructors: `Some`, `None`, `Ok`, `Err`. |
| Collection types | `List<T>`, `Map<K, V>`, `Set`, `Queue`, `Range`; `Set` and `Queue` currently carry integers. A range literal `a..b` is a `Range` value anywhere, not only in a `for` header. |
| Function types | `Fun(A, B) -> R`, including zero-argument functions. A struct field of function type is called directly: `op.run(10)`. |
| Process types | `Pid<M>` checks mailbox message types; untyped `Pid` is an escape hatch. |
| Ordering | `Ordering` with `Less`, `Equal`, `Greater`. |
| Aliases | Transparent `type Name = Type`, generic aliases, and `pub type`. Use for repeated meaningful shapes, not stronger validation. |
| Inference | Hindley–Milner-style inference and generic generalization; annotate public boundaries and ambiguous expressions. |
| Resource declarations | `resource Name` and `resource struct Name do ... end`; resource-containing values are affine. |
| Ownership parameters | `value :: borrow T` reads without transferring ownership; `consume T` transfers ownership. Ordinary resource assignment/parameters move values. |
| Resource cleanup | Compiler-inserted destruction on scope exits; explicit secret destruction is available. Preserve resource-bearing state on recoverable rejection. |
| Resource restrictions | Secrets/resources cannot be printed, derived into ordinary serializers, compared as ordinary values, stored in unrestricted collections, or sent to another actor/node. Resource closure capture is restricted. |
| Secret state | `SecretBytes`, private-key resources, `AeadKey`, `StorageKey`, bounded `SecretMap`, and aggregates containing them. Persist only authenticated wrapped blobs. |
| Database ownership | `PgConn` is affine; transactions and operations borrow it. `SqliteConn` still requires explicit connection/transaction cleanup. |

## Functions, matching, and control flow

| Feature | Surface and application |
| --- | --- |
| Named functions | `fn` or synonymous `def`, with a `do ... end` body. |
| Expression functions | `fn double(x) = x * 2`; useful for small pure helpers. |
| Generics | Explicit `<T, U>` and inferred polymorphism; `where T: Interface` bounds. |
| Function clauses | Consecutive same-name/arity clauses dispatch on parameter patterns and optional `when` guards. Different arities are separate overloads. |
| Recursion | Forward references and mutual recursion. Direct self calls in tail position become loops; mutual or non-tail recursion does not. |
| Closures | Parenthesized or bare parameters, zero-argument closures, `-> ... end` or multiline `do ... end`, lexical capture, multi-clause closures with guards. A `let`-bound closure is as polymorphic as a named function, and a closure can stand alone as a statement or tail expression. |
| Calls | Positional arguments, trailing closures, and trailing keyword arguments collected into one final map. Positional arguments must come first. A function passed where a `Fun(...) -> ()` callback is expected may return anything; its result is discarded, so no `let _ =` wrapper is needed. |
| Early exit | `return expression` or Unit `return`. `return` is an expression, so a match arm can be `Err(_) -> return ...` directly, including in a value-producing `case`. |
| Conditionals | Expression-valued `if ... else if ... else ... end`; use an omitted `else` only when discarding the value. |
| Matching | `case` and `match`; exhaustive coverage is enforced, redundant arms diagnosed. Guarded arms need an exhaustive fallback. An arm with no `->` passes its match through, rebuilt at the `case`'s type: `Ok(value)` means `Ok(value) -> Ok(value)`, which is what an arm needs when another arm maps the error. |
| Basic patterns | `_`, binding names, positive/negative numeric literals, strings, booleans, `nil`, tuples, qualified/unqualified constructors and payloads. |
| List patterns | `head :: tail` for a nonempty list; `[]` and `[first, second]` match a list of exactly that length, element by element. `[]` with `head :: tail` is exhaustive. The row-count idiom is `case rows do [] -> ... [row] -> ... _ -> Err(...) end`. |
| Compound patterns | `left \| right` (same bindings on both sides), `pattern as whole`, optional `when` guards. |
| Propagation | `expression?` unwraps `Ok`/`Some`; returns `Err`/`None` from the enclosing function. `From` can convert a propagated error. |
| Comprehensions | `for value in source when predicate do expression end` returns a list. Sources: end-exclusive ranges, lists, maps, sets, custom iterable implementations. A tuple pattern in the header destructures each element: `for (key, value) in pairs when key > 1 do ... end`. |
| Map iteration | `for {key, value} in map do ... end`. |
| Loops | `while ... do ... end` returns Unit; `break` and `continue` apply to loops. Bindings remain immutable. |
| Eager collection functions | `List.map`, `filter`, `reduce`, `find`, `any`, `all`, and other collection operations replace manual index/accumulator traversal where appropriate. |
| Lazy iteration | `Iter.from(list)`, `map`, `filter`, `take`, `skip`, `enumerate`, `zip`; terminals `count`, `sum`, `any`, `all`, `find`, `reduce`. |
| Collection from iterators | `List.collect`, `Map.collect`, `Set.collect`, `String.collect`. |
| Custom iteration | Implement `Iterator` with `Item`, and `Iterable` with `Item`/`Iter`. |

## Interfaces, conversion, and generated implementations

| Feature | Surface and application |
| --- | --- |
| Interfaces | `interface Name<T> do ... end`; required/default methods, instance/static methods, associated types. |
| Implementations | `impl Interface for Type`; methods and associated types must match; duplicate/ambiguous implementations are rejected. |
| Arithmetic interfaces | `Add`, `Sub`, `Mul`, `Div`, `Mod`, `Neg`, with associated `Output`. |
| Comparison/logic | `Eq`, `Ord`, `Not`. |
| Presentation/identity | `Display`, `Debug`, `Hash`, `Default`. |
| Conversion | `From` generates the corresponding `Into`; `TryFrom` generates `TryInto`. Use typed errors rather than discarding failure information. |
| Serialization interfaces | Generated `ToJson`, `FromJson`, `FromRow`, schema metadata. |
| Selective deriving | `deriving(...)` selects implementations; `deriving()` selects none. |
| Struct derives | `Eq`, `Ord`, `Display`, `Debug`, `Hash`, `Json`, `Row`, `Schema`; `Ord` requires `Eq`. |
| Sum-type derives | `Eq`, `Ord`, `Display`, `Debug`, `Hash`, `Json`; row/schema derives are not for sum types. |
| Legacy default derives | Omitted deriving gives structs `Debug`, `Eq`, `Ord`, `Hash`; sums get `Debug`, `Eq`, `Ord`. `Display`, `Json`, `Row`, `Schema` require selection. Resource restrictions still apply. |
| Row/schema support | Row conversion validates supported scalar/optional fields; schema metadata describes tables, keys, fields, and relationships for PostgreSQL ORM APIs. |

## Concurrency, services, and distribution

| Feature | Surface and constraints |
| --- | --- |
| Actors | `actor`, typed `spawn`, `send`, actor-local `self()`, isolated mailboxes. Check `send`'s returned status where delivery matters. |
| Receiving | `receive ... after timeout ... end`; use one receive arm and dispatch with `case`, because current native code generation only executes the first receive arm. |
| Actor lifecycle | Failure links, `terminate` cleanup, one-way `Process.monitor`/`demonitor`; monitors belong to their creating actor. |
| Services | `service` with initialization, calls and casts, state transitions, generated client functions. |
| Supervision | `supervisor`, child specifications, restart policies and rate limits; one-for-one, one-for-all, and rest-for-one strategies. |
| Jobs | `Job.async`, `await`, `await_timeout`, `map`; results preserve failures. A timeout does not cancel the job; await from its originating actor. |
| Timers | Scheduler-aware sleep and delayed typed messages using monotonic deadlines. |
| Channels | Item/byte-bounded integer queues, nonblocking producers, receive timeout, depth/drop counters; reject-newest, drop-oldest, latest-only policies. |
| Local registry | `Process.register`, `whereis`; missing names/failures have explicit sentinel values. |
| Shutdown | Signal installation, shutdown request/inspection, native process exit, draining HTTP servers. |
| Remote processes | Node bootstrap/connectivity, remote actor operations, node monitoring, global registration. |
| Cluster work | `@cluster` or `@cluster(N)` on a uniquely named public function; default replication count is 2. `HTTP.clustered` exposes declared work through a route. |
| Cluster runtime | Membership/identity, admission, routing, continuity/replay policy, capacity management, bounded operator telemetry. Configuration remains explicit. |

## Built-in module inventory

Every name in the compiler's `STDLIB_MODULE_NAMES` registry is included below.
This includes source APIs omitted by the website's summary, such as `Host`,
`BytesBuilder`, and the secret-storage modules.

| Modules | Capabilities |
| --- | --- |
| `String`, `Regex` | Text manipulation, search, splitting/joining, numeric conversion, regular expressions. |
| `List`, `Map`, `Set`, `Tuple`, `Range`, `Queue`, `Iter` | Immutable collections, lookup/transformation/reduction, ranges, lazy pipelines, collection. |
| `Int`, `Float`, `Math`, `Checked` | Numeric conversion and math; checked arithmetic, fixed-point rescaling, explicit rounding. |
| `U64`, `U128`, `I128` | Wide parsing, comparison, checked arithmetic, conversion, decimal formatting. |
| `Bytes` | Bounded binary construction/slicing/concatenation, constant-time equality, UTF-8 validation, integer reads/writes, hex/base64/base58 encoding. |
| `BytesBuilder` | Bounded affine binary builder; write bytes and unsigned fields, then consume with `finish`. |
| `Json`, `JSON`, `Base64`, `Hex` | Structured JSON parse/access/encode and text encodings; `Json`/`JSON` are the same family. |
| `IO`, `Env`, `File` | Console and environment access, secret environment ingestion, filesystem operations, bounded binary range I/O. |
| `DateTime`, `Monotonic`, `Duration` | Wall-clock dates/timestamps, elapsed time, checked duration conversions. |
| `Random` | Deterministic state-threaded random streams; never key generation. |
| `Crypto` | OS randomness, SHA-256/512, HMAC/HKDF, Argon2id, X25519, Ed25519, public Edwards25519 curve membership, ChaCha20-Poly1305, HPKE including secret payloads, ML-KEM-768, BR1 blind RSA, UUIDs. |
| `Secret`, `SecretMap` | Move-only random/derived material, explicit destruction, bounded secret collections with independent `SecretMap.fork` candidates, authenticated storage wrapping. |
| `StorageKey`, `X25519PrivateKey`, `SigningPrivateKey`, `MlKemPrivateKey`, `BlindRsaSecretKey`, `BlindRsaBlindingState` | Platform/ephemeral storage keys and typed private-key or blinding-state sealing/unsealing; context/purpose binding. BR1 issuance operations are available on Linux/macOS; clients and state recovery also compile for mobile. |
| `Host` | Native callbacks for secure storage, push tokens, background scheduling, network state, clocks, redacted logs. |
| `Job`, `Timer`, `Channel`, `Process` | Jobs, scheduling, bounded queues, registries, monitors, process/shutdown management. |
| `Test` | Test-owned actors, secure-store/push fixtures, and test runtime helpers; test-only builtins are rejected in production builds. |
| `HTTP`, `Request` | HTTP routing, middleware, text/binary responses, parameters/headers/body access, serving and shutdown. |
| `Http` | Outbound HTTP builders, bounded response bodies, streaming, cancellation, keep-alive clients, retries and metrics. |
| `Ws`, `WsClient` | Inbound/outbound WebSockets, callbacks, typed messages, rooms/broadcasts; inbound source-level TLS is unavailable. |
| `Sqlite`, `Pg`, `Pool` | Embedded SQLite and PostgreSQL connections/pools, parameterized queries, typed `DbValue` binary/text/null values, explicit or scoped transactions. |
| `Orm`, `Expr`, `Query`, `Repo` | PostgreSQL schema/query/expression construction, repository reads/writes, transactions, explicit SQL escape hatches. |
| `Changeset`, `Migration` | Typed data validation/change application and migration lifecycle. |
| `Node`, `Global`, `Continuity`, `Cluster` | Distributed actors/names, runtime-owned work routing, continuity and cluster operations. |

Database support also includes PostgreSQL-specific types/operators, row
conversion, filtering, ordering, joins, projections, aggregate queries,
pagination, changesets, and migration management. Keep fixed, parameterized SQL
when a higher-level API does not express locking, binary values, or atomicity.

## Native integration, packages, tests, and tools

| Feature | Surface and constraints |
| --- | --- |
| Native imports | `@native("c_symbol")` on a public, concrete, bodyless function with fully annotated parameters/return in a manifest-listed bindings file. |
| GC aggregate layout | Mixed sum payloads use aligned, zero-initialized machine words so nested live pointers survive conservative collection. The relay scheduler dogfoods optimized native admission and recovery under allocation pressure. Rebuild compiled libraries with the fixed compiler; see Mesh `docs/gc-value-layout.md`. |
| Native ABI 1 | Scalars `Int`, `Float`, `Bool`, `String`, `Bytes`, `U64`, `U128`, `I128`; optional/result returns over supported payloads. No arbitrary struct/collection/closure ABI. |
| Library exports | `@export("symbol")` with a Mesh body; messenger boundary uses `Bytes -> Bytes ! String`. Static/dynamic library builds generate C, Swift, Kotlin/JNI and TypeScript bindings. |
| Cross-compilation | Exact target triple, compatible LLVM/linker/runtime archives; compiler target selection does not install platform SDKs. |
| Dependencies | Manifest source/git/path/registry/native packages, lockfiles and checksummed exact-target native archives; packages do not execute build scripts. |
| Official packages | `mesh-binary` (bounded binary codecs, used here), `mesh-borsh`, `mesh-anchor`, `mesh-solana` (RPC/account/unsigned transaction tooling; no signing/submission). Morse's anchor reader uses its bounded account slices, context slots, public PDA derivation and typed block-time requests. The custody reader dogfoods atomic account batches with minimum context slots and explicit optional accounts. The relay discovers active and unbonding historical keys through context-aware bounded program-account queries and whole-set RPC agreement, reads the typed Clock sysvar for age admission, and emits unsigned ATA/settlement instruction reports. Its lookup-table lifecycle instructions and finalized recovery reader use `Solana.LookupTable`; its closure decision quorum dogfoods the public `Solana.SlotHashes` decoder and `lookup_table_status`, preserving full-width slots and the SDK cooldown rule. |
| Test DSL | `.test.mpl`, `test`, `describe`, scoped `setup`/`teardown`, `assert`, `assert_eq`, `assert_ne`, `assert_raises`, `assert_receive`. |
| Private test support | Sibling `*.test-support.mpl` fragments are merged for tests and excluded from production builds. |
| Secure test fixtures | In-memory secure store and push token fixtures use the production host callback frames; cleaned between tests. |
| Build/init/deps | `meshc build`, `init`, `deps`; native binaries, libraries, optional LLVM IR, JSON diagnostics, target/optimization selection. |
| Formatting | `meshc fmt PATH`, `--check`, `--line-width`, `--indent-size`; shared formatter also serves the LSP. |
| Linting | `meshc lint PATH`: control flow nested more than four levels, an `else` holding only an `if`, arms that repeat their pattern, comparisons with `true`/`false`. CI runs it over `mesh-private-messenger` and fails on any finding. |
| Test runner | `meshc test PATH`, project/directory/file selection, `--quiet`; coverage is explicitly unsupported. |
| Interactive/editor | LLVM-backed `meshc repl`, `meshc lsp`, VS Code and Neovim support. |
| Operations | `meshc migrate`, `cluster`, `proof`, `update`. |
| Registry CLI | `meshpkg login`, `search`, `install`, `publish`, `update`. |

## Limitations to check before adopting a feature

- Reserved words `alias`, `cond`, `trait`, `trap`, and `with` do not implement
  those language constructs. Use imports, conditionals, interfaces, results,
  and actor lifecycle APIs instead.
- There are no glob imports or struct-field patterns.
- Plain module imports are addressed by their final path component. Two plain
  imports cannot bind different modules to the same namespace. Selective
  `from ... import ...` imports resolve their full paths and may share a final
  module segment; gossip dogfoods this with `Mobile.Gossip` and `Transparency.Gossip`.
  Missing dotted imports cannot silently resolve to a standard module with the
  same final segment.
- Public functions currently keep unqualified native symbols. The compiler
  rejects two modules defining the same public function name, even with
  qualified source calls. Shared helpers use distinct `protocol_`
  and `group_` names until Mesh supports qualified native symbols.
- Types in an imported function's signature must be available to the consuming
  module. The current local compiler preserves reachable public return-type
  layouts across imports; older released compilers may still require importing
  the defining type module when inspecting a returned record.
- Qualified nullary variants currently fail native lowering in some contexts.
  When two imported enums share a constructor name, construct it in its defining
  module rather than depending on import order.
- Collection subscript syntax is a parser placeholder, not a supported
  executable operation. Use `List.get`, `Map.get`, or JSON accessors.
- `Iter.from` starts from lists; `for` has a broader iterable surface.
- `Set`, `Queue`, and `Channel` have integer payload limits; ordinary containers
  cannot hold secrets. Use `SecretMap` for supported secret collections.
- Ownership after a returning branch follows the paths that can reach the next
  statement. Loop `break`/`continue` paths remain conservative; use explicit
  state threading for those resource transitions rather than bypassing checks.
- Resource captures in closures and cross-actor transfers are restricted.
  Do not weaken ownership just to fit a collection combinator.
- Tail-call elimination covers direct self tail calls only.
- In a closure, `?` exits that closure; directly in a function it exits the
  function. A plain block does not create a cleanup/propagation boundary.
- Guard function calls must use an unqualified function name; qualified calls
  such as `String.contains(...)` are rejected in guards by this compiler.
- SQLite is local storage; shared multi-node persistence needs PostgreSQL.
- A `Row` derive accepts supported string-map fields, not arbitrary binary rows.
- Native `receive` currently runs only its first arm. Always dispatch inside it.
- `Channel.recv` is a synchronous bounded wait; keep waits short on actors.
- Native packages require an archive for the exact target; no package build hook.
- `meshc test --coverage` is unavailable; do not treat it as a verification gate.
- Formatting is not compilation or behavior verification. The baseline formatter
  at the revision above could truncate malformed input; the accompanying Mesh
  tooling fix preserves it and makes the CLI fail on parse errors.

## Sources and maintenance

- [Local complete reference](mesh-lang/website/docs/docs/reference/index.md),
  [language basics](mesh-lang/website/docs/docs/language-basics/index.md),
  [type system](mesh-lang/website/docs/docs/type-system/index.md),
  [iterators](mesh-lang/website/docs/docs/iterators/index.md).
- [Standard library](mesh-lang/website/docs/docs/stdlib/index.md),
  [databases](mesh-lang/website/docs/docs/databases/index.md),
  [web](mesh-lang/website/docs/docs/web/index.md),
  [concurrency](mesh-lang/website/docs/docs/concurrency/index.md).
- [Testing](mesh-lang/website/docs/docs/testing/index.md),
  [tooling](mesh-lang/website/docs/docs/tooling/index.md),
  [packages](mesh-lang/website/docs/docs/packages/index.md),
  [native packages](mesh-lang/website/docs/docs/native-packages/index.md).
- [Builtin module registry](mesh-lang/compiler/mesh-typeck/src/infer.rs),
  [builtin functions](mesh-lang/compiler/mesh-typeck/src/builtins.rs),
  [declaration parser](mesh-lang/compiler/mesh-parser/src/parser/items.rs),
  [library bindings](mesh-lang/compiler/meshc/src/library_bindings.rs),
  [ownership contract](mesh-lang/docs/security/secret-memory-model.md),
  [binary package](mesh-lang/packages/mesh-binary).
- Public documentation: [complete reference](https://meshlang.dev/docs/reference/)
  and [language guide](https://meshlang.dev/docs/language-basics/).

When updating Mesh, refresh the revision above, compare the module registry and
reference headings, and compile any newly adopted syntax before applying it
across the backend. This inventory should change with the language.
