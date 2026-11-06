# Witness inventory and pinning statements

Status: Bootstrap configuration inventory, verified against repository code on
2026-10-22. This is not a live registry export, a statement of uptime, or evidence
that an outside operator has joined. No operator signatures are fabricated here.

| Witness ID | Operator | Configuration role | Software | Signed pinning statement |
|---|---|---|---|---|
| `witness-a` | Morse | Pinned when an empty registry bootstraps | Mesh | Not published here |
| `witness-b` | Morse | Pinned when an empty registry bootstraps | Mesh | Not published here |

`Storage.WitnessRegistry.bootstrap_witness_registry` obtains the exact public
keys from `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX` and
`MESSENGER_WITNESS_B_PUBLIC_KEY_HEX`; it rejects duplicate keys and only seeds an
empty registry. A populated registry controls its own pinned/shadow/retired
entries. Native release configuration, rather than this document or an on-chain
registry, determines the keys a client accepts.

Legacy configuration requires both bootstrap signatures. Both operators are
Morse, so Morse can satisfy that threshold. They do not establish independent
trust against Morse. New configuration supports bounded majority policies;
capability alone does not establish outside membership. See
[trust profiles](witness-network-v1.md#trust-profiles).

No outside pinned or shadow witness is announced by this inventory. Before
announcing one, publish its actual key, operator, jurisdiction, implementation,
status and signed statement, then link its shadow-week evidence and the exact
release that pins it. Do not substitute fixture keys, application examples or
unsigned applications for an operator's statement. Public chain records are
reported separately on the [network page](../apps/landing/network.html).

## Statement format

The operator signs the UTF-8 lines before `signature`, using its witness
Ed25519 key. The following is a template, not a signed statement:

```text
morse-witness-pin-v1
witness_id: <id>
public_key: <64 hex>
operator: <label>
jurisdiction: <country>
software: mesh <version> | c2sp <implementation> <version>
payout: <Solana address>
date: <YYYY-MM-DD>
signature: <Ed25519 over the lines above, hex>
```

Key rotation needs a new statement and release pin transition. Retired statements
remain as history with their retirement status; removing a key from a server
registry does not retroactively change what an installed client trusts.
