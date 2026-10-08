# Witnesses

This is the public list of the witnesses Morse releases pin, and of those in
their shadow week. It changes only together with a release: the security
config inside each native build is what a phone actually trusts
([witness-network-v1.md](witness-network-v1.md), "Security config v2"), and
this page must match it.

## Current profile

**Bootstrap.** Both pinned witnesses are run by Morse, and phones need both
signatures (2 of 2). Nothing here is independent of Morse yet. Outside
witnesses join through a shadow week and then a release that pins them
([WITNESS_NETWORK_PLAN.md](../../WITNESS_NETWORK_PLAN.md) §4, §9).

## Pinned

| Witness | Operator | Software | Runs on | Since |
|---|---|---|---|---|
| `witness-a` | Morse | mesh (push mode, `/attest`) | Cloudflare Worker + container | first release |
| `witness-b` | Morse | mesh (push mode, `/attest`) | Cloudflare Worker + container | first release |

Their public keys are the ones in each release's security config, and the
directory publishes them at `GET /v1/transparency/registry`. The two share one
operator and one Cloudflare account, so together they protect only against a
fault confined to one deployment, not against Morse.

## Shadow

None yet. A new witness is added to the directory registry as `shadow`, its
attestations are stored and cosigned on-chain but ignored by phones, and it is
pinned only after a clean shadow week (plan §9.4).

Planned next: `witness-c`, Morse's third witness in pull mode on a Hetzner VPS
in Germany ([ops/witness/witness-c.md](../ops/witness/witness-c.md)). Pinning
it moves production to B1 (a, b, c; 2 of 3).

## Pinning statements

Every witness pinned from now on has a pinning statement here, signed by the
witness key itself, in the format of plan §9.2:

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

The operator makes it on the machine that holds the key with
`node ops/witness/pinning-statement.mjs sign …` (or `message` + `assemble` for
an HSM or KMS), and anyone can check one with
`node ops/witness/pinning-statement.mjs verify <file>`. Statements are added
below as they are published; a release that pins a witness without one here is
not to be shipped.

<!-- Statements, newest first. Paste each verified statement in its own
     fenced block under a "### <witness_id>" heading. -->
