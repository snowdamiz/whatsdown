# Witness Network v1

Status: proposed. Nothing in this document is implemented. The landing page
presents it as what comes next, in the order below. Each step stands on its own
without the ones after it.

## Why

[Key transparency](key-transparency-v1.md) is only as strong as witnesses the
directory operator does not control, and today both witnesses share one
operator. This plan opens the witness set to outside operators, backs each
witness's signature with a bond it loses if it signs a fork, and pays for that
with optional, anonymous credits.

## Rules that do not change

- Messaging never needs credits, a wallet or the token. Proof of work (`PWR`)
  stays the free path for every request that needs it today.
- Wallet addresses never reach the privacy edge, the directory or the delivery
  core, and are never linked to an account (see the
  [privacy contract](privacy-contract.md)).
- Nothing per message, per contact or per account is written to a chain. A
  chain sees checkpoint commitments, bonds, fork proofs and credit purchases.
- Each app release pins the witness keys a client trusts and the threshold it
  requires. On-chain state decides who may bond and whose bond is taken, never
  which witnesses a client trusts, so holding tokens cannot change which keys a
  phone accepts.
- Nothing rewards in-app activity. Measuring activity is what the servers are
  built not to do.

## Steps

1. **Public checkpoints.** The directory posts each checkpoint commitment (tree
   size, root, sequence and the witness cosignatures) to a public chain. The
   chain receives what witnesses already see and nothing more.
2. **Independent witnesses.** Operators outside Morse run the existing witness
   service with their own keys. Releases pin them with a threshold below the
   pinned count, so one operator going offline does not stop lookups.
3. **Anonymous credits.** Privacy Pass issuance (RFC 9578, blind RSA from
   RFC 9474). A client pays on-chain in USDC, SOL or BTC to a one-time address
   and receives blind-signed credits; it spends them at the privacy edge beside
   `PWR`, and the edge keeps a spent set. Issuer keys, one per epoch and
   denomination, are published in the transparency log so the issuer cannot
   hand one user a unique key to tag their credits. Credits buy extras: larger
   attachments, longer mailbox retention, postage a recipient may require on
   message requests, and priority when registration is closed by a flood.
4. **The token.** Witnesses, and the directory's own service key, bond it.
   Buying credits burns it: clients may pay in other assets and the purchase
   swaps before burning. Witnesses are paid for each anchored checkpoint they
   cosigned. Missing a checkpoint forfeits that payment, not the bond.

## Fork proof

Two service-signed checkpoints that can't both be true prove a fork, and every
witness that cosigned both signed it. Three forms are accepted: the same tree
size with different roots; the same leaf index reading differently in two
checkpoints, shown by compact inclusion proofs (this catches forks that never
share a size); and sequence and size moving in opposite directions. Each is
checked on-chain with Ed25519 verifications and SHA-256 path recomputation.
Whoever submits it receives 10% of what it slashes; the rest is locked or
burned, never paid to Morse.

Phones require a strict majority of the pinned witnesses, so two conflicting
checkpoints that both reach the threshold always share at least one witness
that signed both.

The implementation order, parameters and tests are in
[WITNESS_NETWORK_PLAN.md](../../WITNESS_NETWORK_PLAN.md).

A witness that keeps the last checkpoint it signed (the witness service already
does, in `verify_history`) cannot produce a fork proof against itself unless
its key is stolen or its state is lost. Downtime is never slashed.

## Open questions

- Chain: Solana (decided 2026-09-25). Its native Ed25519 program makes fork
  proofs cheap.
- A credit purchase is public on its chain. Clients should buy in batches and
  spend later to weaken timing correlation.
