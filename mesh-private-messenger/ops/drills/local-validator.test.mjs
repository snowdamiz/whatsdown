// Integration: the jobs Worker's anchor poster, cosign crank and bond counter,
// the relay (staged, and with an address lookup table for ten implicated
// witnesses), the canary fork drill with re-bond and the rewards drill, all
// against morse-judge and morse-rewards on a local solana-test-validator.
// Skips when the Solana tools are not installed (programs/README.md).
import assert from 'node:assert/strict';
import test from 'node:test';
import { rmSync } from 'node:fs';
import { postAnchor, crankCosigns } from '../cloudflare/anchor.mjs';
import { bondSnapshot } from '../cloudflare/bond-counter.mjs';
import { relayServer } from '../relay/relay.mjs';
import {
  LOG_CANARY, LOG_MAIN, addressBytes, ata, bytes, checkpointHash, concat, createAtaIdempotent, decodeLog, decodeRingEntry, decodeRingHeader, decodeTokenAccount,
  decodeWitness, judgeAddresses, judgeInstructions, readU64, rewardsAddresses, rewardsInstructions, ringEntryOffset, solanaChain, token, u64be,
} from '../relay/judge.mjs';
import { canaryForkDrill, rebond } from './canary-fork.mjs';
import { airdrop, newKey, setupLocal, setupLog, solanaToolsAvailable, startValidator } from './local.mjs';
import { rewardsDrill } from './rewards.mjs';

const memory = () => { const m = new Map(); return { get: k => m.get(k), set: (k, v) => m.set(k, v) }; };
const quiet = () => {};

async function checkpoint(service, sequence, size, root) {
  const body = concat(u64be(sequence), u64be(size), root, new Uint8Array(32), u64be(Date.now()), service.publicKey);
  return concat(Uint8Array.of(1), bytes('KTK'), body, await service.sign(concat(bytes('mesh-key-transparency-v1'), Uint8Array.of(0, 1), body)));
}
const vector = value => { const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, value.length); return concat(n, value); };

test('chain writers and drills against a local judge', { skip: !solanaToolsAvailable() && 'solana-test-validator is not installed', timeout: 1_200_000 }, async t => {
  const validator = await startValidator({ port: Number(process.env.MORSE_DRILL_RPC_PORT ?? 18990) });
  try {
    const local = await setupLocal(validator);
    const { chain, judge, payer } = local;
    const main = local.logs['morse-main'];
    const at = judgeAddresses(judge);

    await t.test('the anchor poster posts, records and treats DuplicateAnchor as landed; the crank cosigns', async () => {
      const served = { anchors: [] };
      const call = async (path, init = {}) => {
        if (path === '/v1/transparency/checkpoint') return { status: 200, bytes: served.checkpoint };
        if (path === '/v1/transparency/witnesses/1') return { status: 200, bytes: served.ktw };
        if (path === '/internal/v1/transparency/anchors') { served.anchors.push(JSON.parse(init.body)); return { status: 201 }; }
        throw new Error(path);
      };
      served.checkpoint = await checkpoint(main.service, 1n, 5n, crypto.getRandomValues(new Uint8Array(32)));
      const state = memory();
      const args = { chain, judge, logName: 'morse-main', payer, authority: main.anchor, call, state };
      assert.equal((await postAnchor({ ...args, nowMs: Date.now() })).status, 'posted');
      assert.equal(served.anchors[0].ring_index, 0);
      assert.equal(served.anchors[0].sequence, 1);
      // A second poster that never saw the first landing: DuplicateAnchor, found in the ring.
      const again = await postAnchor({ ...args, state: memory(), nowMs: Date.now() });
      assert.equal(again.status, 'posted');
      assert.equal(served.anchors[1].tx_signature, served.anchors[0].tx_signature);
      const hash = checkpointHash(served.checkpoint);
      served.ktw = concat(Uint8Array.of(2), bytes('KTW'), Uint8Array.of(0, main.witnesses.length), ...(await Promise.all(main.witnesses.map(async w =>
        concat(Uint8Array.of(1), vector(bytes(w.id)), hash, await w.key.sign(concat(bytes('mesh-msg/v1/transparency-witness'), bytes(w.id), hash)))))));
      assert.deepEqual(await crankCosigns(args), { cosigned: 2, open: 0 });
      const log = decodeLog((await chain.account(await at.log('morse-main'))).data);
      const entry = decodeRingEntry((await chain.account(log.ring, { offset: ringEntryOffset(0), length: 104 })).data);
      assert.equal(entry.bitmap, 0b11, 'both Morse witnesses cosigned on-chain');
    });

    await t.test('the bond counter reads morse-main from two agreeing providers', async () => {
      const snapshot = await bondSnapshot({ chains: [solanaChain({ url: local.url }), solanaChain({ url: local.url })], judge,
        rewards: local.rewards, cluster: 'devnet', state: memory(), alert: quiet });
      assert.equal(snapshot.status, 'ok', JSON.stringify(snapshot));
      assert.equal(snapshot.bonded.directory.usd, '50000.00');
      assert.deepEqual(snapshot.bonded.witnesses.map(w => [w.witness_id, w.status, w.usd]), [['witness-a', 'Active', '10000.00'], ['witness-b', 'Active', '10000.00']]);
      assert.equal(snapshot.last_public_checkpoint.sequence, '1');
      assert.equal(snapshot.slashed.never, true);
    });

    await t.test('the canary fork drill files through a relay, slashes T3 and the canary directory, pays the finder, and re-bonds', async () => {
      const canary = local.logs['morse-canary'];
      const t3 = canary.witnesses.find(w => w.id === 't3');
      const relayWallet = await newKey();
      await airdrop(chain, relayWallet.address, 5);
      const server = relayServer({ chain, judge, logs: [{ name: 'morse-canary', directory: null }], wallet: relayWallet, alert: quiet });
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      try {
        const finder = (await newKey()).address;
        const report = await canaryForkDrill({ chain, judge, serviceSeed: canary.serviceSeed, witnesses: [{ id: 't3', seed: t3.seed }],
          anchor: canary.anchor, payer, finder, relay: { url: `http://127.0.0.1:${server.address().port}` }, say: quiet });
        assert.equal(report.serviceSlashed, true);
        assert.deepEqual(report.witnesses, [{ id: 't3', status: 'Slashed' }]);
        assert.equal(report.paid, String(100_000_000n / 10n * 2n), 'the finder named by the phone gets 10% of both $100 bonds');
      } finally {
        server.close();
      }
      const main = decodeLog((await chain.account(await at.log('morse-main'))).data);
      assert.equal(main.serviceSlashed, false, 'the canary never touches morse-main');
      assert.equal(main.kind, LOG_MAIN);
      const slashedCanary = decodeLog((await chain.account(await at.log('morse-canary'))).data);
      assert.equal(slashedCanary.kind, LOG_CANARY, 'the drill\'s log is registered as a canary log');
      // Its ring rent comes back only 28 days after the slash; main logs never close.
      const close = async log => chain.send([await judgeInstructions(judge).closeLog({ log, authority: local.gov.address, destination: payer.address })],
        { payer, signers: [local.gov] });
      await assert.rejects(close('morse-canary'), error => error.code === 6036);
      await assert.rejects(close('morse-main'), error => error.code === 6035);
      await rebond({ chain, judge, witnessId: 't3', newId: 't3-r1', newSeed: crypto.getRandomValues(new Uint8Array(32)), operator: t3.operator,
        governance: local.gov, payer, usdc: local.usdc, amount: 100_000_000n, say: quiet });
      const after = decodeLog((await chain.account(await at.log('morse-canary'))).data);
      assert.equal(after.witnesses[2].id, 't3-r1', 'the new ID takes the slashed witness\'s slot');
      assert.equal(decodeWitness((await chain.account(after.witnesses[2].account)).data).status, 1, 'and is Active');
    });

    await t.test('a proof implicating ten witnesses lands through an address lookup table', async () => {
      const wide = await setupLog({ chain, judge, gov: local.gov, payer, usdc: local.usdc, name: 'morse-wide',
        witnesses: Array.from({ length: 10 }, (_, i) => `w${i}`), directoryBond: 1_000_000n, witnessBond: 1_000_000n, kind: LOG_CANARY });
      const report = await canaryForkDrill({ chain, judge, log: 'morse-wide', serviceSeed: wide.serviceSeed, anchor: wide.anchor, payer,
        witnesses: wide.witnesses.map(w => ({ id: w.id, seed: w.seed })), relay: { wallet: payer }, say: quiet });
      assert.equal(report.witnesses.filter(w => w.status === 'Slashed').length, 10);
    });

    await t.test('the rewards drill settles with no payable witness and carries the pool over', async () => {
      const report = await rewardsDrill({ chain, rewards: local.rewards, payer, say: quiet });
      assert.equal(report.payable, 0);
      assert.equal(report.allocations, 0);
      assert.equal(report.carried_over, report.budget);
      assert.equal(report.pool_after, report.pool_before);
      assert.equal(report.pool_before, '3000000');
    });

    await t.test('the burn crank\'s burn instruction burns everything in the rewards burn account', async () => {
      const mint = await newKey();
      await chain.send(await token.createMint({ payer: payer.address, mint: mint.address, authority: local.gov.address, rent: await chain.rent(82) }), { payer, signers: [mint] });
      // Governance sets the token mint on morse-rewards (set_param kind 2, immediate behind the Squads time lock).
      const config = await rewardsAddresses(local.rewards).config();
      await chain.send([{ programAddress: local.rewards, accounts: [{ address: local.gov.address, role: 2 }, { address: config, role: 1 }],
        data: concat(Uint8Array.of(1, 2), addressBytes(mint.address)) }], { payer, signers: [local.gov] });
      const burnAuthority = await rewardsAddresses(local.rewards).burn();
      await chain.send([await createAtaIdempotent(payer.address, burnAuthority, mint.address),
        await token.mintTo({ mint: mint.address, owner: burnAuthority, authority: local.gov.address, amount: 5_000_000n })], { payer, signers: [local.gov] });
      await chain.send([await rewardsInstructions(local.rewards).burn({ tokenMint: mint.address })], { payer });
      const account = decodeTokenAccount((await chain.account(await ata(burnAuthority, mint.address))).data);
      assert.equal(account.amount, 0n);
      assert.equal(readU64((await chain.account(mint.address)).data, 36), 0n, 'the supply fell by the burned amount');
    });

    const header = decodeRingHeader((await chain.account(await at.ring('morse-main'), { offset: 0, length: 64 })).data);
    assert.equal(header.count, 1);
  } finally {
    await validator.stop();
    rmSync(validator.dir, { recursive: true, force: true });
  }
});
