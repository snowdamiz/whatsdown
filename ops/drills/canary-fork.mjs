// Monthly canary fork drill (plan §11.3, morse-judge-v1.md §12), up to the phone
// step: sign two conflicting checkpoints with the canary service key, anchor one,
// have witness T3 cosign both (one on-chain, one as an attestation), file the FRK
// through a relay, check the slash on the canary log, then re-bond.
//
//   node ops/drills/canary-fork.mjs --rpc URL --judge ID --service-key FILE --witness t3 --witness-key FILE
//     --anchor KEYPAIR --payer KEYPAIR (--relay https://relay | --relay-wallet KEYPAIR)
//     [--log morse-canary] [--finder ADDRESS] [--operator KEYPAIR --new-witness-key FILE] [--governance KEYPAIR]
//
// FILE holds a 32-byte Ed25519 seed as 64 hex characters. Without --governance the
// governance steps of the re-bond are printed as Squads instructions, not sent.
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { encodeFrk, proofHash } from '../relay/frk.mjs';
import {
  SLASHED, STATUS, addressBytes, ata, bytes, checkpointEntry, checkpointHash, concat, decodeJudgeConfig, decodeLog, decodeRingHeader,
  decodeTokenAccount, decodeWitness, ed25519FromSeed, ed25519Instruction, fromHex, hex, instructionJson, judgeAddresses, judgeInstructions,
  loadKeypair, pause, solanaChain, u64be, unsignedMessage, witnessMessage,
} from '../relay/judge.mjs';
import { prepareEvidence, submitEvidence } from '../relay/relay.mjs';

const balance = async (chain, account) => {
  const found = account && await chain.account(account);
  return found?.data.length === 165 ? decodeTokenAccount(found.data).amount : 0n;
};

async function signCheckpoint(service, sequence, size, root, timestampMs) {
  const body = concat(u64be(sequence), u64be(size), root, new Uint8Array(32), u64be(timestampMs), service.publicKey);
  return concat(Uint8Array.of(1), bytes('KTK'), body, await service.sign(concat(bytes('mesh-key-transparency-v1'), Uint8Array.of(0, 1), body)));
}

// `witnesses`: [{id, seed}] listed on the log that will cosign both versions.
// `relay`: {url} to post to a running relay, or {wallet} to file in-process.
export async function canaryForkDrill({ chain, judge, log = 'morse-canary', serviceSeed, witnesses, anchor, payer, relay, finder = null,
  say = console.log }) {
  const at = judgeAddresses(judge);
  const ix = judgeInstructions(judge);
  const logAddress = await at.log(log);
  const state = decodeLog((await chain.account(logAddress)).data);
  const service = await ed25519FromSeed(serviceSeed);
  if (hex(service.publicKey) !== hex(state.serviceKey)) throw new Error(`the service key file is not ${log}'s service key`);
  const signers = await Promise.all(witnesses.map(async w => {
    const listed = state.witnesses.find(x => x.id === w.id);
    if (!listed) throw new Error(`${w.id} is not in ${log}'s witness list`);
    return { ...listed, ...(await ed25519FromSeed(w.seed)) };
  }));
  const vaults = await Promise.all(signers.map(async s => decodeWitness((await chain.account(s.account)).data).vault));
  const before = { directory: await balance(chain, state.directoryVault), witnesses: await Promise.all(vaults.map(v => balance(chain, v))) };

  // 1. Two conflicting checkpoints: same sequence and size, different roots.
  const header = decodeRingHeader((await chain.account(state.ring, { offset: 0, length: 64 })).data);
  const sequence = header.lastSequence + 1n;
  const size = header.lastSize > 0n ? header.lastSize : 1n;
  const now = BigInt(Date.now());
  const published = await signCheckpoint(service, sequence, size, crypto.getRandomValues(new Uint8Array(32)), now);
  const shown = await signCheckpoint(service, sequence, size, crypto.getRandomValues(new Uint8Array(32)), now);
  say(`drill: ${log} sequence ${sequence}, size ${size}: anchoring one version, showing the other`);
  await chain.send([ed25519Instruction([checkpointEntry(published)]), await ix.postAnchor({ log, anchorAuthority: anchor.address, ktk: published })],
    { payer, signers: [anchor] });
  const ringIndex = header.head;

  // 2. The witnesses cosign both: the anchored one on-chain, the shown one as attestations.
  const publicHash = checkpointHash(published);
  const shownHash = checkpointHash(shown);
  for (let i = 0; i < signers.length; i += 4) {
    const batch = signers.slice(i, i + 4);
    const entries = await Promise.all(batch.map(async s => ({ publicKey: s.publicKey, message: witnessMessage(s.id, publicHash),
      signature: await s.sign(witnessMessage(s.id, publicHash)) })));
    await chain.send([ed25519Instruction(entries), ...(await Promise.all(batch.map(s => ix.cosign({ log, ringIndex, listIndex: s.index, witnessAccount: s.account }))))],
      { payer });
  }
  const attestations = await Promise.all(signers.map(async s => ({ id: s.id, hash: shownHash, signature: await s.sign(witnessMessage(s.id, shownHash)) })));

  // 3. The evidence a phone would build against the ring (the phone step, see README).
  const frk = encodeFrk({ kind: 1, finder: finder ? addressBytes(finder) : new Uint8Array(32), serviceKey: service.publicKey, c1: shown, c2: null,
    ringIndex, attestations, contradiction: null });
  const hash = proofHash(frk);
  say(`drill: FRK ${frk.length} bytes, proof ${hex(hash)}, ring index ${ringIndex}`);

  // 4. File it through a relay.
  let payee = finder;
  if (relay.url) {
    const response = await fetch(new URL('/v1/fork-evidence', relay.url), { method: 'POST', body: frk, headers: { 'Content-Type': 'application/octet-stream' } });
    if (![200, 202].includes(response.status)) throw new Error(`relay refused the evidence: ${response.status} ${await response.text()}`);
    say(`drill: relay answered ${response.status}`);
  } else {
    const prepared = await prepareEvidence(frk, { chain, judge, logs: [{ name: log, directory: null }] });
    const result = await submitEvidence(prepared, { chain, judge, wallet: relay.wallet, attempts: 5 });
    payee ??= relay.wallet.address;
    say(`drill: relay submission ${result.status}`);
  }
  const proofAccount = await at.proof(hash);
  for (let i = 0; !(await chain.account(proofAccount)); i++) {
    if (i > 240) throw new Error('the proof did not land within two minutes');
    await pause(500);
  }

  // 5. The slash, and the finder's 10%.
  const after = decodeLog((await chain.account(logAddress)).data);
  const statuses = await Promise.all(signers.map(async s => decodeWitness((await chain.account(s.account)).data).status));
  const { usdc } = decodeJudgeConfig((await chain.account(await at.config())).data);
  const expected = (before.directory / 10n) + before.witnesses.reduce((sum, amount) => sum + amount / 10n, 0n);
  const paid = payee ? await balance(chain, await ata(payee, usdc)) : null;
  const report = { log, proof: hex(hash), proofAccount, ringIndex, serviceSlashed: after.serviceSlashed,
    witnesses: signers.map((s, i) => ({ id: s.id, status: STATUS[statuses[i]] })), finderShare: String(expected), payee, paid: paid === null ? null : String(paid) };
  if (!after.serviceSlashed || statuses.some(x => x !== SLASHED)) throw new Error(`slash not complete: ${JSON.stringify(report)}`);
  if (payee && paid < expected) throw new Error(`finder paid ${paid}, expected at least ${expected}`);
  say(`drill: slashed ${log} and ${signers.map(s => s.id).join(', ')}; ${payee ?? 'the relay'} received ${paid ?? '?'} (10% = ${expected})`);
  return report;
}

// Re-bond after the drill: the slashed witness comes back under a new ID in its
// list slot (register by its operator, admit by governance, bond); a slashed
// directory bond is final, so the log itself is re-provisioned (printed).
export async function rebond({ chain, judge, log = 'morse-canary', witnessId, newId, newSeed, operator, governance = null, governanceVault = null,
  payer, usdc, amount, say = console.log }) {
  const ix = judgeInstructions(judge);
  const state = decodeLog((await chain.account(await judgeAddresses(judge).log(log))).data);
  const slot = state.witnesses.find(x => x.id === witnessId);
  if (!slot) throw new Error(`${witnessId} is not listed on ${log}`);
  const key = await ed25519FromSeed(newSeed);
  const message = concat(bytes('morse-witness-register-v1'), bytes(newId), addressBytes(operator.address), addressBytes(operator.address));
  await chain.send([ed25519Instruction([{ publicKey: key.publicKey, message, signature: await key.sign(message) }]),
    await ix.registerWitness({ log, operator: operator.address, id: newId, signingKey: key.publicKey, payout: operator.address })], { payer: operator });
  const authority = governance?.address ?? governanceVault;
  if (!authority) throw new Error('re-bonding needs --governance (a local key) or --governance-vault (to print for Squads)');
  const admit = await ix.admitWitness({ log, authority, id: newId, replace: slot.index, replacedId: witnessId });
  const held = await balance(chain, await ata(operator.address, usdc));
  if (held < amount) say(`drill: the operator holds ${held} of the ${amount} USDC base units the bond needs; fund ${await ata(operator.address, usdc)} first`);
  if (governance) {
    await chain.send([admit], { payer, signers: [governance] });
    await chain.send([await ix.bond({ log, operator: operator.address, id: newId, mint: usdc, amount })], { payer: operator });
    say(`drill: ${newId} admitted in slot ${slot.index} and bonded ${amount}`);
  } else {
    say(`drill: governance admits ${newId} into slot ${slot.index} (a Squads vault transaction), then the operator bonds it:`);
    say(JSON.stringify({ vault: authority, instructions: [instructionJson(admit)], message_base58: unsignedMessage([admit], authority) }, null, 2));
  }
  if (state.serviceSlashed) {
    say(`drill: ${log}'s directory bond is slashed for good. Re-provision the canary log before the next drill:
  morse-admin gov register-log <new name> --canary --authority <JUDGE_VAULT> --service-key <new canary service key> --anchor <canary anchor> --usdc <USDC>
  morse-admin grow-ring --log <new name> ...; morse-admin gov bond-directory <new name> --mint <USDC> --amount 100000000 ...
  register and admit T1-T3 on it, and point the canary backend at it (MORSE_LOG_ID, MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX).
  28 days after the slash, reclaim ${log}'s ring rent (about 2.2 SOL):
  morse-admin gov close-log ${log} --authority <JUDGE_VAULT> --destination <account>`);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { values: v } = parseArgs({ options: Object.fromEntries(['rpc', 'judge', 'log', 'service-key', 'witness', 'witness-key', 'anchor', 'payer',
    'relay', 'relay-wallet', 'finder', 'operator', 'new-witness-key', 'governance', 'governance-vault', 'bond-amount'].map(k => [k, { type: 'string' }])) });
  for (const k of ['rpc', 'judge', 'service-key', 'witness', 'witness-key', 'anchor', 'payer']) if (!v[k]) throw new Error(`--${k} is required`);
  const chain = solanaChain({ url: v.rpc });
  const key = file => loadKeypair(readFileSync(file, 'utf8'));
  const seed = file => fromHex(readFileSync(file, 'utf8').trim());
  const payer = await key(v.payer);
  const log = v.log ?? 'morse-canary';
  const report = await canaryForkDrill({ chain, judge: v.judge, log, serviceSeed: seed(v['service-key']), witnesses: [{ id: v.witness, seed: seed(v['witness-key']) }],
    anchor: await key(v.anchor), payer, finder: v.finder ?? null, relay: v.relay ? { url: v.relay } : { wallet: await key(v['relay-wallet'] ?? v.payer) } });
  console.log(JSON.stringify(report, null, 2));
  if (v.operator) {
    let next = v['new-witness-key'];
    if (!next) {
      next = `${v['witness-key']}.next`;
      writeFileSync(next, hex(crypto.getRandomValues(new Uint8Array(32))), { mode: 0o600 });
      console.log(`drill: new witness key for the re-bonded witness written to ${next}; configure the witness host with it`);
    }
    const { usdc } = decodeJudgeConfig((await chain.account(await judgeAddresses(v.judge).config())).data);
    await rebond({ chain, judge: v.judge, log, witnessId: v.witness, newId: `${v.witness.replace(/-r\d{8}$/, '')}-r${new Date().toISOString().slice(0, 10).replaceAll('-', '')}`,
      newSeed: seed(next), operator: await key(v.operator), governance: v.governance ? await key(v.governance) : null,
      governanceVault: v['governance-vault'] ?? null, payer, usdc,
      amount: BigInt(v['bond-amount'] ?? 100_000_000) });
  }
}
