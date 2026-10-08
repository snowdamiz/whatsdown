// Bond counter snapshot (plan §6.17, morse-judge-v1.md §11): morse-main's bonds,
// slashes and last public checkpoint, read from two RPC providers that must
// agree. Disagreement or a failed read is "unavailable", never a number. The
// canary log is never read. Every slash stays in the history for good.
import {
  SLASHED, STATUS, TOKEN, decodeJudgeConfig, decodeLog, decodePriceFeed, decodeProof, decodeRewardsConfig, decodeRingHeader,
  decodeTokenAccount, decodeWitness, judgeAddresses, rewardsAddresses,
} from './judge.mjs';

export const COUNTED_LOG = 'morse-main';

export const explorer = cluster => {
  const suffix = cluster === 'devnet' ? '?cluster=devnet' : '';
  return {
    address: a => `https://explorer.solana.com/address/${a}${suffix}`,
    block: slot => `https://explorer.solana.com/block/${slot}${suffix}`,
    tx: signature => `https://explorer.solana.com/tx/${signature}${suffix}`,
  };
};

const owned = (account, owner) => {
  if (!account || account.owner !== owner) throw new Error('account missing or not owned by the expected program');
  return account.data;
};
const tokenBalance = account => {
  if (!account) return null;
  const { mint, amount } = decodeTokenAccount(owned(account, TOKEN));
  return { mint, amount: amount.toString() };
};

// Everything the counter shows, from one provider, as plain comparable values.
async function readView(chain, judge, rewards) {
  const at = judgeAddresses(judge);
  const logAddress = await at.log(COUNTED_LOG);
  const log = decodeLog(owned(await chain.account(logAddress), judge));
  const ring = decodeRingHeader(owned(await chain.account(log.ring, { offset: 0, length: 64 }), judge));
  const config = decodeJudgeConfig(owned(await chain.account(await at.config()), judge));
  const witnesses = await chain.accounts(log.witnesses.map(x => x.account));
  const decoded = witnesses.map(w => decodeWitness(owned(w, judge)));
  const vaults = await chain.accounts([log.directoryVault, ...decoded.map(w => w.vault)]);
  let price = null;
  if (rewards && config.token) {
    const rc = decodeRewardsConfig(owned(await chain.account(await rewardsAddresses(rewards).config()), rewards));
    const feed = rc.priceFeed && rc.oracle ? await chain.account(rc.priceFeed) : null;
    if (feed && feed.owner === rc.oracle) {
      const f = decodePriceFeed(feed.data);
      price = { price: f.price.toString(), exponent: f.exponent, publishTime: f.publishTime.toString() };
    }
  }
  return {
    logAddress, serviceSlashed: log.serviceSlashed, directoryStatus: STATUS[log.directoryStatus] ?? String(log.directoryStatus),
    directoryVault: log.directoryVault, directory: tokenBalance(vaults[0]), usdc: config.usdc, token: config.token, price,
    ring: { lastSequence: ring.lastSequence.toString(), lastSize: ring.lastSize.toString(), lastSlot: ring.lastSlot.toString(), count: ring.count },
    lastTime: ring.count ? String(await chain.blockTime(ring.lastSlot) ?? '') : '',
    witnesses: log.witnesses.map((x, i) => ({ id: x.id, account: x.account, status: STATUS[decoded[i].status], excluded: decoded[i].excluded,
      vault: decoded[i].vault, bond: tokenBalance(vaults[i + 1]) })),
  };
}

// USDC base units -> "12.34"; the token at the feed's 7-day TWAP (§10.4).
function usd(bond, view) {
  if (!bond) return null;
  let units = BigInt(bond.amount);
  if (bond.mint === view.token) {
    if (!view.price) return null;
    const { price, exponent } = view.price;
    units = exponent >= 0 ? units * BigInt(price) * 10n ** BigInt(exponent) : units * BigInt(price) / 10n ** BigInt(-exponent);
  } else if (bond.mint !== view.usdc) return null;
  return `${units / 1_000_000n}.${String((units % 1_000_000n) / 10_000n).padStart(2, '0')}`;
}

// New Proof accounts of morse-main, confirmed on the second provider before they
// join the history; each keeps its transaction link forever.
async function discoverSlashes([primary, second], judge, view, history, links) {
  const proofs = await primary.programAccounts(judge, [
    { dataSize: 112n },
    { memcmp: { offset: 0n, bytes: '6', encoding: 'base58' } }, // tag 5 (Proof), base58
    { memcmp: { offset: 8n, bytes: view.logAddress, encoding: 'base58' } },
  ]);
  const known = new Set(history.map(x => x.proof));
  const added = [];
  for (const found of proofs.filter(x => !known.has(x.address))) {
    const confirmed = await second.account(found.address);
    if (!confirmed || confirmed.owner !== judge) continue;
    const proof = decodeProof(confirmed.data);
    if (proof.log !== view.logAddress) continue;
    const signatures = await primary.signaturesFor(found.address, 20);
    const landed = signatures.filter(x => !x.err).at(-1);
    added.push({ proof: found.address, kind: proof.kind, slot: proof.slot.toString(), paid_to: proof.paidTo,
      tx_signature: landed?.signature ?? null, link: landed ? links.tx(landed.signature) : links.address(found.address),
      account_link: links.address(found.address) });
  }
  return added;
}

// One snapshot. `state` keeps the slash history and the last good snapshot.
export async function bondSnapshot({ chains, judge, rewards = null, cluster, state, nowMs = Date.now(), alert = console.error }) {
  const links = explorer(cluster);
  const history = state.get('slash_history') ?? [];
  const unavailable = reason => {
    const previous = state.get('bond_snapshot');
    const out = { log: COUNTED_LOG, status: 'unavailable', reason, generated_at: new Date(nowMs).toISOString(),
      last_good_at: previous?.status === 'ok' ? previous.generated_at : previous?.last_good_at ?? null, slash_history: history };
    state.set('bond_snapshot', out);
    alert(`WARN bond_counter_${reason}`);
    return out;
  };
  if (chains.length < 2) return unavailable('needs_two_rpc_providers');
  let views;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      views = await Promise.all(chains.slice(0, 2).map(chain => readView(chain, judge, rewards)));
    } catch {
      views = null;
      continue;
    }
    if (JSON.stringify(views[0]) === JSON.stringify(views[1])) break;
    views = 'disagree';
  }
  if (!views) return unavailable('rpc_error');
  if (views === 'disagree') return unavailable('rpc_disagree');
  const view = views[0];
  const slashedWitnesses = view.witnesses.filter(w => w.status === STATUS[SLASHED]).length;
  const parties = slashedWitnesses + (view.serviceSlashed ? 1 : 0);
  if (parties > (state.get('slashed_parties_seen') ?? 0)) {
    try {
      const added = await discoverSlashes(chains, judge, view, history, links);
      if (added.length) {
        history.push(...added);
        state.set('slash_history', history);
        state.set('slashed_parties_seen', parties);
      }
    } catch (error) {
      alert(`WARN bond_counter_slash_lookup_failed ${String(error.message).slice(0, 200)}`);
    }
  }
  const time = view.lastTime ? Number(view.lastTime) : null;
  const out = {
    log: COUNTED_LOG, status: 'ok', generated_at: new Date(nowMs).toISOString(), cluster: cluster === 'devnet' ? 'devnet' : 'mainnet-beta',
    judge_program: judge, log_account: { address: view.logAddress, link: links.address(view.logAddress) },
    last_public_checkpoint: view.ring.count ? { slot: view.ring.lastSlot, sequence: view.ring.lastSequence, tree_size: view.ring.lastSize,
      time: time === null ? null : new Date(time * 1000).toISOString(), age_seconds: time === null ? null : Math.max(0, Math.floor(nowMs / 1000) - time),
      link: links.block(view.ring.lastSlot) } : null,
    bonded: {
      directory: { status: view.directoryStatus, amount: view.directory?.amount ?? '0', mint: view.directory?.mint ?? null,
        usd: usd(view.directory, view), account: view.directoryVault, link: links.address(view.directoryVault) },
      witnesses: view.witnesses.map(w => ({ witness_id: w.id, status: w.status, excluded: w.excluded, amount: w.bond?.amount ?? '0',
        mint: w.bond?.mint ?? null, usd: usd(w.bond, view), account: w.account, vault: w.vault, link: links.address(w.vault) })),
    },
    slashed: { service: view.serviceSlashed, witnesses: slashedWitnesses, never: !view.serviceSlashed && slashedWitnesses === 0 && history.length === 0,
      link: links.address(view.logAddress) },
    slash_history: history,
  };
  state.set('bond_snapshot', out);
  return out;
}

