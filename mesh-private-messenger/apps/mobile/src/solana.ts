import { wallet_rpc_urls_export } from '../modules/mesh-messenger';
import { fetch, isDevelopmentBuild } from './transport';
import {
  SOL_DECIMALS,
  USDC_DECIMALS,
  USDC_MINT,
  baseUnits,
  fromBase58,
  raiseBountyIndex,
  signTransfer,
  walletAddress,
  type PayRequest,
  type Transfer,
} from './wallet.ts';

// The wallet's reads and transfers go to the Solana RPC providers this build pins
// (security config; the core hands the list over) and nowhere else. On the desktop
// the host lets the web view reach exactly those URLs. A provider sees the addresses
// asked about and this device's IP (protocol/privacy-contract.md); Morse sees nothing.

// `usdcMint` is the cluster's real USDC (see clusterOf); without it nothing is
// paid or counted in USDC.
export type Rpc = ((method: string, params: unknown[]) => Promise<unknown>) & { usdcMint?: string };
type Post = (url: string, body: string) => Promise<{ status: number; body: string }>;

export function poster(send: typeof fetch = fetch): Post {
  return async (url, body) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8_000);
    try {
      const response = await send(url, {
        method: 'POST',
        redirect: 'error',
        headers: { 'Content-Type': 'application/json' },
        body: new TextEncoder().encode(body).buffer as ArrayBuffer,
        signal: controller.signal,
      });
      return { status: response.status, body: await response.text() };
    } finally {
      clearTimeout(timeout);
    }
  };
}

// Providers are tried in random order until one answers; an error it returns is its answer.
export function rpcOver(urls: string[], post: Post = poster(), random: () => number = Math.random): Rpc {
  return async (method, params) => {
    const order = [...urls];
    for (let index = order.length - 1; index > 0; index -= 1) {
      const other = Math.floor(random() * (index + 1));
      [order[index], order[other]] = [order[other]!, order[index]!];
    }
    for (const url of order) {
      let answer: { status: number; body: string };
      try { answer = await post(url, JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })); } catch { continue; }
      if (answer.status !== 200) continue;
      const reply = JSON.parse(answer.body) as { result?: unknown; error?: { message?: string } };
      if (reply.error) throw new Error(`rpc_error: ${reply.error.message ?? 'unknown'}`);
      return reply.result;
    }
    throw new Error('rpc_unavailable');
  };
}

// Which chain the pinned providers serve, by its genesis hash, and so which mint
// is USDC there (Circle's addresses). Every provider is asked; at least two must
// answer and none may disagree. Any other chain (a local validator) is refused,
// unless a development build names its USDC mint in EXPO_PUBLIC_MORSE_DEV_USDC_MINT;
// release builds ignore that variable.
export const CLUSTERS: Record<string, { name: string; usdcMint: string }> = {
  '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d': { name: 'mainnet-beta', usdcMint: USDC_MINT },
  EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG: { name: 'devnet', usdcMint: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU' },
};

export async function clusterOf(
  urls: string[],
  post: Post = poster(),
  development = isDevelopmentBuild(),
  override = process.env.EXPO_PUBLIC_MORSE_DEV_USDC_MINT ?? '',
): Promise<{ name: string; usdcMint: string }> {
  const answers = (await Promise.all(urls.map(async (url) => {
    try {
      const answer = await post(url, JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getGenesisHash', params: [] }));
      const result = (JSON.parse(answer.body) as { result?: unknown }).result;
      return answer.status === 200 && typeof result === 'string' ? result : null;
    } catch {
      return null;
    }
  }))).filter((value): value is string => value !== null);
  if (answers.length < 2) throw new Error('rpc_unavailable');
  if (answers.some((value) => value !== answers[0])) throw new Error('rpc_disagree');
  const known = CLUSTERS[answers[0]!];
  if (known) return known;
  if (development && override) {
    if (fromBase58(override).length !== 32) throw new Error('bad_usdc_mint');
    return { name: 'development', usdcMint: override };
  }
  throw new Error('unsupported_cluster');
}

// Asked once per app run (again after a failure).
const clusters = new Map<string, Promise<{ name: string; usdcMint: string }>>();

function cachedCluster(urls: string[]): Promise<{ name: string; usdcMint: string }> {
  const key = urls.join('\n');
  let found = clusters.get(key);
  if (!found) {
    found = clusterOf(urls);
    clusters.set(key, found);
    found.catch(() => clusters.delete(key));
  }
  return found;
}

const usdcOf = (rpc: Rpc): string => {
  if (!rpc.usdcMint) throw new Error('unsupported_cluster');
  return rpc.usdcMint;
};

// Mobile.WalletConfig: u8 1 || u8 count || count x vector32(url). Null when none is pinned.
export async function pinnedRpc(): Promise<Rpc | null> {
  const frame = await wallet_rpc_urls_export(new Uint8Array());
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  if (frame[0] !== 1) throw new Error('bad_frame');
  const urls: string[] = [];
  let offset = 2;
  for (let index = 0; index < frame[1]!; index += 1) {
    const length = view.getUint32(offset);
    urls.push(new TextDecoder().decode(frame.subarray(offset + 4, offset + 4 + length)));
    offset += 4 + length;
  }
  if (offset !== frame.length) throw new Error('bad_frame');
  if (!urls.length) return null;
  return Object.assign(rpcOver(urls), { usdcMint: (await cachedCluster(urls)).usdcMint });
}

type TokenAccounts = { value: { pubkey?: string; account: { data: { parsed: { info: { tokenAmount: { amount: string } } } } } }[] };
const usdcAccounts = (rpc: Rpc, owner: string) =>
  rpc('getTokenAccountsByOwner', [owner, { mint: usdcOf(rpc) }, { encoding: 'jsonParsed', commitment: 'confirmed' }]) as Promise<TokenAccounts>;

// Lamports and USDC base units.
export async function balances(rpc: Rpc, owner: string): Promise<{ sol: bigint; usdc: bigint }> {
  const [lamports, tokens] = await Promise.all([
    rpc('getBalance', [owner, { commitment: 'confirmed' }]) as Promise<{ value: number }>,
    usdcAccounts(rpc, owner),
  ]);
  const usdc = tokens.value.reduce((total, entry) => total + BigInt(entry.account.data.parsed.info.tokenAmount.amount), 0n);
  return { sol: BigInt(lamports.value), usdc };
}

const pause = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// Submits a signed transaction and returns its signature once it is finalized.
export async function sendAndConfirm(rpc: Rpc, transaction: string, lastValidBlockHeight: number, wait = pause): Promise<string> {
  const signature = await rpc('sendTransaction', [transaction, { encoding: 'base64', preflightCommitment: 'confirmed' }]) as string;
  for (;;) {
    const statuses = await rpc('getSignatureStatuses', [[signature]]) as { value: ({ err: unknown; confirmationStatus?: string } | null)[] };
    const status = statuses.value[0];
    if (status?.err) throw new Error('transaction_failed');
    if (status?.confirmationStatus === 'finalized') return signature;
    if (!status && (await rpc('getBlockHeight', [{ commitment: 'finalized' }]) as number) > lastValidBlockHeight) {
      throw new Error('transaction_expired');
    }
    await wait(2_000);
  }
}

// ponytail: no priority fee (compute unit price 0); add getRecentPrioritizationFees if transfers stall.
async function send(rpc: Rpc, transfer: Omit<Transfer, 'blockhash'>): Promise<string> {
  const latest = await rpc('getLatestBlockhash', [{ commitment: 'confirmed' }]) as { value: { blockhash: string; lastValidBlockHeight: number } };
  const signed = await signTransfer({ ...transfer, blockhash: latest.value.blockhash });
  return sendAndConfirm(rpc, signed.transaction, latest.value.lastValidBlockHeight);
}

// Pays a Solana Pay transfer request from account 0: SOL, or USDC (a quote's fresh
// deposit address has no USDC account yet, so the payer creates it).
export async function pay(rpc: Rpc, request: PayRequest): Promise<string> {
  if (!request.amount) throw new Error('amount_required');
  // Only the cluster's real USDC, or SOL.
  const mint = request.splToken === null ? null : usdcOf(rpc);
  if (request.splToken !== null && request.splToken !== mint) throw new Error('unsupported_token');
  const usdc = mint !== null;
  return send(rpc, {
    owner: { kind: 'account', index: 0 },
    feePayer: 0,
    asset: usdc ? { kind: 'spl', mint: mint!, decimals: USDC_DECIMALS } : { kind: 'sol' },
    amount: baseUnits(request.amount, usdc ? USDC_DECIMALS : SOL_DECIMALS),
    recipient: request.recipient,
    createRecipientAccount: usdc,
    references: request.references,
    memo: request.memo,
    computeUnitLimit: 0,
    computeUnitPrice: 0n,
  });
}

// Moves a bounty's whole USDC balance to `recipient`. Account 0 pays the fee, which
// links the two addresses on chain: the app says so before the first move.
export async function moveBounty(rpc: Rpc, index: number, recipient: string): Promise<string> {
  const { usdc } = await balances(rpc, await walletAddress({ kind: 'bounty', index }));
  if (usdc === 0n) throw new Error('nothing_to_move');
  return send(rpc, {
    owner: { kind: 'bounty', index },
    feePayer: 0,
    asset: { kind: 'spl', mint: usdcOf(rpc), decimals: USDC_DECIMALS },
    amount: usdc,
    recipient,
    createRecipientAccount: true,
    references: [],
    memo: '',
    computeUnitLimit: 0,
    computeUnitPrice: 0n,
  });
}

// A restored wallet does not know which bounty addresses it handed out. Scan until
// `gap` in a row have no history, issuing each index before deriving it (so the scan
// never lowers the index); returns the next index.
export async function discoverBounties(rpc: Rpc, gap = 10): Promise<number> {
  let issued = await raiseBountyIndex(0);
  let empty = 0;
  for (let index = 0; empty < gap; index += 1) {
    if (index >= issued) issued = await raiseBountyIndex(index + 1);
    const address = await walletAddress({ kind: 'bounty', index });
    const history = await rpc('getSignaturesForAddress', [address, { limit: 1 }]) as unknown[];
    empty = history.length ? 0 : empty + 1;
  }
  return issued;
}

type ParsedTransaction = {
  transaction: { message: { accountKeys: ({ pubkey: string } | string)[] } };
  meta: Record<'preTokenBalances' | 'postTokenBalances', { accountIndex: number; uiTokenAmount: { amount: string } }[] | undefined>;
};

// What a landed bounty paid, and in which transaction: the oldest transfer into the
// finder address's USDC account (the relay may have created the account first).
export async function bountyPayout(rpc: Rpc, owner: string): Promise<{ amount: bigint; signature: string } | null> {
  const account = (await usdcAccounts(rpc, owner)).value[0]?.pubkey;
  if (!account) return null;
  const history = await rpc('getSignaturesForAddress', [account, { limit: 20, commitment: 'finalized' }]) as { signature: string; err: unknown }[];
  for (const { signature } of history.filter((entry) => !entry.err).reverse()) {
    const tx = await rpc('getTransaction', [signature, { encoding: 'jsonParsed', commitment: 'finalized', maxSupportedTransactionVersion: 0 }]) as ParsedTransaction;
    const position = tx.transaction.message.accountKeys.findIndex((key) => (typeof key === 'string' ? key : key.pubkey) === account);
    const held = (list: ParsedTransaction['meta']['preTokenBalances']) =>
      BigInt(list?.find((entry) => entry.accountIndex === position)?.uiTokenAmount.amount ?? '0');
    const amount = held(tx.meta.postTokenBalances) - held(tx.meta.preTokenBalances);
    if (amount > 0n) return { amount, signature };
  }
  return null;
}
