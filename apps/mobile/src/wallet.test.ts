import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

// The native side (Keychain / Keystore / OS credential store + wallet-core) is faked:
// each test installs the answers and reads back the calls.
type Call = { method: string; args: unknown[] };
const calls: Call[] = [];
const answers: Record<string, (...args: never[]) => unknown> = {};
(globalThis as typeof globalThis & { __walletNative: unknown }).__walletNative = new Proxy({}, {
  get: (_, method: string) => async (...args: unknown[]) => {
    calls.push({ method, args });
    const answer = answers[method];
    if (!answer) throw new Error(`Unexpected wallet call: ${method}`);
    return (answer as (...values: unknown[]) => unknown)(...args);
  },
});
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === '../modules/mesh-messenger/wallet' && context.parentURL?.includes('/src/wallet.ts')) {
      return { shortCircuit: true, url: 'data:text/javascript,export const walletNative = globalThis.__walletNative;' };
    }
    return nextResolve(specifier, context);
  },
});

const wallet = await import('./wallet.ts');

const hex = (text: string): Uint8Array => Uint8Array.from(text.match(/../g)!.map((pair) => parseInt(pair, 16)));
const reset = (): void => { calls.length = 0; for (const key of Object.keys(answers)) delete answers[key]; };
const u32 = (value: number): number[] => [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
const vec32 = (bytes: Uint8Array): number[] => [...u32(bytes.length), ...bytes];

// "abandon ×11 about": wallet-core's solana-keygen known answers (src/derive.rs).
const ACCOUNT_0 = 'HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk';
const ACCOUNT_0_KEY = hex('f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7');
const BOUNTY_0 = 'DZJcJWPaEvx8DB2naCC9CEDxpWcdRuiSg88N8uXRR3zo';
const BOUNTY_0_KEY = hex('ba92bd3a778c98fe31f179da063d062c625339348f6a61f749c60287be95dae0');
const USDC_KEY = hex('c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61');

test('base58 matches Solana addresses both ways and refuses anything but 32 bytes', () => {
  assert.equal(wallet.base58(ACCOUNT_0_KEY), ACCOUNT_0);
  assert.deepEqual(wallet.fromBase58(wallet.USDC_MINT), USDC_KEY);
  assert.equal(wallet.base58(new Uint8Array(32)), '1'.repeat(32));
  assert.deepEqual(wallet.fromBase58('1'.repeat(32)), new Uint8Array(32));
  const leading = Uint8Array.of(0, 0, ...BOUNTY_0_KEY.subarray(2));
  assert.deepEqual(wallet.fromBase58(wallet.base58(leading)), leading);
  assert.throws(() => wallet.fromBase58('0OIl'), /bad_base58/);
  assert.throws(() => wallet.fromBase58('1111'), /bad_base58/);
});

test('addresses name the account or bounty key and only ever get public keys back', async () => {
  reset();
  answers.walletCall = (op: number, body: Uint8Array) =>
    op === 4 && body[0] === 1 ? ACCOUNT_0_KEY : BOUNTY_0_KEY;
  assert.equal(await wallet.walletAddress(), ACCOUNT_0);
  assert.equal(await wallet.walletAddress({ kind: 'bounty', index: 0x01020304 }), BOUNTY_0);
  assert.deepEqual(calls.map((call) => [call.args[0], [...(call.args[1] as Uint8Array)]]), [
    [4, [1, 0, 0, 0, 0]],
    [4, [2, 1, 2, 3, 4]],
  ]);
  answers.walletCall = () => new Uint8Array(31);
  await assert.rejects(wallet.walletAddress(), /bad_frame/);
});

test('the next bounty address comes from the host, which advances its index first', async () => {
  reset();
  answers.walletNextBountyAddress = () => Uint8Array.of(...u32(7), ...BOUNTY_0_KEY);
  assert.deepEqual(await wallet.nextBountyAddress(), { index: 7, address: BOUNTY_0 });
  // Listing derives only the indexes already handed out.
  answers.walletBountyIndex = () => 2;
  answers.walletCall = () => BOUNTY_0_KEY;
  assert.deepEqual(await wallet.bountyAddresses(), [{ index: 0, address: BOUNTY_0 }, { index: 1, address: BOUNTY_0 }]);
  assert.deepEqual(calls.map((call) => call.method), ['walletNextBountyAddress', 'walletBountyIndex', 'walletCall', 'walletCall']);
  assert.deepEqual(calls[1]!.args, [0]);
  assert.deepEqual([...(calls[3]!.args[1] as Uint8Array)], [2, 0, 0, 0, 1]);
});

test('a bounty move is signed with the bounty key as owner and an account paying the fee', async () => {
  reset();
  answers.walletCall = () => Uint8Array.of(...vec32(new TextEncoder().encode('sig')), ...vec32(new TextEncoder().encode('dHg=')));
  const blockhash = wallet.base58(new Uint8Array(32).fill(9));
  const reference = wallet.base58(new Uint8Array(32).fill(4));
  const signed = await wallet.signTransfer({
    owner: { kind: 'bounty', index: 3 },
    feePayer: 0,
    asset: { kind: 'spl', mint: wallet.USDC_MINT, decimals: 6 },
    amount: 1_500_000n,
    recipient: ACCOUNT_0,
    createRecipientAccount: true,
    references: [reference],
    memo: 'hi',
    computeUnitLimit: 200_000,
    computeUnitPrice: 5n,
    blockhash,
  });
  assert.deepEqual(signed, { signature: 'sig', transaction: 'dHg=' });
  assert.equal(calls[0]!.args[0], 5);
  assert.deepEqual([...(calls[0]!.args[1] as Uint8Array)], [
    2, 0, 0, 0, 3, // owner: bounty 3
    1, 0, 0, 0, 0, // fee payer: account 0
    2, ...USDC_KEY, 6, // SPL, mint, decimals
    0, 0, 0, 0, 0, 0x16, 0xe3, 0x60, // 1.5 USDC
    ...ACCOUNT_0_KEY,
    1, // create the recipient's token account
    1, ...new Uint8Array(32).fill(4),
    0, 0, 0, 2, 104, 105,
    0, 3, 0x0d, 0x40,
    0, 0, 0, 0, 0, 0, 0, 5,
    ...new Uint8Array(32).fill(9),
  ]);
  answers.walletCall = () => Uint8Array.of(...vec32(new TextEncoder().encode('sig')));
  await assert.rejects(wallet.signTransfer({
    owner: { kind: 'account', index: 0 }, feePayer: 0, asset: { kind: 'sol' }, amount: 1n, recipient: ACCOUNT_0,
    createRecipientAccount: false, references: [], memo: '', computeUnitLimit: 0, computeUnitPrice: 0n, blockhash,
  }), /bad_frame/);
});

test('a Solana Pay URL is parsed by wallet-core and read back field by field', async () => {
  reset();
  const refs = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
  const text = (value: string) => vec32(new TextEncoder().encode(value));
  answers.walletCall = () => Uint8Array.of(
    ...ACCOUNT_0_KEY, 1, 0, 0, 0, 0, 0, 0, 0, 15, 1, 1, ...USDC_KEY, 2, ...refs[0]!, ...refs[1]!,
    ...text('Morse credits'), ...text(''), ...text('order 7'),
  );
  const url = `solana:${ACCOUNT_0}?amount=1.5&spl-token=${wallet.USDC_MINT}`;
  const request = await wallet.parsePayUrl(url);
  assert.deepEqual([...(calls[0]!.args[1] as Uint8Array)], vec32(new TextEncoder().encode(url)));
  assert.deepEqual(request, {
    recipient: ACCOUNT_0,
    amount: { mantissa: 15n, scale: 1 },
    splToken: wallet.USDC_MINT,
    references: refs.map(wallet.base58),
    label: 'Morse credits',
    message: '',
    memo: 'order 7',
  });
  assert.equal(wallet.baseUnits(request.amount!, 6), 1_500_000n);
  assert.throws(() => wallet.baseUnits({ mantissa: 1n, scale: 7 }, 6), /too_many_decimals/);
  answers.walletCall = () => Uint8Array.of(...ACCOUNT_0_KEY, 0, 0, 0, ...text(''), ...text(''));
  await assert.rejects(wallet.parsePayUrl(url), /bad_frame/);
});
