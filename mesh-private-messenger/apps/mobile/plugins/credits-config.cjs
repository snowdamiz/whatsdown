// This value enters signed native resources only. OTA JavaScript cannot select
// a credit purpose or enable an issuer disabled by the security frame.
module.exports = function creditPurpose(environment) {
  const purpose = environment.MESSENGER_CREDIT_PURPOSE;
  if (purpose === undefined) return undefined;
  if (purpose !== 'live' && purpose !== 'test') throw new Error('MESSENGER_CREDIT_PURPOSE must be live or test');
  const origin = environment.MESSENGER_CREDIT_ISSUER_ORIGIN;
  // Wallet custody and bounty addresses remain local capabilities while the
  // issuer kill-switch is off. Mesh still requires an active pinned origin
  // before any credit purchase or spend; a purpose alone cannot enable it.
  if (origin === undefined || origin === '-') return purpose;
  let url;
  try { url = new URL(origin); } catch { throw new Error('Credits require a pinned HTTPS issuer origin'); }
  if (url.protocol !== 'https:' || origin !== url.origin || url.username || url.password ||
      environment.MESSENGER_TRANSPARENCY_LOG_VERSION !== '2') {
    throw new Error('Credits require a pinned HTTPS issuer origin and RFC transparency log');
  }
  return purpose;
};

module.exports.walletMint = function walletMint(environment) {
  const value = environment.MESSENGER_CREDIT_USDC_MINT_ADDRESS;
  if (value === undefined) return undefined;
  if (!module.exports(environment)) throw new Error('A wallet mint requires native credit purpose configuration');
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  if (typeof value !== 'string' || value.length < 32 || value.length > 44) throw new Error('Invalid native USDC mint address');
  let number = 0n;
  for (const char of value) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) throw new Error('Invalid native USDC mint address');
    number = number * 58n + BigInt(digit);
  }
  if (number === 0n) throw new Error('Native USDC mint cannot be zero');
  let hex = number.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const leading = /^1*/.exec(value)[0].length;
  if (leading + hex.length / 2 !== 32) throw new Error('Native USDC mint must encode exactly32bytes');
  return '00'.repeat(leading) + hex;
};

module.exports.lightningNetwork = function lightningNetwork(environment) {
  const value = environment.MESSENGER_CREDIT_LIGHTNING_NETWORK;
  if (value === undefined) return undefined;
  const purpose = module.exports(environment);
  if ((purpose === 'live' && value === 'mainnet') ||
      (purpose === 'test' && ['testnet', 'regtest', 'signet', 'simnet'].includes(value))) return value;
  throw new Error('Native Lightning network must match the configured credit purpose');
};
