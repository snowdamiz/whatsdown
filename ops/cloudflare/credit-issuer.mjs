import { bearerMatches } from './edge.mjs';

// The credit issuer (services/credit-issuer) deploys on its own, like the push
// broker: it holds the key-wrapping seed that opens its signing keys, the
// treasury deposit seed and its own database, and nothing of the backend's.
// Buyers reach it only through the privacy edge, which presents
// MORSE_CREDIT_EDGE_TOKEN, so the issuer never sees a buyer's connection.

const issuerRoutes = new Set(['POST /v1/credits/quote', 'POST /v1/credits/issue']);

// Settings the container may receive; nothing else passes, so an
// over-provisioned deployment still gives it only its own.
const optionalSettings = ['MORSE_CREDIT_ASSETS', 'MORSE_CREDIT_SOLANA_RPC_URL', 'MORSE_CREDIT_USDC_MINT',
  'MORSE_CREDIT_ORACLE_URL', 'MORSE_CREDIT_LND_URL', 'MORSE_CREDIT_LND_MACAROON_HEX',
  'MORSE_CREDIT_TREASURY_ADDRESS', 'MORSE_CREDIT_TREASURY_USDC_ACCOUNT', 'MORSE_CREDIT_SWEEP',
  'MORSE_CREDIT_SWEEP_MIN_DELAY_S', 'MORSE_CREDIT_SWEEP_MAX_DELAY_S', 'MORSE_CREDIT_SETTLEMENT_SPLIT',
  'MORSE_CREDIT_MAX_OPEN_QUOTES', 'MESSENGER_ABUSE_DIFFICULTY'];

export const creditIssuerSecrets = ['CREDIT_DATABASE_URL', 'MORSE_CREDIT_KEY_WRAPPING_SEED_HEX',
  'MORSE_CREDIT_DEPOSIT_SEED_HEX', 'MORSE_CREDIT_ISSUER_INTERNAL_TOKEN', 'MORSE_CREDIT_EDGE_TOKEN',
  'MORSE_CREDIT_LND_MACAROON_HEX'];

export function creditIssuerContainerEnv(env) {
  const mode = env.MORSE_CREDITS_MODE ?? 'off';
  if (!['off', 'test', 'live'].includes(mode)) throw new Error('MORSE_CREDITS_MODE must be off, test or live');
  if (!env.CREDIT_DATABASE_URL) throw new Error('Missing CREDIT_DATABASE_URL');
  const needed = mode === 'off' ? [] : ['MORSE_CREDIT_ISSUER_NAME', 'MORSE_CREDIT_KEY_WRAPPING_SEED_HEX',
    'MORSE_CREDIT_DIRECTORY_URL', 'MORSE_CREDIT_ISSUER_INTERNAL_TOKEN'];
  for (const name of needed) if (!env[name]) throw new Error(`Missing ${name}`);
  const pass = names => Object.fromEntries(names.filter(name => env[name] !== undefined && env[name] !== '').map(name => [name, String(env[name])]));
  return {
    MORSE_CREDITS_MODE: mode,
    MORSE_CREDIT_DATABASE_URL: env.CREDIT_DATABASE_URL,
    ...pass(['MORSE_CREDIT_ISSUER_NAME', 'MORSE_CREDIT_KEY_WRAPPING_SEED_HEX', 'MORSE_CREDIT_DEPOSIT_SEED_HEX',
      'MORSE_CREDIT_DIRECTORY_URL', 'MORSE_CREDIT_ISSUER_INTERNAL_TOKEN']),
    ...pass(optionalSettings),
  };
}

// The issuer Worker's routes: health for anyone, the two purchase routes only
// with the edge's bearer (when one is set). A Response when refused, else the
// request for the container: the body and its type, no client header.
export function issuerIngress(request, env) {
  const url = new URL(request.url);
  const route = `${request.method} ${url.pathname}`;
  if (route === 'GET /health' && !url.search) return new Request(url, { method: 'GET' });
  if (!issuerRoutes.has(route) || url.search) return new Response(null, { status: 404 });
  if (!env.MORSE_CREDIT_EDGE_TOKEN) return new Response(null, { status: 503 });
  if (!bearerMatches(request, env.MORSE_CREDIT_EDGE_TOKEN)) return new Response(null, { status: 401 });
  return new Request(url, { method: 'POST', body: request.body, duplex: 'half', redirect: 'manual',
    headers: { 'content-type': 'application/octet-stream' } });
}
