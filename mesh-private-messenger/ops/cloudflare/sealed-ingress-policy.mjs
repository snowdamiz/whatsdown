import { httpsOrigin } from './witness.mjs';

const policyNames = ['MORSE_SEALED_INGRESS_MTLS', 'MORSE_SEALED_INGRESS_ORIGIN', 'MORSE_EDGE_CLIENT_CERT_SHA256'];

export function sealedIngressMtlsConfigured(env) {
  return policyNames.some(name => env[name] !== undefined);
}

// Opt-in backend gate only. This does not make Cloudflare's outbound mTLS
// binding compatible with a Cloudflare-proxied Worker target. See INGRESS_MTLS.md.
export function sealedIngressMtlsConfig(env) {
  if (!sealedIngressMtlsConfigured(env)) return null;
  const origin = env.MORSE_SEALED_INGRESS_ORIGIN;
  const fingerprint = env.MORSE_EDGE_CLIENT_CERT_SHA256;
  let canonical;
  try { canonical = httpsOrigin(origin); } catch { /* fail closed below */ }
  if (env.MORSE_SEALED_INGRESS_MTLS !== 'required' || typeof origin !== 'string' || !canonical || canonical !== origin ||
      typeof fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(fingerprint)) {
    throw new Error('Invalid sealed ingress mTLS policy');
  }
  return { MORSE_SEALED_INGRESS_MTLS: 'required', MORSE_SEALED_INGRESS_ORIGIN: origin, MORSE_EDGE_CLIENT_CERT_SHA256: fingerprint };
}

export function sealedIngressClientAllowed(request, env) {
  let policy;
  try { policy = sealedIngressMtlsConfig(env); } catch { return false; }
  if (!policy) return true; // Preserve the existing, explicitly non-mTLS development topology.
  if (new URL(request.url).origin !== policy.MORSE_SEALED_INGRESS_ORIGIN) return false;
  // Only Cloudflare's connection metadata is authoritative. Never use a
  // forwarded HTTP certificate/fingerprint header, including RFC9440 headers.
  const tls = request.cf?.tlsClientAuth;
  return tls?.certPresented === '1' && tls.certVerified === 'SUCCESS' && tls.certRevoked === '0' &&
    tls.certFingerprintSHA256 === policy.MORSE_EDGE_CLIENT_CERT_SHA256;
}

export function assertSealedEdgeTopology(env, config = {}) {
  if (sealedIngressMtlsConfigured(env) || env.MORSE_EDGE_MTLS_CERTIFICATE_ID !== undefined ||
      env.SEALED_INGRESS_MTLS !== undefined || config.mtls_certificates?.length) {
    throw new Error('Worker-to-Worker mTLS is unsupported by the current Cloudflare outbound binding; no sealed-ingress fallback is allowed');
  }
}
