import assert from 'node:assert/strict';
import securityConfig from '../../mobile/plugins/security-config.cjs';
import networkCounterConfig from '../../mobile/plugins/network-counter-config.cjs';
import creditPurpose from '../../mobile/plugins/credits-config.cjs';
import networkConfig from '../../mobile/plugins/network-config.cjs';
import issuerTLSRoot from '../../mobile/plugins/issuer-tls-root.cjs';
import ohttpConfig from '../../mobile/plugins/ohttp-config.cjs';
import rpcTLSRoots from '../../mobile/plugins/rpc-tls-roots.cjs';

export function windowsSigningConfig(env) {
  assert.ok(env.WINDOWS_SIGN_COMMAND?.includes('%1'), 'Set WINDOWS_SIGN_COMMAND with the Tauri %1 file placeholder');
  assert.match(env.WINDOWS_SIGNER_THUMBPRINT ?? '', /^[A-Fa-f0-9]{40}$/, 'Set WINDOWS_SIGNER_THUMBPRINT to the expected signing certificate');
  return { bundle: { windows: { signCommand: env.WINDOWS_SIGN_COMMAND, digestAlgorithm: 'sha256' } } };
}

export function checkMacSigning(env) {
  for (const name of ['APPLE_CERTIFICATE', 'APPLE_CERTIFICATE_PASSWORD', 'APPLE_SIGNING_IDENTITY',
    'APPLE_ID', 'APPLE_PASSWORD', 'APPLE_TEAM_ID']) {
    assert.ok(env[name]?.trim(), `Set the ${name} GitHub Actions secret for signed Mac releases`);
  }
  assert.match(env.APPLE_SIGNING_IDENTITY, /^Developer ID Application: .+ \([A-Z0-9]{10}\)$/, 'Use a Developer ID Application signing identity');
  assert.match(env.APPLE_TEAM_ID, /^[A-Z0-9]{10}$/, 'Invalid APPLE_TEAM_ID');
}

export function desktopConfig(env, development = false) {
  function endpoint(value, stream = false) {
    const url = new URL(value);
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    assert.ok(!url.username && !url.password && !url.search && !url.hash, 'Invalid service URL');
    assert.ok(url.protocol === (stream ? 'wss:' : 'https:') ||
      (development && local && url.protocol === (stream ? 'ws:' : 'http:')), 'Services require TLS');
    return url.toString().replace(/\/$/, '');
  }
  const baseUrl = endpoint(env.EXPO_PUBLIC_MESSENGER_BASE_URL ?? (development ? 'http://127.0.0.1:18086' : ''));
  const edgeUrl = endpoint(env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL ?? (development ? 'http://127.0.0.1:18087' : ''));
  const streamUrl = endpoint(env.EXPO_PUBLIC_MESSENGER_STREAM_URL ||
    (development && !env.EXPO_PUBLIC_MESSENGER_BASE_URL
      ? 'ws://127.0.0.1:18090/v1/mailbox/stream'
      : `${baseUrl.replace(/^http/, 'ws')}/v1/mailbox/stream`), true);
  // The production worker serves object routes on the messenger origin; local
  // development runs the object store as its own service.
  const objectUrl = endpoint(env.EXPO_PUBLIC_MESSENGER_OBJECT_URL ||
    (development && !env.EXPO_PUBLIC_MESSENGER_BASE_URL ? 'http://127.0.0.1:18089' : baseUrl));
  const securityFrame = securityConfig(env, { development }) ?? '';
  assert.ok(development || securityFrame, 'Set the MESSENGER security pins before building a release');
  const purpose = creditPurpose(env) ?? '';
  const networkFrame = networkConfig({ EXPO_PUBLIC_MESSENGER_BASE_URL: baseUrl,
    EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL: edgeUrl, EXPO_PUBLIC_MESSENGER_OBJECT_URL: objectUrl,
    EXPO_PUBLIC_MESSENGER_STREAM_URL: streamUrl,
    EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY: env.EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY }, { development });
  const ohttpFrame = ohttpConfig(env, networkFrame, securityFrame);
  const rpcRoots = rpcTLSRoots(env, securityFrame);
  return { baseUrl, edgeUrl, streamUrl, objectUrl, securityFrame, ohttpFrame, networkCounterFrame: networkCounterConfig(env, securityFrame), creditPurpose: purpose,
    ...(rpcRoots ? { rpcTlsRoots: rpcRoots.toString('base64') } : {}),
    issuerTlsRoot: issuerTLSRoot(env)?.toString('base64') ?? '',
    creditIssuerOrigin: purpose && env.MESSENGER_CREDIT_ISSUER_ORIGIN !== '-' ? env.MESSENGER_CREDIT_ISSUER_ORIGIN ?? '' : '',
    lightningNetwork: creditPurpose.lightningNetwork(env) ?? '',
    creditUsdcMintHex: creditPurpose.walletMint(env) ?? '', networkFrame, development };
}
