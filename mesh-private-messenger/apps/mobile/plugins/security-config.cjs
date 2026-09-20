const SECURITY_FIELDS = [
  'MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX',
  'MESSENGER_WITNESS_A_PUBLIC_KEY_HEX',
  'MESSENGER_WITNESS_B_PUBLIC_KEY_HEX',
  'MESSENGER_DELIVERY_PUBLIC_KEY_HEX',
  'MESSENGER_ABUSE_DIFFICULTY',
];


module.exports = function securityConfig(environment) {
  const securityProvisioned = SECURITY_FIELDS.some(
    (name) => environment[name] !== undefined,
  );
  let securityFrame;
  if (securityProvisioned) {
    for (const name of SECURITY_FIELDS.slice(0, 4)) {
      if (!/^[0-9a-f]{64}$/.test(environment[name] ?? '')) {
        throw new Error(`${name} must be a 32-byte lowercase-hex key`);
      }
    }
    if (
      !/^([1-9]|1[0-9]|2[0-4])$/.test(
        environment.MESSENGER_ABUSE_DIFFICULTY ?? '',
      )
    ) {
      throw new Error(
        'MESSENGER_ABUSE_DIFFICULTY must be a canonical integer from 1 through 24',
      );
    }
    if (
      environment.MESSENGER_WITNESS_A_PUBLIC_KEY_HEX ===
      environment.MESSENGER_WITNESS_B_PUBLIC_KEY_HEX
    ) {
      throw new Error('MESSENGER witness public keys must be distinct');
    }
    securityFrame = `1\n${SECURITY_FIELDS.map((name) => environment[name]).join(
      '\n',
    )}`;
  }
  return securityFrame;
};
