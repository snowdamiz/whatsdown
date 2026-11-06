const fs = require('node:fs');
const { X509Certificate } = require('node:crypto');

// Build inputs are files, never runtime trust stores. Bound reads before parsing
// and use O_NONBLOCK so a mistaken FIFO cannot hang a native build.
function readBoundedFile(file, maximum, label) {
  if (typeof file !== 'string' || !file) throw new Error(`Provide a build-only ${label} file`);
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  try {
    if (!fs.fstatSync(descriptor).isFile()) throw new Error(`${label} must be a regular file`);
    const bounded = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < bounded.length) {
      const count = fs.readSync(descriptor, bounded, length, bounded.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length < 1 || length > maximum) throw new Error(`${label} must contain 1–${maximum} bytes`);
    return bounded.subarray(0, length);
  } finally { fs.closeSync(descriptor); }
}

function readCaPEM(file) {
  const pem = readBoundedFile(file, 65536, 'CA PEM');
  if (pem.some(byte => byte > 127)) throw new Error('CA PEM must be ASCII');
  let remainder = pem.toString('ascii').trim();
  let count = 0;
  while (remainder) {
    const match = /^-----BEGIN CERTIFICATE-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END CERTIFICATE-----/.exec(remainder);
    if (!match || ++count > 8) throw new Error('Provide only 1–8 PEM CA certificates');
    const base64 = match[1].replace(/[\r\n]/g, '');
    const der = Buffer.from(base64, 'base64');
    if (!base64 || der.toString('base64') !== base64) throw new Error('CA certificate encoding is invalid');
    const certificate = new X509Certificate(der);
    if (!certificate.ca || !certificate.raw.equals(der)) throw new Error('Trust roots must be exact CA certificates');
    remainder = remainder.slice(match[0].length).trim();
  }
  if (!count) throw new Error('Provide 1–8 PEM CA certificates');
  return pem;
}

module.exports = { readBoundedFile, readCaPEM };
