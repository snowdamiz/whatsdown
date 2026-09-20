const chunkSize = 900;
const maximumLength = 48_200;

// Detect mixed/corrupt frames; Mesh still authenticates the assembled protocol payload.
function checksum(value: string): string {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash = Math.imul(hash ^ value.charCodeAt(index), 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

export function qrFrames(value: string): string[] {
  if (value.length === 0 || value.length > maximumLength) throw new Error('Invalid QR payload size');
  if (value.length <= chunkSize) return [value];
  const count = Math.ceil(value.length / chunkSize);
  const id = checksum(value);
  return Array.from({ length: count }, (_, index) =>
    `mesh://part/${id}/${index}/${count}/${value.slice(index * chunkSize, (index + 1) * chunkSize)}`,
  );
}

export function createQrCollector() {
  let current = '';
  let complete = false;
  const parts = new Map<number, string>();
  return {
    reset() {
      current = '';
      complete = false;
      parts.clear();
    },
    scan(value: string): string | null {
      if (complete) return null;
      if (value.length === 0 || value.length > maximumLength) throw new Error('Invalid QR payload size');
      if (!value.startsWith('mesh://part/')) {
        complete = true;
        return value;
      }
      const match = /^mesh:\/\/part\/([0-9a-f]{8})\/(0|[1-9]\d?)\/([1-9]\d?)\/([\s\S]+)$/.exec(value);
      if (!match) throw new Error('Invalid QR fragment');
      const id = match[1]!;
      const index = Number(match[2]);
      const count = Number(match[3]);
      const chunk = match[4]!;
      if (count < 2 || count > Math.ceil(maximumLength / chunkSize) || index >= count ||
          chunk.length > chunkSize || (index < count - 1 && chunk.length !== chunkSize)) {
        throw new Error('Invalid QR fragment');
      }
      const key = `${id}/${count}`;
      if (current !== key) {
        current = key;
        parts.clear();
      }
      if (parts.has(index) && parts.get(index) !== chunk) throw new Error('Conflicting QR fragment');
      parts.set(index, chunk);
      if (parts.size !== count) return null;
      const assembled = Array.from({ length: count }, (_, part) => parts.get(part)!).join('');
      if (assembled.length > maximumLength || checksum(assembled) !== id) {
        throw new Error('QR fragments did not match. Scan again.');
      }
      complete = true;
      return assembled;
    },
  };
}
