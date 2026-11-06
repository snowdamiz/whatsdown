import assert from 'node:assert/strict';
import { ohttpRelayResponse } from './ohttp.mjs';

assert.equal(typeof global.gc, 'function');
global.gc();
const baseline = process.memoryUsage().heapUsed;
let peak = baseline;
let chunks = 0;
const byte = new Uint8Array([91]);
const result = await ohttpRelayResponse(new Response(new ReadableStream({
  pull(controller) {
    if (chunks === 50_000) return controller.close();
    if (++chunks % 5_000 === 0) {
      global.gc();
      peak = Math.max(peak, process.memoryUsage().heapUsed);
    }
    controller.enqueue(byte);
  },
}), { headers: { 'Content-Type': 'message/ohttp-res', 'Cache-Control': 'no-store' } }));
const body = new Uint8Array(await result.arrayBuffer());
const metrics = { status: result.status, chunks, bytes: body.length, retainedHeapIncrease: peak - baseline };
console.log(JSON.stringify(metrics));
assert.equal(result.status, 200);
assert.equal(body.length, 50_000);
assert.ok(body.every(value => value === 91));
// A deliberately generous margin around the 1-MiB buffers/runtime setup.
// Retaining one abort reaction per chunk used >30 MiB for only 50 KiB.
assert.ok(peak - baseline < 16 * 1024 * 1024, 'tiny chunks retain unbounded per-read state');
