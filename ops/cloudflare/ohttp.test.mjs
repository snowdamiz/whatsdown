import assert from 'node:assert/strict';
import test from 'node:test';
import {
  decapsulateResponse, decodeKeyConfig, decodeKeys, decodeResponse, encapsulateRequest, encapsulateResponse,
  encodeRequest, hex, hpke, x25519Public,
} from './ohttp.mjs';

test('HPKE matches RFC 9180 A.2.1 (X25519, HKDF-SHA256, ChaCha20-Poly1305)', () => {
  const suite = hpke(3);
  const skE = suite.deriveKeyPair(hex('909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b'));
  assert.equal(skE.toString('hex'), 'f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600');
  const sender = suite.setupSender(skE, hex('4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a'),
    hex('4f6465206f6e2061204772656369616e2055726e'));
  assert.equal(sender.enc.toString('hex'), '1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a');
  assert.equal(sender.key.toString('hex'), 'ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91');
  assert.equal(sender.baseNonce.toString('hex'), '5c4d98150661b848853b547f');
  assert.equal(sender.exporterSecret.toString('hex'), 'a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922');
  assert.equal(sender.export(Buffer.from('TestContext'), 32).toString('hex'),
    '5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53');
});

const skR = hex('3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a');
const skE = hex('bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73');
const request = hex('00034745540568747470730b6578616d706c652e636f6d012f');

test('OHTTP matches RFC 9458 Appendix A, and Morse\'s ChaCha20-Poly1305 exchange the Mesh gateway opens', () => {
  const rfc = decodeKeyConfig(hex('01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003'));
  assert.deepEqual(rfc.suites, [[1, 1], [1, 3]]);
  assert.deepEqual(Buffer.from(rfc.publicKey), x25519Public(skR));
  const aes = encapsulateRequest(rfc, request, { aead: 1, ephemeral: skE });
  assert.equal(aes.encapsulated.toString('hex'),
    '010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525');
  const response = encapsulateResponse(aes.context, hex('0140c8'), hex('c789e7151fcba46158ca84b04464910d'));
  assert.equal(response.toString('hex'), 'c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd');
  assert.equal(decapsulateResponse(aes.context, response).toString('hex'), '0140c8');
  // packages/messenger-protocol/tests/ohttp.test.mpl pins these bytes.
  const morse = encapsulateRequest(rfc, request, { ephemeral: skE });
  assert.equal(morse.encapsulated.toString('hex'),
    '010020000100034b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472c956d3d9bc7cb56a25766a5ad36c4d5c3f40480e331005e514b03bd29c38e1dc74753d6e1c310fdd7f');
  const nonce = Buffer.concat([hex('c789e7151fcba46158ca84b04464910d'), hex('c789e7151fcba46158ca84b04464910d')]);
  assert.equal(encapsulateResponse(morse.context, hex('0140c8'), nonce).toString('hex'),
    'c789e7151fcba46158ca84b04464910dc789e7151fcba46158ca84b04464910d682d0cfaf89cd461faeca9b2451f504fc3d432');
  const tampered = encapsulateResponse(morse.context, hex('0140c8'));
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => decapsulateResponse(morse.context, tampered));
});

test('Binary HTTP requests pad to their bucket and responses read the RFC 9292 example', () => {
  const lookup = encodeRequest('POST', '/v1/devices/resolve', Buffer.from('al'));
  assert.equal(lookup.length, 256);
  assert.equal(lookup.subarray(0, 6).toString('hex'), '0004504f5354');
  const figure13 = decodeResponse(hex('0140c8001d5468697320636f6e74656e7420636f6e7461696e732043524c462e0d0a0d07747261696c65720474657874'));
  assert.equal(figure13.status, 200);
  assert.equal(figure13.content.toString(), 'This content contains CRLF.\r\n');
  assert.deepEqual(decodeResponse(hex('0140670040c800')).status, 200);
  const list = decodeKeys(Buffer.concat([hex('0029'), hex('01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155000400010003')]));
  assert.equal(list.length, 1);
  assert.equal(decodeKeyConfig(list[0]).keyId, 1);
  assert.throws(() => decodeKeys(hex('0029')));
});
