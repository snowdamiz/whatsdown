import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { readFile } from 'node:fs/promises';
import { createKeyPairSignerFromPrivateKeyBytes, getBase58Encoder } from '@solana/kit';
import { signAnchorPost, signAnchorCosigns } from './anchor-transactions.mjs';
import { openAnchorAccounts } from './anchor-accounts.mjs';
import { createAnchorDirectory } from './anchor-directory.mjs';

test('Mesh instruction bytes and Kit signatures execute in the actual judge SBF with real Ed25519 verification', {
  skip: !process.env.MORSE_ANCHOR_SBF_BRIDGE || !process.env.MORSE_ANCHOR_WORK_PATH,
  timeout: 120_000,
}, async () => {
  const fixtures = JSON.parse(await readFile(process.env.MORSE_ANCHOR_WORK_PATH, 'utf8'));
  const feePayer = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(41));
  const anchorAuthority = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(42));
  for (const fixture of fixtures.flatMap(value=>[false,true].map(attendance=>({...value,attendance})))) {
    const child = spawn(process.env.MORSE_ANCHOR_SBF_BRIDGE, [], { stdio: ['pipe', 'pipe', 'inherit'] });
    const completion = new Promise((resolve, reject) => {
      child.once('exit', code => code === 0 ? resolve() : reject(new Error(`SBF bridge exit ${code}`)));
      child.once('error', reject);
    });
    completion.catch(() => {}); // The finally block below observes startup failures too.
    const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
    const call = async request => {
      child.stdin.write(JSON.stringify(request) + '\n');
      const response = await lines.next();
      assert.equal(response.done, false, 'SBF bridge stopped');
      return JSON.parse(response.value);
    };
    try {
      const setup = await call({ method: 'initialize', version: fixture.version, service: fixture.service_key,
        witness: fixture.witness_key, payer: feePayer.address, authority: anchorAuthority.address, attendance:fixture.attendance });
      const accounts = { ...setup, feePayer, anchorAuthority };
      const rpc = {getAccountInfo:(address, options)=>({send:async()=> {
        const response = await call({method:'account',address,offset:Number(options.dataSlice.offset),length:Number(options.dataSlice.length)});
        response.context.slot = BigInt(response.context.slot);
        if (response.value) {
          response.value.space = BigInt(response.value.space);
          response.value.lamports = BigInt(response.value.lamports);
        }
        return response;
      }})};
      const reader = await openAnchorAccounts(rpc,{program:setup.program,logName:'morse-main',version:fixture.version,
        serviceKey:fixture.service_key,authority:anchorAuthority.address,origin:fixture.version === 2 ? 'morseapp.io/log/main/v2' : ''});
      const lifetime = async () => ({ ...(await call({ method: 'context' })), lastValidBlockHeight: 1000n });
      const send = async transaction => call({ method: 'send', transaction: transaction.wire });
      accounts.attendance=await reader.attendanceForPost();
      const postTransaction = await signAnchorPost(fixture.post, accounts, await lifetime());
      const first = await send(postTransaction);
      assert.equal(first.ok, true, JSON.stringify(first));
      assert.equal(first.fee_lamports, 15_000, 'two wallet signatures plus the service Ed25519 verification');
      assert.equal(first.count, 1);
      assert.equal(first.checkpoint_hash, fixture.checkpoint_hash);
      const intent = {kind:'post',version:fixture.version,checkpointHash:fixture.checkpoint_hash,
        sequence:fixture.post.sequence,treeSize:fixture.post.tree_size};
      assert.deepEqual(await reader.readback(intent,{minContextSlot:100n}),{slot:'100',ringIndex:0});
      const expectedReceipt = Buffer.from(fixture.receipt,'hex');
      expectedReceipt.set(getBase58Encoder().encode(postTransaction.signature),56);
      let recorded = false;
      const directory = createAnchorDirectory({MESSENGER_DELIVERY_INTERNAL_TOKEN:'11'.repeat(32),
        DIRECTORY:{getByName:()=>({fetch:async(url,request)=> {
          assert.equal(url,'http://service/internal/v1/transparency/anchors');
          assert.deepEqual(Buffer.from(request.body),expectedReceipt,'writer receipt agrees with the Mesh codec');
          recorded = true;
          return new Response(null,{status:201});
        }})}}, {version:fixture.version,serviceKey:fixture.service_key,logId:reader.logId});
      await directory.record(intent,{...await reader.readback(intent,{minContextSlot:100n}),signature:postTransaction.signature});
      assert.equal(recorded,true);
      assert.equal((await reader.witnessSet(7)).address,setup.generation);
      const replay = await send(await signAnchorPost(fixture.post, accounts, await lifetime()));
      assert.equal(replay.ok, true, JSON.stringify(replay));
      assert.equal(replay.count, 1);
      assert.equal(replay.slot, first.slot);
      accounts.attendance=await reader.attendanceForCosign({ringIndex:0,slot:'100'});
      if (fixture.c2sp) {
        const [transaction] = await signAnchorCosigns([fixture.c2sp], accounts, await lifetime());
        const result = await send(transaction);
        assert.equal(result.ok, true, JSON.stringify(result));
        assert.equal(result.cosign_bitmap, 1);
        assert.equal(result.native_bitmap, 0);
      }
      // These precompiles are valid on their own. The judge must still bind
      // the witness key and reconstructed native statement, not just execute one.
      for (const ed25519 of [fixture.post.ed25519, ...(fixture.c2sp ? [fixture.c2sp.ed25519] : [])]) {
        const [transaction] = await signAnchorCosigns([{ ...fixture.native, ed25519 }], accounts, await lifetime());
        const refused = await send(transaction);
        assert.equal(refused.ok, false, JSON.stringify(refused));
        assert.equal(refused.native_bitmap, 0);
      }
      const altered = Buffer.from(fixture.native.ed25519, 'hex');
      altered[altered.length - 1] ^= 1;
      const [bad] = await signAnchorCosigns([{ ...fixture.native, ed25519: altered.toString('hex') }], accounts, await lifetime());
      const refused = await send(bad);
      assert.equal(refused.ok, false, JSON.stringify(refused));
      assert.equal(refused.native_bitmap, 0);
      const [native] = await signAnchorCosigns([fixture.native], accounts, await lifetime());
      const result = await send(native);
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(result.cosign_bitmap, 1);
      assert.equal(result.native_bitmap, 1);
      assert.equal(result.fee_lamports, 10_000, 'one fee payer signature plus one witness Ed25519 verification');
      assert.deepEqual(await reader.readback({...intent,kind:'cosign',ringIndex:0,slot:'100',generation:7,witnessIndices:[0]},
        {minContextSlot:100n}),{slot:'100',ringIndex:0});
      const old = Buffer.from(fixture.native.instruction, 'hex');
      old[0] = 7;
      const legacy = { ...fixture.native, instruction: Buffer.concat([old,
        Buffer.from(fixture.native.ed25519, 'hex').subarray(48, 112)]).toString('hex') };
      const [compatible] = await signAnchorCosigns([legacy], accounts, await lifetime());
      assert.equal((await send(compatible)).ok, true, 'existing native tag 7 remains accepted');
      if(fixture.attendance) {
        const response=await call({method:'account',address:accounts.attendance.epoch,offset:0,length:2640});
        const bytes=Buffer.from(response.value.data[0],'base64');
        assert.equal(bytes.readBigUInt64LE(44),1n,'duplicate posts count once');
        assert.equal(bytes.readUInt16LE(60),1);
        assert.equal(bytes.readBigUInt64LE(112),1n,'native, compact and C2SP cosigns share one attendance bit');
      }
    } finally {
      child.stdin.end();
      await completion;
    }
  }
});
