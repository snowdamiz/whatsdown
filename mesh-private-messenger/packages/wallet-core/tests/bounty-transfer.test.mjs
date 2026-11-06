// Public repeated01 fixture seed only; independent Kit and Node/OpenSSL signing
// followed by real SPL/ATA execution. Never uses RPC or real funds.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac, createPrivateKey, createPublicKey, sign, verify} from 'node:crypto';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const product = path.resolve(import.meta.dirname, '../../..');
const kit = createRequire(path.join(product, 'ops/rewards/package.json'))('@solana/kit');
const bridge = process.env.WALLET_FIXTURE_BRIDGE ?? path.join(product, 'packages/wallet-core/target/debug/examples/wallet_fixture_bridge');
const oracle = process.env.WALLET_PAYMENT_ORACLE ?? path.join(product, 'programs/target/debug/examples/credit_payment_fixture');
const SYSTEM = kit.address('11111111111111111111111111111111');
const TOKEN = kit.address('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
const ATA = kit.address('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
const address = bytes => kit.getAddressDecoder().decode(bytes);
const bytes = key => Buffer.from(kit.getAddressEncoder().encode(key));
const derive = path => {
  let node = createHmac('sha512', 'ed25519 seed').update(Buffer.alloc(32, 1)).digest();
  for (const index of path) {
    const child = Buffer.alloc(37); node.copy(child, 1, 0, 32); child.writeUInt32BE(index + 0x80000000, 33);
    node = createHmac('sha512', node.subarray(32)).update(child).digest();
  }
  return node.subarray(0, 32);
};
const privateKey = seed => createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), seed]), format:'der', type:'pkcs8'});
const publicKey = seed => createPublicKey(privateKey(seed));
const account = (address, role) => ({address, role});
const associated = async (owner, mint) => (await kit.getProgramDerivedAddress({programAddress:ATA, seeds:[bytes(owner),bytes(TOKEN),bytes(mint)]}))[0];
function call(binary, input) {
  const result = spawnSync(binary, [], {input:JSON.stringify(input), encoding:'utf8'});
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('bounty SDK matches independent two-signer Kit wire and executes owned finder transfers', {timeout:120000}, async () => {
  const feeSeed = derive([44,501,0,0]);
  const feeSigner = await kit.createKeyPairSignerFromPrivateKeyBytes(feeSeed);
  const now = Math.floor(Date.now()/1000), hash = address(Buffer.alloc(32,4));
  let executions = 0, replays = 0;
  for (const spec of [
    {index:0, amount:1n, decimals:6, mintTag:7, toWallet:true},
    {index:1, amount:9007199254740993n, decimals:6, mintTag:7, existing:true},
    {index:2, amount:18446744073709551614n, decimals:0, mintTag:11, prefund:1},
    {index:3, amount:100000000000000001n, decimals:18, mintTag:12, existing:true},
  ]) {
    const finderSeed = derive([44,501,2147483647,spec.index]);
    const finderSigner = await kit.createKeyPairSignerFromPrivateKeyBytes(finderSeed);
    const mint = address(Buffer.alloc(32,spec.mintTag));
    const recipient = spec.toWallet ? feeSigner.address : address(Buffer.alloc(32,40+spec.index));
    const source = await associated(finderSigner.address,mint), destination = await associated(recipient,mint);
    const input = Buffer.alloc(166); input.set(Buffer.from('01425754','hex'));
    input.writeBigUInt64BE(BigInt(spec.index),4); input.set(bytes(finderSigner.address),12);
    input.set(bytes(recipient),44); input.set(bytes(mint),76); input.writeBigUInt64BE(spec.amount,108);
    input.set(bytes(hash),116); input.writeBigUInt64BE(BigInt(now),148); input.writeBigUInt64BE(BigInt(now+300),156);
    input[164]=1; input[165]=spec.decimals;
    const actual = call(bridge,{bounty_count:spec.index+1,bounty_transfer_hex:input.toString('hex')});
    assert.equal(actual.bounties[spec.index].address_hex,bytes(finderSigner.address).toString('hex'));
    const wire = Buffer.from(actual.wire_hex,'hex'); assert.equal(wire[0],2);
    const data = Buffer.alloc(10); data[0]=12; data.writeBigUInt64LE(spec.amount,1); data[9]=spec.decimals;
    const instructions = [
      {programAddress:ATA,accounts:[account(feeSigner.address,3),account(destination,1),account(recipient,0),account(mint,0),account(SYSTEM,0),account(TOKEN,0)],data:Uint8Array.of(1)},
      {programAddress:TOKEN,accounts:[account(source,1),account(mint,0),account(destination,1),account(finderSigner.address,2)],data},
    ];
    let message = kit.createTransactionMessage({version:'legacy'});
    message = kit.setTransactionMessageFeePayerSigner(feeSigner,message);
    message = kit.setTransactionMessageLifetimeUsingBlockhash({blockhash:hash,lastValidBlockHeight:123n},message);
    message = kit.appendTransactionMessageInstructions(instructions,message);
    const compiled = kit.compileTransactionMessage(message), keys=compiled.staticAccounts;
    assert.equal(compiled.header.numSignerAccounts,2); assert.equal(compiled.header.numReadonlySignerAccounts,1);
    const writableEnd = keys.length-compiled.header.numReadonlyNonSignerAccounts;
    const compare = (a,b) => Buffer.compare(bytes(a),bytes(b));
    const ordered = [keys[0],keys[1],...keys.slice(2,writableEnd).sort(compare),...keys.slice(writableEnd).sort(compare)];
    const remap = index => ordered.indexOf(keys[index]);
    const canonical = {...compiled,staticAccounts:ordered,instructions:compiled.instructions.map(ix=>({...ix,programAddressIndex:remap(ix.programAddressIndex),accountIndices:ix.accountIndices.map(remap)}))};
    const expected = Buffer.from(kit.getCompiledTransactionMessageEncoder().encode(canonical));
    assert.deepEqual(wire.subarray(129),expected);
    for (const [index,seed] of [feeSeed,finderSeed].entries()) {
      const signature = wire.subarray(1+index*64,65+index*64);
      assert.deepEqual(signature,sign(null,expected,privateKey(seed)));
      assert.ok(verify(null,expected,publicKey(seed),signature));
    }
    assert.ok(actual.authorization_text.includes('links the one-time bounty address'));
    assert.ok(actual.authorization_text.includes(`Destination owner: ${recipient}`));
    assert.ok(actual.authorization_text.includes(`Token mint: ${mint}`));
    const fixture = {version:'legacy',asset:0,payer:feeSigner.address,source_owner:finderSigner.address,mint,source,destination,deposit:recipient,wire_hex:actual.wire_hex};
    const executed = call(oracle,{fixture,token_source_amount:(spec.amount+1n).toString(),token_decimals:spec.decimals,existing_ata:spec.existing??false,prefund:spec.prefund??0,block_time:now,replay_count:2});
    const response = JSON.parse(executed.response);
    assert.equal(response.result.meta.err,null);
    const post = response.result.meta.postTokenBalances;
    assert.equal(post.find(row=>row.owner===finderSigner.address).uiTokenAmount.amount,'1');
    assert.equal(post.find(row=>row.owner===recipient).uiTokenAmount.amount,spec.amount.toString());
    assert.equal(executed.replay_rejections,2);
    executions++; replays+=2;
  }
  const report = {schema_version:1,passed:true,fixture_seed:'public repeated01',full_kit_wire_matches:executions,independent_node_signatures:executions*2,real_spl_ata_executions:executions,duplicate_rejections:replays,above_2pow53:true,decimals:[0,6,18],real_funds:false};
  if(process.env.BOUNTY_SDK_REPORT) await fs.writeFile(process.env.BOUNTY_SDK_REPORT,JSON.stringify(report,null,2)+'\n');
  console.log('BOUNTY_SDK_JSON='+JSON.stringify(report));
});
