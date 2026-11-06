import assert from 'node:assert/strict';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { closeSync, cpSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { relayArchiveArguments } from './package.mjs';

const image=process.env.MORSE_ARCHIVE_TEST_IMAGE;
if(!image)throw new Error('MORSE_ARCHIVE_TEST_IMAGE must pin the Docker archive fixture image');
const env={MORSE_SERVICES_IMAGE:image,MORSE_REVISION:'b'.repeat(40),MESH_LANG_REVISION:'c'.repeat(40),SOURCE_DATE_EPOCH:'1791490000'};
relayArchiveArguments(env);

test('the actual image source stage and normalized relay archive preserve runnable JS while excluding local secrets and tests',{timeout:240000},t=>{
  const directory=mkdtempSync(join(tmpdir(),'morse-package-proof-'));t.after(()=>rmSync(directory,{recursive:true,force:true}));
  const context=join(directory,'context'),sources=join(context,'mesh-private-messenger/ops/relay'),exported=join(directory,'exported');
  mkdirSync(sources,{recursive:true});
  const origin=fileURLToPath(new URL('../relay/',import.meta.url));
  for(const name of readdirSync(origin))if(/\.(mjs|json|md)$/.test(name))cpSync(join(origin,name),join(sources,name));
  writeFileSync(join(sources,'.env'),'not-a-real-secret');writeFileSync(join(sources,'wallet.json'),'not-a-real-wallet');
  const dockerfile=fileURLToPath(new URL('../cloudflare/Dockerfile',import.meta.url));
  execFileSync('docker',['buildx','build','--platform','linux/amd64','--target','relay-sources','--file',dockerfile,'--output',`type=local,dest=${exported}`,context],{stdio:'pipe',timeout:120000});
  const names=readdirSync(join(exported,'morse-relay'));assert.ok(!names.some(name=>name.endsWith('.test.mjs')||name==='wallet.json'||name==='.env'||name==='node_modules'));
  // The native binary is deliberately a fixture. This proof tests distribution
  // and source completeness, not Linux Mesh ABI or a reviewed release image.
  const native=join(exported,'morse-fork-verifier');writeFileSync(native,'native-binary-fixture\n',{mode:0o755});
  const archive=number=>{
    const args=relayArchiveArguments(env);args.splice(args.indexOf(image),0,'--mount',`type=bind,src=${exported},dst=/app,readonly`);
    const file=join(directory,`relay-${number}.tar`),fd=openSync(file,'wx');
    try{execFileSync('docker',args,{stdio:['ignore',fd,'pipe'],timeout:60000});}finally{closeSync(fd);}
    return file;
  };
  const first=archive(1);utimesSync(native,new Date(),new Date());const second=archive(2);
  const digest=file=>createHash('sha256').update(readFileSync(file)).digest('hex');assert.equal(digest(first),digest(second));
  const unpacked=join(directory,'unpacked');mkdirSync(unpacked);execFileSync('tar',['-xf',first,'-C',unpacked]);
  assert.equal(readFileSync(join(unpacked,'morse-fork-verifier'),'utf8'),'native-binary-fixture\n');
  const relay=join(unpacked,'morse-relay');
  execFileSync('npm',['ci','--ignore-scripts','--no-audit','--no-fund'],{cwd:relay,stdio:'pipe',timeout:60000});
  const help=execFileSync(process.execPath,[join(relay,'cli.mjs'),'--help'],{encoding:'utf8',timeout:10000});
  assert.match(help,/morse-relay submit evidence.frk --wallet/);
  rmSync(native);assert.throws(()=>archive(3),/Command failed/,'an image without its native verifier cannot produce a valid bundle');
  t.diagnostic(`Reproducible fixture archive SHA-256 ${digest(first)}; unpacked CLI loaded all production modules`);
});
