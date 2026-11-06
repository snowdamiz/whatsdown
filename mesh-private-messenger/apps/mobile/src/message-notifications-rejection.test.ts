import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
for(const mode of ['direct','group','normal'])test(`notification batches handle ${mode} outcome before the other batch settles`,()=>{
 const result=spawnSync(process.execPath,['--experimental-strip-types',new URL('../scripts/probe-notification-rejection.mjs',import.meta.url).pathname,mode],{encoding:'utf8',timeout:10000});
 console.log(result.stdout.trim());assert.equal(result.status,0,result.stdout+result.stderr);
});
