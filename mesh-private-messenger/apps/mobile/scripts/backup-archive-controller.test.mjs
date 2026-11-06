import assert from 'node:assert/strict';
import {test} from 'node:test';
import {fixture,active,previewed,symbols,parseRequest,deferred,id,idText,otherId,otherIdText,overview,page,inventory,maximumTime} from './backup-archive-fixture.mjs';

test('authenticated preview is required before exact once-only import, with captured profile/file ownership',async()=>{
 const f=fixture(),preview=await previewed(f);assert.deepEqual(symbols(f),['preview']);
 assert.equal(preview.id,idText);assert.equal(preview.overview.createdAt,maximumTime);
 assert.equal(preview.overview.candidateCount,8);assert.equal(preview.overview.omittedTimed,1);assert.equal(preview.overview.conversations[0].name,'Historical group');
 assert.ok(f.files[0].every(byte=>byte===0),'transferred chooser bytes released after independent capture');
 f.profile.fill(7);const input=parseRequest(f.calls[0].encoded);assert.deepEqual([...input.expectedProfile],[1,2,3]);assert.deepEqual([...input.next()],[9,8,7]);
 await f.client.confirmImport(preview);assert.deepEqual(symbols(f),['preview','import','list']);
 assert.deepEqual([...f.calls[1].encoded.slice(-32)],[...id]);assert.deepEqual([...parseRequest(f.calls[1].encoded).expectedProfile],[1,2,3]);
 assert.equal(active(f).import.kind,'imported');await assert.rejects(f.client.confirmImport(preview),/stale_backup_confirmation/);assert.equal(symbols(f).filter(x=>x==='import').length,1);
 f.client.dispose();assert.equal(f.subscriptions(),0);
});
test('edited or replaced preview cannot publish late or replay against a newer preview with the same ID',async()=>{
 const pending=deferred();let waiting=false;const f=fixture({reply:symbol=>symbol.endsWith('_preview')&&waiting?pending.promise:undefined});
 const first=await previewed(f);f.client.setRecoveryCode('NEW CODE');waiting=true;const loading=f.client.preview();f.client.setRecoveryCode('CHANGED AGAIN');pending.resolve(overview());await loading;
 assert.equal(active(f).import.kind,'selected');await assert.rejects(f.client.confirmImport(first),/stale_backup_confirmation/);
 waiting=false;await f.client.preview();const current=active(f).import;assert.equal(current.kind,'preview');assert.equal(current.preview.id,first.id);assert.notEqual(current.preview,first);
 await assert.rejects(f.client.confirmImport(first),/stale_backup_confirmation/);assert.equal(symbols(f).includes('import'),false);f.client.dispose();
});
test('implicit chooser replacement aborts without native discard; explicit cancel discards and late bytes clear',async()=>{
 const old=deferred(),next=deferred();let count=0;const f=fixture({choose:()=>++count===1?old.promise:next.promise});
 const first=f.client.choose();assert.equal(f.signals.length,1);const second=f.client.choose();assert.equal(f.signals[0].aborted,true);
 const stale=Buffer.from([1,2]),fresh=Buffer.from([3,4]);next.resolve(fresh);await second;old.resolve(stale);await first;
 assert.equal(active(f).import.kind,'selected');assert.ok(stale.every(x=>x===0)&&fresh.every(x=>x===0));assert.equal(f.discards(),0);
 await f.client.cancelImport();assert.equal(f.discards(),1);assert.equal(active(f).import.kind,'empty');f.client.dispose();assert.equal(f.discards(),1);
});
test('actual native scope loss before its JS disposal event clears a delayed authenticated view',async()=>{
 const pending=deferred();const f=fixture({reply:symbol=>symbol.endsWith('_preview')?pending.promise:undefined});await f.client.choose();f.client.setRecoveryCode('CODE');const loading=f.client.preview();
 assert.deepEqual(symbols(f),['preview']);f.revoke();const bytes=overview();pending.resolve(bytes);await loading;
 assert.deepEqual(f.client.getSnapshot(),{kind:'closed'});assert.ok(bytes.every(x=>x===0));assert.equal(f.subscriptions(),0);await assert.rejects(f.client.choose(),/backup_view_closed/);assert.equal(f.discards(),0);
});
test('archive navigation is separate and uses fresh bounded pages with actual cursors, not source ordinals',async()=>{
 const f=fixture();await f.client.refreshArchives();assert.equal(active(f).inventory.rows.length,2);await f.client.openArchive(idText);let reader=active(f).reader;assert.equal(reader.kind,'overview');
 await f.client.openConversation(reader.overview.conversations[0]);reader=active(f).reader;assert.equal(reader.kind,'page');assert.equal(reader.page.entries[0].ordinal,4);assert.equal(reader.page.entries[1].attachmentOmitted,true);assert.equal(reader.page.entries[1].text,'');
 await f.client.nextPage();reader=active(f).reader;assert.equal(reader.page.offset,2);assert.equal(reader.page.entries[0].text,'second page');assert.equal(reader.canPrevious,true);
 await f.client.previousPage();assert.equal(active(f).reader.page.offset,0);assert.deepEqual(symbols(f),['list','overview','page','page','page']);
 for(const c of f.calls.filter(c=>c.symbol.endsWith('_page')))assert.equal(c.encoded.at(-1),16);f.client.dispose();
});
test('late archive/page work cannot replace a newly selected archive view',async()=>{
 const pending=deferred();let delayed=false;const f=fixture({reply:symbol=>symbol.endsWith('_page')&&delayed?pending.promise:undefined});await f.client.refreshArchives();await f.client.openArchive(idText);assert.equal(active(f).reader.kind,'overview');const first=active(f).reader.overview;
 delayed=true;const loading=f.client.openConversation(first.conversations[0]);await f.client.openArchive(otherIdText);pending.resolve(page());await loading;
 const reader=active(f).reader;assert.equal(reader.kind,'overview');assert.equal(reader.overview.id,otherIdText);await assert.rejects(f.client.openConversation(first.conversations[0]),/stale_backup_conversation/);f.client.dispose();
});
test('removal requires its exact explicit confirmation, runs once and cannot be undone by a late inventory',async()=>{
 const pending=deferred();let delayList=false;const f=fixture({reply:symbol=>symbol.endsWith('_list')&&delayList?pending.promise:undefined});await f.client.refreshArchives();f.client.requestRemove(idText);const removal=active(f).removal;assert.ok(removal);
 await assert.rejects(f.client.confirmRemove({...removal,id:otherIdText}),/stale_backup_confirmation/);assert.deepEqual(symbols(f),['list']);
 delayList=true;const listing=f.client.refreshArchives();f.client.requestRemove(idText);const current=active(f).removal;await f.client.confirmRemove(current);await assert.rejects(f.client.confirmRemove(current),/stale_backup_confirmation/);
 pending.resolve(inventory());await listing;assert.equal(active(f).inventory.rows.some(x=>x.id===idText),false);assert.deepEqual([...f.calls.find(c=>c.symbol.endsWith('_remove')).encoded.slice(-32)],[...id]);assert.ok(symbols(f).every(x=>['list','remove'].includes(x)));f.client.dispose();
});
test('disposal clears selected code, preview/messages and owned chooser work without retiring a fresh controller',async()=>{
 const pending=deferred();const f=fixture({choose:()=>pending.promise});const choosing=f.client.choose();assert.equal(f.signals.length,1);f.client.dispose();assert.equal(f.signals[0].aborted,true);
 const late=Buffer.from([5,6]);pending.resolve(late);await choosing;assert.ok(late.every(x=>x===0));assert.deepEqual(f.client.getSnapshot(),{kind:'closed'});assert.equal(f.discards(),0);assert.equal(f.subscriptions(),0);
 const other=fixture();await previewed(other);other.disposeScope();assert.deepEqual(other.client.getSnapshot(),{kind:'closed'});assert.equal(other.subscriptions(),0);
});

test('request replacement during the actual controller ownership check refuses the delayed preview',async()=>{
 const pending=deferred(),f=fixture({reply:symbol=>symbol.endsWith('_preview')?pending.promise:undefined});await f.client.choose();f.client.setRecoveryCode('ORIGINAL');const loading=f.client.preview();
 f.onControllerCheck(()=>f.client.setRecoveryCode('REPLACED DURING CHECK'));pending.resolve(overview());await loading;
 assert.equal(active(f).import.kind,'selected');assert.equal(active(f).import.code,'REPLACED DURING CHECK');assert.equal(symbols(f).includes('import'),false);f.client.dispose();
});
test('replacement clears the owned in-flight ciphertext copy before the native promise settles',async()=>{
 const pending=deferred();let passed;
 const f=fixture({reply:symbol=>symbol.endsWith('_preview')?pending.promise:undefined,wrapServices:services=>({...services,previewBackup(args){passed=args.wire;return services.previewBackup(args);}})});
 await f.client.choose();f.client.setRecoveryCode('CODE');const loading=f.client.preview();assert.deepEqual([...passed],[9,8,7]);f.client.setRecoveryCode('REPLACEMENT');
 assert.ok(passed.every(byte=>byte===0));pending.resolve(overview());await loading;f.client.dispose();
});
test('the original scope, services and chooser stay captured if the caller replaces its ports object fields',async()=>{
 const f=fixture(),other=fixture();f.ports.scope=other.ports.scope;f.ports.services=other.ports.services;f.ports.chooseBackupSource=other.ports.chooseBackupSource;
 await previewed(f);assert.deepEqual(symbols(f),['preview']);assert.equal(other.calls.length,0);assert.equal(f.signals.length,1);assert.equal(other.signals.length,0);f.client.dispose();other.client.dispose();
});
