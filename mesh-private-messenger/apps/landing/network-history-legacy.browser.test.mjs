import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
const { chromium } = await import(process.env.MORSE_PLAYWRIGHT_MODULE || new URL('../mobile/node_modules/playwright/index.mjs', import.meta.url).href);
const read = name => ({ ...JSON.parse(fs.readFileSync(new URL(`../../ops/public-chain/fixtures/legacy-${name}-history-report.json`, import.meta.url))), scope: 'configured-rpc' });
test('explicit legacy custody renders active/settled single-mint values and independent stale/code banks without network', {timeout:30000}, async()=>{
 const browser=await chromium.launch({executablePath:process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH});const observations=[];
 try{for(const width of [390,1440]){
  const page=await browser.newPage({viewport:{width,height:900}}),errors=[],requests=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(!r.url().startsWith('file:')&&!r.url().startsWith('data:'))requests.push(r.url());});
  await page.goto(new URL('./network.html',import.meta.url).href);
  const mount=report=>page.evaluate(report=>globalThis.MorseNetworkReport.mount(document,report,Number(report.generated_at_unix)),report);
  const active=read('active');await mount(active);assert.equal(await page.locator('#report-status').textContent(),'Configured snapshot available');assert.match(await page.locator('.history-content').textContent(),/no configured token program/);
  await page.locator('[data-family="witnesses"]').click();assert.match(await page.locator('.history-record dl').textContent(),/100\.000000/);assert.match(await page.locator('.history-content').textContent(),/No USDC, MORSE or fiat identity is assigned/);assert.match(await page.locator('.history-record').textContent(),/no v2 pending-liability field/);
  await page.locator('[data-family="proofs"]').click();assert.match(await page.locator('.history-content').textContent(),/filtered set was empty/);assert.equal(await page.locator('.history-record').count(),0);
  const settled=read('settled');await mount(settled);await page.locator('[data-family="proofs"]').click();assert.match(await page.locator('.history-record dl').textContent(),/600\.000000/);assert.match(await page.locator('.history-record dl').textContent(),/60\.000000/);assert.match(await page.locator('.history-record').textContent(),/v1 layout has no witness ID seed/);
  assert.match(await page.locator('.history-content').textContent(),new RegExp(`index slot ${settled.history.proofs.index_slot}`));assert.match(await page.locator('.history-record').textContent(),new RegExp(`Value context slot ${settled.history.proofs.pages[0].values.context_slot}`));
  const changed=structuredClone(settled);changed.history.proofs.pages[0].values.code_current=false;await mount(changed);assert.equal(await page.locator('#report-status').textContent(),'Code pin changed');await page.locator('[data-family="proofs"]').click();assert.match(await page.locator('.history-record .state').textContent(),/code pin changed/);
  const stale=structuredClone(settled);stale.history.witnesses.source_time_unix=String(Number(stale.generated_at_unix)-901);await mount(stale);assert.equal(await page.locator('#report-status').textContent(),'Snapshot is stale');
  const mixed=structuredClone(settled);mixed.burns=JSON.parse(fs.readFileSync(new URL('../../ops/public-chain/fixtures/burn-history-report.json',import.meta.url))).burns;await mount(mixed);assert.equal(await page.locator('#report-status').textContent(),'Report unavailable');
  const malformed=structuredClone(settled);malformed.history.proofs.pages[0].values.schema_version=2;await mount(malformed);assert.equal(await page.locator('#report-status').textContent(),'Report unavailable');assert.equal(await page.locator('.history-record').count(),0);
  await mount(settled);await page.locator('[data-family="proofs"]').click();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(errors,[]);assert.deepEqual(requests,[]);
  observations.push({width,activePrincipal:'100000000',settledSlash:'600000000',finder:'60000000',indexSlot:settled.history.proofs.index_slot,valueSlot:settled.history.proofs.pages[0].values.context_slot,externalRequests:requests,pageErrors:errors});await page.close();
 }}finally{await browser.close();}
 if(process.env.MORSE_LEGACY_BROWSER_EVIDENCE)fs.writeFileSync(process.env.MORSE_LEGACY_BROWSER_EVIDENCE,JSON.stringify({captures:false,observations},null,2)+'\n',{flag:'wx'});
});
