// Durable, deduplicated operator alerts. These contain only public chain
// identity, fee balances and bounded health codes, never keys or RPC URLs.
export async function deliverAnchorAlert(storage,env,report,{fetcher=globalThis.fetch,clock=Date.now} = {}) {
  const now=clock();
  if(!Number.isSafeInteger(now) || now<0 || now>Number.MAX_SAFE_INTEGER-30_000)throw new Error('Invalid anchor alert clock');
  const issues=[...new Set(report.issues ?? [])].sort();
  const level=report.fee?.level;
  const severity=level==='critical' || issues.includes('service_slashed') ? 'critical' :
    (level && level!=='healthy') || issues.length ? 'warning' : 'recovered';
  const fingerprint=JSON.stringify([report.mode,report.program??'',report.logName??'',severity,level??'',issues]);
  const sql=storage.sql;
  sql.exec(`CREATE TABLE IF NOT EXISTS anchor_alert (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1), fingerprint TEXT NOT NULL,
    last_delivered TEXT, pending TEXT, next_attempt INTEGER NOT NULL DEFAULT 0)`);
  let row=sql.exec('SELECT * FROM anchor_alert WHERE singleton = 1').toArray()[0];
  if(!row || row.fingerprint!==fingerprint) {
    let pending=null;
    if(severity!=='recovered' || row?.last_delivered) {
      const payload={kind:'anchor-health',cluster:report.mode,program:report.program??null,log:report.logName??null,
        severity,observedAt:report.observedAt??now,balanceLamports:report.fee?.balanceLamports??null,issues};
      const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify([fingerprint,now]))));
      payload.eventId=[...digest].map(byte=>byte.toString(16).padStart(2,'0')).join('');
      pending=JSON.stringify(payload);
    }
    sql.exec(`INSERT INTO anchor_alert (singleton, fingerprint, pending, next_attempt) VALUES (1, ?, ?, ?)
      ON CONFLICT(singleton) DO UPDATE SET fingerprint=excluded.fingerprint,pending=excluded.pending,next_attempt=excluded.next_attempt`,fingerprint,pending,now);
    row=sql.exec('SELECT * FROM anchor_alert WHERE singleton = 1').one();
  }
  const configured=typeof env.MORSE_ANCHOR_ALERT_URL==='string' && env.MORSE_ANCHOR_ALERT_URL.length>0;
  if(!row.pending || !configured || now<row.next_attempt)return {configured,pending:!!row.pending};
  // A crash or lost HTTP reply repeats the same persisted event ID and body.
  sql.exec('UPDATE anchor_alert SET next_attempt = ? WHERE singleton = 1',now+30_000);
  try {
    const url=new URL(env.MORSE_ANCHOR_ALERT_URL);
    if(url.protocol!=='https:' || url.username || url.password || url.hash)throw new Error('Invalid anchor alert destination');
    const response=await fetcher(url.href,{method:'POST',redirect:'error',signal:AbortSignal.timeout(3000),body:row.pending,
      headers:{'Content-Type':'application/json',...(env.MORSE_ANCHOR_ALERT_TOKEN?{Authorization:`Bearer ${env.MORSE_ANCHOR_ALERT_TOKEN}`}:{})}});
    await response.body?.cancel();
    if(!response.ok)throw new Error('Anchor alert not acknowledged');
    sql.exec('UPDATE anchor_alert SET pending = NULL, last_delivered = fingerprint WHERE singleton = 1 AND fingerprint = ?',row.fingerprint);
    return {configured:true,pending:false};
  } catch {return {configured:true,pending:true};}
}
