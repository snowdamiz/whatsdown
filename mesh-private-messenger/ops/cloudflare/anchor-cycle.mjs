import { AnchorOutbox } from './anchor-outbox.mjs';
import { feePayerHealth } from './anchor-rpc.mjs';

const MINUTE = 60_000, HOUR = 3_600_000, WINDOW = 1500n;
const HEARTBEAT = HOUR-MINUTE; // Leave one minute for dispatch, retries and finality.
const terminal = new Set(['complete','failed','expired']);
const identity = entry => `${entry.slot}/${entry.ringIndex}/${entry.checkpointHash}`;

function milliseconds(clock) {
  const now = clock();
  if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER-HOUR) throw new Error('Invalid anchor scheduler clock');
  return now;
}
function seconds(value) {
  if (typeof value !== 'bigint' || value < 0n || value > 9223372036854775807n) throw new Error('Invalid anchor chain time');
  return value;
}

export class AnchorCycle {
  constructor(storage,scope) {
    this.storage=storage;this.sql=storage.sql;this.outbox=new AnchorOutbox(this.sql,scope);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS anchor_writer_progress (
      singleton INTEGER PRIMARY KEY CHECK(singleton = 1), next_post_at INTEGER NOT NULL DEFAULT 0,
      crank_cursor TEXT NOT NULL DEFAULT '', last_post TEXT)`);
    this.sql.exec('INSERT OR IGNORE INTO anchor_writer_progress (singleton) VALUES (1)');
  }

  async run(config,adapter,clock = Date.now) {
    const report={mode:config.mode,observedAt:milliseconds(clock),issues:[],postsStaged:0,cosignsStaged:0};
    if(config.mode==='off') return {...report,pending:this.outbox.list().length};
    const issue = code => {if(!report.issues.includes(code)) report.issues.push(code);};
    const finished=[], completedPosts=new Set();
    let snapshot, chainTime;
    try {
      const results=await Promise.allSettled([adapter.snapshot({limit:32}),adapter.balance()]);
      for(const result of results) if(result.status==='rejected') throw result.reason;
      snapshot=results[0].value;report.fee=feePayerHealth(results[1].value);
      chainTime=seconds(await adapter.blockTime(snapshot.contextSlot));
    } catch {return {...report,issues:['chain_unavailable'],pending:this.outbox.list().length};}
    const log=adapter.logState();
    // Enforce the cap on operator funding and alert on excess. Anyone can send
    // SOL to this public address; treating excess as a kill switch is a DoS.
    const funded=BigInt(report.fee.balanceLamports)>=25_000n;
    const clockValid=chainTime*1000n<=BigInt(milliseconds(clock));
    const ready=chainTime>=BigInt(log.readyAt);
    if(!clockValid) issue('clock_skew');
    if(!ready) issue('log_timelocked');
    if(log.slashed) issue('service_slashed');
    if(!funded) issue('fee_payer_insufficient');
    if(!report.fee.withinCap) issue('fee_payer_overfunded');
    const maySpend=funded && clockValid && ready && !log.slashed;
    const shouldBroadcast = row => maySpend && (row.intent.kind==='post' ||
      (config.cosign && BigInt(row.intent.slot)<=snapshot.contextSlot && snapshot.contextSlot-BigInt(row.intent.slot)<=WINDOW));
    const recover = async () => {
      // Two passes of five per 15-second job provide room for a post plus
      // sixteen one-pair C2SP transactions/minute, each with finality polling.
      const reports=await this.outbox.drain(adapter,milliseconds(clock),{limit:5,shouldBroadcast});
      if(reports.some(value=>value.retry)) issue('transaction_retry');
      const settled=this.outbox.list().filter(row=>terminal.has(row.phase));
      this.storage.transactionSync(()=> {
        for(const row of settled) {
          if(row.phase==='complete') {
            if(row.intent.kind==='post') {
              completedPosts.add(row.intent.checkpointHash);
              this.sql.exec('UPDATE anchor_writer_progress SET last_post = ? WHERE singleton = 1',JSON.stringify({...row.intent,...row.confirmation}));
            } else finished.push(row.intent);
          } else issue(`transaction_${row.phase}`);
          this.outbox.acknowledge(row.id);
        }
      });
    };
    await recover();
    if(maySpend) {
      try {
        const progress=this.sql.exec('SELECT next_post_at FROM anchor_writer_progress WHERE singleton = 1').one();
        if(!this.outbox.list().some(row=>row.intent.kind==='post') && milliseconds(clock)>=progress.next_post_at) {
          const candidate=await adapter.candidate(), latest=snapshot.entries[0];
          if(candidate && !completedPosts.has(candidate.checkpoint_hash)) {
            let due=!latest;
            if(latest && candidate.checkpoint_hash!==latest.checkpointHash) {
              const postedAt=seconds(await adapter.blockTime(BigInt(latest.slot)))*1000n;
              // Also enforce the minute ceiling from chain time, including a
              // fresh scheduler or a different writer holding the authority.
              if(chainTime*1000n>=postedAt+BigInt(MINUTE)) {
                due=candidate.root!==latest.root || candidate.tree_size!==latest.treeSize || chainTime*1000n>=postedAt+BigInt(HEARTBEAT);
              }
              if(BigInt(candidate.sequence)<=BigInt(latest.sequence)) {due=false;issue('directory_checkpoint_regressed');}
            } else if(latest && chainTime*1000n>=seconds(await adapter.blockTime(BigInt(latest.slot)))*1000n+BigInt(HEARTBEAT)) {
              issue('heartbeat_checkpoint_unavailable');
            }
            if(due) {
              const signed=await adapter.signPost(candidate,await adapter.lifetime());
              const intent={kind:'post',version:candidate.version,sequence:candidate.sequence,treeSize:candidate.tree_size,checkpointHash:candidate.checkpoint_hash};
              const stagedAt=milliseconds(clock);
              this.storage.transactionSync(()=> {
                this.outbox.stage(intent,signed,stagedAt);
                this.sql.exec('UPDATE anchor_writer_progress SET next_post_at = ? WHERE singleton = 1',stagedAt+MINUTE);
              });
              report.postsStaged++;
            }
          }
        }
      } catch {issue('post_preparation_failed');}
      if(config.cosign) {
        try {
          // Grow the read only when the oldest sampled entry is still inside
          // the slot window. No assumed seconds-per-slot can skip old work.
          let limit=32;
          while(snapshot.entries.length===limit && snapshot.header.count>limit &&
            snapshot.contextSlot-BigInt(snapshot.entries.at(-1).slot)<=WINDOW) {
            limit=Math.min(4096,limit*2);snapshot=await adapter.snapshot({limit});
          }
          const pending=this.outbox.list().filter(row=>row.intent.kind==='cosign');
          const free=16-pending.length;
          if(free>0) {
            const entries=snapshot.entries.filter(entry=>entry.generation>0 && BigInt(entry.slot)<=snapshot.contextSlot &&
              snapshot.contextSlot-BigInt(entry.slot)<=WINDOW).reverse();
            const cursor=this.sql.exec('SELECT crank_cursor FROM anchor_writer_progress WHERE singleton = 1').one().crank_cursor;
            const previous=entries.findIndex(entry=>identity(entry)===cursor), ordered=entries.slice(previous+1).concat(entries.slice(0,previous+1));
            const sets=new Map();
            for(const entry of ordered) {
              if(!sets.has(entry.generation)) sets.set(entry.generation,await adapter.witnessSet(entry.generation));
              const set=sets.get(entry.generation), mask=(1<<set.witnesses.length)-1;
              // A complete C2SP bitmap is complete attendance too. Rechecking
              // it must not consume turns needed by still-unsigned anchors.
              if(entry.cosignBitmap===mask) continue;
              this.sql.exec('UPDATE anchor_writer_progress SET crank_cursor = ? WHERE singleton = 1',identity(entry));
              const covered=new Set([...pending.map(row=>row.intent),...finished]
                .filter(value=>identity(value)===identity(entry)).flatMap(value=>value.witnessIndices));
              const material=await adapter.cosigns(entry,set);
              const pairs=material.cosigns.filter(pair=> {
                const index=pair.witness_index, bit=1<<index;
                if(!Number.isInteger(index) || index<0 || index>=set.witnesses.length) throw new Error('Invalid historical witness index');
                const native=['07','09'].includes(pair.instruction?.slice(0,2));
                return !covered.has(index) && (!(entry.cosignBitmap&bit) || (native && !(entry.nativeBitmap&bit)));
              }).sort((a,b)=>a.witness_index-b.witness_index);
              if(pairs.length) {
                const signed=await adapter.signCosigns(pairs,set,entry,await adapter.lifetime());
                this.storage.transactionSync(()=> {
                  for(const transaction of signed.slice(0,free)) {
                    this.outbox.stage({kind:'cosign',version:entry.version,sequence:entry.sequence,treeSize:entry.treeSize,
                      checkpointHash:entry.checkpointHash,ringIndex:entry.ringIndex,slot:entry.slot,generation:entry.generation},transaction,milliseconds(clock));
                    report.cosignsStaged++;
                  }
                });
              }
              // One historical checkpoint per wakeup bounds preparation I/O;
              // the durable cursor prevents a missing signer from starving it.
              break;
            }
          }
        } catch {issue('cosign_preparation_failed');}
      }
    }
    await recover();
    return {...report,observedAt:milliseconds(clock),pending:this.outbox.list().length,
      lastPost:JSON.parse(this.sql.exec('SELECT last_post FROM anchor_writer_progress WHERE singleton = 1').one().last_post ?? 'null')};
  }
}
