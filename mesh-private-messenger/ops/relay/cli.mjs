#!/usr/bin/env node
import { once } from 'node:events';
import { parseRelayArgs, usage } from './command.mjs';
import { openRelayApplication } from './application.mjs';
import { readEvidenceFile, RelayConfigError } from './config.mjs';
import { createRelayHttpServer } from './http.mjs';
import { runRelayLoop } from './service.mjs';
import { RelayJournalError } from './journal.mjs';

async function main() {
  const args=parseRelayArgs(process.argv.slice(2));
  if(args.command==='help'){console.log(usage);return;}
  const evidence=args.command==='submit'?await readEvidenceFile(args.evidence):null;
  const app=await openRelayApplication(args),controller=new AbortController();let server,interrupted=false;
  const stop=()=>{interrupted=true;controller.abort();server?.closeAllConnections();void app.service.close();};
  process.once('SIGINT',stop);process.once('SIGTERM',stop);
  try{
    if(args.command==='serve') {
      server=createRelayHttpServer({submit:app.service.submit});
      server.listen(app.config.listen.port,app.config.listen.host);await once(server,'listening');
      console.error('Morse relay listening');
      let previous;
      await runRelayLoop(app.service,{signal:controller.signal,onCycle:({scheduler})=>{
        if(scheduler.state!==previous&&['unavailable','lease-busy'].includes(scheduler.state))console.error(`Morse relay worker ${scheduler.state}`);
        previous=scheduler.state;
      }});
    }else {
      const pending=app.service.submit(evidence,{signal:controller.signal}).then(value=>({value}),()=>({error:true}));
      await app.service.cycle();const admission=await pending;
      if(admission.error)throw new Error('Relay admission unavailable; durable jobs remain recoverable');
      console.log(JSON.stringify(admission.value));
      const proof=admission.value.proof_hash;let exists=true;
      try{app.journal.job(proof);}catch(error){if(error.message!=='Unknown relay job')throw error;exists=false;}
      if(exists) {
        const done=()=>app.journal.job(proof).state==='complete';
        if(!done())await runRelayLoop(app.service,{signal:controller.signal,onCycle:()=>{if(done())controller.abort();}});
        if(done()) {
          const job=app.journal.job(proof);
          console.log(JSON.stringify({schema_version:1,status:'complete',proof_hash:proof,requested_finder:job.finder,finder:job.receipt.finder}));
        }
      }
    }
  }finally{
    process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);controller.abort();
    if(server)await new Promise(resolve=>{server.close(resolve);server.closeAllConnections();});
    await app.service.close();app.journal.close();
  }
  if(interrupted)process.exitCode=130;
}
main().catch(error=>{
  // Never stringify provider errors, wallet JSON, configuration or request data.
  console.error(error.message===usage?usage:error instanceof RelayConfigError||error instanceof RelayJournalError?error.message:
    'Morse relay could not start or complete the request. Check local configuration and durable journal.');
  process.exitCode=1;
});
