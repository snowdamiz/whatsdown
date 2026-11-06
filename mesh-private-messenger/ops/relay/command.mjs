import { resolve } from 'node:path';

export const usage='usage: morse-relay serve --wallet <keypair> --config <relay.json> | morse-relay submit evidence.frk --wallet <keypair> [--config <relay.json>]\nMORSE_RELAY_CONFIG supplies the config path when --config is omitted.';
export function parseRelayArgs(args,env=process.env) {
  if(args.length===1&&['--help','-h'].includes(args[0]))return {command:'help'};
  const fail=()=>{throw new Error(usage);};
  const command=args[0];if(!['serve','submit'].includes(command))fail();
  let cursor=1,evidence;
  if(command==='submit'){if(!args[cursor]||args[cursor].startsWith('--'))fail();evidence=resolve(args[cursor++]);}
  const options={};
  while(cursor<args.length){const key=args[cursor++],value=args[cursor++];if(!['--config','--wallet'].includes(key)||!value||value.startsWith('--')||options[key])fail();options[key]=value;}
  const config=options['--config']??env.MORSE_RELAY_CONFIG;
  if(!config||!options['--wallet'])fail();
  return {command,evidence,config:resolve(config),wallet:resolve(options['--wallet'])};
}
