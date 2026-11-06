import { loadRelayConfig, readRelayWallet } from './config.mjs';
import { createRelayVerifier } from './verifier.mjs';
import { connectRelayRpc } from './rpc.mjs';
import { RelayJournal } from './journal.mjs';
import { createRelayScheduler } from './scheduler.mjs';
import { createRelayService } from './service.mjs';

export async function openRelayApplication({config:configFile,wallet}) {
  const config=await loadRelayConfig(configFile);
  const signer=await readRelayWallet(wallet,config.pins.submitter);
  const verifier=await createRelayVerifier({binary:config.verifierBinary,tempRoot:config.tempRoot,
    securityConfig:config.securityConfig,plannerConfig:config.plannerConfig,logVersion:config.logVersion,pins:config.pins});
  const rpc=await connectRelayRpc(config.rpc);
  const journal=new RelayJournal({path:config.journalPath,identity:config.identity,pins:config.pins,policy:config.policy});
  const scheduler=createRelayScheduler({journal,verifier,rpc,signer});
  const service=createRelayService({journal,verifier,scheduler});
  return {config,journal,service};
}
