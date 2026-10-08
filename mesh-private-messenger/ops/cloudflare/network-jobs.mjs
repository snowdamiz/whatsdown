// The runtime binding of NetworkCore (network.mjs), kept apart so the logic
// imports no Workers-only module and tests run under Node.
import { DurableObject } from 'cloudflare:workers';
import { NetworkCore } from './network.mjs';

export class NetworkJobs extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.core = new NetworkCore(ctx, env);
  }
  afterCheckpoint() { return this.core.afterCheckpoint(); }
  cron(schedule) { return this.core.cron(schedule); }
  status() { return this.core.status(); }
  alarm() { return this.core.alarm(); }
}
