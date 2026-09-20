import { Container } from '@cloudflare/containers';

export class Witness extends Container {
  sleepAfter = '5m';
  entrypoint = ['/bin/sleep', 'infinity'];
  enableInternet = false;

  async attest() {
    if (this.pending) throw new Error('Witness is busy; retry attestation');
    const current = Promise.resolve().then(async () => {
      if (!this.ctx.container.running) await this.start();
      const process = await this.ctx.container.exec(['/app/transparency-witness'], { env: this.envVars });
      const output = await process.output();
      if (output.exitCode !== 0) {
        throw new Error(`Witness attestation failed (${output.exitCode})`);
      }
    });
    this.pending = current;
    try {
      await current;
    } finally {
      if (this.pending === current) this.pending = undefined;
    }
  }
}

