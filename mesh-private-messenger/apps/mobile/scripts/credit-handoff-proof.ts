// Owned local proof entry. Uses the shipped app, credit adapters and OS launcher.
// Commands and results are app-private files; there is no test network transport.
import '../index';
import { File, Paths } from 'expo-file-system';
import { create_account_export, initialize } from '../modules/mesh-messenger';
import { accountRequest, utf8 } from '../src/codec';
import { databasePath } from '../src/storage';
import { discoverCreditIssuer, prepareCreditPurchase, continueCreditPurchase, recoverCreditPurchase } from '../src/credits';
import { openCreditPayment } from '../src/credit-payment-link';

const file = (name: string) => new File(Paths.document, name);
function writeJson(name: string, value: unknown) {
  const temporary = file(name + '.tmp');
  temporary.write(JSON.stringify(value));
  temporary.move(file(name));
}
const hex = (input: Uint8Array) => Array.from(input, value => value.toString(16).padStart(2, '0')).join('');
const fromHex = (input: string) => {
  if (!/^(?:[0-9a-f]{2})*$/.test(input)) throw new Error('invalid_proof_command');
  return Uint8Array.from(input.match(/../g) ?? [], value => Number.parseInt(value, 16));
};
function plan(value: Awaited<ReturnType<typeof prepareCreditPurchase>>) {
  return { id: hex(value.purchaseId), stage: value.stage, asset: value.asset, quote: hex(value.quote), body: hex(value.body) };
}
async function main() {
  await initialize(utf8(databasePath));
  writeJson('credit-handoff-ready.json', { database: databasePath, fetchBlocked: Object.getOwnPropertyDescriptor(globalThis, 'fetch')?.writable === false });
  while (true) {
    const command = file('credit-handoff-command.json');
    if (!command.exists) { await new Promise(resolve => setTimeout(resolve, 50)); continue; }
    const input = JSON.parse(await command.text()) as { operation: string; id?: string };
    command.delete();
    try {
      let value: unknown = null;
      const id = fromHex(input.id ?? '');
      switch (input.operation) {
        case 'create': await create_account_export(accountRequest(databasePath, 'handoff-proof')); break;
        case 'discover': await discoverCreditIssuer(databasePath); break;
        case 'prepare': value = plan(await prepareCreditPurchase(databasePath, 100, 2)); break;
        case 'continue': value = plan(await continueCreditPurchase(databasePath, id)); break;
        case 'recover': value = plan(await recoverCreditPurchase(databasePath, id)); break;
        case 'open': await openCreditPayment(databasePath, id); break;
        case 'wrong-database': await openCreditPayment(databasePath + '.other', id); break;
        default: throw new Error('invalid_proof_command');
      }
      writeJson('credit-handoff-response.json', { passed: true, value });
    } catch (error) {
      writeJson('credit-handoff-response.json', { passed: false, error: error instanceof Error ? error.message : String(error) });
    }
  }
}
void main().catch(error => writeJson('credit-handoff-fatal.json', { error: String(error) }));
