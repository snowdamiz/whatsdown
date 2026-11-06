import {
  AccountRole, appendTransactionMessageInstructions, assertIsSendableTransaction,
  compileTransaction, createTransactionMessage, getAddressDecoder,
  getBase64EncodedWireTransaction, getSignatureFromTransaction, getTransactionSize,
  setTransactionMessageFeePayerSigner, setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
} from '@solana/kit';

const ED25519 = 'Ed25519SigVerify111111111111111111111111111';
const INSTRUCTIONS = 'Sysvar1nstructions1111111111111111111111111';
const PACKET_LIMIT = 1232;
const readonly = address => ({ address, role: AccountRole.READONLY });
const writable = address => ({ address, role: AccountRole.WRITABLE });

function bytes(value, minimum, maximum = minimum) {
  if (typeof value !== 'string' || value.length < minimum * 2 || value.length > maximum * 2 ||
    value.length % 2 || !/^[a-f0-9]+$/.test(value)) throw new Error('Invalid prepared anchor instruction');
  return Uint8Array.from(value.match(/../g), byte => parseInt(byte, 16));
}

function same(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function read16(data, offset) { return data[offset] | data[offset + 1] << 8; }
function write16(data, offset, value) { data[offset] = value & 255; data[offset + 1] = value >> 8; }

function attendanceAccounts(accounts,post) {
  return accounts.attendance ? [post ? writable(accounts.attendance.clock) : readonly(accounts.attendance.clock),
    writable(accounts.attendance.epoch)] : [];
}

function openAttendanceEpoch(accounts) {
  if(!accounts.attendance) return [];
  const {number}=accounts.attendance;
  if(typeof number!=='bigint' || number<0n || number>18446744073709551615n) throw new Error('Invalid attendance epoch');
  const data=new Uint8Array(9); data[0]=28; new DataView(data.buffer).setBigUint64(1,number,true);
  return [{programAddress:accounts.program,data,accounts:[
    {address:accounts.feePayer.address,role:AccountRole.WRITABLE_SIGNER,signer:accounts.feePayer},
    readonly(accounts.log),readonly(accounts.attendance.clock),writable(accounts.attendance.epoch),
    readonly('11111111111111111111111111111111')]}];
}

function precompile(value) {
  const data = bytes(value, 113, 1024);
  const expected = [1, 0, 48, 0, 255, 255, 16, 0, 255, 255, 112, 0];
  if (!expected.every((value, index) => data[index] === value) || data[14] !== 255 || data[15] !== 255 ||
    read16(data, 12) !== data.length - 112) throw new Error('Invalid prepared Ed25519 instruction');
  return data;
}

function message(instructions, accounts, lifetime) {
  let value = createTransactionMessage({ version: 0 });
  value = setTransactionMessageFeePayerSigner(accounts.feePayer, value);
  value = setTransactionMessageLifetimeUsingBlockhash(lifetime, value);
  return appendTransactionMessageInstructions(instructions, value);
}

async function signed(instructions, accounts, lifetime, witnessIndices = []) {
  const value = message(instructions, accounts, lifetime);
  if (getTransactionSize(compileTransaction(value)) > PACKET_LIMIT) throw new Error('Anchor transaction exceeds packet limit');
  const transaction = await signTransactionMessageWithSigners(value);
  assertIsSendableTransaction(transaction);
  return {
    signature: getSignatureFromTransaction(transaction),
    wire: getBase64EncodedWireTransaction(transaction),
    lastValidBlockHeight: lifetime.lastValidBlockHeight.toString(),
    witnessIndices,
  };
}

// Mesh verifies the service signature and constructs both instruction bodies.
// This transport boundary only accepts the fixed judge subset and account list.
export async function signAnchorPost(material, accounts, lifetime) {
  if (accounts.feePayer.address === accounts.anchorAuthority.address) throw new Error('Anchor authority and fee payer must be separate');
  const data = bytes(material.instruction, 191);
  const checkpoint = bytes(material.checkpoint, 188);
  const service = bytes(material.service_key, 32);
  const ed = precompile(material.ed25519);
  if (data[0] !== 3 || !same(data.subarray(3), checkpoint) || ed.length !== 258 ||
    !same(service, checkpoint.subarray(92, 124)) || !same(service, ed.subarray(16, 48)) ||
    !same(checkpoint.subarray(124), ed.subarray(48, 112))) throw new Error('Invalid prepared anchor instruction');
  const serviceAddress = getAddressDecoder().decode(service);
  if ([accounts.feePayer.address, accounts.anchorAuthority.address].includes(serviceAddress)) throw new Error('Service key and wallets must be separate');
  const initialize=openAttendanceEpoch(accounts);
  write16(data, 1, initialize.length);
  return signed([
    ...initialize,
    { programAddress: ED25519, accounts: [], data: ed },
    { programAddress: accounts.program, data, accounts: [readonly(accounts.log), writable(accounts.ring),
      { address: accounts.anchorAuthority.address, role: AccountRole.READONLY_SIGNER, signer: accounts.anchorAuthority }, readonly(INSTRUCTIONS), ...attendanceAccounts(accounts,true)] },
  ], accounts, lifetime);
}

function cosignPair(value, accounts, edIndex) {
  const data = bytes(value.instruction, 6, 266);
  const ed = precompile(value.ed25519);
  const native = data[0] === 7 && data.length === 70;
  const compact = data[0] === 9 && data.length === 6;
  const c2sp = data[0] === 8 && data.length === 266;
  const compactC2sp = data[0] === 30 && data.length === 202;
  if ((!native && !compact && !c2sp && !compactC2sp) || !Number.isInteger(value.witness_index) || value.witness_index < 0 || value.witness_index >= 16 ||
    data[5] !== value.witness_index || read16(data, 1) >= 4096 ||
    (!compact && !compactC2sp && !same(data.subarray(native ? 6 : 14, native ? 70 : 78), ed.subarray(48, 112)))) throw new Error('Invalid prepared cosign instruction');
  write16(data, 3, edIndex);
  return [
    { programAddress: ED25519, accounts: [], data: ed },
    { programAddress: accounts.program, data, accounts: [readonly(accounts.log), writable(accounts.ring),
      readonly(accounts.generation), readonly(INSTRUCTIONS), ...attendanceAccounts(accounts,false)] },
  ];
}

// Four is the desired batch ceiling. Larger C2SP statements and long IDs can
// hit Solana's v0 packet limit sooner; measure the actual compiled transaction.
export async function signAnchorCosigns(pairs, accounts, lifetime) {
  if (!Array.isArray(pairs) || pairs.length > 16) throw new Error('Invalid cosign batch');
  if (new Set(pairs.map(value => value.witness_index)).size !== pairs.length) throw new Error('Invalid duplicate cosign');
  const results = [];
  let instructions = [], indices = [];
  for (const pair of pairs) {
    let next = cosignPair(pair, accounts, instructions.length);
    if (indices.length && (indices.length === 4 ||
      getTransactionSize(compileTransaction(message([...instructions, ...next], accounts, lifetime))) > PACKET_LIMIT)) {
      results.push(await signed(instructions, accounts, lifetime, indices));
      instructions = []; indices = [];
      next = cosignPair(pair, accounts, 0);
    }
    instructions.push(...next); indices.push(pair.witness_index);
  }
  if (indices.length) results.push(await signed(instructions, accounts, lifetime, indices));
  return results;
}
