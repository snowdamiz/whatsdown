import { assertIsAddress, getAddressDecoder, getAddressEncoder, getProgramDerivedAddress } from '@solana/kit';

const text = new TextEncoder(), decode = new TextDecoder('utf-8',{fatal:true});
const RING_SIZE = 64 + 4096 * 104;
const same = (a,b) => a.length === b.length && a.every((value,index)=>value === b[index]);
const zero = (bytes,start,length) => bytes.subarray(start,start+length).every(value=>value === 0);
const hex = bytes => [...bytes].map(value=>value.toString(16).padStart(2,'0')).join('');
const u16 = (bytes,offset) => new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint16(offset,true);
const u64 = (bytes,offset) => new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getBigUint64(offset,true);
const sha = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));
const rawAddress = value => getAddressEncoder().encode(value);
const address = bytes => getAddressDecoder().decode(bytes);

function uint(value) {
  if (typeof value !== 'bigint' || value < 0n || value > 18446744073709551615n) throw new Error('Invalid anchor account integer');
  return value;
}

function bytesHex(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value) || /^0+$/.test(value)) throw new Error('Invalid anchor service key');
  return Uint8Array.from(value.match(/../g),byte=>parseInt(byte,16));
}

function cat(...parts) {
  const bytes = new Uint8Array(parts.reduce((size,value)=>size+value.length,0));
  let offset = 0;
  for (const part of parts) {bytes.set(part,offset); offset += part.length;}
  return bytes;
}

// Writer-side account validation. The configured RPC is trusted to report
// finalized chain state; phone acceptance still uses its separate RPC quorum.
export async function openAnchorAccounts(rpc, config, options = {}) {
  assertIsAddress(config.program); assertIsAddress(config.authority);
  if (typeof config.logName !== 'string' || !/^[a-z0-9-]{1,32}$/.test(config.logName) || ![1,2].includes(config.version)) throw new Error('Invalid anchor log configuration');
  const service = bytesHex(config.serviceKey), name = text.encode(config.logName), logId = await sha(name);
  const program = config.program;
  const derive = async seeds => (await getProgramDerivedAddress({programAddress:program,seeds}))[0];
  const log = await derive([text.encode('log'),name]), ring = await derive([text.encode('ring'),name]);
  let floor = uint(options.minContextSlot ?? 0n);

  async function account(key, size, offset, length, minimum = 0n, owner = program) {
    const requestedFloor = uint(minimum) > floor ? minimum : floor;
    const reply = await rpc.getAccountInfo(key,{commitment:'finalized',encoding:'base64',minContextSlot:requestedFloor,
      dataSlice:{offset:BigInt(offset),length:BigInt(length)}}).send();
    const value = reply?.value, context = uint(reply?.context?.slot);
    if (context < requestedFloor || !value || value.owner !== owner || value.executable !== false ||
      uint(value.lamports) === 0n || value.space !== BigInt(size) || !Array.isArray(value.data) || value.data.length !== 2 ||
      value.data[1] !== 'base64' || typeof value.data[0] !== 'string' || value.data[0].length > 4*Math.ceil(length/3)) {
      throw new Error('Invalid anchor account metadata or context');
    }
    const binary = atob(value.data[0]);
    if (binary.length !== length || btoa(binary) !== value.data[0]) throw new Error('Invalid anchor account slice');
    if (context > floor) floor = context;
    return Uint8Array.from(binary,char=>char.charCodeAt(0));
  }

  const logBytes = await account(log,352,0,352);
  const originLength = u16(logBytes,210), ready = u64(logBytes,200);
  if (!same(logBytes.subarray(0,4),text.encode('MLG\x01')) || logBytes[4] !== config.version || logBytes[5] > 1 ||
    logBytes[6] !== name.length || logBytes[7] > 1 || !same(logBytes.subarray(8,8+name.length),name) ||
    !zero(logBytes,8+name.length,32-name.length) || !same(logBytes.subarray(40,72),logId) ||
    !same(logBytes.subarray(72,104),service) || !same(logBytes.subarray(104,136),rawAddress(config.authority)) ||
    !same(logBytes.subarray(136,168),rawAddress(ring)) || ready > 9223372036854775807n ||
    originLength > 128 || (config.version === 1 ? originLength !== 0 : originLength === 0) ||
    !zero(logBytes,212+originLength,128-originLength) || !zero(logBytes,340,12)) throw new Error('Invalid anchor Log or pins');
  const origin = decode.decode(logBytes.subarray(212,212+originLength));
  if ((origin && !/^[\x21-\x2a\x2c-\x7e]+$/.test(origin)) || origin !== (config.origin ?? '')) throw new Error('Anchor origin mismatch');
  const logState = {generation:u16(logBytes,208),slashed:logBytes[5] === 1,readyAt:ready.toString(),origin,attendanceEnabled:logBytes[7] === 1};

  async function attendanceClock() {
    const clock = await derive([text.encode('attendance'),logId]);
    const bytes = await account(clock,65616,0,80);
    const activatedAt=u64(bytes,36), activatedSlot=u64(bytes,44), firstFullEpoch=u64(bytes,52), latestPostEpoch=u64(bytes,60);
    if (!same(bytes.subarray(0,4),text.encode('MAC\x01')) || !same(bytes.subarray(4,36),logId) ||
      !zero(bytes,68,12) || activatedAt===0n || activatedAt>9223372036854775807n || activatedSlot>floor ||
      firstFullEpoch!==activatedAt/604800n+1n || latestPostEpoch<activatedAt/604800n) throw new Error('Invalid attendance clock');
    return {clock,activatedAt,activatedSlot,latestPostEpoch};
  }

  async function attendanceAddress(clock,number) {
    const encoded=new Uint8Array(8); new DataView(encoded.buffer).setBigUint64(0,uint(number),true);
    return {clock,number,epoch:await derive([text.encode('attendance-epoch'),logId,encoded])};
  }

  async function attendanceForPost() {
    if (!logState.attendanceEnabled) return undefined;
    const value=await attendanceClock();
    const chain=await account('SysvarC1ock11111111111111111111111111111111',40,0,40,0n,'Sysvar1111111111111111111111111111111111111');
    const now=u64(chain,32), slot=u64(chain,0), number=now/604800n;
    if(now>9223372036854775807n || slot>floor || slot<value.activatedSlot || number<value.latestPostEpoch) throw new Error('Invalid attendance chain clock');
    return attendanceAddress(value.clock,number);
  }

  async function attendanceForCosign(entry) {
    if (!logState.attendanceEnabled) return undefined;
    if (!Number.isInteger(entry.ringIndex) || entry.ringIndex<0 || entry.ringIndex>=4096 || !/^(0|[1-9][0-9]*)$/.test(entry.slot)) throw new Error('Invalid attendance coordinate');
    const posted=uint(BigInt(entry.slot)), value=await attendanceClock();
    const bytes=await account(value.clock,65616,80+entry.ringIndex*16,16);
    const marker=u64(bytes,0), slot=u64(bytes,8);
    // Pre-activation entries may still finish cosigning, but are never paid.
    if(marker===0n && slot===0n && posted<=value.activatedSlot) return attendanceAddress(value.clock,value.latestPostEpoch);
    if(marker===0n || slot!==posted || slot<value.activatedSlot) throw new Error('Attendance entry overwritten or untracked');
    return attendanceAddress(value.clock,marker-1n);
  }

  function header(bytes) {
    const value = {head:u16(bytes,36),count:u16(bytes,38),sequence:u64(bytes,40),treeSize:u64(bytes,48),slot:u64(bytes,56)};
    if (!same(bytes.subarray(0,4),text.encode('MRG\x01')) || !same(bytes.subarray(4,36),logId) ||
      value.head >= 4096 || value.count > 4096 || (value.count > 0 && value.count < 4096 && value.head !== value.count-1) ||
      (value.count === 0 && (value.head || value.sequence || value.treeSize || value.slot)) || value.slot > floor) throw new Error('Invalid anchor ring header');
    return value;
  }

  function entry(bytes,index,head) {
    const result = {ringIndex:index,sequence:u64(bytes,0).toString(),treeSize:u64(bytes,8).toString(),root:hex(bytes.subarray(16,48)),
      checkpointHash:hex(bytes.subarray(48,80)),timestampMs:u64(bytes,80).toString(),slot:u64(bytes,88).toString(),
      cosignBitmap:u16(bytes,96),version:bytes[98],rollback:bytes[99] === 1,nativeBitmap:u16(bytes,100),generation:u16(bytes,102)};
    if (result.version !== config.version || bytes[99] > 1 || BigInt(result.slot) > head.slot ||
      (result.nativeBitmap & ~result.cosignBitmap) !== 0 || (result.generation === 0 && result.cosignBitmap !== 0) ||
      (index === head.head && (BigInt(result.sequence) !== head.sequence || BigInt(result.treeSize) !== head.treeSize || BigInt(result.slot) !== head.slot))) {
      throw new Error('Invalid anchor ring entry');
    }
    return result;
  }

  async function snapshot(select, minimum) {
    const before = await account(ring,RING_SIZE,0,64,minimum), head = header(before);
    const wanted = select(head), pages = new Map();
    for (const index of wanted) {
      if (!Number.isInteger(index) || index < 0 || index >= 4096 || ((head.head-index+4096)%4096) >= head.count) throw new Error('Anchor entry is unfilled');
      const page = Math.floor(index/128), current = pages.get(page) ?? {start:index,end:index};
      pages.set(page,{start:Math.min(current.start,index),end:Math.max(current.end,index)});
    }
    const values = new Map(), ranges = [...pages.values()];
    for (let start = 0; start < ranges.length; start += 4) {
      const settled = await Promise.allSettled(ranges.slice(start,start+4).map(async range => {
        const bytes = await account(ring,RING_SIZE,64+range.start*104,(range.end-range.start+1)*104);
        return {range,bytes};
      }));
      for (const result of settled) {
        if (result.status === 'rejected') throw result.reason;
        const {range,bytes} = result.value;
        for (let index = range.start; index <= range.end; index++) values.set(index,entry(bytes.subarray((index-range.start)*104,(index-range.start+1)*104),index,head));
      }
    }
    const after = await account(ring,RING_SIZE,0,64);
    if (!same(before,after)) throw new Error('Anchor ring snapshot changed');
    return {header:head,contextSlot:floor,entries:wanted.map(index=>values.get(index))};
  }

  async function readRing({limit = 16,minContextSlot = 0n} = {}) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 4096) throw new Error('Invalid anchor read limit');
    return snapshot(head=>Array.from({length:Math.min(limit,head.count)},(_,distance)=>(head.head-distance+4096)%4096),minContextSlot);
  }

  async function witnessSet(generation,{minContextSlot = 0n} = {}) {
    if (!Number.isInteger(generation) || generation < 1 || generation > 65535) throw new Error('Invalid witness generation');
    const encoded = Uint8Array.of(generation&255,generation>>8);
    const key = await derive([text.encode('witness-set'),logId,encoded]);
    const bytes = await account(key,2752,0,2752,minContextSlot), count = bytes[38];
    if (!same(bytes.subarray(0,4),text.encode('MWS\x01')) || !same(bytes.subarray(4,36),logId) || u16(bytes,36) !== generation ||
      count < 1 || count > 16 || bytes[39] !== 0 || u64(bytes,40) > 9223372036854775807n || !zero(bytes,48,16) ||
      !zero(bytes,64+count*168,(16-count)*168)) throw new Error('Invalid witness generation account');
    const witnesses = [];
    for (let index = 0; index < count; index++) {
      const slot = bytes.subarray(64+index*168,64+(index+1)*168), length = slot[32];
      if (length < 1 || length > 64 || !zero(slot,33,7) || !zero(slot,40+length,64-length) ||
        zero(slot,104,32) || zero(slot,136,32)) throw new Error('Invalid witness slot');
      const idBytes = slot.subarray(40,40+length), id = decode.decode(idBytes), publicKey = slot.subarray(104,136);
      if (!/^[a-z0-9-]+$/.test(id) || (index && witnesses[index-1].id >= id) ||
        witnesses.some(witness=>witness.publicKey === hex(publicKey))) throw new Error('Invalid witness ordering or key');
      const identity = await sha(cat(text.encode('morse-witness-record-v1'),Uint8Array.of(length),idBytes,publicKey));
      const expected = await derive([text.encode('witness'),logId,identity]);
      if (address(slot.subarray(0,32)) !== expected) throw new Error('Invalid witness record PDA');
      witnesses.push({id,publicKey:hex(publicKey),address:expected,payout:address(slot.subarray(136,168))});
    }
    return {address:key,bytes,generation,witnesses,contextSlot:floor};
  }

  async function readback(intent,{minContextSlot = 0n} = {}) {
    const matches = value => value.version === intent.version && value.checkpointHash === intent.checkpointHash &&
      value.sequence === intent.sequence && value.treeSize === intent.treeSize;
    let found;
    if (intent.kind === 'cosign') {
      const view = await snapshot(()=>[intent.ringIndex],minContextSlot);
      found = view.entries[0];
      if (!matches(found) || found.generation !== intent.generation || found.slot !== intent.slot) throw new Error('Anchor cosign entry changed');
      const set = await witnessSet(found.generation);
      if (!Array.isArray(intent.witnessIndices) || !intent.witnessIndices.length ||
        intent.witnessIndices.some(index=>!Number.isInteger(index) || index < 0 || index >= set.witnesses.length || !(found.cosignBitmap & (1<<index))) ||
        (found.cosignBitmap >> set.witnesses.length) !== 0) throw new Error('Anchor cosign bitmap missing or invalid');
    } else if (intent.kind === 'post') {
      found = (await readRing({limit:1,minContextSlot})).entries.find(matches);
      if (!found) found = (await readRing({limit:4096,minContextSlot})).entries.find(matches);
    } else throw new Error('Invalid anchor readback intent');
    if (!found) throw new Error('Finalized anchor entry unavailable');
    return {slot:found.slot,ringIndex:found.ringIndex};
  }

  return {program,log,ring,logId:hex(logId),logState,readRing,witnessSet,readback,attendanceForPost,attendanceForCosign,get contextSlot(){return floor;}};
}
