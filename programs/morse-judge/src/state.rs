//! Account layouts. Every offset here is documented byte for byte in
//! `protocol/morse-judge-v1.md`; integers are little-endian.

// ---- compile-time rules of the immutable judge ----
pub const EPOCH_SECONDS: i64 = 604_800; // 7 days
pub const COSIGN_WINDOW_SLOTS: u64 = 1_500;
pub const PROOF_WINDOW_MS: u64 = 28 * 86_400 * 1_000;
pub const UNBONDING_SECONDS: i64 = 30 * 86_400;
pub const TIMELOCK_SECONDS: i64 = 14 * 86_400;
/// The finder receives `amount / FINDER_DIVISOR` (10%, rounded down).
pub const FINDER_DIVISOR: u64 = 10;
pub const MAX_WITNESSES: usize = 16;
pub const MAX_FRK_LEN: usize = 8_192;
pub const COUNTER_SLOTS: u64 = 4;

// ---- account tags (byte 0); byte 1 is the layout version ----
pub const TAG_CONFIG: u8 = 1;
pub const TAG_LOG: u8 = 2;
pub const TAG_WITNESS: u8 = 3;
pub const TAG_STAGE: u8 = 4;
pub const TAG_PROOF: u8 = 5;
pub const VERSION: u8 = 1;

// ---- bond statuses (witness and directory) ----
pub const REGISTERED: u8 = 0;
pub const ACTIVE: u8 = 1;
pub const UNBONDING: u8 = 2;
pub const SLASHED: u8 = 3;
pub const WITHDRAWN: u8 = 4;

// ---- Config, PDA ["config"] ----
pub const CONFIG_LEN: usize = 192;
pub const CFG_BUMP: usize = 2;
pub const CFG_PENDING_KIND: usize = 3;
pub const CFG_AUTHORITY: usize = 8;
pub const CFG_USDC_MINT: usize = 40;
pub const CFG_TOKEN_MINT: usize = 72;
pub const CFG_REWARDS: usize = 104;
pub const CFG_MIN_BOND_USDC: usize = 136;
pub const CFG_MIN_BOND_TOKEN: usize = 144;
pub const CFG_PENDING_AFTER: usize = 152;
pub const CFG_PENDING_VALUE: usize = 160;

pub const PARAM_AUTHORITY: u8 = 1;
pub const PARAM_TOKEN_MINT: u8 = 2;
pub const PARAM_REWARDS: u8 = 3;
pub const PARAM_MIN_BOND_USDC: u8 = 4;
pub const PARAM_MIN_BOND_TOKEN: u8 = 5;

// ---- Log, PDA ["log", log_id] ----
pub const LOG_BUMP: usize = 2;
pub const LOG_SERVICE_SLASHED: usize = 3;
pub const LOG_WITNESS_COUNT: usize = 4;
pub const LOG_DIR_STATUS: usize = 5;
pub const LOG_KIND: usize = 6; // was padding: 0 main (never closable), 1 canary
pub const LOG_DIR_VAULT_BUMP: usize = 7;
pub const LOG_SLASHED_AT: usize = 8; // was padding: unix seconds of the directory slash
pub const KIND_MAIN: u8 = 0;
pub const KIND_CANARY: u8 = 1;
pub const LOG_ID: usize = 16;
pub const LOG_SERVICE_KEY: usize = 48;
pub const LOG_ANCHOR_AUTHORITY: usize = 80;
pub const LOG_RING: usize = 112;
pub const LOG_DIR_VAULT: usize = 144;
pub const LOG_LOCKED_VAULT: usize = 176;
pub const LOG_DIR_UNBOND_AT: usize = 208;
pub const LOG_ANCHOR_COUNTS: usize = 216;
pub const LOG_LIST: usize = 280;
pub const ENTRY_LEN: usize = 144;
pub const E_ID_LEN: usize = 0;
pub const E_ID: usize = 1;
pub const E_KEY: usize = 72;
pub const E_ACCOUNT: usize = 104;
pub const E_SINCE_SLOT: usize = 136;
pub const LOG_LEN: usize = LOG_LIST + MAX_WITNESSES * ENTRY_LEN; // 2,584

pub fn entry(i: usize) -> usize {
    LOG_LIST + i * ENTRY_LEN
}

// ---- AnchorRing, PDA ["ring", log_id] (plan §6.5) ----
pub const RING_CAPACITY: u32 = 4_096;
pub const RING_HEADER_LEN: usize = 64;
pub const RING_ENTRY_LEN: usize = 104;
pub const RING_LEN: usize = RING_HEADER_LEN + RING_CAPACITY as usize * RING_ENTRY_LEN; // 426,048
pub const RING_GROW_STEP: usize = 10_240;
pub const RH_LOG_ID: usize = 0;
pub const RH_HEAD: usize = 32;
pub const RH_COUNT: usize = 36;
pub const RH_LAST_SEQUENCE: usize = 40;
pub const RH_LAST_SIZE: usize = 48;
pub const RH_LAST_SLOT: usize = 56;
pub const RE_SEQUENCE: usize = 0;
pub const RE_SIZE: usize = 8;
pub const RE_ROOT: usize = 16;
pub const RE_HASH: usize = 48;
pub const RE_TIMESTAMP: usize = 80;
pub const RE_SLOT: usize = 88;
pub const RE_BITMAP: usize = 96;
pub const RE_EVIDENCE: usize = 98;
pub const RE_EPOCH: usize = 100;

pub fn ring_entry(i: u32) -> usize {
    RING_HEADER_LEN + i as usize * RING_ENTRY_LEN
}

// ---- Witness, PDA ["witness", log_id, sha256(witness_id)] ----
pub const WITNESS_LEN: usize = 336;
pub const W_BUMP: usize = 2;
pub const W_STATUS: usize = 3;
pub const W_EXCLUDED: usize = 4;
pub const W_LIST_INDEX: usize = 5;
/// `W_LIST_INDEX` of a witness that is not (or no longer) in its log's list.
pub const NOT_LISTED: u8 = 0xFF;
pub const W_VAULT_BUMP: usize = 6;
pub const W_ID_LEN: usize = 7;
pub const W_ID: usize = 8;
pub const W_LOG: usize = 72;
pub const W_KEY: usize = 104;
pub const W_OPERATOR: usize = 136;
pub const W_PAYOUT: usize = 168;
pub const W_OPERATOR_HASH: usize = 200;
pub const W_VAULT: usize = 232;
pub const W_UNBOND_AT: usize = 264;
pub const W_COSIGN_COUNTS: usize = 272;

// ---- Stage, PDA ["stage", submitter, nonce u64 LE] ----
pub const STAGE_HEADER_LEN: usize = 96;
pub const S_BUMP: usize = 2;
pub const S_MARKS: usize = 4;
pub const S_SUBMITTER: usize = 8;
pub const S_LOG: usize = 40;
pub const S_NONCE: usize = 72;
pub const S_TOTAL: usize = 80;
pub const S_WRITTEN: usize = 82;

// ---- Proof, PDA ["proof", proof_hash] ----
pub const PROOF_LEN: usize = 112;
pub const P_KIND: usize = 3;
pub const P_LOG: usize = 8;
pub const P_HASH: usize = 40;
pub const P_PAID_TO: usize = 72;
pub const P_SLOT: usize = 104;

// ---- little-endian field access ----
pub fn u16_at(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
pub fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}
pub fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
pub fn i64_at(d: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
pub fn key_at(d: &[u8], o: usize) -> [u8; 32] {
    d[o..o + 32].try_into().unwrap()
}
pub fn put_u16(d: &mut [u8], o: usize, v: u16) {
    d[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u32(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn put_u64(d: &mut [u8], o: usize, v: u64) {
    d[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
pub fn put_i64(d: &mut [u8], o: usize, v: i64) {
    d[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
pub fn put(d: &mut [u8], o: usize, v: &[u8]) {
    d[o..o + v.len()].copy_from_slice(v);
}

pub fn epoch_of(unix_seconds: i64) -> u64 {
    (unix_seconds.max(0) / EPOCH_SECONDS) as u64
}

/// Adds one to the `{u64 epoch, u64 count}` counter for `epoch` in a
/// 4-slot table at `base` (slot = epoch % 4; a stale slot restarts at 0).
pub fn bump_counter(d: &mut [u8], base: usize, epoch: u64) {
    let o = base + (epoch % COUNTER_SLOTS) as usize * 16;
    let count = if u64_at(d, o) == epoch { u64_at(d, o + 8) } else { 0 };
    put_u64(d, o, epoch);
    put_u64(d, o + 8, count + 1);
}
