//! Test harness for `morse-judge` and `morse-rewards`, run in LiteSVM against
//! the built `.so` files. Every encoding here follows
//! `protocol/morse-judge-v1.md` independently of the program sources, so the
//! tests also check the document.
#![allow(clippy::result_large_err)]

pub mod rpc;

use ed25519_dalek::{Signer as _, SigningKey};
use litesvm::types::TransactionResult;
pub use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_account::Account;
pub use solana_address::Address;
use solana_clock::Clock;
pub use solana_instruction::{AccountMeta, Instruction};
use solana_instruction_error::InstructionError;
pub use solana_keypair::Keypair;
pub use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;

pub const JUDGE_SO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy/morse_judge.so");
pub const REWARDS_SO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/deploy/morse_rewards.so");

pub const SYSTEM: Address = Address::new_from_array([0; 32]);
pub const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const ATA: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const ED25519: Address = Address::from_str_const("Ed25519SigVerify111111111111111111111111111");
pub const SYSVAR_INSTRUCTIONS: Address = Address::from_str_const("Sysvar1nstructions1111111111111111111111111");
pub const LOADER_V3: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
pub const COMPUTE_BUDGET: Address = Address::from_str_const("ComputeBudget111111111111111111111111111111");

// Judge discriminators (spec §5).
pub mod ix {
    pub const INITIALIZE: u8 = 0;
    pub const PROPOSE: u8 = 1;
    pub const APPLY: u8 = 2;
    pub const REGISTER_LOG: u8 = 3;
    pub const SET_ANCHOR_AUTHORITY: u8 = 4;
    pub const GROW_RING: u8 = 5;
    pub const POST_ANCHOR: u8 = 6;
    pub const COSIGN: u8 = 7;
    pub const REGISTER_WITNESS: u8 = 8;
    pub const BOND_DIRECTORY: u8 = 9;
    pub const BOND: u8 = 10;
    pub const REQUEST_UNBOND: u8 = 11;
    pub const WITHDRAW: u8 = 12;
    pub const STAGE_INIT: u8 = 13;
    pub const STAGE_WRITE: u8 = 14;
    pub const STAGE_VERIFY: u8 = 15;
    pub const STAGE_CLOSE: u8 = 16;
    pub const PROVE_SAME_SIZE: u8 = 17;
    pub const PROVE_CONTRADICTION: u8 = 18;
    pub const PROVE_ROLLBACK: u8 = 19;
    pub const ADMIT_WITNESS: u8 = 20;
    pub const CLOSE_LOG: u8 = 21;
}

// Judge error codes (spec §8).
pub mod code {
    pub const WRONG_ACCOUNT: u32 = 6000;
    pub const UNAUTHORIZED: u32 = 6001;
    pub const INVALID_DATA: u32 = 6002;
    pub const TIMELOCK_ACTIVE: u32 = 6003;
    pub const NO_PENDING_CHANGE: u32 = 6004;
    pub const INVALID_PARAMETER: u32 = 6005;
    pub const RING_NOT_READY: u32 = 6006;
    pub const RING_ALREADY_GROWN: u32 = 6007;
    pub const INVALID_CHECKPOINT: u32 = 6008;
    pub const SIGNATURE_NOT_VERIFIED: u32 = 6009;
    pub const DUPLICATE_ANCHOR: u32 = 6010;
    pub const STALE_ANCHOR: u32 = 6011;
    pub const RING_INDEX_INVALID: u32 = 6012;
    pub const COSIGN_WINDOW_CLOSED: u32 = 6013;
    pub const INVALID_STATUS: u32 = 6014;
    pub const WITNESS_LIST_FULL: u32 = 6015;
    pub const SLOT_NOT_REUSABLE: u32 = 6016;
    pub const DUPLICATE_SIGNING_KEY: u32 = 6017;
    pub const INVALID_WITNESS_ID: u32 = 6018;
    pub const MINT_NOT_ALLOWED: u32 = 6019;
    pub const BOND_BELOW_MINIMUM: u32 = 6020;
    pub const UNBONDING_NOT_ELAPSED: u32 = 6021;
    pub const STAGE_INVALID: u32 = 6022;
    pub const FRK_MALFORMED: u32 = 6023;
    pub const WRONG_LOG_KEY: u32 = 6024;
    pub const NOT_A_FORK: u32 = 6025;
    pub const PROOF_WINDOW_CLOSED: u32 = 6026;
    pub const ATTESTATION_NOT_VERIFIED: u32 = 6027;
    pub const ALREADY_PROVEN: u32 = 6028;
    pub const IMPLICATED_ACCOUNTS_MISMATCH: u32 = 6029;
    pub const FINDER_ACCOUNT_MISMATCH: u32 = 6030;
    pub const NOTHING_TO_SLASH: u32 = 6031;
    pub const KIND_MISMATCH: u32 = 6032;
    pub const AMOUNT_ZERO: u32 = 6033;
    pub const WRONG_DESTINATION: u32 = 6034;
    pub const NOT_CLOSABLE: u32 = 6035;
    pub const CLOSE_TOO_EARLY: u32 = 6036;
}

// Account layouts (spec §3).
pub mod layout {
    pub const RING_LEN: usize = 426_048;
    pub const LOG_LEN: usize = 2_584;
    pub const LOG_SERVICE_SLASHED: usize = 3;
    pub const LOG_WITNESS_COUNT: usize = 4;
    pub const LOG_DIR_STATUS: usize = 5;
    pub const LOG_ANCHOR_AUTHORITY: usize = 80;
    pub const LOG_ANCHOR_COUNTS: usize = 216;
    pub const LOG_LIST: usize = 280;
    pub const ENTRY_LEN: usize = 144;
    pub const RH_HEAD: usize = 32;
    pub const RH_COUNT: usize = 36;
    pub const RH_LAST_SEQUENCE: usize = 40;
    pub const RH_LAST_SIZE: usize = 48;
    pub const RH_LAST_SLOT: usize = 56;
    pub const W_STATUS: usize = 3;
    pub const W_EXCLUDED: usize = 4;
    pub const W_COSIGN_COUNTS: usize = 272;
    pub const S_MARKS: usize = 4;
    pub const P_PAID_TO: usize = 72;
    pub const REGISTERED: u8 = 0;
    pub const ACTIVE: u8 = 1;
    pub const UNBONDING: u8 = 2;
    pub const SLASHED: u8 = 3;
    pub const WITHDRAWN: u8 = 4;
    pub fn ring_entry(i: u32) -> usize {
        64 + i as usize * 104
    }
}

pub const DAY: i64 = 86_400;
pub const EPOCH: i64 = 7 * DAY;
pub const MAIN: &str = "morse-main";
pub const CANARY: &str = "morse-canary";

pub fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn log_id(name: &str) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..name.len()].copy_from_slice(name.as_bytes());
    id
}

pub fn u64le(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
pub fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
pub fn pubkey(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

// ------------------------------------------------------------ Morse formats

pub const KTK_LEN: usize = 188;

/// `u8 1 ‖ "KTK" ‖ u64 seq ‖ u64 size ‖ root ‖ prev ‖ u64 ts_ms ‖ key ‖ sig` (BE).
pub fn ktk(service: &SigningKey, seq: u64, size: u64, root: [u8; 32], ts_ms: u64) -> [u8; KTK_LEN] {
    let mut k = [0u8; KTK_LEN];
    k[0] = 1;
    k[1..4].copy_from_slice(b"KTK");
    k[4..12].copy_from_slice(&seq.to_be_bytes());
    k[12..20].copy_from_slice(&size.to_be_bytes());
    k[20..52].copy_from_slice(&root);
    k[52..84].copy_from_slice(&sha(&[b"prev", &seq.to_be_bytes()]));
    k[84..92].copy_from_slice(&ts_ms.to_be_bytes());
    k[92..124].copy_from_slice(&pubkey(service));
    let sig = service.sign(&statement(&k)).to_bytes();
    k[124..188].copy_from_slice(&sig);
    k
}

pub fn statement(k: &[u8; KTK_LEN]) -> Vec<u8> {
    let mut s = b"mesh-key-transparency-v1".to_vec();
    s.extend_from_slice(&1u16.to_be_bytes());
    s.extend_from_slice(&k[4..124]);
    assert_eq!(s.len(), 146);
    s
}

pub fn ktk_sig(k: &[u8; KTK_LEN]) -> [u8; 64] {
    k[124..188].try_into().unwrap()
}

pub fn checkpoint_hash(k: &[u8; KTK_LEN]) -> [u8; 32] {
    sha(&[b"mesh-msg/v1/transparency-checkpoint", &statement(k), &k[124..188]])
}

pub fn witness_msg(id: &str, hash: &[u8; 32]) -> Vec<u8> {
    [&b"mesh-msg/v1/transparency-witness"[..], id.as_bytes(), hash].concat()
}

pub fn witness_sig(k: &SigningKey, id: &str, hash: &[u8; 32]) -> [u8; 64] {
    k.sign(&witness_msg(id, hash)).to_bytes()
}

pub fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    sha(&[b"mesh-msg/v1/transparency-leaf", entry])
}
pub fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    sha(&[b"mesh-msg/v1/transparency-node", l, r])
}
fn split(n: usize) -> usize {
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}
/// RFC 6962 MTH with Morse hashes.
pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => sha(&[b"mesh-msg/v1/transparency-empty"]),
        1 => leaves[0],
        n => {
            let k = split(n);
            node(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}
/// RFC 6962 PATH(m, D[n]).
pub fn path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n <= 1 {
        return vec![];
    }
    let k = split(n);
    if m < k {
        let mut p = path(m, &leaves[..k]);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = path(m - k, &leaves[k..]);
        p.push(root(&leaves[..k]));
        p
    }
}

pub enum C2 {
    Inline([u8; KTK_LEN]),
    Ring(u32),
}

pub struct Contradiction {
    pub index: u64,
    pub path1: Vec<[u8; 32]>,
    pub leaf1: [u8; 32],
    pub path2: Vec<[u8; 32]>,
    pub leaf2: [u8; 32],
}

pub struct Frk {
    pub kind: u8,
    pub finder: [u8; 32],
    pub log_key: [u8; 32],
    pub c1: [u8; KTK_LEN],
    pub c2: C2,
    pub attestations: Vec<(String, [u8; 32], [u8; 64])>,
    pub contradiction: Option<Contradiction>,
}

impl Frk {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![1];
        b.extend_from_slice(b"FRK");
        b.push(self.kind);
        b.extend_from_slice(&self.finder);
        b.extend_from_slice(&self.log_key);
        b.extend_from_slice(&self.c1);
        match &self.c2 {
            C2::Inline(k) => {
                b.push(0);
                b.extend_from_slice(k);
            }
            C2::Ring(i) => {
                b.push(1);
                b.extend_from_slice(&i.to_be_bytes());
            }
        }
        b.push(self.attestations.len() as u8);
        for (id, hash, sig) in &self.attestations {
            b.push(id.len() as u8);
            b.extend_from_slice(id.as_bytes());
            b.extend_from_slice(hash);
            b.extend_from_slice(sig);
        }
        if let Some(c) = &self.contradiction {
            b.extend_from_slice(&c.index.to_be_bytes());
            b.push(c.path1.len() as u8);
            c.path1.iter().for_each(|p| b.extend_from_slice(p));
            b.extend_from_slice(&c.leaf1);
            b.push(c.path2.len() as u8);
            c.path2.iter().for_each(|p| b.extend_from_slice(p));
            b.extend_from_slice(&c.leaf2);
        }
        b
    }
}

pub fn proof_hash(frk: &[u8]) -> [u8; 32] {
    sha(&[b"morse-frk-v1/proof", &frk[..5], &frk[37..]])
}

// ------------------------------------------------------------ Ed25519 program

/// One self-contained Ed25519 instruction (all instruction indexes u16::MAX).
pub fn ed25519_ix(entries: &[(&[u8; 32], &[u8], &[u8; 64])]) -> Instruction {
    let header = 2 + 14 * entries.len();
    let mut offsets = vec![entries.len() as u8, 0];
    let mut body = vec![];
    for (pk, msg, sig) in entries {
        let pk_off = header + body.len();
        body.extend_from_slice(*pk);
        let sig_off = header + body.len();
        body.extend_from_slice(*sig);
        let msg_off = header + body.len();
        body.extend_from_slice(msg);
        for v in [sig_off, 0xFFFF, pk_off, 0xFFFF, msg_off, msg.len(), 0xFFFF] {
            offsets.extend_from_slice(&(v as u16).to_le_bytes());
        }
    }
    offsets.extend(body);
    Instruction { program_id: ED25519, accounts: vec![], data: offsets }
}

pub fn ed25519_sign(k: &SigningKey, msg: &[u8]) -> Instruction {
    let sig = k.sign(msg).to_bytes();
    ed25519_ix(&[(&pubkey(k), msg, &sig)])
}

pub fn compute_budget(units: u32) -> Instruction {
    let mut data = vec![2];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction { program_id: COMPUTE_BUDGET, accounts: vec![], data }
}

// ------------------------------------------------------------ token helpers

pub fn mint_data(decimals: u8) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[36..44].copy_from_slice(&u64::MAX.to_le_bytes()[..]); // supply: ample for burns
    d[44] = decimals;
    d[45] = 1;
    d
}

pub fn token_account_data(mint: &Address, owner: &Address, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

pub fn ata(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()], &ATA).0
}

pub fn create_ata_idempotent(payer: &Address, owner: &Address, mint: &Address) -> Instruction {
    Instruction {
        program_id: ATA,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata(owner, mint), false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(TOKEN, false),
        ],
        data: vec![1],
    }
}

// ------------------------------------------------------------ results

pub fn custom_code(res: &TransactionResult) -> Option<u32> {
    match res {
        Err(f) => match &f.err {
            TransactionError::InstructionError(_, InstructionError::Custom(c)) => Some(*c),
            _ => None,
        },
        Ok(_) => None,
    }
}

#[track_caller]
pub fn assert_code(res: TransactionResult, code: u32) {
    match &res {
        Ok(_) => panic!("expected error {code}, transaction succeeded"),
        Err(f) => assert_eq!(custom_code(&res), Some(code), "expected {code}, got {:?}\nlogs: {:#?}", f.err, f.meta.logs),
    }
}

#[track_caller]
pub fn assert_ok(res: TransactionResult) -> litesvm::types::TransactionMetadata {
    match res {
        Ok(m) => m,
        Err(f) => panic!("transaction failed: {:?}\nlogs: {:#?}", f.err, f.meta.logs),
    }
}

// ------------------------------------------------------------ environment

pub struct Witness {
    pub id: String,
    pub key: SigningKey,
    pub operator: Keypair,
    pub payout: Keypair,
    pub log: [u8; 32],
}

impl Witness {
    pub fn account(&self, judge: &Address) -> Address {
        pda(&[b"witness", &self.log, &sha(&[self.id.as_bytes()])], judge)
    }
    pub fn vault(&self, judge: &Address) -> Address {
        pda(&[b"bond", &self.log, &sha(&[self.id.as_bytes()])], judge)
    }
}

pub fn pda(seeds: &[&[u8]], program: &Address) -> Address {
    Address::find_program_address(seeds, program).0
}

pub struct Env {
    pub svm: LiteSVM,
    pub judge: Address,
    pub rewards: Address,
    pub deployer: Keypair,
    pub gov: Keypair,
    pub payer: Keypair,
    pub usdc: Address,
    pub token_mint: Address,
    pub anchor: Keypair,
    pub now: i64,
    pub slot: u64,
}

pub const START: i64 = 1_790_000_000; // 2026-09-21, inside epoch 2959

impl Env {
    /// Programs loaded with upgrade authority `deployer`, two mints, nothing
    /// initialized.
    pub fn bare() -> Env {
        let mut svm = LiteSVM::new().with_transaction_history(0);
        let judge = Address::new_unique();
        let rewards = Address::new_unique();
        let deployer = Keypair::new();
        svm.add_program(judge, &std::fs::read(JUDGE_SO).expect("run cargo-build-sbf first")).unwrap();
        if let Ok(bytes) = std::fs::read(REWARDS_SO) {
            svm.add_program(rewards, &bytes).unwrap();
        }
        for program in [judge, rewards] {
            let pd = pda(&[program.as_ref()], &LOADER_V3);
            if let Some(mut a) = svm.get_account(&pd) {
                a.data[12] = 1;
                a.data[13..45].copy_from_slice(deployer.pubkey().as_ref());
                svm.set_account(pd, a).unwrap();
            }
        }
        let gov = Keypair::new();
        let payer = Keypair::new();
        let anchor = Keypair::new();
        for k in [&deployer, &gov, &payer, &anchor] {
            svm.airdrop(&k.pubkey(), 1_000_000_000_000).unwrap();
        }
        let usdc = Address::new_unique();
        let token_mint = Address::new_unique();
        let mut env = Env { svm, judge, rewards, deployer, gov, payer, usdc, token_mint, anchor, now: START, slot: 1_000 };
        env.set_mint(usdc);
        env.set_mint(token_mint);
        env.set_clock(START, 1_000);
        env
    }

    /// Judge initialized, `morse-main` registered with a full ring.
    pub fn new() -> (Env, SigningKey) {
        let mut env = Env::bare();
        env.initialize(1_000_000_000, 1_000_000_000).unwrap();
        let service = key(0x51);
        env.register_log(MAIN, &service).unwrap();
        env.grow_ring_full(MAIN);
        (env, service)
    }

    pub fn set_clock(&mut self, unix: i64, slot: u64) {
        self.now = unix;
        self.slot = slot;
        let mut c: Clock = self.svm.get_sysvar();
        c.unix_timestamp = unix;
        c.slot = slot;
        self.svm.set_sysvar(&c);
    }
    pub fn advance(&mut self, seconds: i64, slots: u64) {
        self.set_clock(self.now + seconds, self.slot + slots);
    }
    pub fn now_ms(&self) -> u64 {
        self.now as u64 * 1000
    }

    pub fn set_mint(&mut self, addr: Address) {
        self.svm.set_account(addr, Account { lamports: 10_000_000, data: mint_data(6), owner: TOKEN, executable: false, rent_epoch: 0 }).unwrap();
    }
    pub fn set_token_account(&mut self, addr: Address, mint: &Address, owner: &Address, amount: u64) {
        self.svm
            .set_account(
                addr,
                Account { lamports: 10_000_000, data: token_account_data(mint, owner, amount), owner: TOKEN, executable: false, rent_epoch: 0 },
            )
            .unwrap();
    }
    /// A funded token account (at the owner's ATA address).
    pub fn fund(&mut self, owner: &Address, mint: &Address, amount: u64) -> Address {
        let a = ata(owner, mint);
        self.set_token_account(a, mint, owner, amount);
        a
    }
    pub fn balance(&self, addr: &Address) -> u64 {
        self.svm.get_account(addr).filter(|a| a.data.len() == 165).map(|a| u64le(&a.data, 64)).unwrap_or(0)
    }
    pub fn data(&self, addr: &Address) -> Vec<u8> {
        self.svm.get_account(addr).map(|a| a.data).unwrap_or_default()
    }
    pub fn exists(&self, addr: &Address) -> bool {
        self.svm.get_account(addr).is_some_and(|a| a.lamports > 0)
    }

    pub fn send(&mut self, ixs: &[Instruction], signers: &[&Keypair]) -> TransactionResult {
        self.svm.expire_blockhash();
        let mut all: Vec<&Keypair> = vec![&self.payer];
        all.extend(signers.iter().copied().filter(|k| k.pubkey() != self.payer.pubkey()));
        let tx = Transaction::new_signed_with_payer(ixs, Some(&self.payer.pubkey()), &all, self.svm.latest_blockhash());
        self.svm.send_transaction(tx)
    }

    /// Serialized size of a legacy transaction paid by `payer` (limit 1,232).
    pub fn wire_size(&self, ixs: &[Instruction]) -> usize {
        let tx = Transaction::new_with_payer(ixs, Some(&self.payer.pubkey()));
        bincode::serialize(&tx).unwrap().len()
    }

    // ---------------------------------------------------------- addresses
    pub fn config(&self) -> Address {
        pda(&[b"config"], &self.judge)
    }
    pub fn log(&self, name: &str) -> Address {
        pda(&[b"log", &log_id(name)], &self.judge)
    }
    pub fn ring(&self, name: &str) -> Address {
        pda(&[b"ring", &log_id(name)], &self.judge)
    }
    pub fn dir_vault(&self, name: &str) -> Address {
        pda(&[b"bond", &log_id(name), b"directory"], &self.judge)
    }
    pub fn locked(&self, name: &str) -> Address {
        pda(&[b"locked", &log_id(name)], &self.judge)
    }
    pub fn stage(&self, submitter: &Address, nonce: u64) -> Address {
        pda(&[b"stage", submitter.as_ref(), &nonce.to_le_bytes()], &self.judge)
    }
    pub fn proof(&self, hash: &[u8; 32]) -> Address {
        pda(&[b"proof", hash], &self.judge)
    }
    pub fn programdata(&self, program: &Address) -> Address {
        pda(&[program.as_ref()], &LOADER_V3)
    }

    // ---------------------------------------------------------- governance
    pub fn initialize_ix(&self, signer: &Address, authority: &Address, token_mint: &[u8; 32], min_usdc: u64, min_token: u64) -> Instruction {
        let mut data = vec![ix::INITIALIZE];
        data.extend_from_slice(authority.as_ref());
        data.extend_from_slice(self.usdc.as_ref());
        data.extend_from_slice(token_mint);
        data.extend_from_slice(self.rewards.as_ref());
        data.extend_from_slice(&min_usdc.to_le_bytes());
        data.extend_from_slice(&min_token.to_le_bytes());
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new(*signer, true),
                AccountMeta::new(self.config(), false),
                AccountMeta::new_readonly(self.programdata(&self.judge), false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data,
        }
    }
    pub fn initialize(&mut self, min_usdc: u64, min_token: u64) -> TransactionResult {
        let i = self.initialize_ix(&self.deployer.pubkey(), &self.gov.pubkey(), &[0; 32], min_usdc, min_token);
        let d = self.deployer.insecure_clone();
        self.send(&[i], &[&d])
    }
    pub fn propose_ix(&self, authority: &Address, kind: u8, value: [u8; 32]) -> Instruction {
        let mut data = vec![ix::PROPOSE, kind];
        data.extend_from_slice(&value);
        Instruction {
            program_id: self.judge,
            accounts: vec![AccountMeta::new_readonly(*authority, true), AccountMeta::new(self.config(), false)],
            data,
        }
    }
    pub fn apply_ix(&self) -> Instruction {
        Instruction { program_id: self.judge, accounts: vec![AccountMeta::new(self.config(), false)], data: vec![ix::APPLY] }
    }
    /// propose + wait 14 days + apply, as governance.
    pub fn govern(&mut self, kind: u8, value: [u8; 32]) {
        let gov = self.gov.insecure_clone();
        assert_ok(self.send(&[self.propose_ix(&gov.pubkey(), kind, value)], &[&gov]));
        self.advance(14 * DAY, 10);
        assert_ok(self.send(&[self.apply_ix()], &[]));
    }
    pub fn set_token_mint(&mut self) {
        let m = self.token_mint;
        self.govern(2, m.to_bytes());
    }

    /// `kind`: 0 main (never closable), 1 canary.
    pub fn register_log_ix(&self, name: &str, service: &[u8; 32], anchor: &Address, authority: &Address, kind: u8) -> Instruction {
        let mut data = vec![ix::REGISTER_LOG];
        data.extend_from_slice(&log_id(name));
        data.extend_from_slice(service);
        data.extend_from_slice(anchor.as_ref());
        data.push(kind);
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new_readonly(*authority, true),
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new(self.log(name), false),
                AccountMeta::new(self.locked(name), false),
                AccountMeta::new_readonly(self.usdc, false),
                AccountMeta::new_readonly(SYSTEM, false),
                AccountMeta::new_readonly(TOKEN, false),
            ],
            data,
        }
    }
    /// Registers `name`; the `morse-canary` name is registered as canary kind.
    pub fn register_log(&mut self, name: &str, service: &SigningKey) -> TransactionResult {
        let gov = self.gov.insecure_clone();
        let i = self.register_log_ix(name, &pubkey(service), &self.anchor.pubkey(), &gov.pubkey(), (name == CANARY) as u8);
        self.send(&[i], &[&gov])
    }
    /// close_log with (stage, submitter) pairs.
    pub fn close_log_ix(&self, name: &str, authority: &Address, destination: &Address, stages: &[(Address, Address)]) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(self.config(), false),
            AccountMeta::new_readonly(self.log(name), false),
            AccountMeta::new(self.ring(name), false),
            AccountMeta::new(*destination, false),
        ];
        for (stage, submitter) in stages {
            accounts.push(AccountMeta::new(*stage, false));
            accounts.push(AccountMeta::new(*submitter, false));
        }
        Instruction { program_id: self.judge, accounts, data: vec![ix::CLOSE_LOG] }
    }
    pub fn set_anchor_authority_ix(&self, name: &str, authority: &Address, new: &Address) -> Instruction {
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new_readonly(*authority, true),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new(self.log(name), false),
            ],
            data: [&[ix::SET_ANCHOR_AUTHORITY][..], new.as_ref()].concat(),
        }
    }
    pub fn grow_ring_ix(&self, name: &str) -> Instruction {
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                AccountMeta::new_readonly(self.log(name), false),
                AccountMeta::new(self.ring(name), false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data: vec![ix::GROW_RING],
        }
    }
    pub fn grow_ring_full(&mut self, name: &str) {
        while self.data(&self.ring(name)).len() < layout::RING_LEN {
            let ixs = vec![self.grow_ring_ix(name); 8];
            let len = self.data(&self.ring(name)).len();
            let n = if len == 0 { 1 } else { ((layout::RING_LEN - len).div_ceil(10_240)).min(8) };
            assert_ok(self.send(&ixs[..n], &[]));
        }
    }

    // ---------------------------------------------------------- anchoring
    pub fn post_anchor_ix(&self, name: &str, authority: &Address, ed_ix: u8, k: &[u8; KTK_LEN]) -> Instruction {
        let mut data = vec![ix::POST_ANCHOR, ed_ix];
        data.extend_from_slice(k);
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new_readonly(*authority, true),
                AccountMeta::new(self.log(name), false),
                AccountMeta::new(self.ring(name), false),
                AccountMeta::new_readonly(SYSVAR_INSTRUCTIONS, false),
            ],
            data,
        }
    }
    /// Posts `k` with its service signature verified by instruction 0.
    pub fn post(&mut self, name: &str, service: &SigningKey, k: &[u8; KTK_LEN]) -> TransactionResult {
        let a = self.anchor.insecure_clone();
        let ed = ed25519_ix(&[(&pubkey(service), &statement(k), &ktk_sig(k))]);
        let post = self.post_anchor_ix(name, &a.pubkey(), 0, k);
        self.send(&[ed, post], &[&a])
    }
    pub fn cosign_ix(&self, name: &str, ring_index: u32, list_index: u8, witness: &Address, ed_ix: u8) -> Instruction {
        let mut data = vec![ix::COSIGN];
        data.extend_from_slice(&ring_index.to_le_bytes());
        data.push(list_index);
        data.push(ed_ix);
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new_readonly(self.log(name), false),
                AccountMeta::new(self.ring(name), false),
                AccountMeta::new(*witness, false),
                AccountMeta::new_readonly(SYSVAR_INSTRUCTIONS, false),
            ],
            data,
        }
    }
    pub fn cosign(&mut self, name: &str, ring_index: u32, list_index: u8, w: &Witness) -> TransactionResult {
        let hash: [u8; 32] = self.data(&self.ring(name))[layout::ring_entry(ring_index) + 48..][..32].try_into().unwrap();
        let sig = witness_sig(&w.key, &w.id, &hash);
        let ed = ed25519_ix(&[(&pubkey(&w.key), &witness_msg(&w.id, &hash), &sig)]);
        let c = self.cosign_ix(name, ring_index, list_index, &w.account(&self.judge), 0);
        self.send(&[ed, c], &[])
    }

    // ---------------------------------------------------------- witnesses
    pub fn witness(&mut self, name: &str, id: &str, seed: u8) -> Witness {
        let w = Witness { id: id.into(), key: key(seed), operator: Keypair::new(), payout: Keypair::new(), log: log_id(name) };
        self.svm.airdrop(&w.operator.pubkey(), 100_000_000_000).unwrap();
        w
    }
    pub fn register_msg(w: &Witness) -> Vec<u8> {
        [&b"morse-witness-register-v1"[..], w.id.as_bytes(), w.operator.pubkey().as_ref(), w.payout.pubkey().as_ref()].concat()
    }
    #[allow(clippy::too_many_arguments)]
    pub fn register_witness_ix(&self, name: &str, w: &Witness, excluded: u8, ed_ix: u8) -> Instruction {
        let mut data = vec![ix::REGISTER_WITNESS];
        data.extend_from_slice(&pubkey(&w.key));
        data.extend_from_slice(w.payout.pubkey().as_ref());
        data.extend_from_slice(&sha(&[b"operator ", w.id.as_bytes()]));
        data.extend_from_slice(&[excluded, ed_ix, w.id.len() as u8]);
        data.extend_from_slice(w.id.as_bytes());
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new(w.operator.pubkey(), true),
                AccountMeta::new_readonly(self.log(name), false),
                AccountMeta::new(w.account(&self.judge), false),
                AccountMeta::new_readonly(SYSVAR_INSTRUCTIONS, false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data,
        }
    }
    pub fn admit_witness_ix(&self, name: &str, witness: &Address, authority: &Address, replace: u8, excluded: u8, replaced: &Address) -> Instruction {
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new_readonly(*authority, true),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new(self.log(name), false),
                AccountMeta::new(*witness, false),
                if replace == 0xFF { AccountMeta::new_readonly(*replaced, false) } else { AccountMeta::new(*replaced, false) },
            ],
            data: vec![ix::ADMIT_WITNESS, replace, excluded],
        }
    }
    /// The operator's registration alone (key proof, not yet in the list).
    pub fn register_only(&mut self, name: &str, w: &Witness, excluded: bool) -> TransactionResult {
        let ed = ed25519_sign(&w.key, &Env::register_msg(w));
        let r = self.register_witness_ix(name, w, excluded as u8, 0);
        let op = w.operator.insecure_clone();
        self.send(&[ed, r], &[&op])
    }
    pub fn admit(&mut self, name: &str, w: &Witness, replace: u8, excluded: bool, replaced: Address) -> TransactionResult {
        let gov = self.gov.insecure_clone();
        let i = self.admit_witness_ix(name, &w.account(&self.judge), &gov.pubkey(), replace, excluded as u8, &replaced);
        self.send(&[i], &[&gov])
    }
    /// Registration by the operator, then admission to the list by governance.
    pub fn register(&mut self, name: &str, w: &Witness, excluded: bool) -> TransactionResult {
        self.register_replacing(name, w, excluded, 0xFF, self.judge)
    }
    pub fn register_replacing(&mut self, name: &str, w: &Witness, excluded: bool, replace: u8, replaced: Address) -> TransactionResult {
        if !self.exists(&w.account(&self.judge)) {
            let r = self.register_only(name, w, excluded);
            if r.is_err() {
                return r;
            }
        }
        self.admit(name, w, replace, false, replaced)
    }
    pub fn bond_ix(&self, name: &str, w: &Witness, mint: &Address, amount: u64) -> Instruction {
        let mut data = vec![ix::BOND];
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new(w.operator.pubkey(), true),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new_readonly(self.log(name), false),
                AccountMeta::new(w.account(&self.judge), false),
                AccountMeta::new(w.vault(&self.judge), false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(ata(&w.operator.pubkey(), mint), false),
                AccountMeta::new_readonly(SYSTEM, false),
                AccountMeta::new_readonly(TOKEN, false),
            ],
            data,
        }
    }
    /// Funds the operator and bonds `amount` of `mint`.
    pub fn bond(&mut self, name: &str, w: &Witness, mint: &Address, amount: u64) -> TransactionResult {
        let have = self.balance(&ata(&w.operator.pubkey(), mint));
        self.fund(&w.operator.pubkey(), mint, have + amount);
        let i = self.bond_ix(name, w, mint, amount);
        let op = w.operator.insecure_clone();
        self.send(&[i], &[&op])
    }
    pub fn bond_directory_ix(&self, name: &str, authority: &Address, mint: &Address, amount: u64) -> Instruction {
        let mut data = vec![ix::BOND_DIRECTORY];
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new(*authority, true),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new(self.log(name), false),
                AccountMeta::new(self.dir_vault(name), false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(ata(authority, mint), false),
                AccountMeta::new_readonly(SYSTEM, false),
                AccountMeta::new_readonly(TOKEN, false),
            ],
            data,
        }
    }
    pub fn bond_directory(&mut self, name: &str, mint: &Address, amount: u64) -> TransactionResult {
        let gov = self.gov.insecure_clone();
        let have = self.balance(&ata(&gov.pubkey(), mint));
        self.fund(&gov.pubkey(), mint, have + amount);
        let i = self.bond_directory_ix(name, &gov.pubkey(), mint, amount);
        self.send(&[i], &[&gov])
    }
    pub fn unbond_ix(&self, name: &str, owner: &Address, target: u8, witness: &Address) -> Instruction {
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new_readonly(*owner, true),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new(self.log(name), false),
                AccountMeta::new(*witness, false),
            ],
            data: vec![ix::REQUEST_UNBOND, target],
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw_ix(&self, name: &str, owner: &Address, target: u8, witness: &Address, vault: &Address, destination: &Address) -> Instruction {
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new_readonly(*owner, true),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new(self.log(name), false),
                AccountMeta::new(*witness, false),
                AccountMeta::new(*vault, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(TOKEN, false),
            ],
            data: vec![ix::WITHDRAW, target],
        }
    }
    pub fn unbond_witness(&mut self, name: &str, w: &Witness) -> TransactionResult {
        let i = self.unbond_ix(name, &w.operator.pubkey(), 1, &w.account(&self.judge));
        let op = w.operator.insecure_clone();
        self.send(&[i], &[&op])
    }
    pub fn withdraw_witness(&mut self, name: &str, w: &Witness, mint: &Address) -> TransactionResult {
        let dest = self.fund(&w.operator.pubkey(), mint, self.balance(&ata(&w.operator.pubkey(), mint)));
        let i = self.withdraw_ix(name, &w.operator.pubkey(), 1, &w.account(&self.judge), &w.vault(&self.judge), &dest);
        let op = w.operator.insecure_clone();
        self.send(&[i], &[&op])
    }

    // ---------------------------------------------------------- proofs
    pub fn stage_init_ix(&self, name: &str, submitter: &Address, nonce: u64, total: u16) -> Instruction {
        let mut data = vec![ix::STAGE_INIT];
        data.extend_from_slice(&nonce.to_le_bytes());
        data.extend_from_slice(&total.to_le_bytes());
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new(*submitter, true),
                AccountMeta::new_readonly(self.log(name), false),
                AccountMeta::new(self.stage(submitter, nonce), false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data,
        }
    }
    pub fn stage_write_ix(&self, submitter: &Address, stage: &Address, offset: u16, bytes: &[u8]) -> Instruction {
        let mut data = vec![ix::STAGE_WRITE];
        data.extend_from_slice(&offset.to_le_bytes());
        data.extend_from_slice(bytes);
        Instruction { program_id: self.judge, accounts: vec![AccountMeta::new_readonly(*submitter, true), AccountMeta::new(*stage, false)], data }
    }
    pub fn stage_verify_ix(&self, name: &str, stage: &Address, ed_ix: u8) -> Instruction {
        Instruction {
            program_id: self.judge,
            accounts: vec![
                AccountMeta::new(*stage, false),
                AccountMeta::new_readonly(self.log(name), false),
                AccountMeta::new_readonly(SYSVAR_INSTRUCTIONS, false),
            ],
            data: vec![ix::STAGE_VERIFY, ed_ix],
        }
    }
    pub fn stage_close_ix(&self, submitter: &Address, stage: &Address) -> Instruction {
        Instruction {
            program_id: self.judge,
            accounts: vec![AccountMeta::new(*submitter, true), AccountMeta::new(*stage, false)],
            data: vec![ix::STAGE_CLOSE],
        }
    }

    /// Stages `frk` for `submitter` (nonce 0): init, 900-byte writes, and
    /// one stage_verify per signature entry (each its own transaction).
    pub fn stage_proof(&mut self, name: &str, submitter: &Keypair, nonce: u64, frk: &[u8], entries: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> Address {
        let s = self.stage(&submitter.pubkey(), nonce);
        assert_ok(self.send(&[self.stage_init_ix(name, &submitter.pubkey(), nonce, frk.len() as u16)], &[submitter]));
        for (i, chunk) in frk.chunks(900).enumerate() {
            assert_ok(self.send(&[self.stage_write_ix(&submitter.pubkey(), &s, (i * 900) as u16, chunk)], &[submitter]));
        }
        for (pk, msg, sig) in entries {
            let ed = ed25519_ix(&[(pk.as_slice().try_into().unwrap(), msg, sig.as_slice().try_into().unwrap())]);
            assert_ok(self.send(&[ed, self.stage_verify_ix(name, &s, 0)], &[]));
        }
        s
    }

    pub fn prove_accounts(
        &self,
        name: &str,
        submitter: &Address,
        hash: &[u8; 32],
        stage: Option<&Address>,
        finder_usdc: &Address,
        finder_token: &Address,
        pairs: &[(Address, Address)],
    ) -> Vec<AccountMeta> {
        let mut a = vec![
            AccountMeta::new(*submitter, true),
            AccountMeta::new_readonly(self.config(), false),
            AccountMeta::new(self.log(name), false),
            AccountMeta::new_readonly(self.ring(name), false),
            AccountMeta::new(self.proof(hash), false),
            match stage {
                Some(s) => AccountMeta::new(*s, false),
                None => AccountMeta::new_readonly(self.judge, false), // inline: unused slot
            },
            AccountMeta::new_readonly(SYSVAR_INSTRUCTIONS, false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(TOKEN, false),
            AccountMeta::new(self.locked(name), false),
            AccountMeta::new(self.token_mint, false),
            AccountMeta::new(*finder_usdc, false),
            AccountMeta::new(*finder_token, false),
            AccountMeta::new(self.dir_vault(name), false),
        ];
        for (w, v) in pairs {
            a.push(AccountMeta::new(*w, false));
            a.push(AccountMeta::new(*v, false));
        }
        a
    }

    pub fn prove_inline_ix(&self, kind: u8, accounts: Vec<AccountMeta>, ed_ix: u8, frk: &[u8]) -> Instruction {
        let mut data = vec![ix::PROVE_SAME_SIZE + kind - 1, 0, ed_ix];
        data.extend_from_slice(frk);
        Instruction { program_id: self.judge, accounts, data }
    }
    pub fn prove_staged_ix(&self, kind: u8, accounts: Vec<AccountMeta>) -> Instruction {
        Instruction { program_id: self.judge, accounts, data: vec![ix::PROVE_SAME_SIZE + kind - 1, 1] }
    }

    pub fn witness_status(&self, w: &Witness) -> u8 {
        self.data(&w.account(&self.judge))[layout::W_STATUS]
    }
    pub fn log_data(&self, name: &str) -> Vec<u8> {
        self.data(&self.log(name))
    }
}
