//! Rewards execute as compiled SBF with the real SPL token and ATA programs.
//! Judge data are canonical, judge-owned fixtures; judge custody has separate SBF tests.
use judge_core::attendance::{
    activate_clock, initialize_clock, initialize_epoch, CLOCK_LEN, EPOCH_LEN,
};
use litesvm::LiteSVM;
use morse_rewards::state::*;
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_sha256_hasher::{hash, hashv};
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::path::PathBuf;
const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const LOADER: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
fn ro(a: Address) -> AccountMeta {
    AccountMeta::new_readonly(a, false)
}
fn rw(a: Address) -> AccountMeta {
    AccountMeta::new(a, false)
}
fn sig(a: Address) -> AccountMeta {
    AccountMeta::new(a, true)
}
fn ata(a: Address, m: Address) -> Address {
    Address::find_program_address(&[a.as_ref(), TOKEN.as_ref(), m.as_ref()], &ATA).0
}
#[derive(Clone)]
struct Witness {
    address: Address,
    bond: Address,
    member: Address,
    vault: Address,
    payout: Address,
    signed: u64,
}
struct H {
    svm: LiteSVM,
    payer: Keypair,
    outsider: Keypair,
    program: Address,
    judge: Address,
    pool: Address,
    vault: Address,
    log: Address,
    clock: Address,
    economy: Address,
    id: [u8; 32],
    mint: Address,
    source: Address,
    started: i64,
    first: u64,
    witnesses: Vec<Witness>,
    init: Instruction,
}
impl H {
    fn account(svm: &mut LiteSVM, a: Address, o: Address, d: Vec<u8>) {
        svm.set_account(
            a,
            Account {
                lamports: svm.minimum_balance_for_rent_exemption(d.len()),
                data: d,
                owner: o,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }
    fn new() -> Self {
        Self::new_count(3)
    }
    fn new_count(count: usize) -> Self {
        let mut svm = LiteSVM::new();
        let payer = Keypair::new();
        let outsider = Keypair::new();
        for k in [&payer, &outsider] {
            svm.airdrop(&k.pubkey(), 30_000_000_000).unwrap();
        }
        let program = Address::new_unique();
        let judge = Address::new_unique();
        let binary = std::env::var_os("MORSE_REWARDS_SBF_PATH").map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/morse_rewards.so"),
            PathBuf::from,
        );
        svm.add_program_from_file(program, &binary)
            .expect("build rewards SBF first");
        // A genuine executable account pins judge identity; canonical fixture ownership
        // remains independent of reward authority.
        let executable = svm.get_account(&TOKEN).unwrap();
        svm.set_account(judge, executable).unwrap();
        let programdata = Address::find_program_address(&[program.as_ref()], &LOADER).0;
        let mut pd = svm.get_account(&programdata).unwrap();
        pd.data[12] = 1;
        pd.data[13..45].copy_from_slice(payer.pubkey().as_ref());
        svm.set_account(programdata, pd).unwrap();
        let started = 1_700_000_000;
        let first = (started / EPOCH_SECONDS) as u64 + 1;
        let mut c = svm.get_sysvar::<Clock>();
        c.unix_timestamp = started;
        c.slot = 100_000;
        svm.set_sysvar(&c);
        let name = b"rewards-test";
        let id = hash(name).to_bytes();
        let log = Address::find_program_address(&[b"log", name], &judge).0;
        let mut d = vec![0; 352];
        d[..4].copy_from_slice(b"MLG\x01");
        d[4] = 1;
        d[6] = name.len() as u8;
        d[7] = 1;
        d[8..8 + name.len()].copy_from_slice(name);
        d[40..72].copy_from_slice(&id);
        d[72..104].copy_from_slice(&[11; 32]);
        d[104..136].copy_from_slice(payer.pubkey().as_ref());
        let ring = Address::find_program_address(&[b"ring", name], &judge).0;
        d[136..168].copy_from_slice(ring.as_ref());
        H::account(&mut svm, log, judge, d);
        let clock = Address::find_program_address(&[b"attendance", &id], &judge).0;
        let mut d = vec![0; CLOCK_LEN];
        initialize_clock(&mut d, &id).unwrap();
        activate_clock(&mut d, started, 100_000).unwrap();
        H::account(&mut svm, clock, judge, d);
        let mint = Address::new_unique();
        H::account(&mut svm, mint, TOKEN, vec![0; 82]);
        let source = ata(payer.pubkey(), mint);
        let directory = Address::find_program_address(&[b"bond", &id, b"directory"], &judge).0;
        let mut log_record = svm.get_account(&log).unwrap();
        log_record.data[168..200].copy_from_slice(ata(directory, mint).as_ref());
        svm.set_account(log, log_record).unwrap();
        let pool = Address::find_program_address(&[b"pool"], &program).0;
        let vault = ata(pool, mint);
        let economy = Address::find_program_address(&[b"economics", &id], &judge).0;
        let mut d = vec![0; 192];
        d[..4].copy_from_slice(b"MEC\x01");
        d[4..36].copy_from_slice(&id);
        d[36..68].copy_from_slice(mint.as_ref());
        d[68..100].copy_from_slice(payer.pubkey().as_ref());
        put64(&mut d, 100, 100_000_000);
        put64(&mut d, 108, 500_000_000);
        put64(&mut d, 148, count as u64 * 100_000_000);
        put64(&mut d, 156, (count as u64 * 100_000_000).max(500_000_000));
        d[164] = 1;
        H::account(&mut svm, economy, judge, d);
        let mut witnesses = vec![];
        for (n, signed) in (0..count).map(|n| (n, [95, 90, 80][n % 3])) {
            let wid = format!("outside-{n}");
            let key = [(n + 11) as u8; 32];
            let identity = hashv(&[
                b"morse-witness-record-v1",
                &[wid.len() as u8],
                wid.as_bytes(),
                &key,
            ]);
            let address =
                Address::find_program_address(&[b"witness", &id, identity.as_ref()], &judge).0;
            let bond = Address::find_program_address(&[b"bond", &id, identity.as_ref()], &judge).0;
            let v = ata(bond, mint);
            let member = Address::find_program_address(&[b"member", address.as_ref()], &program).0;
            let payout = Address::new_unique();
            let mut w = vec![0; 320];
            w[..4].copy_from_slice(b"MWI\x01");
            w[4] = wid.len() as u8;
            w[5] = 1;
            w[8..8 + wid.len()].copy_from_slice(wid.as_bytes());
            w[72..104].copy_from_slice(&key);
            w[104..136].copy_from_slice(payer.pubkey().as_ref());
            w[136..168].copy_from_slice(payout.as_ref());
            w[200..232].copy_from_slice(&id);
            w[232..264].copy_from_slice(v.as_ref());
            H::account(&mut svm, address, judge, w);
            let mut b = vec![0; 208];
            b[..4].copy_from_slice(b"MBD\x01");
            b[4] = 1;
            b[5] = 1;
            b[8..40].copy_from_slice(&id);
            b[40..72].copy_from_slice(address.as_ref());
            b[72..104].copy_from_slice(payer.pubkey().as_ref());
            b[104..136].copy_from_slice(mint.as_ref());
            b[136..168].copy_from_slice(v.as_ref());
            put64(&mut b, 168, 100_000_000);
            b[176..184].copy_from_slice(&started.to_le_bytes());
            H::account(&mut svm, bond, judge, b);
            witnesses.push(Witness {
                address,
                bond,
                member,
                vault: v,
                payout,
                signed,
            });
        }
        witnesses.sort_by_key(|w| w.address);
        let init = Instruction {
            program_id: program,
            accounts: vec![
                sig(payer.pubkey()),
                sig(payer.pubkey()),
                rw(pool),
                rw(vault),
                ro(program),
                ro(programdata),
                ro(judge),
                ro(log),
                ro(clock),
                ro(mint),
                ro(TOKEN),
                ro(ATA),
                ro(Address::default()),
            ],
            data: [
                vec![0],
                payer.pubkey().as_ref().to_vec(),
                started.to_le_bytes().to_vec(),
                witnesses[2].address.as_ref().to_vec(),
            ]
            .concat(),
        };
        let mut h = Self {
            svm,
            payer,
            outsider,
            program,
            judge,
            pool,
            vault,
            log,
            clock,
            economy,
            id,
            mint,
            source,
            started,
            first,
            witnesses,
            init,
        };
        let initmint = Instruction {
            program_id: TOKEN,
            accounts: vec![rw(mint)],
            data: [vec![20, 6], h.payer.pubkey().as_ref().to_vec(), vec![0]].concat(),
        };
        let create = h.create_ata(h.payer.pubkey());
        let mintto = Instruction {
            program_id: TOKEN,
            accounts: vec![rw(mint), rw(source), sig(h.payer.pubkey())],
            data: [vec![7], 20_000_000_000u64.to_le_bytes().to_vec()].concat(),
        };
        assert!(h.send(&[initmint, create, mintto], false));
        for w in h.witnesses.clone() {
            let create = h.create_ata(w.payout);
            assert!(h.send(&[create], false));
            let create = Instruction {
                program_id: ATA,
                accounts: vec![
                    sig(h.payer.pubkey()),
                    rw(w.vault),
                    ro(w.bond),
                    ro(mint),
                    ro(Address::default()),
                    ro(TOKEN),
                ],
                data: vec![1],
            };
            let mintto = Instruction {
                program_id: TOKEN,
                accounts: vec![rw(mint), rw(w.vault), sig(h.payer.pubkey())],
                data: [vec![7], 100_000_000u64.to_le_bytes().to_vec()].concat(),
            };
            assert!(h.send(&[create, mintto], false));
        }
        h
    }
    fn ix(&self, a: Vec<AccountMeta>, d: Vec<u8>) -> Instruction {
        Instruction {
            program_id: self.program,
            accounts: a,
            data: d,
        }
    }
    fn send(&mut self, ix: &[Instruction], outsider: bool) -> bool {
        self.svm.expire_blockhash();
        let mut keys = vec![&self.payer];
        if outsider {
            keys.push(&self.outsider)
        }
        let tx = Transaction::new(
            &keys,
            Message::new(ix, Some(&self.payer.pubkey())),
            self.svm.latest_blockhash(),
        );
        assert!(bincode::serialize(&tx).unwrap().len() <= 1232);
        match self.svm.send_transaction(tx) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("refusal {:?} {:?}", e.err, e.meta.logs);
                false
            }
        }
    }
    fn time(&mut self, n: i64) {
        let mut c = self.svm.get_sysvar::<Clock>();
        c.unix_timestamp = n;
        c.slot += 2000;
        self.svm.set_sysvar(&c);
    }
    fn create_ata(&self, owner: Address) -> Instruction {
        Instruction {
            program_id: ATA,
            accounts: vec![
                sig(self.payer.pubkey()),
                rw(ata(owner, self.mint)),
                ro(owner),
                ro(self.mint),
                ro(Address::default()),
                ro(TOKEN),
            ],
            data: vec![1],
        }
    }
    fn ledger(&self, e: u64) -> Address {
        Address::find_program_address(&[b"epoch", &e.to_le_bytes()], &self.program).0
    }
    fn week(&self, e: u64) -> Address {
        Address::find_program_address(
            &[b"attendance-epoch", &self.id, &e.to_le_bytes()],
            &self.judge,
        )
        .0
    }
    fn open(&self, e: u64) -> Instruction {
        self.ix(
            vec![
                sig(self.payer.pubkey()),
                ro(self.pool),
                rw(self.ledger(e)),
                ro(Address::default()),
            ],
            [vec![1], e.to_le_bytes().to_vec()].concat(),
        )
    }
    fn fund(&self, e: u64, subsidy: bool, amount: u64) -> Instruction {
        self.ix(
            vec![
                sig(self.payer.pubkey()),
                rw(self.pool),
                rw(self.ledger(e)),
                rw(self.vault),
                rw(self.source),
                ro(self.mint),
                ro(TOKEN),
            ],
            [vec![2, u8::from(subsidy)], amount.to_le_bytes().to_vec()].concat(),
        )
    }
    fn propose(&self, n: usize, status: u8) -> Instruction {
        let w = &self.witnesses[n];
        self.ix(
            vec![
                sig(self.payer.pubkey()),
                sig(self.payer.pubkey()),
                ro(self.pool),
                ro(w.address),
                rw(w.member),
                ro(Address::default()),
            ],
            vec![3, status],
        )
    }
    fn apply(&self, n: usize) -> Instruction {
        self.ix(vec![ro(self.pool), rw(self.witnesses[n].member)], vec![4])
    }
    fn stage(&self, e: u64, tag: u8) -> Instruction {
        self.ix(
            vec![
                rw(self.pool),
                rw(self.ledger(e)),
                ro(self.log),
                ro(self.clock),
                ro(self.week(e)),
                ro(self.economy),
            ],
            vec![tag],
        )
    }
    fn append(&self, e: u64, n: usize) -> Instruction {
        let mut i = self.stage(e, 6);
        let w = &self.witnesses[n];
        i.accounts.extend([ro(w.address), ro(w.bond), ro(w.member)]);
        i
    }
    fn receipt(&mut self, e: u64) {
        let mut d = vec![0; EPOCH_LEN];
        initialize_epoch(&mut d, &self.id, e).unwrap();
        put64(&mut d, 44, 100);
        put64(&mut d, 52, 100_001);
        d[60..62].copy_from_slice(&(self.witnesses.len() as u16).to_le_bytes());
        d[62] = 1;
        for (n, w) in self.witnesses.iter().enumerate() {
            let o = 80 + n * 40;
            d[o..o + 32].copy_from_slice(w.address.as_ref());
            put64(&mut d, o + 32, w.signed)
        }
        let address = self.week(e);
        H::account(&mut self.svm, address, self.judge, d);
        let mut clock = self.svm.get_account(&self.clock).unwrap();
        let latest = u64_at(&clock.data, 60).max(e);
        put64(&mut clock.data, 60, latest);
        self.svm.set_account(self.clock, clock).unwrap();
    }
    fn settle(&mut self, e: u64) {
        self.receipt(e);
        assert!(self.send(&[self.open(e)], false));
        assert!(self.send(&[self.stage(e, 5)], false));
        for n in 0..self.witnesses.len() {
            assert!(self.send(&[self.append(e, n)], false));
        }
        assert!(self.send(&[self.stage(e, 7)], false));
    }
    fn p(&self) -> Pool {
        Pool::parse(&self.svm.get_account(&self.pool).unwrap().data).unwrap()
    }
    fn balance(&self, a: Address) -> u64 {
        u64_at(&self.svm.get_account(&a).unwrap().data, 64)
    }
    fn setup(&mut self) {
        let init = self.init.clone();
        assert!(self.send(std::slice::from_ref(&init), false));
        for n in 0..2 {
            assert!(self.send(&[self.propose(n, 1)], false));
        }
        assert!(!self.send(&[self.apply(0)], false));
        self.time(self.started + TIMELOCK_SECONDS);
        for n in 0..2 {
            assert!(self.send(&[self.apply(n)], false));
        }
        for e in self.first..self.first + 2 {
            self.time((e + 1) as i64 * EPOCH_SECONDS);
            self.settle(e);
        }
        self.time((self.first + 2) as i64 * EPOCH_SECONDS);
    }
    fn claim(&self, e: u64, n: usize) -> Instruction {
        self.ix(
            vec![
                rw(self.pool),
                rw(self.ledger(e)),
                rw(self.vault),
                rw(ata(self.witnesses[n].payout, self.mint)),
                ro(self.mint),
                ro(TOKEN),
            ],
            vec![8, n as u8],
        )
    }
    fn snapshot(&self, e: u64, name: &str) -> serde_json::Value {
        let mut keys = vec![
            self.pool,
            self.ledger(e),
            self.log,
            self.clock,
            self.economy,
            self.mint,
            self.vault,
            self.week(e),
            self.program,
        ];
        for w in &self.witnesses {
            keys.extend([w.address, w.bond, w.member, w.vault]);
        }
        let accounts:Vec<_>=keys.into_iter().filter_map(|address|self.svm.get_account(&address).map(|a|serde_json::json!({"address":address.to_string(),"owner":a.owner.to_string(),"executable":a.executable,"lamports":a.lamports.to_string(),"space":a.data.len().to_string(),"data_hex":hex::encode(a.data)}))).collect();
        let p = self.p();
        serde_json::json!({"name":name,"log_name":"rewards-test","mint":self.mint.to_string(),"log":self.log.to_string(),"clock":self.clock.to_string(),"week":self.week(e).to_string(),"economics":self.economy.to_string(),"vault":self.vault.to_string(),"context_slot":self.svm.get_sysvar::<Clock>().slot.to_string(),"program":self.program.to_string(),"judge":self.judge.to_string(),"log_id":hex::encode(self.id),"epoch":e.to_string(),"pool":self.pool.to_string(),"ledger":self.ledger(e).to_string(),"accounts":accounts,"expected":{"next_epoch":p.next_epoch.to_string(),"subsidy":p.subsidy.to_string(),"carry":p.carry.to_string(),"liabilities":p.liabilities.to_string(),"accounted":p.accounted.to_string()}})
    }
    fn revision(&mut self) {
        let mut a = self.svm.get_account(&self.economy).unwrap();
        let v = u64_at(&a.data, 168);
        put64(&mut a.data, 168, v + 1);
        self.svm.set_account(self.economy, a).unwrap();
    }
}

#[test]
fn only_loader_upgrade_authority_can_bootstrap_and_morse_is_never_admitted() {
    let mut h = H::new();
    let mut i = h.init.clone();
    i.accounts[0] = sig(h.outsider.pubkey());
    assert!(!h.send(&[i], true));
    let mut i = h.init.clone();
    i.accounts[5] = ro(h.outsider.pubkey());
    assert!(!h.send(&[i], false));
    h.svm
        .airdrop(&h.pool, h.svm.minimum_balance_for_rent_exemption(0))
        .unwrap();
    assert!(h.send(&[h.init.clone()], false));
    assert!(!h.send(&[h.init.clone()], false));
    assert!(!h.send(&[h.propose(2, 1)], false));
    assert_eq!(h.p().accounted, 0);
}

#[test]
fn revenue_epoch_isolation_floor_topup_atomicity_fixed_claims_and_bonds_unchanged() {
    let mut h = H::new();
    h.setup();
    let e = h.first + 2;
    let before: Vec<_> = h
        .witnesses
        .iter()
        .map(|w| h.svm.get_account(&w.vault).unwrap())
        .collect();
    assert!(h.send(&[h.open(e), h.fund(e, false, 1_000_003)], false));
    // A direct token donation is deliberately absent from every accounting field.
    let donation = Instruction {
        program_id: TOKEN,
        accounts: vec![rw(h.source), rw(h.vault), sig(h.payer.pubkey())],
        data: [vec![3], 5_000_000u64.to_le_bytes().to_vec()].concat(),
    };
    assert!(h.send(&[donation], false));
    assert_eq!(h.p().accounted, 1_000_003);
    h.time((e + 1) as i64 * EPOCH_SECONDS);
    assert!(h.send(&[h.open(e + 1), h.fund(e + 1, false, 200_000_000)], false));
    h.receipt(e);
    assert!(h.send(&[h.stage(e, 5)], false));
    for n in 0..3 {
        assert!(h.send(&[h.append(e, n)], false));
    }
    let pool_before = h.svm.get_account(&h.pool).unwrap();
    let ledger_before = h.svm.get_account(&h.ledger(e)).unwrap();
    assert!(!h.send(&[h.stage(e, 7)], false));
    assert_eq!(h.svm.get_account(&h.pool).unwrap(), pool_before);
    assert_eq!(h.svm.get_account(&h.ledger(e)).unwrap(), ledger_before);
    assert!(h.send(&[h.fund(e + 1, true, 300_000_000)], false));
    assert!(h.send(&[h.stage(e, 7)], false));
    let p = h.p();
    assert_eq!(p.next_epoch, e + 1);
    assert!(
        p.liabilities < 200_000_000,
        "old settlement did not capture new epoch revenue"
    );
    assert_eq!(p.carry, 0);
    assert!(
        p.subsidy > 100_000_000,
        "one weekly floor did not consume annual reserve"
    );
    let mut snapshots = vec![h.snapshot(e, "settled")];
    let liability = p.liabilities;
    let mut paid = 0;
    // A later custody mutation cannot revoke a finalized earned payout.
    h.revision();
    for n in 0..3 {
        let amount = u64_at(
            &h.svm.get_account(&h.ledger(e)).unwrap().data,
            LEDGER_HEADER + n * ROW_LEN + 120,
        );
        if amount > 0 {
            let mut bad = h.claim(e, n);
            bad.accounts[3] = rw(h.source);
            assert!(!h.send(&[bad], false));
            assert!(h.send(&[h.claim(e, n)], false));
            assert!(!h.send(&[h.claim(e, n)], false));
            assert_eq!(h.balance(ata(h.witnesses[n].payout, h.mint)), amount);
            paid += amount;
        }
    }
    snapshots.push(h.snapshot(e, "claimed"));
    if let Ok(path) = std::env::var("MORSE_REWARDS_FIXTURES_PATH") {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&serde_json::json!({"version":1,"snapshots":&snapshots,"reader_snapshots":&snapshots}))
                .unwrap(),
        )
        .unwrap();
    }
    assert_eq!(paid, liability);
    assert_eq!(h.p().liabilities, 0);
    assert_eq!(h.balance(h.vault), h.p().accounted + 5_000_000);
    for (n, w) in h.witnesses.iter().enumerate() {
        assert_eq!(h.svm.get_account(&w.vault).unwrap(), before[n]);
    }
}

#[test]
fn all_rows_canonical_accounts_and_coherent_revision_are_mandatory() {
    let mut h = H::new();
    h.setup();
    let e = h.first + 2;
    assert!(h.send(&[h.open(e), h.fund(e, true, 300_000_000)], false));
    h.time((e + 1) as i64 * EPOCH_SECONDS);
    h.receipt(e);
    assert!(h.send(&[h.stage(e, 5)], false));
    assert!(!h.send(&[h.stage(e, 7)], false));
    assert!(!h.send(&[h.append(e, 1)], false));
    let mut fake = h.append(e, 0);
    fake.accounts[7] = ro(h.witnesses[1].bond);
    assert!(!h.send(&[fake], false));
    let original = h.witnesses[0].address;
    let a = h.svm.get_account(&original).unwrap();
    let mut wrong = a.clone();
    wrong.owner = h.program;
    h.svm.set_account(original, wrong).unwrap();
    assert!(!h.send(&[h.append(e, 0)], false));
    h.svm.set_account(original, a).unwrap();
    assert!(h.send(&[h.append(e, 0)], false));
    // Admission execution is frozen while a snapshot is being assembled.
    assert!(h.send(&[h.propose(0, 0)], false));
    assert!(!h.send(&[h.apply(0)], false));
    let cancel = h.ix(vec![rw(h.pool), rw(h.ledger(e)), ro(h.economy)], vec![11]);
    assert!(!h.send(std::slice::from_ref(&cancel), false));
    h.revision();
    assert!(!h.send(&[h.append(e, 1)], false));
    assert!(!h.send(&[h.stage(e, 7)], false));
    let subsidy = h.p().subsidy;
    assert!(h.send(&[cancel], false));
    assert_eq!(h.p().subsidy, subsidy);
    assert_eq!(h.p().next_epoch, e);
    assert_eq!(h.p().liabilities, 0);
    assert!(h.send(&[h.stage(e, 5)], false));
    for n in 0..3 {
        assert!(h.send(&[h.append(e, n)], false));
    }
    h.revision();
    assert!(!h.send(&[h.stage(e, 7)], false));
}

#[test]
fn bootstrap_no_eligible_witnesses_carry_revenue_without_consuming_subsidy() {
    let mut h = H::new();
    assert!(h.send(&[h.init.clone()], false));
    let e = h.first;
    h.time(e as i64 * EPOCH_SECONDS);
    assert!(h.send(
        &[
            h.open(e),
            h.fund(e, false, 99),
            h.fund(e, true, 300_000_000)
        ],
        false
    ));
    h.time((e + 1) as i64 * EPOCH_SECONDS);
    h.settle(e);
    assert_eq!(h.p().carry, 99);
    assert_eq!(h.p().subsidy, 300_000_000);
    assert_eq!(h.p().liabilities, 0);
    assert!(!h.send(&[h.stage(e, 5)], false));
    assert!(!h.send(&[h.fund(e, false, 1)], false));
}

#[test]
fn registered_bootstrap_rows_without_bonds_are_still_consumed() {
    let mut h = H::new();
    assert!(h.send(&[h.init.clone()], false));
    for w in h.witnesses.clone() {
        let mut a = h.svm.get_account(&w.address).unwrap();
        a.data[5] = 0;
        a.data[232..272].fill(0);
        h.svm.set_account(w.address, a).unwrap();
        h.svm.set_account(w.bond, Account::default()).unwrap();
    }
    let e = h.first;
    h.time((e + 1) as i64 * EPOCH_SECONDS);
    h.settle(e);
    assert_eq!(h.p().liabilities, 0);
}

#[test]
fn expired_staging_cancels_without_moving_money_or_allowing_late_finalize() {
    let mut h = H::new();
    h.setup();
    let e = h.first + 2;
    assert!(h.send(
        &[
            h.open(e),
            h.fund(e, false, 99),
            h.fund(e, true, 300_000_000)
        ],
        false
    ));
    h.time((e + 1) as i64 * EPOCH_SECONDS);
    h.receipt(e);
    assert!(h.send(&[h.stage(e, 5)], false));
    assert!(h.send(&[h.append(e, 0)], false));
    let cancel = h.ix(vec![rw(h.pool), rw(h.ledger(e)), ro(h.economy)], vec![11]);
    assert!(!h.send(std::slice::from_ref(&cancel), false));
    let p = h.p();
    h.time((e + 1) as i64 * EPOCH_SECONDS + 3600);
    assert!(!h.send(&[h.append(e, 1)], false));
    assert!(!h.send(&[h.stage(e, 7)], false));
    assert!(h.send(&[cancel], false));
    assert_eq!(h.p().subsidy, p.subsidy);
    assert_eq!(h.p().carry, p.carry);
    assert_eq!(h.p().liabilities, p.liabilities);
    assert_eq!(h.p().next_epoch, p.next_epoch);
    assert_eq!(
        u64_at(&h.svm.get_account(&h.ledger(e)).unwrap().data, 44),
        99
    );
    assert!(h.send(&[h.stage(e, 5)], false));
}

#[test]
fn sixty_four_rows_and_high_claim_bit_work_without_large_stack_frames() {
    let mut h = H::new_count(64);
    h.setup();
    let e = h.first + 2;
    let w = h.witnesses[63].clone();
    let mut d = vec![0; MEMBER_LEN];
    d[..4].copy_from_slice(b"MRM\x01");
    d[4..36].copy_from_slice(w.address.as_ref());
    d[36] = 1;
    d[48..56].copy_from_slice(&h.started.to_le_bytes());
    H::account(&mut h.svm, w.member, h.program, d);
    h.witnesses[63].signed = 95;
    assert!(h.send(&[h.open(e), h.fund(e, true, 500_000_000)], false));
    h.time((e + 1) as i64 * EPOCH_SECONDS);
    h.settle(e);
    let before = h.p().liabilities;
    assert!(h.send(&[h.claim(e, 63)], false));
    assert!(!h.send(&[h.claim(e, 63)], false));
    assert!(h.p().liabilities < before);
    assert_eq!(
        u64_at(&h.svm.get_account(&h.ledger(e)).unwrap().data, 160),
        1u64 << 63
    );
}

#[test]
fn canonical_mint_week_and_pdas_are_checked_even_when_account_bytes_look_valid() {
    let mut h = H::new();
    h.setup();
    let e = h.first + 2;
    assert!(h.send(&[h.open(e)], false));
    let before = h.svm.get_account(&h.pool).unwrap();
    let mut alias = h.fund(e, false, 100);
    alias.accounts[3] = rw(h.witnesses[0].vault);
    assert!(!h.send(&[alias], false));
    let mut alias = h.fund(e, false, 100);
    alias.accounts[4] = rw(h.vault);
    assert!(!h.send(&[alias], false));
    let mut alias = h.fund(e, false, 100);
    alias.accounts[2] = rw(h.pool);
    assert!(!h.send(&[alias], false));
    assert_eq!(h.svm.get_account(&h.pool).unwrap(), before);
    let fake_mint = Address::new_unique();
    let a = h.svm.get_account(&h.mint).unwrap();
    h.svm.set_account(fake_mint, a).unwrap();
    let mut wrong = h.fund(e, false, 100);
    wrong.accounts[5] = ro(fake_mint);
    assert!(!h.send(&[wrong], false));
    h.time((e + 1) as i64 * EPOCH_SECONDS);
    h.receipt(e);
    let fake_week = Address::new_unique();
    let a = h.svm.get_account(&h.week(e)).unwrap();
    h.svm.set_account(fake_week, a.clone()).unwrap();
    let mut wrong = h.stage(e, 5);
    wrong.accounts[4] = ro(fake_week);
    assert!(!h.send(&[wrong], false));
    let mut changed = a.clone();
    changed.owner = h.program;
    h.svm.set_account(h.week(e), changed).unwrap();
    assert!(!h.send(&[h.stage(e, 5)], false));
    h.svm.set_account(h.week(e), a.clone()).unwrap();
    assert!(h.send(&[h.stage(e, 5)], false));
    let mut changed = a;
    put64(&mut changed.data, 44, 101);
    h.svm.set_account(h.week(e), changed).unwrap();
    assert!(!h.send(&[h.append(e, 0)], false));
}

#[test]
fn later_epoch_settlement_cannot_redistribute_unclaimed_liabilities() {
    let mut h = H::new();
    h.setup();
    let e = h.first + 2;
    assert!(h.send(&[h.open(e), h.fund(e, true, 500_000_000)], false));
    h.time((e + 1) as i64 * EPOCH_SECONDS);
    h.settle(e);
    let first_liability = h.p().liabilities;
    let first_amount = u64_at(
        &h.svm.get_account(&h.ledger(e)).unwrap().data,
        LEDGER_HEADER + 120,
    );
    assert!(h.send(&[h.open(e + 1), h.fund(e + 1, false, 200_000_000)], false));
    h.time((e + 2) as i64 * EPOCH_SECONDS);
    h.settle(e + 1);
    assert!(h.p().liabilities >= first_liability + 200_000_000 - 2);
    assert_eq!(
        u64_at(
            &h.svm.get_account(&h.ledger(e)).unwrap().data,
            LEDGER_HEADER + 120
        ),
        first_amount
    );
    if first_amount > 0 {
        assert!(h.send(&[h.claim(e, 0)], false));
        assert_eq!(h.balance(ata(h.witnesses[0].payout, h.mint)), first_amount);
    }
}

#[test]
fn ready_governance_changes_wait_for_staging_and_permanent_exclusion_cannot_reopen() {
    let mut h = H::new();
    h.setup();
    let e = h.first + 2;
    assert!(h.send(&[h.open(e), h.propose(0, 0)], false));
    let proposal = h.ix(
        vec![sig(h.payer.pubkey()), rw(h.pool)],
        [vec![9], h.outsider.pubkey().as_ref().to_vec()].concat(),
    );
    assert!(h.send(&[proposal], false));
    let apply_governance = h.ix(vec![rw(h.pool)], vec![10]);
    assert!(!h.send(std::slice::from_ref(&apply_governance), false));
    let ready = e as i64 * EPOCH_SECONDS + TIMELOCK_SECONDS;
    h.time(ready);
    h.receipt(e);
    assert!(h.send(&[h.stage(e, 5)], false));
    assert!(!h.send(&[h.apply(0)], false));
    assert!(!h.send(std::slice::from_ref(&apply_governance), false));
    h.time(ready + 3600);
    let cancel = h.ix(vec![rw(h.pool), rw(h.ledger(e)), ro(h.economy)], vec![11]);
    assert!(h.send(&[cancel, h.apply(0), apply_governance], false));
    assert_eq!(h.p().governance, *h.outsider.pubkey().as_array());
    assert!(!h.send(&[h.propose(1, 2)], false));
    let mut proposal = h.propose(1, 2);
    proposal.accounts[0] = sig(h.outsider.pubkey());
    assert!(h.send(&[proposal], true));
    h.time(ready + 3600 + TIMELOCK_SECONDS);
    assert!(h.send(&[h.apply(1)], false));
    let mut reopen = h.propose(1, 1);
    reopen.accounts[0] = sig(h.outsider.pubkey());
    assert!(!h.send(&[reopen], true));
}

#[test]
fn actual_judge_active_topup_does_not_invalidate_a_partial_reward_snapshot() {
    let mut h = H::new();
    h.setup();
    let e = h.first + 2;
    let judge_binary = std::env::var_os("MORSE_JUDGE_SBF_PATH").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/morse_judge.so"),
        PathBuf::from,
    );
    h.svm
        .add_program_from_file(h.judge, judge_binary)
        .expect("build judge SBF before rewards integration");
    let mut economy = h.svm.get_account(&h.economy).unwrap();
    put64(&mut economy.data, 148, 300_000_000);
    put64(&mut economy.data, 156, 500_000_000);
    h.svm.set_account(h.economy, economy).unwrap();
    assert!(h.send(&[h.open(e), h.fund(e, true, 300_000_000)], false));
    h.time((e + 1) as i64 * EPOCH_SECONDS);
    h.receipt(e);
    assert!(h.send(&[h.stage(e, 5), h.append(e, 0)], false));
    let w = h.witnesses[0].clone();
    let topup = Instruction {
        program_id: h.judge,
        accounts: vec![
            sig(h.payer.pubkey()),
            ro(h.log),
            rw(h.economy),
            rw(w.address),
            rw(w.bond),
            rw(w.vault),
            rw(h.source),
            ro(h.mint),
            ro(TOKEN),
            ro(ATA),
            ro(Address::default()),
        ],
        data: [vec![18], 1u64.to_le_bytes().to_vec()].concat(),
    };
    assert!(h.send(&[topup], false));
    assert_eq!(u64_at(&h.svm.get_account(&h.economy).unwrap().data, 168), 0);
    for n in 1..3 {
        assert!(h.send(&[h.append(e, n)], false));
    }
    assert!(h.send(&[h.stage(e, 7)], false));
}

#[test]
fn a_mid_week_bond_never_earns_the_full_week_floor() {
    let mut h = H::new();
    h.setup();
    let e = h.first + 2;
    for w in h.witnesses.clone() {
        let mut b = h.svm.get_account(&w.bond).unwrap();
        b.data[176..184].copy_from_slice(&(e as i64 * EPOCH_SECONDS + 1).to_le_bytes());
        h.svm.set_account(w.bond, b).unwrap();
    }
    assert!(h.send(
        &[
            h.open(e),
            h.fund(e, false, 99),
            h.fund(e, true, 300_000_000)
        ],
        false
    ));
    h.time((e + 1) as i64 * EPOCH_SECONDS);
    h.settle(e);
    assert_eq!(h.p().carry, 99);
    assert_eq!(h.p().subsidy, 300_000_000);
    assert_eq!(h.p().liabilities, 0);
}

impl H {
    fn receipt_address(&self, id: [u8; 32]) -> Address {
        Address::find_program_address(
            &[b"funding", self.payer.pubkey().as_ref(), &id],
            &self.program,
        )
        .0
    }
    fn idempotent_fund(&self, e: u64, kind: u8, amount: u64, id: [u8; 32]) -> Instruction {
        self.ix(
            vec![
                sig(self.payer.pubkey()),
                sig(self.payer.pubkey()),
                rw(self.pool),
                rw(self.ledger(e)),
                rw(self.vault),
                rw(self.source),
                ro(self.mint),
                ro(TOKEN),
                rw(self.receipt_address(id)),
                ro(Address::default()),
            ],
            [vec![12, kind], amount.to_le_bytes().to_vec(), id.to_vec()].concat(),
        )
    }
}
#[test]
fn durable_funding_receipts_make_re_signed_and_expired_retries_exactly_once() {
    let mut h = H::new();
    h.setup();
    let e = h.first + 2;
    assert!(h.send(&[h.open(e)], false));
    let id = [44; 32];
    let receipt = h.receipt_address(id);
    h.svm
        .airdrop(&receipt, h.svm.minimum_balance_for_rent_exemption(0))
        .unwrap();
    let intent = h.idempotent_fund(e, 0, 99, id);
    assert!(h.send(std::slice::from_ref(&intent), false));
    let source = h.balance(h.source);
    let accounted = h.p().accounted;
    let original = h.svm.get_account(&receipt).unwrap();
    assert!(h.send(std::slice::from_ref(&intent), false));
    assert_eq!(h.balance(h.source), source);
    assert_eq!(h.p().accounted, accounted);
    assert!(!h.send(&[h.idempotent_fund(e, 0, 100, id)], false));
    assert!(!h.send(&[h.idempotent_fund(e, 1, 99, id)], false));
    assert_eq!(h.svm.get_account(&receipt).unwrap(), original);
    h.time((e + 1) as i64 * EPOCH_SECONDS);
    assert!(h.send(&[h.open(e + 1)], false));
    assert!(!h.send(&[h.idempotent_fund(e + 1, 0, 99, id)], false));
    assert!(h.send(std::slice::from_ref(&intent), false));
    assert!(h.send(&[h.fund(e + 1, true, 300_000_000)], false));
    h.settle(e);
    assert!(h.send(&[intent], false));
    assert_eq!(h.balance(h.source), source - 300_000_000);
}
#[test]
fn idempotent_funding_receipt_and_token_move_rollback_together() {
    let mut h = H::new();
    h.setup();
    let e = h.first + 2;
    assert!(h.send(&[h.open(e)], false));
    let id = [45; 32];
    let before = h.svm.get_account(&h.pool).unwrap();
    let source = h.balance(h.source);
    assert!(!h.send(&[h.idempotent_fund(e, 0, source + 1, id)], false));
    assert!(h.svm.get_account(&h.receipt_address(id)).is_none());
    assert_eq!(h.svm.get_account(&h.pool).unwrap(), before);
    let mut wrong = h.idempotent_fund(e, 0, 10, id);
    wrong.accounts[8] = rw(h.witnesses[0].member);
    assert!(!h.send(&[wrong], false));
    assert!(!h.send(&[h.idempotent_fund(e, 0, 10, [0; 32])], false));
    assert_eq!(h.balance(h.source), source);
}
