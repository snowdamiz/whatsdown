//! morse-rewards: pool, epochs, pay factor, floor, carry-over, excluded
//! witnesses, token-bond eligibility and burns.

use morse_program_tests::*;

const MIN: u64 = 1_000_000_000;

mod rcode {
    pub const WRONG_ACCOUNT: u32 = 7000;
    pub const UNAUTHORIZED: u32 = 7001;
    pub const EPOCH_NOT_OVER: u32 = 7003;
    pub const ALREADY_SETTLED: u32 = 7004;
    pub const ALREADY_CLAIMED: u32 = 7005;
    pub const WRONG_DESTINATION: u32 = 7006;
    pub const WITNESS_ACCOUNTS_MISMATCH: u32 = 7007;
    pub const NO_TOKEN_MINT: u32 = 7008;
}

struct R {
    env: Env,
    service: ed25519_dalek::SigningKey,
    oracle: Address,
    feed: Address,
}

impl R {
    fn new() -> R {
        let (mut env, service) = Env::new();
        let r = env.rewards;
        let mut data = vec![0u8];
        data.extend_from_slice(env.gov.pubkey().as_ref());
        data.extend_from_slice(env.judge.as_ref());
        data.extend_from_slice(env.log(MAIN).as_ref());
        data.extend_from_slice(env.usdc.as_ref());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0i64.to_le_bytes());
        let d = env.deployer.insecure_clone();
        let i = Instruction {
            program_id: r,
            accounts: vec![
                AccountMeta::new(d.pubkey(), true),
                AccountMeta::new(pda(&[b"config"], &r), false),
                AccountMeta::new_readonly(env.programdata(&r), false),
                AccountMeta::new_readonly(SYSTEM, false),
            ],
            data,
        };
        assert_ok(env.send(&[i], &[&d]));
        let pool_owner = pda(&[b"pool"], &r);
        let usdc = env.usdc;
        env.fund(&pool_owner, &usdc, 0);
        R { env, service, oracle: Address::new_unique(), feed: Address::new_unique() }
    }
    fn config(&self) -> Address {
        pda(&[b"config"], &self.env.rewards)
    }
    fn pool(&self) -> Address {
        ata(&pda(&[b"pool"], &self.env.rewards), &self.env.usdc)
    }
    fn epoch_account(&self, e: u64) -> Address {
        pda(&[b"epoch", &e.to_le_bytes()], &self.env.rewards)
    }
    fn set_param(&mut self, kind: u8, value: &[u8]) -> litesvm::types::TransactionResult {
        let gov = self.env.gov.insecure_clone();
        let mut v = [0u8; 32];
        v[..value.len()].copy_from_slice(value);
        let i = Instruction {
            program_id: self.env.rewards,
            accounts: vec![AccountMeta::new_readonly(gov.pubkey(), true), AccountMeta::new(self.config(), false)],
            data: [&[1, kind][..], &v].concat(),
        };
        self.env.send(&[i], &[&gov])
    }
    fn fund_pool(&mut self, amount: u64) {
        let funder = Keypair::new();
        let usdc = self.env.usdc;
        let src = self.env.fund(&funder.pubkey(), &usdc, amount);
        let i = Instruction {
            program_id: self.env.rewards,
            accounts: vec![
                AccountMeta::new_readonly(funder.pubkey(), true),
                AccountMeta::new(src, false),
                AccountMeta::new(self.pool(), false),
                AccountMeta::new_readonly(self.config(), false),
                AccountMeta::new_readonly(TOKEN, false),
            ],
            data: [&[2u8][..], &amount.to_le_bytes()].concat(),
        };
        assert_ok(self.env.send(&[i], &[&funder]));
    }
    fn settle_ix(&self, epoch: u64, pairs: &[(Address, Address)]) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(self.env.payer.pubkey(), true),
            AccountMeta::new(self.config(), false),
            AccountMeta::new_readonly(self.env.log(MAIN), false),
            AccountMeta::new_readonly(self.pool(), false),
            AccountMeta::new(self.epoch_account(epoch), false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(self.feed, false),
        ];
        for (w, v) in pairs {
            accounts.push(AccountMeta::new_readonly(*w, false));
            accounts.push(AccountMeta::new_readonly(*v, false));
        }
        Instruction { program_id: self.env.rewards, accounts, data: [&[3u8][..], &epoch.to_le_bytes()].concat() }
    }
    fn settle(&mut self, epoch: u64, ws: &[&Witness]) -> litesvm::types::TransactionResult {
        let pairs: Vec<(Address, Address)> = ws.iter().map(|w| (w.account(&self.env.judge), w.vault(&self.env.judge))).collect();
        let i = self.settle_ix(epoch, &pairs);
        self.env.send(&[i], &[])
    }
    fn claim(&mut self, epoch: u64, index: u8, destination: Address) -> litesvm::types::TransactionResult {
        let i = Instruction {
            program_id: self.env.rewards,
            accounts: vec![
                AccountMeta::new(self.config(), false),
                AccountMeta::new(self.epoch_account(epoch), false),
                AccountMeta::new(self.pool(), false),
                AccountMeta::new_readonly(pda(&[b"pool"], &self.env.rewards), false),
                AccountMeta::new(destination, false),
                AccountMeta::new_readonly(TOKEN, false),
            ],
            data: [&[4u8][..], &epoch.to_le_bytes(), &[index]].concat(),
        };
        self.env.send(&[i], &[])
    }
    fn allocations(&self, epoch: u64) -> Vec<(Address, Address, u64)> {
        let d = self.env.data(&self.epoch_account(epoch));
        (0..d[3] as usize)
            .map(|i| {
                let o = 40 + i * 80;
                (Address::try_from(&d[o..o + 32]).unwrap(), Address::try_from(&d[o + 32..o + 64]).unwrap(), u64le(&d, o + 64))
            })
            .collect()
    }
    fn reserved(&self) -> u64 {
        u64le(&self.env.data(&self.config()), 256)
    }
    fn epoch(&self) -> u64 {
        (self.env.now / EPOCH) as u64
    }
    fn end_epoch(&mut self) {
        let next = (self.env.now / EPOCH + 1) * EPOCH + 900;
        let slots = (next - self.env.now) as u64 * 2;
        self.env.set_clock(next, self.env.slot + slots);
    }
    /// Posts `anchors` checkpoints; witness i cosigns the first `cosigns[i]`.
    fn attend(&mut self, anchors: u64, ws: &[(&Witness, u8, u64)]) {
        let base = u64le(&self.env.data(&self.env.ring(MAIN)), layout::RH_LAST_SEQUENCE) + 1;
        let start = u32le(&self.env.data(&self.env.ring(MAIN)), layout::RH_HEAD);
        for n in 0..anchors {
            let s = self.service.clone();
            let k = ktk(&s, base + n, base + n, [n as u8; 32], self.env.now_ms());
            assert_ok(self.env.post(MAIN, &s, &k));
            for (w, list_index, cosigns) in ws {
                if n < *cosigns {
                    assert_ok(self.env.cosign(MAIN, start + n as u32, *list_index, w));
                }
            }
            self.env.advance(60, 150);
        }
    }
    fn bonded(&mut self, id: &str, seed: u8, excluded: bool) -> Witness {
        let w = self.env.witness(MAIN, id, seed);
        assert_ok(self.env.register(MAIN, &w, excluded));
        let usdc = self.env.usdc;
        assert_ok(self.env.bond(MAIN, &w, &usdc, MIN));
        w
    }
    fn set_feed(&mut self, price: i64, exponent: i32, at: i64) {
        let mut d = price.to_le_bytes().to_vec();
        d.extend_from_slice(&exponent.to_le_bytes());
        d.extend_from_slice(&at.to_le_bytes());
        self.env
            .svm
            .set_account(self.feed, solana_account::Account { lamports: 1_000_000, data: d, owner: self.oracle, executable: false, rent_epoch: 0 })
            .unwrap();
    }
}

#[test]
fn pay_follows_attendance_and_excluded_witnesses_are_never_paid() {
    let mut r = R::new();
    let a = r.bonded("witness-a", 0xA1, false);
    let b = r.bonded("witness-b", 0xB2, false);
    let c = r.bonded("witness-c", 0xC3, false);
    let m = r.bonded("morse-1", 0x4D, true);
    r.fund_pool(3_000_000);
    let e = r.epoch();
    // 20 anchors: a 100%, b 90% (factor 2/3), c 80% (factor 0), Morse 100%.
    r.attend(20, &[(&a, 0, 20), (&b, 1, 18), (&c, 2, 16), (&m, 3, 20)]);
    assert_code(r.settle(e, &[&a, &b, &c, &m]), rcode::EPOCH_NOT_OVER);
    r.end_epoch();
    assert_code(r.settle(e, &[&a, &b, &c]), rcode::WITNESS_ACCOUNTS_MISMATCH);
    assert_code(r.settle(e, &[&b, &a, &c, &m]), rcode::WITNESS_ACCOUNTS_MISMATCH);
    assert_ok(r.settle(e, &[&a, &b, &c, &m]));
    let allocs = r.allocations(e);
    let j = r.env.judge;
    assert_eq!(allocs, vec![(a.account(&j), a.payout.pubkey(), 1_000_000), (b.account(&j), b.payout.pubkey(), 666_666)]);
    assert_eq!(r.reserved(), 1_666_666);
    assert_eq!(u64le(&r.env.data(&r.epoch_account(e)), 32), 20, "anchors recorded");
    assert_code(r.settle(e, &[&a, &b, &c, &m]), rcode::ALREADY_SETTLED);
    // Claims go to the payout address only, once.
    let usdc = r.env.usdc;
    let wrong = r.env.fund(&a.operator.pubkey(), &usdc, 0);
    assert_code(r.claim(e, 0, wrong), rcode::WRONG_DESTINATION);
    let dest = r.env.fund(&a.payout.pubkey(), &usdc, 0);
    assert_ok(r.claim(e, 0, dest));
    assert_eq!(r.env.balance(&dest), 1_000_000);
    assert_code(r.claim(e, 0, dest), rcode::ALREADY_CLAIMED);
    assert_eq!(r.reserved(), 666_666);
    assert_eq!(r.env.balance(&r.pool()), 2_000_000);
    // Next epoch nobody attends: the unallocated pool carries over untouched.
    let e2 = r.epoch();
    r.end_epoch();
    assert_ok(r.settle(e2, &[&a, &b, &c, &m]));
    assert!(r.allocations(e2).is_empty());
    assert_eq!(u64le(&r.env.data(&r.epoch_account(e2)), 16), 2_000_000 - 666_666, "budget excludes unclaimed pay");
    assert_eq!(r.reserved(), 666_666);
}

#[test]
fn bootstrap_with_only_morse_witnesses_pays_nobody_and_carries_over() {
    let mut r = R::new();
    let m1 = r.bonded("morse-1", 0x41, true);
    let m2 = r.bonded("morse-2", 0x42, true);
    r.fund_pool(500_000);
    let e = r.epoch();
    r.attend(5, &[(&m1, 0, 5), (&m2, 1, 5)]);
    r.end_epoch();
    assert_ok(r.settle(e, &[&m1, &m2]));
    assert!(r.allocations(e).is_empty());
    assert_eq!(r.reserved(), 0);
    assert_eq!(r.env.balance(&r.pool()), 500_000);
}

#[test]
fn empty_registry_settles_and_carries_over() {
    let mut r = R::new();
    r.fund_pool(10);
    let e = r.epoch();
    r.end_epoch();
    assert_ok(r.settle(e, &[]));
    assert!(r.allocations(e).is_empty());
    assert_eq!(r.env.balance(&r.pool()), 10);
}

#[test]
fn floor_raises_the_share_while_it_lasts_but_never_beyond_the_pool() {
    let mut r = R::new();
    let a = r.bonded("witness-a", 0xA1, false);
    let b = r.bonded("witness-b", 0xB2, false);
    r.fund_pool(1_000);
    assert_ok(r.set_param(5, &800u64.to_le_bytes()));
    let until = r.env.now + 30 * DAY;
    assert_ok(r.set_param(6, &until.to_le_bytes()));
    let e = r.epoch();
    r.attend(4, &[(&a, 0, 4)]);
    r.end_epoch();
    assert_ok(r.settle(e, &[&a, &b]));
    assert_eq!(r.allocations(e)[0].2, 800, "floor beats the 500 equal share");
    // Both at full attendance: 2 × 800 > 1,000 available, scaled to the pool.
    r.fund_pool(800);
    let e2 = r.epoch();
    r.attend(4, &[(&a, 0, 4), (&b, 1, 4)]);
    r.end_epoch();
    assert_ok(r.settle(e2, &[&a, &b]));
    let al = r.allocations(e2);
    assert_eq!((al[0].2, al[1].2), (500, 500));
    // After the floor period: plain equal shares.
    r.env.set_clock(until + 1, r.env.slot + 10);
    r.fund_pool(1_000);
    let e3 = r.epoch();
    r.attend(4, &[(&a, 0, 4)]);
    r.end_epoch();
    assert_ok(r.settle(e3, &[&a, &b]));
    assert_eq!(r.allocations(e3)[0].2, 500);
}

#[test]
fn only_active_witnesses_are_paid() {
    let mut r = R::new();
    let a = r.bonded("witness-a", 0xA1, false);
    let reg = r.env.witness(MAIN, "witness-r", 0xAA);
    assert_ok(r.env.register(MAIN, &reg, false));
    r.fund_pool(1_000);
    let e = r.epoch();
    r.attend(2, &[(&a, 0, 2), (&reg, 1, 2)]);
    assert_ok(r.env.unbond_witness(MAIN, &a));
    r.end_epoch();
    assert_ok(r.settle(e, &[&a, &reg]));
    assert!(r.allocations(e).is_empty(), "unbonding and unbonded witnesses earn nothing");
}

#[test]
fn a_token_bond_below_80_percent_for_7_days_loses_pay_but_is_never_slashed() {
    let mut r = R::new();
    r.env.set_token_mint();
    let tm = r.env.token_mint;
    assert_ok(r.set_param(2, tm.as_ref()));
    let oracle = r.oracle;
    let feed = r.feed;
    assert_ok(r.set_param(3, oracle.as_ref()));
    assert_ok(r.set_param(4, feed.as_ref()));
    assert_ok(r.set_param(7, &10_000_000_000u64.to_le_bytes())); // $10,000 target
    let t = r.env.witness(MAIN, "witness-t", 0x71);
    assert_ok(r.env.register(MAIN, &t, false));
    assert_ok(r.env.bond(MAIN, &t, &tm, MIN)); // 1,000 tokens
    let check = |r: &R| Instruction {
        program_id: r.env.rewards,
        accounts: vec![
            AccountMeta::new(r.config(), false),
            AccountMeta::new_readonly(r.env.log(MAIN), false),
            AccountMeta::new_readonly(r.feed, false),
            AccountMeta::new_readonly(t.account(&r.env.judge), false),
            AccountMeta::new_readonly(t.vault(&r.env.judge), false),
        ],
        data: vec![6],
    };
    let below_since = |r: &R| u64le(&r.env.data(&r.config()), 264 + 32) as i64;
    // $10 per token: worth $10,000, fine.
    r.set_feed(1_000, -2, r.env.now);
    assert_ok(r.env.send(&[check(&r)], &[]));
    assert_eq!(below_since(&r), 0);
    // $7: worth $7,000 < $8,000. The clock starts.
    r.set_feed(700, -2, r.env.now);
    let started = r.env.now;
    assert_ok(r.env.send(&[check(&r)], &[]));
    assert_eq!(below_since(&r), started);
    // Within the 7 days: still paid.
    r.fund_pool(2_000);
    let e1 = r.epoch();
    r.attend(2, &[(&t, 0, 2)]);
    r.end_epoch();
    assert!(r.env.now - started < 7 * DAY);
    r.set_feed(700, -2, r.env.now);
    assert_ok(r.settle(e1, &[&t]));
    assert_eq!(r.allocations(e1).len(), 1, "paid inside the grace period");
    // A stale feed changes nothing.
    r.set_feed(1_000, -2, r.env.now - 2 * DAY);
    assert_ok(r.env.send(&[check(&r)], &[]));
    assert_eq!(below_since(&r), started);
    // Past 7 days below target: settlement leaves it out.
    r.env.set_clock(started + 7 * DAY + 3600, r.env.slot + 10_000);
    r.fund_pool(2_000);
    let e2 = r.epoch();
    r.attend(2, &[(&t, 0, 2)]);
    r.end_epoch();
    r.set_feed(700, -2, r.env.now);
    assert_ok(r.settle(e2, &[&t]));
    assert!(r.allocations(e2).is_empty(), "ineligible after 7 days below 80%");
    assert_eq!(r.env.witness_status(&t), layout::ACTIVE, "never slashed");
    assert_eq!(r.env.balance(&t.vault(&r.env.judge)), MIN, "bond untouched");
    // Topping up (or a price recovery) restores eligibility.
    r.set_feed(1_000, -2, r.env.now);
    assert_ok(r.env.send(&[check(&r)], &[]));
    assert_eq!(below_since(&r), 0);
}

#[test]
fn burn_destroys_every_token_the_burn_account_holds() {
    let mut r = R::new();
    let tm = r.env.token_mint;
    let burn_owner = pda(&[b"burn"], &r.env.rewards);
    let holding = r.env.fund(&burn_owner, &tm, 5_000);
    let burn_ix = |r: &R, holding: Address| Instruction {
        program_id: r.env.rewards,
        accounts: vec![
            AccountMeta::new_readonly(r.config(), false),
            AccountMeta::new_readonly(burn_owner, false),
            AccountMeta::new(holding, false),
            AccountMeta::new(tm, false),
            AccountMeta::new_readonly(TOKEN, false),
        ],
        data: vec![5],
    };
    assert_code(r.env.send(&[burn_ix(&r, holding)], &[]), rcode::NO_TOKEN_MINT);
    assert_ok(r.set_param(2, tm.as_ref()));
    let someone = r.env.fund(&Keypair::new().pubkey(), &tm, 10);
    assert_code(r.env.send(&[burn_ix(&r, someone)], &[]), rcode::WRONG_ACCOUNT);
    let supply = u64le(&r.env.data(&tm), 36);
    assert_ok(r.env.send(&[burn_ix(&r, holding)], &[]));
    assert_eq!(r.env.balance(&holding), 0);
    assert_eq!(u64le(&r.env.data(&tm), 36), supply - 5_000);
    assert_eq!(r.env.balance(&someone), 10);
}

#[test]
fn governance_only_and_initialize_once() {
    let mut r = R::new();
    let stranger = Keypair::new();
    let i = Instruction {
        program_id: r.env.rewards,
        accounts: vec![AccountMeta::new_readonly(stranger.pubkey(), true), AccountMeta::new(r.config(), false)],
        data: [&[1u8, 5][..], &[0; 32]].concat(),
    };
    assert_code(r.env.send(&[i], &[&stranger]), rcode::UNAUTHORIZED);
    // The pool can only be the pool.
    let usdc = r.env.usdc;
    let funder = Keypair::new();
    let src = r.env.fund(&funder.pubkey(), &usdc, 5);
    let elsewhere = r.env.fund(&Keypair::new().pubkey(), &usdc, 0);
    let i = Instruction {
        program_id: r.env.rewards,
        accounts: vec![
            AccountMeta::new_readonly(funder.pubkey(), true),
            AccountMeta::new(src, false),
            AccountMeta::new(elsewhere, false),
            AccountMeta::new_readonly(r.config(), false),
            AccountMeta::new_readonly(TOKEN, false),
        ],
        data: [&[2u8][..], &5u64.to_le_bytes()].concat(),
    };
    assert_code(r.env.send(&[i], &[&funder]), rcode::WRONG_ACCOUNT);
}

#[test]
fn pay_factor_boundaries() {
    use morse_rewards::pay_factor_ppm as f;
    assert_eq!(f(95, 100), 1_000_000);
    assert_eq!(f(100, 100), 1_000_000);
    assert_eq!(f(80, 100), 0);
    assert_eq!(f(875, 1000), 500_000);
    assert_eq!(f(5, 0), 0);
    assert_eq!(f(200, 100), 1_000_000, "attendance is capped at 100%");
}
