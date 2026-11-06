//! Local actual SBF entrypoints and classic SPL/ATA CPIs; no live mint or funds.
use litesvm::LiteSVM;
use morse_token::{ALLOCATIONS, SUPPLY};
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::path::PathBuf;
const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const LOADER: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
fn ata(owner: Address, mint: Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()], &ATA).0
}
fn rw(a: Address) -> AccountMeta {
    AccountMeta::new(a, false)
}
fn ro(a: Address) -> AccountMeta {
    AccountMeta::new_readonly(a, false)
}
struct H {
    svm: LiteSVM,
    payer: Keypair,
    program: Address,
    config: Address,
    mint: Address,
    allocations: [Address; 7],
    vaults: [Address; 7],
    beneficiaries: [Address; 7],
    init: Instruction,
}
impl H {
    fn new() -> Self {
        Self::with_keys(Keypair::new(), Address::new_unique())
    }
    fn with_keys(payer: Keypair, program: Address) -> Self {
        let mut svm = LiteSVM::new();
        svm.airdrop(&payer.pubkey(), 50_000_000_000).unwrap();
        let path = std::env::var_os("MORSE_TOKEN_SBF_PATH").map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/morse_token.so"),
            PathBuf::from,
        );
        svm.add_program_from_file(program, &path)
            .expect("build token SBF first");
        let pd = Address::find_program_address(&[program.as_ref()], &LOADER).0;
        let mut image = svm.get_account(&pd).unwrap();
        // Deployment precedes the explicitly controlled local observation clock.
        image.data[4..12].copy_from_slice(&0u64.to_le_bytes());
        image.data[12] = 1;
        image.data[13..45].copy_from_slice(payer.pubkey().as_ref());
        svm.set_account(pd, image).unwrap();
        let mut clock = svm.get_sysvar::<Clock>();
        clock.unix_timestamp = 1_700_000_000;
        svm.set_sysvar(&clock);
        let config = Address::find_program_address(&[b"token"], &program).0;
        let mint = Address::find_program_address(&[b"mint"], &program).0;
        let allocations = std::array::from_fn(|i| {
            Address::find_program_address(&[b"allocation", &[i as u8]], &program).0
        });
        let vaults = allocations.map(|a| ata(a, mint));
        let beneficiaries =
            std::array::from_fn(|i| Keypair::new_from_array([20 + i as u8; 32]).pubkey());
        let mut data = vec![0];
        data.extend_from_slice(payer.pubkey().as_ref());
        for key in beneficiaries {
            data.extend_from_slice(key.as_ref());
        }
        let mut accounts = vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new(payer.pubkey(), true),
            rw(config),
            rw(mint),
            ro(program),
            ro(pd),
            ro(TOKEN),
            ro(ATA),
            ro(Address::default()),
        ];
        for i in 0..7 {
            accounts.extend([rw(allocations[i]), rw(vaults[i])]);
        }
        let init = Instruction {
            program_id: program,
            accounts,
            data,
        };
        Self {
            svm,
            payer,
            program,
            config,
            mint,
            allocations,
            vaults,
            beneficiaries,
            init,
        }
    }
    fn send(&mut self, ix: Instruction) -> bool {
        self.svm.expire_blockhash();
        let budget = Instruction {
            program_id: Address::from_str_const("ComputeBudget111111111111111111111111111111"),
            accounts: vec![],
            data: [vec![2], 400_000u32.to_le_bytes().to_vec()].concat(),
        };
        let tx = Transaction::new_signed_with_payer(
            &[budget, ix],
            Some(&self.payer.pubkey()),
            &[&self.payer],
            self.svm.latest_blockhash(),
        );
        let result = self.svm.send_transaction(tx);
        if let Err(e) = &result {
            eprintln!("{:?}\n{:?}", e.err, e.meta.logs);
        }
        result.is_ok()
    }
    fn amount(&self, a: Address) -> u64 {
        let d = self.svm.get_account(&a).unwrap().data;
        u64::from_le_bytes(d[64..72].try_into().unwrap())
    }
}
#[test]
fn fixed_supply_all_allocations_and_permanent_authority_revocation_execute_atomically() {
    let mut h = H::new();
    assert!(h.send(h.init.clone()), "fixed mint bootstrap failed");
    let mint = h.svm.get_account(&h.mint).unwrap();
    assert_eq!(mint.owner, TOKEN);
    assert_eq!(mint.data.len(), 82);
    assert_eq!(mint.data[44], 6);
    assert_eq!(&mint.data[..4], &[0; 4]);
    assert_eq!(&mint.data[46..50], &[0; 4]);
    assert_eq!(
        u64::from_le_bytes(mint.data[36..44].try_into().unwrap()),
        SUPPLY
    );
    for (i, amount) in ALLOCATIONS.into_iter().enumerate() {
        assert_eq!(h.amount(h.vaults[i]), amount);
        assert_eq!(
            h.svm.get_account(&h.allocations[i]).unwrap().owner,
            h.program
        );
    }
    assert!(
        h.send(h.init.clone()),
        "identical bootstrap retry must not mint again"
    );
    assert_eq!(h.svm.get_account(&h.mint).unwrap().data, mint.data);
}
impl H {
    fn prepare(&self) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(self.payer.pubkey(), true),
            rw(self.config),
            ro(Address::default()),
        ];
        accounts.extend(self.allocations.map(rw));
        Instruction {
            program_id: self.program,
            accounts,
            data: vec![2],
        }
    }
    fn claim(&self, kind: usize) -> Instruction {
        Instruction {
            program_id: self.program,
            accounts: vec![
                AccountMeta::new(self.payer.pubkey(), true),
                ro(self.config),
                rw(self.allocations[kind]),
                rw(self.vaults[kind]),
                rw(ata(self.beneficiaries[kind], self.mint)),
                ro(self.beneficiaries[kind]),
                ro(self.mint),
                ro(TOKEN),
                ro(ATA),
                ro(Address::default()),
            ],
            data: vec![1, kind as u8],
        }
    }
    fn warp(&mut self, time: i64) {
        let mut clock = self.svm.get_sysvar::<Clock>();
        clock.unix_timestamp = time;
        self.svm.set_sysvar(&clock);
    }
    fn claimed(&self, kind: usize) -> u64 {
        u64::from_le_bytes(
            self.svm.get_account(&self.allocations[kind]).unwrap().data[88..96]
                .try_into()
                .unwrap(),
        )
    }
}
#[test]
fn prefunded_metadata_preparation_never_exposes_a_mint_or_claims_bootstrap_authority() {
    let mut h = H::new();
    for key in [h.config, h.mint]
        .into_iter()
        .chain(h.allocations)
        .chain(h.vaults)
    {
        h.svm
            .set_account(
                key,
                solana_account::Account {
                    lamports: 1,
                    owner: Address::default(),
                    ..solana_account::Account::default()
                },
            )
            .unwrap();
    }
    assert!(h.send(h.prepare()));
    assert!(h.send(h.prepare()));
    assert_eq!(
        h.svm.get_account(&h.mint).unwrap().owner,
        Address::default()
    );
    assert_eq!(h.svm.get_account(&h.config).unwrap().data, vec![0; 320]);
    let before = h.svm.get_account(&h.config).unwrap();
    let pd = Address::find_program_address(&[h.program.as_ref()], &LOADER).0;
    let mut image = h.svm.get_account(&pd).unwrap();
    let original = image.clone();
    image.data[13..45].copy_from_slice(Address::new_unique().as_ref());
    h.svm.set_account(pd, image).unwrap();
    assert!(!h.send(h.init.clone()));
    assert_eq!(h.svm.get_account(&h.config).unwrap(), before);
    h.svm.set_account(pd, original).unwrap();
    assert!(h.send(h.init.clone()));
    assert_eq!(h.amount(h.vaults[4]), ALLOCATIONS[4]);
    assert!(!h.send(h.prepare()));
    let mut changed = h.init.clone();
    changed.data[33] ^= 1;
    assert!(!h.send(changed));
    assert_eq!(h.amount(h.vaults[4]), ALLOCATIONS[4]);
}
#[test]
fn original_calendar_vesting_cliff_fixed_payout_and_retry_execute_real_spl_transfers() {
    let mut h = H::new();
    let start = 1_706_704_496;
    h.warp(start);
    assert!(h.send(h.init.clone()));
    assert!(h.send(h.claim(2)));
    assert_eq!(h.claimed(2), 0);
    assert!(h
        .svm
        .get_account(&ata(h.beneficiaries[2], h.mint))
        .is_none());
    let cliff = morse_rewards_math::utc_month_anniversary(start, 12).unwrap();
    h.warp(cliff - 1);
    assert!(h.send(h.claim(2)));
    assert_eq!(h.claimed(2), 0);
    h.warp(cliff);
    let mut wrong = h.claim(2);
    wrong.accounts[5] = ro(h.beneficiaries[3]);
    wrong.accounts[4] = rw(ata(h.beneficiaries[3], h.mint));
    assert!(!h.send(wrong));
    assert_eq!(h.claimed(2), 0);
    assert!(h.send(h.claim(2)));
    assert_eq!(h.claimed(2), ALLOCATIONS[2] / 4);
    assert_eq!(
        h.amount(ata(h.beneficiaries[2], h.mint)),
        ALLOCATIONS[2] / 4
    );
    assert!(h.send(h.claim(2)));
    assert_eq!(
        h.amount(ata(h.beneficiaries[2], h.mint)),
        ALLOCATIONS[2] / 4
    );
    h.warp(morse_rewards_math::utc_month_anniversary(start, 48).unwrap());
    assert!(h.send(h.claim(2)));
    assert_eq!(h.claimed(2), ALLOCATIONS[2]);
    assert_eq!(h.amount(h.vaults[2]), 0);
    assert_eq!(h.amount(ata(h.beneficiaries[2], h.mint)), ALLOCATIONS[2]);
    assert!(h.send(h.claim(2)));
    assert!(!h.send(h.claim(4)));
    assert_eq!(h.amount(h.vaults[4]), ALLOCATIONS[4]);
    for kind in [0, 1, 3, 5, 6] {
        assert!(h.send(h.claim(kind)));
        assert_eq!(
            h.amount(ata(h.beneficiaries[kind], h.mint)),
            ALLOCATIONS[kind]
        );
    }
    let mut unauthorized = Instruction {
        program_id: TOKEN,
        accounts: vec![
            rw(h.mint),
            rw(h.vaults[2]),
            AccountMeta::new_readonly(h.payer.pubkey(), true),
        ],
        data: vec![14],
    };
    unauthorized.data.extend_from_slice(&1u64.to_le_bytes());
    unauthorized.data.push(6);
    assert!(!h.send(unauthorized));
    assert_eq!(
        u64::from_le_bytes(
            h.svm.get_account(&h.mint).unwrap().data[36..44]
                .try_into()
                .unwrap()
        ),
        SUPPLY
    );
}
const PYTH: Address = Address::from_str_const("rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ");

fn source_update(time: i64, price: i64) -> solana_account::Account {
    let mut d = vec![0; 134];
    d[..8].copy_from_slice(&[34, 241, 35, 99, 157, 126, 244, 205]);
    d[8..40].fill(99);
    d[40] = 1;
    d[41..73].fill(7);
    d[73..81].copy_from_slice(&price.to_le_bytes());
    d[89..93].copy_from_slice(&(-6i32).to_le_bytes());
    d[93..101].copy_from_slice(&time.to_le_bytes());
    d[101..109].copy_from_slice(&(time - 1).to_le_bytes());
    d[125..133].copy_from_slice(&77u64.to_le_bytes());
    solana_account::Account {
        lamports: 10_000_000,
        data: d,
        owner: PYTH,
        ..solana_account::Account::default()
    }
}
fn oracle_instruction(h: &H, tag: u8, source: Address) -> Instruction {
    let oracle = Address::find_program_address(&[b"oracle"], &h.program).0;
    if tag == 3 {
        let mut data = vec![3];
        data.extend(source.as_ref());
        data.extend([7; 32]);
        Instruction {
            program_id: h.program,
            accounts: vec![
                AccountMeta::new_readonly(h.payer.pubkey(), true),
                AccountMeta::new(h.payer.pubkey(), true),
                ro(h.config),
                ro(h.mint),
                rw(oracle),
                ro(PYTH),
                ro(source),
                ro(Address::default()),
            ],
            data,
        }
    } else if tag == 4 {
        Instruction {
            program_id: h.program,
            accounts: vec![ro(h.config), ro(h.mint), rw(oracle), ro(PYTH), ro(source)],
            data: vec![4],
        }
    } else {
        Instruction {
            program_id: h.program,
            accounts: vec![ro(h.config), ro(h.mint), ro(oracle)],
            data: vec![5],
        }
    }
}
#[test]
fn authenticated_oracle_pins_reject_wrong_owner_feed_verification_and_gaps() {
    let mut h = H::new();
    assert!(h.send(h.init.clone()));
    let source = Address::new_unique();
    let time = 1_700_002_800;
    h.warp(time);
    let mut clock = h.svm.get_sysvar::<Clock>();
    clock.slot = 100;
    h.svm.set_sysvar(&clock);
    // Pyth-owned serialized account fixtures; guardian verification is outside this local codec proof.
    h.svm
        .set_account(PYTH, h.svm.get_account(&TOKEN).unwrap())
        .unwrap();
    h.svm
        .set_account(source, source_update(time, 1_000_000))
        .unwrap();
    assert!(h.send(oracle_instruction(&h, 3, source)));
    assert!(!h.send(oracle_instruction(&h, 5, source)));
    let oracle = Address::find_program_address(&[b"oracle"], &h.program).0;
    let before = h.svm.get_account(&oracle).unwrap();
    h.warp(time + 60);
    for mutation in 0..4 {
        let mut bad = source_update(time + 60, 1_000_000);
        match mutation {
            0 => bad.owner = Address::default(),
            1 => bad.data[40] = 0,
            2 => bad.data[41] ^= 1,
            _ => bad.data[93..101].copy_from_slice(&(time + 61).to_le_bytes()),
        };
        h.svm.set_account(source, bad).unwrap();
        assert!(!h.send(oracle_instruction(&h, 4, source)));
        assert_eq!(h.svm.get_account(&oracle).unwrap(), before);
    }
    h.svm
        .set_account(source, source_update(time + 60, 1_000_000))
        .unwrap();
    assert!(h.send(oracle_instruction(&h, 4, source)));
    assert!(h.send(oracle_instruction(&h, 4, source)));
    h.warp(time + 180);
    h.svm
        .set_account(source, source_update(time + 180, 1_000_000))
        .unwrap();
    assert!(h.send(oracle_instruction(&h, 4, source)));
    assert!(
        h.svm.get_account(&oracle).unwrap().data[morse_token::oracle::HEADER..]
            .iter()
            .all(|x| *x == 0)
    );
}
#[test]
fn oracle_source_rotation_is_timelocked_and_discards_old_coverage() {
    let mut h = H::new();
    assert!(h.send(h.init.clone()));
    let time = 1_700_002_800;
    h.warp(time);
    let mut clock = h.svm.get_sysvar::<Clock>();
    clock.slot = 100;
    h.svm.set_sysvar(&clock);
    h.svm
        .set_account(PYTH, h.svm.get_account(&TOKEN).unwrap())
        .unwrap();
    let source = Address::new_unique();
    h.svm
        .set_account(source, source_update(time, 1_000_000))
        .unwrap();
    assert!(h.send(oracle_instruction(&h, 3, source)));
    let other = Address::new_unique();
    let mut update = source_update(time, 2_000_000);
    update.data[41..73].fill(8);
    h.svm.set_account(other, update).unwrap();
    let oracle = Address::find_program_address(&[b"oracle"], &h.program).0;
    let proposal = Instruction {
        program_id: h.program,
        accounts: vec![
            AccountMeta::new_readonly(h.payer.pubkey(), true),
            ro(h.config),
            ro(h.mint),
            rw(oracle),
            ro(PYTH),
            ro(other),
        ],
        data: [vec![6], other.as_ref().to_vec(), vec![8; 32]].concat(),
    };
    assert!(h.send(proposal.clone()));
    let before = h.svm.get_account(&oracle).unwrap();
    assert!(h.send(proposal));
    assert_eq!(h.svm.get_account(&oracle).unwrap(), before);
    let execute = Instruction {
        program_id: h.program,
        accounts: vec![ro(h.config), ro(h.mint), rw(oracle), ro(PYTH), ro(other)],
        data: vec![7],
    };
    assert!(!h.send(execute.clone()));
    assert_eq!(h.svm.get_account(&oracle).unwrap(), before);
    let ready = time + 14 * 86400;
    h.warp(ready);
    let mut update = source_update(ready, 2_000_000);
    update.data[41..73].fill(8);
    h.svm.set_account(other, update).unwrap();
    assert!(h.send(execute));
    let after = h.svm.get_account(&oracle).unwrap().data;
    assert_eq!(&after[100..132], other.as_ref());
    assert_eq!(&after[132..164], &[8; 32]);
    assert_eq!(u64::from_le_bytes(after[292..300].try_into().unwrap()), 2);
    assert!(after[morse_token::oracle::HEADER..].iter().all(|x| *x == 0));
    assert!(!h.send(oracle_instruction(&h, 4, source)));
    assert!(!h.send(oracle_instruction(&h, 5, other)));
}
#[test]
fn actual_sbf_accumulates_all_10080_publications_before_accepting_seven_day_twap() {
    let mut h = H::new();
    assert!(h.send(h.init.clone()));
    let start = 1_700_002_800;
    h.warp(start);
    let mut clock = h.svm.get_sysvar::<Clock>();
    clock.slot = 100;
    h.svm.set_sysvar(&clock);
    h.svm
        .set_account(PYTH, h.svm.get_account(&TOKEN).unwrap())
        .unwrap();
    let source = Address::new_unique();
    h.svm
        .set_account(source, source_update(start, 1_000_000))
        .unwrap();
    assert!(h.send(oracle_instruction(&h, 3, source)));
    let observe = oracle_instruction(&h, 4, source);
    for delta in (60..=604800).step_by(60) {
        let time = start + delta;
        h.warp(time);
        h.svm
            .set_account(
                source,
                source_update(time, if delta < 302400 { 1_000_000 } else { 3_000_000 }),
            )
            .unwrap();
        assert!(h.send(observe.clone()), "publication {delta} failed");
    }
    assert!(h.send(oracle_instruction(&h, 5, source)));
    let oracle = Address::find_program_address(&[b"oracle"], &h.program).0;
    assert_eq!(
        morse_token::oracle::twap(&h.svm.get_account(&oracle).unwrap().data, start + 604800),
        Ok(2_000_000)
    );
    if let Some(path) = std::env::var_os("MORSE_TOKEN_FIXTURES_PATH") {
        use base64::Engine;
        let report = |ix: Instruction| serde_json::json!({"schemaVersion":1,"programId":ix.program_id.to_string(),"accountCount":ix.accounts.len(),"accountKeys":ix.accounts.iter().map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"signerKeys":ix.accounts.iter().filter(|a|a.is_signer).map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"writableKeys":ix.accounts.iter().filter(|a|a.is_writable).map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"dataBase64":base64::engine::general_purpose::STANDARD.encode(&ix.data),"dataBytes":ix.data.len()});
        let allocations=(0..7).map(|i|serde_json::json!({"address":h.allocations[i].to_string(),"vault":h.vaults[i].to_string(),"beneficiary":h.beneficiaries[i].to_string(),"data_hex":hex::encode(h.svm.get_account(&h.allocations[i]).unwrap().data),"amount":ALLOCATIONS[i].to_string()})).collect::<Vec<_>>();
        let fixture = serde_json::json!({"schema_version":1,"program":h.program.to_string(),"payer":h.payer.pubkey().to_string(),"source":source.to_string(),"feed_hex":hex::encode([7;32]),"now":(start+604800).to_string(),"config_address":h.config.to_string(),"mint_address":h.mint.to_string(),"oracle_address":oracle.to_string(),"config_hex":hex::encode(h.svm.get_account(&h.config).unwrap().data),"mint_hex":hex::encode(h.svm.get_account(&h.mint).unwrap().data),"oracle_hex":hex::encode(h.svm.get_account(&oracle).unwrap().data),"allocations":allocations,"instructions":{"initialize":report(h.init.clone()),"prepare":report(h.prepare()),"claim":report(h.claim(2)),"oracle_initialize":report(oracle_instruction(&h,3,source)),"observe":report(oracle_instruction(&h,4,source))},"boundary":"Actual Morse SBF/SPL/ATA execution; Pyth account publications are injected canonical owner/data fixtures, no guardian verification or live feed claimed."});
        std::fs::write(path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    }

    h.warp(start + 604861);
    assert!(!h.send(oracle_instruction(&h, 5, source)));
    h.svm
        .set_account(source, source_update(start + 604861, 3_000_000))
        .unwrap();
    assert!(h.send(observe));
    assert!(!h.send(oracle_instruction(&h, 5, source)));
}

#[cfg(feature = "dex")]
#[path = "support/dex.rs"]
mod dex;
