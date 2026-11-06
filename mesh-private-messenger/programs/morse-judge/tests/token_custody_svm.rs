//! Local versioned custody integration. Pyth-owned publication fixtures are injected;
//! minting, token transfers, oracle accumulation and reward settlement execute SBF.
#[path = "support/collateral_proof_scenarios.rs"]
mod collateral_proof_scenarios;
#[path = "support/custody.rs"]
#[allow(dead_code)]
mod custody_support;
#[path = "support/public_history_index.rs"]
mod public_history_index;
#[path = "support/token_fork.rs"]
mod token_fork;
use base64::Engine;
use custody_support::*;
use ed25519_dalek::Signer as _;
use morse_judge::attendance::{activate_clock, initialize_clock, CLOCK_LEN};
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_sha256_hasher::hash;
use solana_signer::Signer;
use std::path::PathBuf;
const LOADER: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
const PYTH: Address = Address::from_str_const("rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ");
const START: i64 = 1_700_002_800;
const WEEK: i64 = 604800;
fn pd(program: Address) -> Address {
    Address::find_program_address(&[program.as_ref()], &LOADER).0
}
fn source_update(time: i64) -> Vec<u8> {
    let mut d = vec![0; 134];
    d[..8].copy_from_slice(&hash(b"account:PriceUpdateV2").to_bytes()[..8]);
    d[8..40].fill(7);
    d[40] = 1;
    d[41..73].fill(9);
    d[73..81].copy_from_slice(&2_000_000i64.to_le_bytes());
    d[89..93].copy_from_slice(&(-6i32).to_le_bytes());
    d[93..101].copy_from_slice(&time.to_le_bytes());
    d[101..109].copy_from_slice(&time.to_le_bytes());
    d[125..133].copy_from_slice(&77u64.to_le_bytes());
    d
}
fn instruction_report(ix: &Instruction) -> serde_json::Value {
    serde_json::json!({"schemaVersion":1,"programId":ix.program_id.to_string(),"accountCount":ix.accounts.len(),"accountKeys":ix.accounts.iter().map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"signerKeys":ix.accounts.iter().filter(|a|a.is_signer).map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"writableKeys":ix.accounts.iter().filter(|a|a.is_writable).map(|a|a.pubkey.to_string()).collect::<Vec<_>>(),"dataBase64":base64::engine::general_purpose::STANDARD.encode(&ix.data),"dataBytes":ix.data.len()})
}
fn replay_instructions() -> Vec<Instruction> {
    let Ok(path) = std::env::var("MORSE_TOKEN_WRITE_INSTRUCTIONS_PATH") else {
        return Vec::new();
    };
    let root: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    root["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| Instruction {
            program_id: item["program"].as_str().unwrap().parse().unwrap(),
            data: hex::decode(item["data_hex"].as_str().unwrap()).unwrap(),
            accounts: item["accounts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| AccountMeta {
                    pubkey: m["key"].as_str().unwrap().parse().unwrap(),
                    is_signer: m["signer"].as_bool().unwrap(),
                    is_writable: m["writable"].as_bool().unwrap(),
                })
                .collect(),
        })
        .collect()
}
struct TokenHarness {
    h: Harness,
    token: Address,
    token_config: Address,
    morse: Address,
    oracle: Address,
    source: Address,
    rewards: Address,
    pool: Address,
    clock: Address,
    binding: Address,
    started: i64,
    replay_instructions: Vec<Instruction>,
    replayed_tags: [u64; 20],
}
impl TokenHarness {
    fn fixture_log_name(&self) -> String {
        let raw = self.h.svm.get_account(&self.h.log).unwrap().data;
        String::from_utf8(raw[8..8 + raw[6] as usize].to_vec()).unwrap()
    }

    fn snapshot(
        &self,
        name: &str,
        subjects: &[(Address, Address, Address)],
        proof: Option<Address>,
    ) -> serde_json::Value {
        let directory = Address::find_program_address(
            &[b"bond", &self.h.log_id, b"directory"],
            &self.h.program,
        )
        .0;
        let directory_pending =
            Address::find_program_address(&[b"bond-pending", directory.as_ref()], &self.h.program)
                .0;
        let directory_data = self.h.svm.get_account(&directory).unwrap().data;
        let directory_mint = Address::new_from_array(directory_data[104..136].try_into().unwrap());
        let mut roles = vec![
            (
                "clock".to_string(),
                Address::from_str_const("SysvarC1ock11111111111111111111111111111111"),
            ),
            ("log".to_string(), self.h.log),
            ("economics".to_string(), self.h.economy),
            ("binding".to_string(), self.binding),
            ("token_config".to_string(), self.token_config),
            ("morse".to_string(), self.morse),
            ("usdc".to_string(), self.h.mint),
            ("oracle".to_string(), self.oracle),
            ("pool".to_string(), self.pool),
            (
                "reserve_profile".to_string(),
                Address::find_program_address(&[b"reserve-config"], &self.token).0,
            ),
            (
                "token_pool".to_string(),
                Address::find_program_address(&[b"token-pool"], &self.rewards).0,
            ),
            ("pool_morse_vault".to_string(), ata(&self.pool, &self.morse)),
            ("attendance_clock".to_string(), self.clock),
            ("directory".to_string(), directory),
            ("directory_pending".to_string(), directory_pending),
            (
                "directory_vault".to_string(),
                ata(&directory, &directory_mint),
            ),
            (
                "directory_usdc_vault".to_string(),
                ata(&directory, &self.h.mint),
            ),
            (
                "directory_morse_vault".to_string(),
                ata(&directory, &self.morse),
            ),
        ];
        if std::env::var("MORSE_NETWORK_COUNTER_FIXTURE_LOG").as_deref() == Ok("morse-main") {
            roles.push(("judge_config".to_string(), self.h.config));
        }
        for (label, program) in [
            ("judge", self.h.program),
            ("token", self.token),
            ("rewards", self.rewards),
        ] {
            roles.push((label.into(), program));
            roles.push((format!("{label}_data"), pd(program)));
        }
        if let Some(address) = proof {
            roles.push(("proof".into(), address));
        }
        let mut expected = Vec::new();
        for (i, (w, b, p)) in subjects.iter().enumerate() {
            let raw = self
                .h
                .svm
                .get_account(b)
                .map(|account| account.data)
                .unwrap_or_default();
            let state = if raw.len() == morse_judge::custody::BOND_LEN {
                let mut compatible = raw.clone();
                compatible[3] = 2;
                Some(morse_judge::token_custody::decode_bond(&compatible).unwrap())
            } else {
                assert_eq!(
                    std::env::var("MORSE_NETWORK_COUNTER_FIXTURE_LOG").as_deref(),
                    Ok("morse-main")
                );
                assert!(
                    raw.is_empty(),
                    "only an actual absent/empty registered bond is exported"
                );
                None
            };
            // This alias is solely a keyed account role. Both asset ATAs are
            // exported from the same bank; no asset is assigned to a missing bond.
            let mint = state
                .as_ref()
                .map(|_| Address::new_from_array(raw[104..136].try_into().unwrap()))
                .unwrap_or(self.morse);
            for (label, address) in [
                ("witness", *w),
                ("bond", *b),
                ("pending", *p),
                ("vault", ata(b, &mint)),
                ("usdc_vault", ata(b, &self.h.mint)),
                ("morse_vault", ata(b, &self.morse)),
            ] {
                roles.push((format!("{label}{i}"), address));
            }
            let pending = self
                .h
                .svm
                .get_account(p)
                .filter(|a| a.owner == self.h.program)
                .map(|a| morse_judge::token_deposit::decode_pending(&a.data).unwrap());
            if let Some(state) = state {
                expected.push(serde_json::json!({"witness":w.to_string(),"bond":b.to_string(),"pending":p.to_string(),"version":raw[3],"asset":state.asset,"status":state.status,"principal":state.principal.to_string(),"bonded_at":state.bonded_at.to_string(),"underwater_since":state.underwater_since.to_string(),"target":pending.map_or(0,|p|p.target).to_string(),"pending_recorded":pending.map_or(0,|p|p.amount).to_string(),"pending_liability":if state.status==3{0}else{pending.map_or(0,|p|p.amount)}.to_string()}));
            }
        }
        let accounts:serde_json::Map<String,serde_json::Value>=roles.into_iter().map(|(label,address)|{
            let value=match self.h.svm.get_account(&address){Some(a)=>serde_json::json!({"address":address.to_string(),"owner":a.owner.to_string(),"lamports":a.lamports.to_string(),"space":a.data.len().to_string(),"executable":a.executable,"data_hex":hex::encode(&a.data[..a.data.len().min(8416)])}),None=>serde_json::json!({"address":address.to_string(),"missing":true})};(label,value)
        }).collect();
        let clock = self.h.svm.get_sysvar::<Clock>();
        let clock_account = accounts
            .get("clock")
            .expect("every custody snapshot must include its actual bank Clock account");
        assert_eq!(
            clock_account["data_hex"].as_str().unwrap(),
            hex::encode(bincode::serialize(&clock).unwrap()),
            "exported Clock must belong to the same bank as the custody accounts"
        );
        serde_json::json!({"name":name,"program":self.h.program.to_string(),"token_program":self.token.to_string(),"rewards_program":self.rewards.to_string(),"log_id":hex::encode(self.h.log_id),"log_name":self.fixture_log_name(),"now":clock.unix_timestamp.to_string(),"context_slot":clock.slot.to_string(),"payer":self.h.payer.pubkey().to_string(),"operator":self.h.operator.pubkey().to_string(),"accounts":accounts,"subjects":expected})
    }
    fn reward_snapshot(
        &self,
        label: &str,
        epoch: u64,
        subjects: &[(Address, Address, Address)],
    ) -> serde_json::Value {
        let mut snapshot = self.snapshot(label, subjects, None);
        let accounts = snapshot["accounts"].as_object_mut().unwrap();
        let allocation = Address::find_program_address(&[b"allocation", &[4]], &self.token).0;
        for (label, address) in [
            (
                "epoch",
                Address::find_program_address(&[b"epoch", &epoch.to_le_bytes()], &self.rewards).0,
            ),
            (
                "token_epoch",
                Address::find_program_address(
                    &[b"token-epoch", &epoch.to_le_bytes()],
                    &self.rewards,
                )
                .0,
            ),
            (
                "attendance_epoch",
                Address::find_program_address(
                    &[b"attendance-epoch", &self.h.log_id, &epoch.to_le_bytes()],
                    &self.h.program,
                )
                .0,
            ),
            (
                "reserve_receipt",
                Address::find_program_address(
                    &[b"reserve-epoch", &epoch.to_le_bytes()],
                    &self.token,
                )
                .0,
            ),
            ("reserve_allocation", allocation),
            ("reserve_vault", ata(&allocation, &self.morse)),
            ("pool_usdc_vault", ata(&self.pool, &self.h.mint)),
        ] {
            let value = match self.h.svm.get_account(&address) {
                Some(a) => {
                    serde_json::json!({"address":address.to_string(),"owner":a.owner.to_string(),"lamports":a.lamports.to_string(),"space":a.data.len().to_string(),"executable":a.executable,"data_hex":hex::encode(a.data)})
                }
                None => serde_json::json!({"address":address.to_string(),"missing":true}),
            };
            accounts.insert(label.into(), value);
        }
        let week = Address::find_program_address(
            &[b"attendance-epoch", &self.h.log_id, &epoch.to_le_bytes()],
            &self.h.program,
        )
        .0;
        let data = self.h.svm.get_account(&week).unwrap().data;
        let count = u16::from_le_bytes(data[60..62].try_into().unwrap()) as usize;
        for index in 0..count {
            let address = Address::new_from_array(
                data[80 + index * 40..112 + index * 40].try_into().unwrap(),
            );
            let a = self.h.svm.get_account(&address).unwrap();
            accounts.insert(format!("attendance_witness{index}"), serde_json::json!({"address":address.to_string(),"owner":a.owner.to_string(),"lamports":a.lamports.to_string(),"space":a.data.len().to_string(),"executable":a.executable,"data_hex":hex::encode(a.data)}));
        }
        snapshot["epoch"] = serde_json::json!(epoch.to_string());
        snapshot
    }
    fn reward_write_vectors(
        &self,
        epoch: u64,
        subjects: &[(Address, Address, Address)],
        reserve: &Instruction,
        enable: &Instruction,
    ) -> serde_json::Value {
        let context = self.token_reward_context(epoch);
        let token_pool = context[1].pubkey;
        let ledger = context[2].pubkey;
        let token_epoch = context[3].pubkey;
        let open = Instruction {
            program_id: self.rewards,
            accounts: vec![
                signer(self.h.payer.pubkey()),
                ro(self.pool),
                ro(token_pool),
                rw(ledger),
                rw(token_epoch),
                ro(Address::default()),
            ],
            data: [vec![14], epoch.to_le_bytes().to_vec()].concat(),
        };
        let cohort=subjects.iter().map(|(w,_,_)|{let raw=self.h.svm.get_account(w).unwrap().data;serde_json::json!({"witness":w.to_string(),"id":std::str::from_utf8(&raw[8..8+raw[4] as usize]).unwrap(),"key_hex":hex::encode(&raw[72..104])})}).collect::<Vec<_>>();
        let mut append = Vec::new();
        for chunk in subjects[..1].chunks(1).chain(subjects[1..].chunks(3)) {
            let mut accounts = context.clone();
            for (w, b, p) in chunk {
                accounts.extend([
                    ro(*w),
                    ro(*b),
                    ro(*p),
                    ro(Address::find_program_address(&[b"member", w.as_ref()], &self.rewards).0),
                ]);
            }
            append.push(instruction_report(&Instruction {
                program_id: self.rewards,
                accounts,
                data: vec![16],
            }));
        }
        let claims = subjects
            .iter()
            .enumerate()
            .filter_map(|(n, _)| {
                let state = self.h.svm.get_account(&token_epoch).unwrap();
                let amount =
                    u64::from_le_bytes(state.data[264 + n * 16..272 + n * 16].try_into().unwrap());
                if amount == 0 {
                    return None;
                }
                let ix = Instruction {
                    program_id: self.rewards,
                    accounts: vec![
                        ro(self.pool),
                        rw(token_pool),
                        ro(ledger),
                        rw(token_epoch),
                        rw(ata(&self.pool, &self.morse)),
                        rw(ata(&self.h.payer.pubkey(), &self.morse)),
                        ro(self.morse),
                        ro(TOKEN),
                    ],
                    data: vec![18, n as u8],
                };
                Some(instruction_report(&ix))
            })
            .collect::<Vec<_>>();
        let claims_usdc = subjects
            .iter()
            .enumerate()
            .filter_map(|(n, _)| {
                let data = self.h.svm.get_account(&ledger).unwrap().data;
                let amount =
                    u64::from_le_bytes(data[344 + n * 128..352 + n * 128].try_into().unwrap());
                if amount == 0 {
                    return None;
                }
                Some(instruction_report(&Instruction {
                    program_id: self.rewards,
                    accounts: vec![
                        rw(self.pool),
                        rw(ledger),
                        rw(ata(&self.pool, &self.h.mint)),
                        rw(ata(&self.h.payer.pubkey(), &self.h.mint)),
                        ro(self.h.mint),
                        ro(TOKEN),
                    ],
                    data: vec![8, n as u8],
                }))
            })
            .collect::<Vec<_>>();
        let setup = |mint: Address| {
            instruction_report(&Instruction {
                program_id: ATA,
                accounts: vec![
                    signer(self.h.payer.pubkey()),
                    rw(ata(&self.h.payer.pubkey(), &mint)),
                    ro(self.h.payer.pubkey()),
                    ro(mint),
                    ro(Address::default()),
                    ro(TOKEN),
                ],
                data: vec![1],
            })
        };
        serde_json::json!({"program":self.rewards.to_string(),"judge":self.h.program.to_string(),"token":self.token.to_string(),"log_name":self.fixture_log_name(),"mint":self.h.mint.to_string(),"payer":self.h.payer.pubkey().to_string(),"governance":self.h.payer.pubkey().to_string(),"epoch":epoch.to_string(),"cohort":cohort,"reserve_configure":instruction_report(reserve),"activate":instruction_report(enable),"open":instruction_report(&open),"begin":instruction_report(&Instruction{program_id:self.rewards,accounts:context.clone(),data:vec![15]}),"append":append,"finalize":instruction_report(&self.token_reward_finalize(epoch)),"claim":claims,"claim_usdc":claims_usdc,"claim_setup":setup(self.morse),"claim_usdc_setup":setup(self.h.mint),"cancel":instruction_report(&Instruction{program_id:self.rewards,accounts:context,data:vec![19]})})
    }
    fn new() -> Self {
        Self::new_at(START)
    }
    fn new_at(start: i64) -> Self {
        let mut h = Harness::with_keys(
            Keypair::new_from_array([201; 32]),
            Keypair::new_from_array([202; 32]),
        );
        h.clock(1000);
        assert!(h.send(&[h.configure()], false));
        h.clock(1000 + morse_judge::state::TIMELOCK_SECONDS);
        h.fund_directory();
        assert!(h.send(&[h.deposit(100_000_000)], true));
        h.clock(start);
        let mut clock = h.svm.get_sysvar::<Clock>();
        clock.slot = 100_000;
        h.svm.set_sysvar(&clock);
        let mut judge_data = h.svm.get_account(&pd(h.program)).unwrap();
        judge_data.data[4..12].copy_from_slice(&0u64.to_le_bytes());
        h.svm.set_account(pd(h.program), judge_data).unwrap();
        let token = Address::new_unique();
        let rewards = Address::new_unique();
        for (program, name) in [(token, "morse_token.so"), (rewards, "morse_rewards.so")] {
            h.svm
                .add_program_from_file(
                    program,
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../target/deploy")
                        .join(name),
                )
                .unwrap();
            let mut metadata = h.svm.get_account(&pd(program)).unwrap();
            metadata.data[4..12].copy_from_slice(&0u64.to_le_bytes());
            metadata.data[12] = 1;
            metadata.data[13..45].copy_from_slice(h.payer.pubkey().as_ref());
            h.svm.set_account(pd(program), metadata).unwrap();
        }
        let token_config = Address::find_program_address(&[b"token"], &token).0;
        let morse = Address::find_program_address(&[b"mint"], &token).0;
        let oracle = Address::find_program_address(&[b"oracle"], &token).0;
        let source = Address::new_unique();
        let pool = Address::find_program_address(&[b"pool"], &rewards).0;
        let clock = Address::find_program_address(&[b"attendance", &h.log_id], &h.program).0;
        let binding = Address::find_program_address(&[b"token-binding", &h.log_id], &h.program).0;
        let mut t = Self {
            h,
            token,
            token_config,
            morse,
            oracle,
            source,
            rewards,
            pool,
            clock,
            binding,
            started: 0,
            replay_instructions: replay_instructions(),
            replayed_tags: [0; 20],
        };
        let mut prep = vec![
            signer(t.h.payer.pubkey()),
            rw(token_config),
            ro(Address::default()),
        ];
        let mut init = vec![
            AccountMeta::new_readonly(t.h.payer.pubkey(), true),
            signer(t.h.payer.pubkey()),
            rw(token_config),
            rw(morse),
            ro(token),
            ro(pd(token)),
            ro(TOKEN),
            ro(ATA),
            ro(Address::default()),
        ];
        for kind in 0..7u8 {
            let allocation = Address::find_program_address(&[b"allocation", &[kind]], &token).0;
            prep.push(rw(allocation));
            init.extend([rw(allocation), rw(ata(&allocation, &morse))]);
        }
        assert!(t.send(Instruction {
            program_id: token,
            accounts: prep,
            data: vec![2]
        }));
        let mut payload = vec![0];
        payload.extend(t.h.payer.pubkey().as_ref());
        for _ in 0..7 {
            payload.extend(t.h.payer.pubkey().as_ref());
        }
        assert!(t.send(Instruction {
            program_id: token,
            accounts: init,
            data: payload
        }));
        t.h.svm
            .set_account(PYTH, t.h.svm.get_account(&TOKEN).unwrap())
            .unwrap();
        Harness::account(&mut t.h.svm, source, PYTH, source_update(start));
        let initial = Instruction {
            program_id: token,
            accounts: vec![
                AccountMeta::new_readonly(t.h.payer.pubkey(), true),
                signer(t.h.payer.pubkey()),
                ro(token_config),
                ro(morse),
                rw(oracle),
                ro(PYTH),
                ro(source),
                ro(Address::default()),
            ],
            data: [vec![3], source.as_ref().to_vec(), vec![9; 32]].concat(),
        };
        assert!(t.send(initial));
        t.observe_until(start + WEEK);
        let now = t.h.svm.get_sysvar::<Clock>().unix_timestamp;
        t.started = now / WEEK * WEEK - 1;
        let mut data = vec![0; CLOCK_LEN];
        initialize_clock(&mut data, &t.h.log_id).unwrap();
        activate_clock(&mut data, t.started, 1).unwrap();
        Harness::account(&mut t.h.svm, t.clock, t.h.program, data);
        let mut log = t.h.svm.get_account(&t.h.log).unwrap();
        log.data[7] = 1;
        t.h.svm.set_account(t.h.log, log).unwrap();
        let morse_key = ed25519_dalek::SigningKey::from_bytes(&[14; 32])
            .verifying_key()
            .to_bytes();
        let morse_id = b"morse-owned";
        let identity = solana_sha256_hasher::hashv(&[
            b"morse-witness-record-v1",
            &[morse_id.len() as u8],
            morse_id,
            &morse_key,
        ]);
        let morse_witness = Address::find_program_address(
            &[b"witness", &t.h.log_id, identity.as_ref()],
            &t.h.program,
        )
        .0;
        let mut record = vec![0; 320];
        record[..4].copy_from_slice(b"MWI\x01");
        record[4] = morse_id.len() as u8;
        record[8..8 + morse_id.len()].copy_from_slice(morse_id);
        record[72..104].copy_from_slice(&morse_key);
        record[104..136].copy_from_slice(t.h.payer.pubkey().as_ref());
        record[136..168].copy_from_slice(t.h.payer.pubkey().as_ref());
        record[200..232].copy_from_slice(&t.h.log_id);
        Harness::account(&mut t.h.svm, morse_witness, t.h.program, record);
        let initialize = Instruction {
            program_id: rewards,
            accounts: vec![
                signer(t.h.payer.pubkey()),
                signer(t.h.payer.pubkey()),
                rw(pool),
                rw(ata(&pool, &t.h.mint)),
                ro(rewards),
                ro(pd(rewards)),
                ro(t.h.program),
                ro(t.h.log),
                ro(t.clock),
                ro(t.h.mint),
                ro(TOKEN),
                ro(ATA),
                ro(Address::default()),
            ],
            data: [
                vec![0],
                t.h.payer.pubkey().as_ref().to_vec(),
                t.started.to_le_bytes().to_vec(),
                morse_witness.as_ref().to_vec(),
            ]
            .concat(),
        };
        assert!(t.send(initialize));
        let member = t.member();
        assert!(t.send(Instruction {
            program_id: rewards,
            accounts: vec![
                signer(t.h.payer.pubkey()),
                signer(t.h.payer.pubkey()),
                ro(pool),
                ro(t.h.witness),
                rw(member),
                ro(Address::default())
            ],
            data: vec![3, 1]
        }));
        t
    }
    fn prepared_instruction(&mut self, instruction: Instruction) -> Instruction {
        if let Some(prepared) = self
            .replay_instructions
            .iter()
            .find(|candidate| *candidate == &instruction)
        {
            let tag = instruction.data[0] as usize;
            if tag < self.replayed_tags.len() {
                self.replayed_tags[tag] += 1;
            }
            prepared.clone()
        } else {
            instruction
        }
    }
    fn send(&mut self, instruction: Instruction) -> bool {
        let instruction = self.prepared_instruction(instruction);
        let budget = Instruction {
            program_id: Address::from_str_const("ComputeBudget111111111111111111111111111111"),
            accounts: vec![],
            data: [vec![2], 1_000_000u32.to_le_bytes().to_vec()].concat(),
        };
        self.h.send(&[budget, instruction], false)
    }
    fn observe_until(&mut self, finish: i64) {
        self.observe_price_until(finish, 2_000_000);
    }
    fn observe_price_until(&mut self, finish: i64, price: i64) {
        let d = self.h.svm.get_account(&self.oracle).unwrap().data;
        let previous = i64::from_le_bytes(d[164..172].try_into().unwrap());
        let start = if finish - previous > WEEK {
            finish - WEEK
        } else {
            previous + 60
        };
        for time in (start..=finish).step_by(60) {
            self.h.clock(time);
            let mut update = source_update(time);
            update[73..81].copy_from_slice(&price.to_le_bytes());
            Harness::account(&mut self.h.svm, self.source, PYTH, update);
            let observe = Instruction {
                program_id: self.token,
                accounts: vec![
                    ro(self.token_config),
                    ro(self.morse),
                    rw(self.oracle),
                    ro(PYTH),
                    ro(self.source),
                ],
                data: vec![4],
            };
            assert!(self.h.send(&[observe], false));
        }
        self.h.clock(finish);
    }
    fn binding_instruction(&self, tag: u8) -> Instruction {
        self.h.ix(
            vec![
                signer(self.h.payer.pubkey()),
                signer(self.h.payer.pubkey()),
                ro(self.h.config),
                ro(self.h.log),
                rw(self.h.economy),
                rw(self.binding),
                ro(self.token),
                ro(pd(self.token)),
                ro(self.token_config),
                ro(self.morse),
                ro(self.oracle),
                ro(self.rewards),
                ro(pd(self.rewards)),
                ro(self.pool),
                ro(Address::default()),
            ],
            vec![tag],
        )
    }
    fn member(&self) -> Address {
        Address::find_program_address(&[b"member", self.h.witness.as_ref()], &self.rewards).0
    }
    fn fund_paid_epoch(&mut self, epoch: u64) {
        self.h.clock(epoch as i64 * WEEK);
        let ledger =
            Address::find_program_address(&[b"epoch", &epoch.to_le_bytes()], &self.rewards).0;
        assert!(self.send(Instruction {
            program_id: self.rewards,
            accounts: vec![
                signer(self.h.payer.pubkey()),
                ro(self.pool),
                rw(ledger),
                ro(Address::default())
            ],
            data: [vec![1], epoch.to_le_bytes().to_vec()].concat()
        }));
        let operation = [88u8; 32];
        let receipt = Address::find_program_address(
            &[b"funding", self.h.operator.pubkey().as_ref(), &operation],
            &self.rewards,
        )
        .0;
        let funding = Instruction {
            program_id: self.rewards,
            accounts: vec![
                signer(self.h.operator.pubkey()),
                signer(self.h.payer.pubkey()),
                rw(self.pool),
                rw(ledger),
                rw(ata(&self.pool, &self.h.mint)),
                rw(self.h.source),
                ro(self.h.mint),
                ro(TOKEN),
                rw(receipt),
                ro(Address::default()),
            ],
            data: [
                vec![12, 0],
                100_000_000u64.to_le_bytes().to_vec(),
                operation.to_vec(),
            ]
            .concat(),
        };
        assert!(self.h.send(&[funding], true));
    }
    fn token_witness(&mut self) -> (Address, Address, Address, Address, Address) {
        let allocation = Address::find_program_address(&[b"allocation", &[1]], &self.token).0;
        let owned = ata(&self.h.payer.pubkey(), &self.morse);
        assert!(self.send(Instruction {
            program_id: self.token,
            accounts: vec![
                signer(self.h.payer.pubkey()),
                ro(self.token_config),
                rw(allocation),
                rw(ata(&allocation, &self.morse)),
                rw(owned),
                ro(self.h.payer.pubkey()),
                ro(self.morse),
                ro(TOKEN),
                ro(ATA),
                ro(Address::default())
            ],
            data: vec![1, 1]
        }));
        let key = ed25519_dalek::SigningKey::from_bytes(&[15; 32]);
        let public = key.verifying_key().to_bytes();
        let id = b"token-outside";
        let identity = solana_sha256_hasher::hashv(&[
            b"morse-witness-record-v1",
            &[id.len() as u8],
            id,
            &public,
        ]);
        let witness = Address::find_program_address(
            &[b"witness", &self.h.log_id, identity.as_ref()],
            &self.h.program,
        )
        .0;
        let statement = [
            b"morse-witness-register-v1".as_slice(),
            id,
            self.h.operator.pubkey().as_ref(),
            self.h.payer.pubkey().as_ref(),
        ]
        .concat();
        let signature = key.sign(&statement).to_bytes();
        let mut data = vec![1, 0];
        for value in [
            48,
            u16::MAX,
            16,
            u16::MAX,
            112,
            statement.len() as u16,
            u16::MAX,
        ] {
            data.extend(value.to_le_bytes());
        }
        data.extend(public);
        data.extend(signature);
        data.extend(&statement);
        let proof = Instruction {
            program_id: Address::from_str_const("Ed25519SigVerify111111111111111111111111111"),
            accounts: vec![],
            data,
        };
        let register = self.h.ix(
            vec![
                signer(self.h.operator.pubkey()),
                signer(self.h.payer.pubkey()),
                ro(self.h.log),
                rw(witness),
                ro(Address::default()),
                ro(Address::from_str_const(
                    "Sysvar1nstructions1111111111111111111111111",
                )),
            ],
            [
                vec![4, 0, 0, id.len() as u8],
                id.to_vec(),
                public.to_vec(),
                self.h.payer.pubkey().as_ref().to_vec(),
                vec![0; 32],
                signature.to_vec(),
            ]
            .concat(),
        );
        assert!(self.h.send(&[proof, register], true));
        let bond = Address::find_program_address(
            &[b"bond", &self.h.log_id, identity.as_ref()],
            &self.h.program,
        )
        .0;
        let pending =
            Address::find_program_address(&[b"bond-pending", bond.as_ref()], &self.h.program).0;
        let vault = ata(&bond, &self.morse);
        let source = ata(&self.h.operator.pubkey(), &self.morse);
        for (owner, destination) in [(self.h.operator.pubkey(), source), (bond, vault)] {
            assert!(self.send(Instruction {
                program_id: ATA,
                accounts: vec![
                    signer(self.h.payer.pubkey()),
                    rw(destination),
                    ro(owner),
                    ro(self.morse),
                    ro(Address::default()),
                    ro(TOKEN)
                ],
                data: vec![1]
            }));
        }
        for (destination, amount) in [(source, 500_000_000u64), (vault, 17u64)] {
            assert!(self.send(Instruction {
                program_id: TOKEN,
                accounts: vec![
                    rw(owned),
                    ro(self.morse),
                    rw(destination),
                    signer(self.h.payer.pubkey())
                ],
                data: [vec![12], amount.to_le_bytes().to_vec(), vec![6]].concat()
            }));
        }
        for account in [bond, pending] {
            self.h
                .svm
                .set_account(
                    account,
                    solana_account::Account {
                        lamports: 1,
                        data: vec![],
                        owner: Address::default(),
                        executable: false,
                        rent_epoch: 0,
                    },
                )
                .unwrap();
        }
        (witness, bond, pending, vault, source)
    }
    fn deposit_v2(
        &self,
        accounts: (Address, Address, Address, Address, Address),
        asset: u8,
        amount: u64,
    ) -> Instruction {
        let (witness, bond, pending, vault, source) = accounts;
        let mint = if asset == 0 { self.h.mint } else { self.morse };
        self.h.ix(
            vec![
                signer(self.h.operator.pubkey()),
                ro(self.h.log),
                rw(self.h.economy),
                ro(self.binding),
                rw(witness),
                rw(bond),
                rw(pending),
                rw(vault),
                rw(source),
                ro(mint),
                ro(self.token),
                ro(pd(self.token)),
                ro(self.token_config),
                ro(self.morse),
                ro(self.oracle),
                ro(self.rewards),
                ro(pd(self.rewards)),
                ro(self.pool),
                ro(TOKEN),
                ro(ATA),
                ro(Address::default()),
            ],
            [vec![34, asset], amount.to_le_bytes().to_vec()].concat(),
        )
    }
    fn prepare_proof(
        &self,
        wire: &[u8],
        stage: Address,
        targets: &[(Address, Address)],
    ) -> (Instruction, Address) {
        let fork = morse_judge::fork::Fork::parse(wire).unwrap();
        let second = match fork.second {
            morse_judge::fork::Target::Checkpoint(cp) => {
                morse_judge::checkpoint::Checkpoint::parse(cp)
                    .unwrap()
                    .hash()
            }
            _ => unreachable!(),
        };
        let receipt = Address::find_program_address(
            &[b"proof", &self.h.log_id, &fork.hash()],
            &self.h.program,
        )
        .0;
        let directory = Address::find_program_address(
            &[b"bond", &self.h.log_id, b"directory"],
            &self.h.program,
        )
        .0;
        let mut accounts = vec![
            signer(self.h.payer.pubkey()),
            ro(self.h.log),
            ro(stage),
            ro(self.h.economy),
            ro(self.binding),
            rw(receipt),
            ro(Address::default()),
            ro(directory),
        ];
        for (w, b) in targets {
            accounts.extend([ro(*w), ro(*b)]);
        }
        (
            self.h.ix(accounts, [vec![41], second.to_vec()].concat()),
            receipt,
        )
    }
    fn settle_proof(
        &self,
        receipt: Address,
        targets: &[(Address, Address, Address)],
    ) -> Instruction {
        let directory = Address::find_program_address(
            &[b"bond", &self.h.log_id, b"directory"],
            &self.h.program,
        )
        .0;
        let d = self.h.svm.get_account(&directory).unwrap();
        let mint = Address::new_from_array(d.data[104..136].try_into().unwrap());
        let locked = Address::find_program_address(&[b"locked", &self.h.log_id], &self.h.program).0;
        let mut accounts = vec![
            rw(self.h.log),
            rw(self.h.economy),
            ro(self.binding),
            rw(receipt),
            rw(directory),
            rw(ata(&directory, &mint)),
            ro(self.h.mint),
            rw(ata(&self.h.payer.pubkey(), &self.h.mint)),
            rw(ata(&locked, &self.h.mint)),
            ro(self.morse),
            rw(ata(&self.h.payer.pubkey(), &self.morse)),
            rw(ata(&locked, &self.morse)),
            ro(TOKEN),
        ];
        for (w, b, v) in targets {
            accounts.extend([rw(*w), rw(*b), rw(*v)]);
        }
        self.h.ix(accounts, vec![44])
    }
    fn directory_v2(&self, asset: u8, amount: u64) -> Instruction {
        let directory = Address::find_program_address(
            &[b"bond", &self.h.log_id, b"directory"],
            &self.h.program,
        )
        .0;
        let pending =
            Address::find_program_address(&[b"bond-pending", directory.as_ref()], &self.h.program)
                .0;
        let mint = if asset == 0 { self.h.mint } else { self.morse };
        self.h.ix(
            vec![
                signer(self.h.payer.pubkey()),
                ro(self.h.config),
                signer(self.h.payer.pubkey()),
                rw(self.h.log),
                rw(self.h.economy),
                ro(self.binding),
                rw(directory),
                rw(pending),
                rw(ata(&directory, &mint)),
                rw(ata(&self.h.payer.pubkey(), &mint)),
                ro(mint),
                ro(self.token),
                ro(pd(self.token)),
                ro(self.token_config),
                ro(self.morse),
                ro(self.oracle),
                ro(self.rewards),
                ro(pd(self.rewards)),
                ro(self.pool),
                ro(TOKEN),
                ro(ATA),
                ro(Address::default()),
            ],
            [vec![35, asset], amount.to_le_bytes().to_vec()].concat(),
        )
    }
    fn token_reward_context(&self, epoch: u64) -> Vec<AccountMeta> {
        let token_pool = Address::find_program_address(&[b"token-pool"], &self.rewards).0;
        let ledger =
            Address::find_program_address(&[b"epoch", &epoch.to_le_bytes()], &self.rewards).0;
        let companion =
            Address::find_program_address(&[b"token-epoch", &epoch.to_le_bytes()], &self.rewards).0;
        let week = Address::find_program_address(
            &[b"attendance-epoch", &self.h.log_id, &epoch.to_le_bytes()],
            &self.h.program,
        )
        .0;
        vec![
            rw(self.pool),
            ro(token_pool),
            rw(ledger),
            rw(companion),
            ro(self.h.log),
            ro(self.clock),
            ro(week),
            ro(self.h.economy),
            ro(self.binding),
            ro(self.token),
            ro(pd(self.token)),
            ro(self.token_config),
            ro(self.morse),
            ro(self.oracle),
            ro(self.rewards),
            ro(pd(self.rewards)),
            ro(self.h.program),
            ro(pd(self.h.program)),
            ro(Address::find_program_address(&[b"reserve-config"], &self.token).0),
        ]
    }
    fn token_reward_finalize(&self, epoch: u64) -> Instruction {
        let allocation = Address::find_program_address(&[b"allocation", &[4]], &self.token).0;
        let mut accounts = self.token_reward_context(epoch);
        accounts[1].is_writable = true;
        accounts.extend([
            rw(allocation),
            rw(ata(&allocation, &self.morse)),
            rw(ata(&self.pool, &self.morse)),
            rw(Address::find_program_address(
                &[b"reserve-epoch", &epoch.to_le_bytes()],
                &self.token,
            )
            .0),
            signer(self.h.payer.pubkey()),
            ro(TOKEN),
            ro(Address::default()),
        ]);
        Instruction {
            program_id: self.rewards,
            accounts,
            data: vec![17],
        }
    }
    fn reward_fund(&mut self, amount: u64, kind: u8, operation: [u8; 32]) -> Instruction {
        let epoch = (self.h.svm.get_sysvar::<Clock>().unix_timestamp / WEEK) as u64;
        let ledger =
            Address::find_program_address(&[b"epoch", &epoch.to_le_bytes()], &self.rewards).0;
        assert!(self.send(Instruction {
            program_id: self.rewards,
            accounts: vec![
                signer(self.h.payer.pubkey()),
                ro(self.pool),
                rw(ledger),
                ro(Address::default())
            ],
            data: [vec![1], epoch.to_le_bytes().to_vec()].concat()
        }));
        let receipt = Address::find_program_address(
            &[b"funding", self.h.operator.pubkey().as_ref(), &operation],
            &self.rewards,
        )
        .0;
        let ix = Instruction {
            program_id: self.rewards,
            accounts: vec![
                signer(self.h.operator.pubkey()),
                signer(self.h.payer.pubkey()),
                rw(self.pool),
                rw(ledger),
                rw(ata(&self.pool, &self.h.mint)),
                rw(self.h.source),
                ro(self.h.mint),
                ro(TOKEN),
                rw(receipt),
                ro(Address::default()),
            ],
            data: [
                vec![12, kind],
                amount.to_le_bytes().to_vec(),
                operation.to_vec(),
            ]
            .concat(),
        };
        assert!(self.h.send(std::slice::from_ref(&ix), true));
        ix
    }
    fn drain_week(&mut self, epoch: u64, leave_collecting: bool) {
        let week = Address::find_program_address(
            &[b"attendance-epoch", &self.h.log_id, &epoch.to_le_bytes()],
            &self.h.program,
        )
        .0;
        let ledger =
            Address::find_program_address(&[b"epoch", &epoch.to_le_bytes()], &self.rewards).0;
        assert!(self.send(self.h.ix(
            vec![
                signer(self.h.payer.pubkey()),
                ro(self.h.log),
                ro(self.clock),
                rw(week),
                ro(Address::default())
            ],
            [vec![28], epoch.to_le_bytes().to_vec()].concat()
        )));
        let paid = epoch + 1 == (self.h.svm.get_sysvar::<Clock>().unix_timestamp / WEEK) as u64;
        if paid {
            // Authenticated attendance prestate; anchor/signature validation is
            // independently covered by the judge suites.
            let mut state = self.h.svm.get_account(&week).unwrap();
            state.data[44..52].copy_from_slice(&1u64.to_le_bytes());
            state.data[52..60].copy_from_slice(&77u64.to_le_bytes());
            state.data[60..62].copy_from_slice(&1u16.to_le_bytes());
            state.data[80..112].copy_from_slice(self.h.witness.as_ref());
            state.data[112..120].copy_from_slice(&1u64.to_le_bytes());
            self.h.svm.set_account(week, state).unwrap();
            let mut clock = self.h.svm.get_account(&self.clock).unwrap();
            clock.data[60..68].copy_from_slice(&epoch.to_le_bytes());
            clock.data[80..88].copy_from_slice(&(epoch + 1).to_le_bytes());
            clock.data[88..96].copy_from_slice(&77u64.to_le_bytes());
            self.h.svm.set_account(self.clock, clock).unwrap();
        }
        assert!(self.send(self.h.ix(vec![ro(self.h.log), rw(week)], vec![29])));
        assert!(self.send(Instruction {
            program_id: self.rewards,
            accounts: vec![
                signer(self.h.payer.pubkey()),
                ro(self.pool),
                rw(ledger),
                ro(Address::default())
            ],
            data: [vec![1], epoch.to_le_bytes().to_vec()].concat()
        }));
        let accounts = vec![
            rw(self.pool),
            rw(ledger),
            ro(self.h.log),
            ro(self.clock),
            ro(week),
            ro(self.h.economy),
        ];
        assert!(self.send(Instruction {
            program_id: self.rewards,
            accounts: accounts.clone(),
            data: vec![5]
        }));
        assert!(
            !self.send(self.binding_instruction(32)),
            "no migration across a collecting legacy stage"
        );
        if paid {
            let mut appended = accounts.clone();
            appended.extend([ro(self.h.witness), ro(self.h.bond), ro(self.member())]);
            assert!(self.send(Instruction {
                program_id: self.rewards,
                accounts: appended,
                data: vec![6]
            }));
        }
        if !leave_collecting {
            assert!(self.send(Instruction {
                program_id: self.rewards,
                accounts,
                data: vec![7]
            }));
        }
    }
}
#[test]
fn token_binding_waits_fourteen_days_drains_legacy_epochs_and_migrates_units_explicitly() {
    let mut snapshots = Vec::new();
    let mut t = TokenHarness::new();
    if std::env::var("MORSE_NETWORK_COUNTER_FIXTURE_LOG").as_deref() == Ok("morse-main") {
        let pending =
            Address::find_program_address(&[b"bond-pending", t.h.bond.as_ref()], &t.h.program).0;
        snapshots.push(t.snapshot("legacy-active", &[(t.h.witness, t.h.bond, pending)], None));
    }
    let economy = t.h.svm.get_account(&t.h.economy).unwrap();
    let vault = t.h.svm.get_account(&t.h.vault).unwrap();
    let proposal = t.binding_instruction(31);
    let mut attacker = proposal.clone();
    attacker.accounts[0] = signer(t.h.operator.pubkey());
    assert!(!t.h.send(&[attacker], true));
    assert!(t.send(proposal.clone()));
    let binding = t.h.svm.get_account(&t.binding).unwrap();
    assert!(t.send(proposal));
    assert_eq!(
        t.h.svm.get_account(&t.binding).unwrap(),
        binding,
        "identical proposal preserves the timelock"
    );
    assert!(!t.send(t.binding_instruction(32)));
    assert_eq!(t.h.svm.get_account(&t.h.economy).unwrap(), economy);
    let ready = START + WEEK + morse_judge::state::TIMELOCK_SECONDS;
    t.h.clock(ready);
    assert!(
        !t.send(t.binding_instruction(32)),
        "stale/missing complete oracle coverage cannot activate"
    );
    assert!(t.send(Instruction {
        program_id: t.rewards,
        accounts: vec![ro(t.pool), rw(t.member())],
        data: vec![4]
    }));
    let paid_epoch = (ready / WEEK) as u64 + 1;
    t.fund_paid_epoch(paid_epoch);
    let finish = ready + 2 * WEEK;
    t.observe_until(finish);
    assert!(
        !t.send(t.binding_instruction(32)),
        "closed legacy reward epochs must drain"
    );
    let current = (finish / WEEK) as u64;
    for epoch in (t.started / WEEK + 1) as u64..current {
        t.drain_week(epoch, false);
    }
    if std::env::var_os("MORSE_COLLATERAL_OPERATOR_FIXTURES_PATH").is_some()
        || std::env::var_os("MORSE_COLLATERAL_OPERATOR_REPLAY_PATH").is_some()
    {
        let governance = t.h.payer.pubkey();
        let fee_payer = t.h.operator.pubkey();
        assert_ne!(governance, fee_payer);
        let mut instruction = t.binding_instruction(32);
        instruction.accounts[0] = ro(governance);
        instruction.accounts[1] = ro(fee_payer);
        std::mem::swap(&mut t.h.payer, &mut t.h.operator);
        let activated = t.send(instruction);
        std::mem::swap(&mut t.h.payer, &mut t.h.operator);
        assert!(
            activated,
            "binding activation does not require a governance signature"
        );
        eprintln!("MORSE_COLLATERAL_PERMISSIONLESS_ACTIVATE fee_payer_not_governance=1 governance_signer=0");
    } else {
        assert!(t.send(t.binding_instruction(32)));
    }
    let migrated = t.h.svm.get_account(&t.h.economy).unwrap();
    assert_eq!(&migrated.data[..4], b"MEC\x02");
    assert_eq!(&migrated.data[4..165], &economy.data[4..165]);
    assert_eq!(&migrated.data[165..168], &[0; 3]);
    assert_eq!(&migrated.data[176..], &[0; 16]);
    assert_eq!(t.h.svm.get_account(&t.h.vault).unwrap(), vault);
    snapshots.push(t.snapshot("activated-usdc-migrated", &[], None));
    if std::env::var("MORSE_NETWORK_COUNTER_FIXTURE_LOG").as_deref() == Ok("morse-main") {
        let pending =
            Address::find_program_address(&[b"bond-pending", t.h.bond.as_ref()], &t.h.program).0;
        snapshots.push(t.snapshot(
            "v2-usdc-legacy-bond",
            &[(t.h.witness, t.h.bond, pending)],
            None,
        ));
    }
    assert!(
        !t.h.send(&[t.h.deposit(1)], true),
        "v1 handler refuses explicit v2 units"
    );
    assert!(
        !t.h.send(&[t.h.request()], true),
        "v1 unbond cannot mutate an unmigrated bond in MEC2"
    );
    assert!(
        t.send(t.binding_instruction(32)),
        "activation replay cannot reset epoch or principal"
    );
    assert_eq!(t.h.svm.get_account(&t.h.economy).unwrap(), migrated);
    let ledger =
        Address::find_program_address(&[b"epoch", &paid_epoch.to_le_bytes()], &t.rewards).0;
    let payout = ata(&t.h.payer.pubkey(), &t.h.mint);
    let prior = t.h.balance(payout);
    let claim = Instruction {
        program_id: t.rewards,
        accounts: vec![
            rw(t.pool),
            rw(ledger),
            rw(ata(&t.pool, &t.h.mint)),
            rw(payout),
            ro(t.h.mint),
            ro(TOKEN),
        ],
        data: vec![8, 0],
    };
    let unclaimed_legacy_bank = t.h.svm.clone();
    let legacy_claim = claim.clone();
    assert!(
        t.send(claim.clone()),
        "finalized legacy USD entitlement remains payable after MEC2 activation"
    );
    assert_eq!(t.h.balance(payout) - prior, 100_000_000);
    assert!(!t.send(claim));
    assert_eq!(
        t.h.svm.get_account(&t.h.vault).unwrap(),
        vault,
        "legacy rewards cannot spend judge custody"
    );
    let migrate = t.h.ix(
        vec![
            ro(t.h.log),
            rw(t.h.economy),
            ro(t.binding),
            rw(t.h.bond),
            ro(t.h.witness),
        ],
        vec![33, 1],
    );
    let prior_bond = t.h.svm.get_account(&t.h.bond).unwrap();
    let legacy_usd_snapshot = prior_bond.clone();
    assert!(
        t.send(migrate.clone()),
        "permissionless USDC schema migration never changes custody or units"
    );
    let migrated_bond = t.h.svm.get_account(&t.h.bond).unwrap();
    assert_eq!(&migrated_bond.data[..4], b"MBD\x02");
    assert_eq!(&migrated_bond.data[4..], &prior_bond.data[4..]);
    let migrated_policy = t.h.svm.get_account(&t.h.economy).unwrap();
    assert!(t.send(migrate));
    assert_eq!(t.h.svm.get_account(&t.h.bond).unwrap(), migrated_bond);
    assert_eq!(
        t.h.svm.get_account(&t.h.economy).unwrap(),
        migrated_policy,
        "schema replay cannot keep invalidating staged eligibility"
    );
    let directory =
        Address::find_program_address(&[b"bond", &t.h.log_id, b"directory"], &t.h.program).0;
    assert!(t.send(t.h.ix(
        vec![ro(t.h.log), rw(t.h.economy), ro(t.binding), rw(directory)],
        vec![33, 0]
    )));
    assert_eq!(
        &t.h.svm.get_account(&directory).unwrap().data[..4],
        b"MBD\x02"
    );
    assert_eq!(t.h.svm.get_account(&t.h.vault).unwrap(), vault);
    let (witness, bond, pending, token_vault, source) = t.token_witness();
    if std::env::var("MORSE_NETWORK_COUNTER_FIXTURE_LOG").as_deref() == Ok("morse-main") {
        snapshots.push(t.snapshot("registered-only", &[(witness, bond, pending)], None));
    }
    let prior_source = t.h.balance(source);
    let prior_policy = t.h.svm.get_account(&t.h.economy).unwrap();
    let prior_bond = t.h.svm.get_account(&bond).unwrap();
    let prior_pending = t.h.svm.get_account(&pending).unwrap();
    let insufficient = t.deposit_v2((witness, bond, pending, token_vault, source), 1, 49_999_999);
    assert!(!t.h.send(&[insufficient], true));
    assert_eq!(t.h.svm.get_account(&bond).unwrap(), prior_bond);
    assert_eq!(t.h.svm.get_account(&pending).unwrap(), prior_pending);
    assert_eq!(t.h.svm.get_account(&t.h.economy).unwrap(), prior_policy);
    assert_eq!(t.h.balance(source), prior_source);
    let deposit = t.deposit_v2((witness, bond, pending, token_vault, source), 1, 50_000_000);
    for (role, wrong) in [
        (3, t.h.config),
        (4, t.h.witness),
        (5, t.h.bond),
        (6, Address::new_unique()),
        (7, t.h.vault),
        (8, token_vault),
        (9, t.h.mint),
        (11, pd(t.rewards)),
        (14, t.h.economy),
        (19, TOKEN),
    ] {
        let mut substituted = deposit.clone();
        substituted.accounts[role].pubkey = wrong;
        assert!(
            !t.h.send(&[substituted], true),
            "wrong collateral role {role}"
        );
        assert_eq!(t.h.svm.get_account(&bond).unwrap(), prior_bond);
        assert_eq!(t.h.svm.get_account(&pending).unwrap(), prior_pending);
        assert_eq!(t.h.svm.get_account(&t.h.economy).unwrap(), prior_policy);
        assert_eq!(t.h.balance(source), prior_source);
    }
    let vault_before = t.h.svm.get_account(&token_vault).unwrap();
    let mut delegated = vault_before.clone();
    delegated.data[72..76].copy_from_slice(&1u32.to_le_bytes());
    delegated.data[76..108].copy_from_slice(t.h.payer.pubkey().as_ref());
    t.h.svm.set_account(token_vault, delegated.clone()).unwrap();
    assert!(!t.h.send(std::slice::from_ref(&deposit), true));
    assert_eq!(
        t.h.svm.get_account(&bond).unwrap(),
        prior_bond,
        "late vault rejection rolls back metadata creation"
    );
    assert_eq!(t.h.svm.get_account(&pending).unwrap(), prior_pending);
    assert_eq!(t.h.svm.get_account(&token_vault).unwrap(), delegated);
    assert_eq!(t.h.balance(source), prior_source);
    t.h.svm.set_account(token_vault, vault_before).unwrap();
    assert!(
        t.h.send(&[deposit], true),
        "new MORSE bond covers the exact USD target using the authenticated full TWAP"
    );
    let mut active = t.h.svm.get_account(&bond).unwrap();
    // LiteSVM normalizes the rent epoch when a freshly created account is next loaded.
    active.rent_epoch = u64::MAX;
    assert_eq!(&active.data[..4], b"MBD\x02");
    assert_eq!(active.data[6], 1);
    assert_eq!(
        u64::from_le_bytes(active.data[168..176].try_into().unwrap()),
        50_000_000
    );
    assert_eq!(
        t.h.balance(token_vault),
        50_000_017,
        "direct donations are not active principal"
    );
    let policy = t.h.svm.get_account(&t.h.economy).unwrap();
    snapshots.push(t.snapshot("token-active", &[(witness, bond, pending)], None));
    assert_eq!(
        u64::from_le_bytes(policy.data[148..156].try_into().unwrap()),
        100_000_000
    );
    assert_eq!(
        u64::from_le_bytes(policy.data[176..184].try_into().unwrap()),
        50_000_000
    );
    let topup = t.deposit_v2((witness, bond, pending, token_vault, source), 1, 1);
    assert!(t.h.send(&[topup], true));
    assert_eq!(
        t.h.svm.get_account(&bond).unwrap(),
        active,
        "pending topup cannot mutate a staged eligibility input"
    );
    assert_eq!(
        t.h.svm.get_account(&t.h.economy).unwrap(),
        policy,
        "one base-unit topup cannot invalidate a collecting stage"
    );
    let pending_state = t.h.svm.get_account(&pending).unwrap();
    assert_eq!(&pending_state.data[..4], b"MBP\x02");
    assert_eq!(
        u64::from_le_bytes(pending_state.data[68..76].try_into().unwrap()),
        1
    );
    assert_eq!(t.h.balance(token_vault), 50_000_018);
    snapshots.push(t.snapshot("token-pending", &[(witness, bond, pending)], None));
    assert_eq!(
        u64::from_le_bytes(pending_state.data[84..92].try_into().unwrap()),
        100_000_000,
        "this bond lifetime retains its original USD target"
    );
    let activate_pending = t.h.ix(
        vec![
            ro(t.h.log),
            rw(t.h.economy),
            ro(t.binding),
            rw(bond),
            rw(pending),
            rw(token_vault),
            ro(t.token),
            ro(pd(t.token)),
            ro(t.token_config),
            ro(t.morse),
            ro(t.oracle),
            ro(t.rewards),
            ro(pd(t.rewards)),
            ro(t.pool),
            ro(witness),
        ],
        vec![36, 1],
    );
    let pool = t.h.svm.get_account(&t.pool).unwrap();
    let mut collecting = pool.clone();
    let next = u64::from_le_bytes(pool.data[180..188].try_into().unwrap());
    collecting.data[220..228].copy_from_slice(&(next + 1).to_le_bytes());
    t.h.svm.set_account(t.pool, collecting).unwrap();
    assert!(!t.send(activate_pending.clone()));
    assert_eq!(t.h.svm.get_account(&bond).unwrap(), active);
    assert_eq!(t.h.svm.get_account(&pending).unwrap(), pending_state);
    assert_eq!(t.h.svm.get_account(&t.h.economy).unwrap(), policy);
    t.h.svm.set_account(t.pool, pool).unwrap();
    assert!(
        t.send(activate_pending.clone()),
        "pending activation is permissionless outside collection"
    );
    let applied = t.h.svm.get_account(&bond).unwrap();
    assert_eq!(
        u64::from_le_bytes(applied.data[168..176].try_into().unwrap()),
        50_000_001
    );
    let applied_policy = t.h.svm.get_account(&t.h.economy).unwrap();
    assert_eq!(
        u64::from_le_bytes(applied_policy.data[176..184].try_into().unwrap()),
        50_000_001
    );
    let applied_pending = t.h.svm.get_account(&pending).unwrap();
    assert_eq!(&applied_pending.data[68..84], &[0; 16]);
    assert_eq!(&applied_pending.data[84..92], &pending_state.data[84..92]);
    assert_eq!(t.h.balance(token_vault), 50_000_018);
    assert!(t.send(activate_pending.clone()));
    assert_eq!(t.h.svm.get_account(&bond).unwrap(), applied);
    assert_eq!(t.h.svm.get_account(&pending).unwrap(), applied_pending);
    assert_eq!(t.h.svm.get_account(&t.h.economy).unwrap(), applied_policy);
    let previous = t.h.svm.get_sysvar::<Clock>().unix_timestamp;
    let underwater = previous + WEEK + 3600;
    t.observe_price_until(underwater, 1_500_000);
    let pool = t.h.svm.get_account(&t.pool).unwrap();
    let mut collecting = pool.clone();
    let next = u64::from_le_bytes(pool.data[180..188].try_into().unwrap());
    collecting.data[220..228].copy_from_slice(&(next + 1).to_le_bytes());
    t.h.svm.set_account(t.pool, collecting.clone()).unwrap();
    let topup = t.deposit_v2((witness, bond, pending, token_vault, source), 1, 13);
    assert!(t.h.send(&[topup], true));
    let pending_before = t.h.svm.get_account(&pending).unwrap();
    let policy_before = t.h.svm.get_account(&t.h.economy).unwrap();
    let mut assessment = activate_pending.clone();
    assessment.data = vec![45, 1];
    assessment.accounts[4].is_writable = false;
    assert!(t.send(assessment.clone()),"a genuine grace transition can invalidate a collecting snapshot without activating pending units");
    let policy_after = t.h.svm.get_account(&t.h.economy).unwrap();
    assert_eq!(
        u64::from_le_bytes(policy_after.data[168..176].try_into().unwrap()),
        u64::from_le_bytes(policy_before.data[168..176].try_into().unwrap()) + 1
    );
    assert_eq!(t.h.svm.get_account(&pending).unwrap(), pending_before);
    assert_eq!(t.h.svm.get_account(&t.pool).unwrap(), collecting);
    assert_eq!(
        &t.h.svm.get_account(&bond).unwrap().data[168..176],
        &applied.data[168..176]
    );
    let topup = t.deposit_v2((witness, bond, pending, token_vault, source), 1, 1);
    assert!(t.h.send(&[topup], true));
    let pending_after = t.h.svm.get_account(&pending).unwrap();
    assert!(t.send(assessment));
    assert_eq!(
        t.h.svm.get_account(&t.h.economy).unwrap(),
        policy_after,
        "a one-unit pending topup cannot manufacture another revision change"
    );
    assert_eq!(t.h.svm.get_account(&pending).unwrap(), pending_after);
    eprintln!("MORSE_TOKEN_ASSESSMENT_STAGE genuine_revision_pending_unchanged");
    t.h.svm.set_account(t.pool, pool).unwrap();
    assert!(t.send(activate_pending.clone()));
    let underwater_bond = t.h.svm.get_account(&bond).unwrap();
    assert_eq!(
        i64::from_le_bytes(underwater_bond.data[200..208].try_into().unwrap()),
        underwater
    );
    assert_eq!(underwater_bond.data[4], 1, "price loss is never a slash");
    snapshots.push(t.snapshot("token-underwater", &[(witness, bond, pending)], None));
    let partial = t.deposit_v2((witness, bond, pending, token_vault, source), 1, 10_000_000);
    assert!(t.h.send(&[partial], true));
    assert!(t.send(activate_pending.clone()));
    let partially_recovered = t.h.svm.get_account(&bond).unwrap();
    assert_eq!(
        &partially_recovered.data[200..208],
        &underwater_bond.data[200..208]
    );
    t.observe_price_until(underwater + WEEK, 1_500_000);
    assert!(t.send(activate_pending.clone()));
    let expired = t.h.svm.get_account(&bond).unwrap();
    assert!(!morse_judge::token_custody::eligible(
        morse_judge::token_custody::decode_bond(&expired.data).unwrap(),
        1_500_000,
        100_000_000,
        underwater + WEEK
    )
    .unwrap());
    assert_eq!(expired.data[4], 1);
    snapshots.push(t.snapshot("token-grace-expired", &[(witness, bond, pending)], None));
    let proposal = t.h.ix(
        vec![
            signer(t.h.payer.pubkey()),
            ro(t.h.config),
            ro(t.h.log),
            rw(t.h.economy),
            ro(t.binding),
        ],
        [
            vec![39],
            200_000_000u64.to_le_bytes().to_vec(),
            500_000_000u64.to_le_bytes().to_vec(),
        ]
        .concat(),
    );
    assert!(
        t.send(proposal.clone()),
        "MEC2 minimum changes use their explicit timelocked handler"
    );
    let pending_policy = t.h.svm.get_account(&t.h.economy).unwrap();
    let activate_minimums =
        t.h.ix(vec![ro(t.h.log), rw(t.h.economy), ro(t.binding)], vec![40]);
    assert!(!t.send(activate_minimums.clone()));
    let ready = i64::from_le_bytes(pending_policy.data[140..148].try_into().unwrap());
    t.h.clock(ready - 1);
    assert!(t.send(proposal));
    assert_eq!(
        t.h.svm.get_account(&t.h.economy).unwrap(),
        pending_policy,
        "identical proposal cannot postpone the deadline"
    );
    t.observe_price_until(ready, 1_500_000);
    assert!(t.send(activate_minimums));
    assert_eq!(
        &t.h.svm.get_account(&t.h.economy).unwrap().data[100..108],
        &200_000_000u64.to_le_bytes()
    );
    let full = t.deposit_v2((witness, bond, pending, token_vault, source), 1, 6_666_666);
    assert!(t.h.send(&[full], true));
    assert!(t.send(activate_pending));
    assert_eq!(&t.h.svm.get_account(&bond).unwrap().data[200..208], &[0; 8]);
    let pending_on_exit = t.deposit_v2((witness, bond, pending, token_vault, source), 1, 1);
    assert!(t.h.send(&[pending_on_exit], true));
    let unbond = t.h.ix(
        vec![
            signer(t.h.operator.pubkey()),
            ro(t.h.log),
            rw(t.h.economy),
            ro(t.binding),
            rw(bond),
            ro(pending),
            rw(witness),
        ],
        vec![37, 1],
    );
    assert!(
        t.h.send(std::slice::from_ref(&unbond), true),
        "MORSE owner can start its exact thirty-day exit"
    );
    let unbonded = t.h.svm.get_account(&bond).unwrap();
    let unbonded_policy = t.h.svm.get_account(&t.h.economy).unwrap();
    assert_eq!(unbonded.data[4], 2);
    assert!(t.h.send(&[unbond], true));
    assert_eq!(t.h.svm.get_account(&bond).unwrap(), unbonded);
    assert_eq!(t.h.svm.get_account(&t.h.economy).unwrap(), unbonded_policy);
    let withdraw = t.h.ix(
        vec![
            signer(t.h.operator.pubkey()),
            ro(t.h.log),
            rw(t.h.economy),
            ro(t.binding),
            rw(bond),
            rw(pending),
            rw(token_vault),
            rw(source),
            ro(t.morse),
            ro(TOKEN),
            rw(witness),
        ],
        vec![38, 1],
    );
    assert!(!t.h.send(std::slice::from_ref(&withdraw), true));
    let exit_at =
        t.h.svm.get_sysvar::<Clock>().unix_timestamp + morse_judge::custody::UNBOND_SECONDS;
    t.h.clock(exit_at);
    let custody = t.h.balance(token_vault);
    let destination = t.h.balance(source);
    assert!(
        t.h.send(std::slice::from_ref(&withdraw), true),
        "an unavailable oracle cannot trap a matured owner exit"
    );
    assert_eq!(t.h.balance(token_vault), 0);
    assert_eq!(t.h.balance(source), destination + custody);
    let exited = t.h.svm.get_account(&bond).unwrap();
    assert_eq!(exited.data[4], 4);
    assert_eq!(&exited.data[168..176], &[0; 8]);
    assert_eq!(
        &t.h.svm.get_account(&pending).unwrap().data[68..84],
        &[0; 16]
    );
    let exited_policy = t.h.svm.get_account(&t.h.economy).unwrap();
    assert_eq!(&exited_policy.data[176..184], &[0; 8]);
    assert_eq!(&exited_policy.data[148..156], &100_000_000u64.to_le_bytes());
    assert!(t.h.send(&[withdraw], true));
    assert_eq!(t.h.svm.get_account(&t.h.economy).unwrap(), exited_policy);
    assert_eq!(t.h.svm.get_account(&bond).unwrap(), exited);
    snapshots.push(t.snapshot("token-withdrawn", &[(witness, bond, pending)], None));
    let directory_pending =
        Address::find_program_address(&[b"bond-pending", directory.as_ref()], &t.h.program).0;
    let directory_vault = ata(&directory, &t.h.mint);
    let directory_source = ata(&t.h.payer.pubkey(), &t.h.mint);
    let directory_topup = t.h.ix(
        vec![
            signer(t.h.payer.pubkey()),
            ro(t.h.config),
            signer(t.h.payer.pubkey()),
            rw(t.h.log),
            rw(t.h.economy),
            ro(t.binding),
            rw(directory),
            rw(directory_pending),
            rw(directory_vault),
            rw(directory_source),
            ro(t.h.mint),
            ro(t.token),
            ro(pd(t.token)),
            ro(t.token_config),
            ro(t.morse),
            ro(t.oracle),
            ro(t.rewards),
            ro(pd(t.rewards)),
            ro(t.pool),
            ro(TOKEN),
            ro(ATA),
            ro(Address::default()),
        ],
        [vec![35, 0], 1u64.to_le_bytes().to_vec()].concat(),
    );
    let directory_before = t.h.svm.get_account(&directory).unwrap();
    let policy_before = t.h.svm.get_account(&t.h.economy).unwrap();
    let vault_before = t.h.balance(directory_vault);
    let mut unauthorized = directory_topup.clone();
    unauthorized.accounts[0] = signer(t.h.operator.pubkey());
    assert!(!t.h.send(&[unauthorized], true));
    assert!(
        t.send(directory_topup),
        "a stale token oracle does not block an existing USDC directory topup"
    );
    assert_eq!(t.h.svm.get_account(&directory).unwrap(), directory_before);
    assert_eq!(t.h.svm.get_account(&t.h.economy).unwrap(), policy_before);
    assert_eq!(t.h.balance(directory_vault), vault_before + 1);
    let directory_pending_state = t.h.svm.get_account(&directory_pending).unwrap();
    assert_eq!(&directory_pending_state.data[68..76], &1u64.to_le_bytes());
    assert_eq!(&directory_pending_state.data[84..92], &[0; 8]);
    let current = t.h.svm.get_sysvar::<Clock>().unix_timestamp;
    t.observe_price_until(current + WEEK + 3600, 1_500_000);
    let rebond = t.deposit_v2(
        (witness, bond, pending, token_vault, source),
        1,
        133_333_334,
    );
    assert!(t.h.send(&[rebond], true));
    assert_eq!(
        &t.h.svm.get_account(&pending).unwrap().data[84..92],
        &200_000_000u64.to_le_bytes(),
        "rebond starts a new target lifetime"
    );
    let witnesses = [
        (b"outside".as_slice(), 12, t.h.witness),
        (b"token-outside".as_slice(), 15, witness),
    ];
    if std::env::var_os("MORSE_COLLATERAL_OPERATOR_FIXTURES_PATH").is_some()
        || std::env::var_os("MORSE_COLLATERAL_OPERATOR_REPLAY_PATH").is_some()
    {
        let original_bank = t.h.svm.clone();
        // Real timelocked source rotation in the owned bank: monetary records are
        // produced only by the unchanged SBF handlers. Owner exits must not need
        // the mutable price-source dependency that assessment authenticates.
        let apply = t.h.ix(
            vec![
                ro(t.h.log),
                rw(t.h.economy),
                ro(t.binding),
                rw(bond),
                rw(pending),
                rw(token_vault),
                ro(t.token),
                ro(pd(t.token)),
                ro(t.token_config),
                ro(t.morse),
                ro(t.oracle),
                ro(t.rewards),
                ro(pd(t.rewards)),
                ro(t.pool),
                ro(witness),
            ],
            vec![36, 1],
        );
        assert!(t.send(apply));
        let rotated = Address::new_from_array([0x9d; 32]);
        let now = t.h.svm.get_sysvar::<Clock>().unix_timestamp;
        Harness::account(&mut t.h.svm, rotated, PYTH, source_update(now));
        assert!(t.send(Instruction {
            program_id: t.token,
            accounts: vec![
                signer(t.h.payer.pubkey()),
                ro(t.token_config),
                ro(t.morse),
                rw(t.oracle),
                ro(PYTH),
                ro(rotated)
            ],
            data: [vec![6], rotated.as_ref().to_vec(), vec![9; 32]].concat()
        }));
        let ready = i64::from_le_bytes(
            t.h.svm.get_account(&t.oracle).unwrap().data[284..292]
                .try_into()
                .unwrap(),
        );
        t.h.clock(ready);
        Harness::account(&mut t.h.svm, rotated, PYTH, source_update(ready));
        assert!(t.send(Instruction {
            program_id: t.token,
            accounts: vec![
                ro(t.token_config),
                ro(t.morse),
                rw(t.oracle),
                ro(PYTH),
                ro(rotated)
            ],
            data: vec![7]
        }));
        let changed = t.h.svm.get_account(&t.oracle).unwrap();
        assert_eq!(&changed.data[100..132], rotated.as_ref());
        assert_eq!(
            u64::from_le_bytes(changed.data[292..300].try_into().unwrap()),
            2
        );
        assert!(
            changed.data[320..].iter().all(|v| *v == 0),
            "real source activation clears covered observations"
        );
        let before = t.h.svm.get_account(&bond).unwrap();
        let assess = t.h.ix(
            vec![
                ro(t.h.log),
                rw(t.h.economy),
                ro(t.binding),
                rw(bond),
                ro(pending),
                rw(token_vault),
                ro(t.token),
                ro(pd(t.token)),
                ro(t.token_config),
                ro(t.morse),
                ro(t.oracle),
                ro(t.rewards),
                ro(pd(t.rewards)),
                ro(t.pool),
                ro(witness),
            ],
            vec![45, 1],
        );
        assert!(
            !t.send(assess),
            "changed oracle source/revision refuses price-dependent assessment"
        );
        assert_eq!(t.h.svm.get_account(&bond).unwrap(), before);
        let exit = t.h.ix(
            vec![
                signer(t.h.operator.pubkey()),
                ro(t.h.log),
                rw(t.h.economy),
                ro(t.binding),
                rw(bond),
                ro(pending),
                rw(witness),
            ],
            vec![37, 1],
        );
        assert!(
            t.h.send(&[exit], true),
            "owner unbond is independent of oracle source/revision"
        );
        t.h.clock(t.h.svm.get_sysvar::<Clock>().unix_timestamp + UNBOND);
        let balance = t.h.balance(token_vault);
        let prior = t.h.balance(source);
        let withdraw = t.h.ix(
            vec![
                signer(t.h.operator.pubkey()),
                ro(t.h.log),
                rw(t.h.economy),
                ro(t.binding),
                rw(bond),
                rw(pending),
                rw(token_vault),
                rw(source),
                ro(t.morse),
                ro(TOKEN),
                rw(witness),
            ],
            vec![38, 1],
        );
        assert!(
            t.h.send(&[withdraw], true),
            "matured owner withdrawal survives oracle source/revision change"
        );
        assert_eq!(t.h.balance(source), prior + balance);
        assert_eq!(t.h.balance(token_vault), 0);
        eprintln!(
            "MORSE_COLLATERAL_SOURCE_CHANGE assessment_refused=1 unbond=1 matured_withdraw=1"
        );
        t.h.svm = original_bank.clone();
        for kind in [2u8, 3u8] {
            t.h.svm = original_bank.clone();
            let (wire, stage) =
                collateral_proof_scenarios::prepare_kind(&mut t.h, &witnesses, kind);
            let (mut prepare, receipt) =
                t.prepare_proof(&wire, stage, &[(t.h.witness, t.h.bond), (witness, bond)]);
            prepare.data[0] = 40 + kind;
            assert!(t.send(prepare), "actual v2 proof kind {kind} prepares");
            let before = t.h.svm.get_account(&receipt).unwrap();
            assert_eq!(&before.data[..4], b"MPR\x02");
            assert_eq!(before.data[4], kind);
            assert!(t.h.send(
                &[t.h.ix(vec![signer(t.h.payer.pubkey()), rw(stage)], vec![14])],
                false
            ));
            assert!(t
                .h
                .svm
                .get_account(&stage)
                .is_none_or(|a| a.data.is_empty()));
            assert_eq!(
                t.h.svm.get_account(&receipt).unwrap(),
                before,
                "owner stage closure preserves the permanent prepared proof"
            );
            eprintln!("MORSE_COLLATERAL_KIND kind={kind} owner_close=1 permanent_receipt=1");
        }
        for kind in [1u8, 2u8, 3u8] {
            t.h.svm = original_bank.clone();
            let (wire, stage, ring, set, second) =
                collateral_proof_scenarios::prepare_anchor(&mut t.h, &witnesses, kind);
            let fork = morse_judge::fork::Fork::parse(&wire).unwrap();
            let receipt =
                Address::find_program_address(&[b"proof", &t.h.log_id, &fork.hash()], &t.h.program)
                    .0;
            assert!(t.send(t.h.ix(
                vec![
                    signer(t.h.payer.pubkey()),
                    ro(t.h.log),
                    ro(stage),
                    ro(t.h.economy),
                    ro(t.binding),
                    rw(receipt),
                    ro(Address::default()),
                    ro(directory),
                    ro(ring),
                    ro(set),
                    ro(t.h.witness),
                    ro(t.h.bond),
                    ro(witness),
                    ro(bond)
                ],
                [vec![40 + kind], second.to_vec()].concat()
            )));
            let prepared = t.h.svm.get_account(&receipt).unwrap();
            assert_eq!(prepared.data[5], 1);
            let locked = Address::find_program_address(&[b"locked", &t.h.log_id], &t.h.program).0;
            for owner in [t.h.payer.pubkey(), locked] {
                for mint in [t.h.mint, t.morse] {
                    let destination = ata(&owner, &mint);
                    assert!(t.h.send(
                        &[Instruction {
                            program_id: ATA,
                            accounts: vec![
                                signer(t.h.payer.pubkey()),
                                rw(destination),
                                ro(owner),
                                ro(mint),
                                ro(Address::default()),
                                ro(TOKEN)
                            ],
                            data: vec![1]
                        }],
                        false
                    ));
                }
            }
            assert!(t.send(t.settle_proof(
                receipt,
                &[
                    (t.h.witness, t.h.bond, t.h.vault),
                    (witness, bond, token_vault)
                ]
            )));
            let settled = t.h.svm.get_account(&receipt).unwrap();
            assert_eq!(settled.data[7], 1);
            assert!(t.h.send(
                &[t.h.ix(vec![signer(t.h.payer.pubkey()), rw(stage)], vec![14])],
                false
            ));
            assert_eq!(t.h.svm.get_account(&receipt).unwrap(), settled);
            eprintln!("MORSE_COLLATERAL_ANCHOR kind={kind} actual_set_post_cosign=1 mixed_settle=1 permanent_receipt=1");
        }
        t.h.svm = original_bank;
    }
    // Replay the actual v1-funded account in the otherwise identical local
    // not-yet-migrated branch. There is no production reverse migration.
    assert_eq!(
        &t.h.svm.get_account(&t.h.bond).unwrap().data[4..],
        &legacy_usd_snapshot.data[4..]
    );
    t.h.svm.set_account(t.h.bond, legacy_usd_snapshot).unwrap();
    let (evidence, stage) = token_fork::prepare(&mut t.h, &witnesses);
    let fork = morse_judge::fork::Fork::parse(&evidence).unwrap();
    let receipt =
        Address::find_program_address(&[b"proof", &t.h.log_id, &fork.hash()], &t.h.program).0;
    let prepare = t.h.ix(
        vec![
            signer(t.h.payer.pubkey()),
            ro(t.h.log),
            ro(stage),
            ro(t.h.economy),
            ro(t.binding),
            rw(receipt),
            ro(Address::default()),
            ro(directory),
            ro(t.h.witness),
            ro(t.h.bond),
            ro(witness),
            ro(bond),
        ],
        [
            vec![41],
            match fork.second {
                morse_judge::fork::Target::Checkpoint(cp) => {
                    morse_judge::checkpoint::Checkpoint::parse(cp)
                        .unwrap()
                        .hash()
                        .to_vec()
                }
                _ => unreachable!(),
            },
        ]
        .concat(),
    );
    let balances = [
        t.h.balance(directory_vault),
        t.h.balance(t.h.vault),
        t.h.balance(token_vault),
    ];
    let mut omitted = prepare.clone();
    omitted.accounts.truncate(omitted.accounts.len() - 2);
    assert!(!t.send(omitted));
    assert!(t.h.svm.get_account(&receipt).is_none());
    t.h.svm
        .set_account(
            receipt,
            solana_account::Account {
                lamports: 1,
                data: vec![],
                owner: Address::default(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let mut competing = prepare.clone();
    competing.accounts[0] = signer(t.h.operator.pubkey());
    assert!(
        t.h.send(&[competing], true),
        "another rent payer has no right to change the admitted finder"
    );
    assert!(
        t.send(prepare.clone()),
        "valid mixed-asset verdict preparation transfers no funds"
    );
    assert_eq!(
        [
            t.h.balance(directory_vault),
            t.h.balance(t.h.vault),
            t.h.balance(token_vault)
        ],
        balances
    );
    let prepared = t.h.svm.get_account(&receipt).unwrap();
    assert_eq!(&prepared.data[..4], b"MPR\x02");
    assert_eq!(prepared.data[7], 0);
    snapshots.push(t.snapshot(
        "mixed-proof-prepared",
        &[(witness, bond, pending)],
        Some(receipt),
    ));
    assert!(t.send(prepare.clone()));
    assert_eq!(t.h.svm.get_account(&receipt).unwrap().data, prepared.data);
    let locked = Address::find_program_address(&[b"locked", &t.h.log_id], &t.h.program).0;
    let usd_finder = ata(&t.h.payer.pubkey(), &t.h.mint);
    let token_finder = ata(&t.h.payer.pubkey(), &t.morse);
    let usd_locked = ata(&locked, &t.h.mint);
    let token_locked = ata(&locked, &t.morse);
    for (mint, destination) in [(t.h.mint, usd_locked), (t.morse, token_locked)] {
        assert!(t.send(Instruction {
            program_id: ATA,
            accounts: vec![
                signer(t.h.payer.pubkey()),
                rw(destination),
                ro(locked),
                ro(mint),
                ro(Address::default()),
                ro(TOKEN)
            ],
            data: vec![1]
        }));
    }
    let before_migration = t.settle_proof(
        receipt,
        &[
            (t.h.witness, t.h.bond, t.h.vault),
            (witness, bond, token_vault),
        ],
    );
    assert!(!t.send(before_migration));
    assert_eq!(
        [
            t.h.balance(directory_vault),
            t.h.balance(t.h.vault),
            t.h.balance(token_vault)
        ],
        balances
    );
    assert!(
        t.send(t.h.ix(
            vec![
                ro(t.h.log),
                rw(t.h.economy),
                ro(t.binding),
                rw(t.h.bond),
                ro(t.h.witness)
            ],
            vec![33, 1]
        )),
        "an intervening exact USDC schema migration preserves the prepared lifetime"
    );
    let usd_pending =
        Address::find_program_address(&[b"bond-pending", t.h.bond.as_ref()], &t.h.program).0;
    let topup = t.deposit_v2(
        (t.h.witness, t.h.bond, usd_pending, t.h.vault, t.h.source),
        0,
        7,
    );
    assert!(t.h.send(&[topup], true));
    let topup = t.deposit_v2((witness, bond, pending, token_vault, source), 1, 5);
    assert!(t.h.send(&[topup], true));
    assert!(t.h.send(
        &[Instruction {
            program_id: TOKEN,
            accounts: vec![
                rw(source),
                ro(t.morse),
                rw(token_vault),
                signer(t.h.operator.pubkey())
            ],
            data: [vec![12], 19u64.to_le_bytes().to_vec(), vec![6]].concat()
        }],
        true
    ));
    let settle = t.h.ix(
        vec![
            rw(t.h.log),
            rw(t.h.economy),
            ro(t.binding),
            rw(receipt),
            rw(directory),
            rw(directory_vault),
            ro(t.h.mint),
            rw(usd_finder),
            rw(usd_locked),
            ro(t.morse),
            rw(token_finder),
            rw(token_locked),
            ro(TOKEN),
            rw(t.h.witness),
            rw(t.h.bond),
            rw(t.h.vault),
            rw(witness),
            rw(bond),
            rw(token_vault),
        ],
        vec![44],
    );
    let usd_total = t.h.balance(directory_vault) + t.h.balance(t.h.vault);
    let usd_bounty = t.h.balance(directory_vault) / 10 + t.h.balance(t.h.vault) / 10;
    let token_total = t.h.balance(token_vault);
    let token_bounty = token_total / 10;
    let before = [
        t.h.balance(usd_finder),
        t.h.balance(usd_locked),
        t.h.balance(token_finder),
        t.h.balance(token_locked),
    ];
    let bank = t.h.svm.clone();
    // A late real SPL failure must roll back even the preceding USDC transfers.
    let mut overflow = t.h.svm.get_account(&token_locked).unwrap();
    overflow.data[64..72].copy_from_slice(&u64::MAX.to_le_bytes());
    t.h.svm.set_account(token_locked, overflow).unwrap();
    t.h.svm.expire_blockhash();
    let budget = Instruction {
        program_id: Address::from_str_const("ComputeBudget111111111111111111111111111111"),
        accounts: vec![],
        data: [vec![2], 1_000_000u32.to_le_bytes().to_vec()].concat(),
    };
    let packet = solana_transaction::Transaction::new(
        &[&t.h.payer],
        solana_message::Message::new(&[budget, settle.clone()], Some(&t.h.payer.pubkey())),
        t.h.svm.latest_blockhash(),
    );
    let failure = t.h.svm.send_transaction(packet).unwrap_err();
    let token_invocations = failure
        .meta
        .logs
        .iter()
        .filter(|line| line.starts_with(&format!("Program {TOKEN} invoke")))
        .count();
    assert!(
        token_invocations >= 6,
        "failure must reach the later MORSE CPI: {failure:?}"
    );
    eprintln!("MORSE_MIXED_LATE_CPI_ROLLBACK token_invocations={token_invocations}");
    assert_eq!(
        [
            t.h.balance(directory_vault),
            t.h.balance(t.h.vault),
            t.h.balance(token_vault)
        ],
        [balances[0], balances[1] + 7, balances[2] + 24]
    );
    assert_eq!(t.h.balance(usd_finder), before[0]);
    assert_eq!(t.h.balance(usd_locked), before[1]);
    assert_eq!(t.h.svm.get_account(&receipt).unwrap().data, prepared.data);
    t.h.svm = bank.clone();
    for index in [7usize, 8, 9, 14, 16] {
        let mut wrong = settle.clone();
        wrong.accounts[index].pubkey = Address::new_unique();
        assert!(!t.send(wrong));
        assert_eq!(t.h.svm.get_account(&receipt).unwrap().data, prepared.data);
    }
    let mut omitted = settle.clone();
    omitted.accounts.truncate(omitted.accounts.len() - 3);
    assert!(!t.send(omitted));
    // A fresh proof prepared while an already mature unbond is still held
    // cannot recover those funds after the owner finishes the permitted exit.
    let request = t.h.ix(
        vec![
            signer(t.h.operator.pubkey()),
            ro(t.h.log),
            rw(t.h.economy),
            ro(t.binding),
            rw(t.h.bond),
            ro(usd_pending),
            rw(t.h.witness),
        ],
        vec![37, 1],
    );
    assert!(t.h.send(&[request], true));
    let current = t.h.svm.get_sysvar::<Clock>().unix_timestamp;
    t.h.clock(current + morse_judge::custody::UNBOND_SECONDS);
    let (wire, staged) = token_fork::prepare(&mut t.h, &witnesses);
    let (fresh_prepare, fresh_receipt) =
        t.prepare_proof(&wire, staged, &[(t.h.witness, t.h.bond), (witness, bond)]);
    assert!(t.send(fresh_prepare));
    let withdraw = t.h.ix(
        vec![
            signer(t.h.operator.pubkey()),
            ro(t.h.log),
            rw(t.h.economy),
            ro(t.binding),
            rw(t.h.bond),
            rw(usd_pending),
            rw(t.h.vault),
            rw(t.h.source),
            ro(t.h.mint),
            ro(TOKEN),
            rw(t.h.witness),
        ],
        vec![38, 1],
    );
    assert!(t.h.send(&[withdraw], true));
    assert!(!t.send(t.settle_proof(
        fresh_receipt,
        &[
            (t.h.witness, t.h.bond, t.h.vault),
            (witness, bond, token_vault)
        ]
    )));
    assert_eq!(t.h.balance(token_vault), balances[2] + 24);
    assert_eq!(t.h.svm.get_account(&fresh_receipt).unwrap().data[7], 0);
    t.h.svm = bank.clone();
    // Another fully verified proof may settle the directory and USD witness;
    // the older prepared proof can then settle only the still-held MORSE bond.
    let now = t.h.svm.get_sysvar::<Clock>().unix_timestamp;
    t.h.clock(now + 1);
    let (wire, staged) = token_fork::prepare(&mut t.h, &witnesses[..1]);
    let (other_prepare, other_receipt) = t.prepare_proof(&wire, staged, &[(t.h.witness, t.h.bond)]);
    assert!(t.send(other_prepare));
    assert!(t.send(t.settle_proof(other_receipt, &[(t.h.witness, t.h.bond, t.h.vault)])));
    let paid_usd = [t.h.balance(usd_finder), t.h.balance(usd_locked)];
    assert!(t.send(settle.clone()));
    assert_eq!([t.h.balance(usd_finder), t.h.balance(usd_locked)], paid_usd);
    assert_eq!(t.h.balance(token_vault), 0);
    t.h.svm = bank.clone();
    // The full mixed sixteen-subject case remains one atomic financial packet.
    for (destination, amount) in [
        (usd_finder, 3_000_000_000u64),
        (t.h.source, 3_000_000_000u64),
    ] {
        assert!(t.send(Instruction {
            program_id: TOKEN,
            accounts: vec![rw(t.h.mint), rw(destination), signer(t.h.payer.pubkey())],
            data: [vec![7], amount.to_le_bytes().to_vec()].concat()
        }));
    }
    assert!(t.send(t.directory_v2(0, 3_000_000_000)));
    assert!(t.send(t.h.ix(
        vec![
            ro(t.h.log),
            rw(t.h.economy),
            ro(t.binding),
            rw(directory),
            rw(directory_pending),
            rw(directory_vault),
            ro(t.token),
            ro(pd(t.token)),
            ro(t.token_config),
            ro(t.morse),
            ro(t.oracle),
            ro(t.rewards),
            ro(pd(t.rewards)),
            ro(t.pool)
        ],
        vec![36, 0]
    )));
    let mut additional = Vec::new();
    for index in 0..14u8 {
        let id = format!("additional-{index:02}");
        let (w, b, p, v) = token_fork::register(&mut t.h, id.as_bytes(), 40 + index);
        let deposit = t.deposit_v2((w, b, p, v, t.h.source), 0, 200_000_000);
        assert!(t.h.send(&[deposit], true));
        additional.push((id, 40 + index, w, b, v));
    }
    let mut all = vec![
        (b"outside".as_slice(), 12, t.h.witness),
        (b"token-outside".as_slice(), 15, witness),
    ];
    all.extend(
        additional
            .iter()
            .map(|(id, seed, w, _, _)| (id.as_bytes(), *seed, *w)),
    );
    let (wire, staged) = token_fork::prepare(&mut t.h, &all);
    let mut target_pairs = vec![(t.h.witness, t.h.bond), (witness, bond)];
    target_pairs.extend(additional.iter().map(|(_, _, w, b, _)| (*w, *b)));
    let (max_prepare, max_receipt) = t.prepare_proof(&wire, staged, &target_pairs);
    let prepared_stats = token_fork::send_v0(&mut t.h, max_prepare).unwrap();
    let mut target_triples = vec![
        (t.h.witness, t.h.bond, t.h.vault),
        (witness, bond, token_vault),
    ];
    target_triples.extend(additional.iter().map(|(_, _, w, b, v)| (*w, *b, *v)));
    let max_settle = t.settle_proof(max_receipt, &target_triples);
    let settled_stats = token_fork::send_v0(&mut t.h, max_settle).unwrap();
    assert_eq!(settled_stats.0, 64);
    assert!(settled_stats.2 <= 1_400_000);
    assert_eq!(t.h.svm.get_account(&max_receipt).unwrap().data[7], 1);
    assert!(target_triples.iter().all(|(_, _, v)| t.h.balance(*v) == 0));
    eprintln!("MORSE_MIXED_MAXIMUM prepared={prepared_stats:?} settled={settled_stats:?}");
    let held_collateral_bank = bank.clone();
    t.h.svm = bank;
    assert!(
        t.send(settle.clone()),
        "every authenticated mixed-asset target settles in the same atomic instruction"
    );
    assert_eq!(
        [
            t.h.balance(directory_vault),
            t.h.balance(t.h.vault),
            t.h.balance(token_vault)
        ],
        [0; 3]
    );
    assert_eq!(
        [
            t.h.balance(usd_finder),
            t.h.balance(usd_locked),
            t.h.balance(token_finder),
            t.h.balance(token_locked)
        ],
        [
            before[0] + usd_bounty,
            before[1] + usd_total - usd_bounty,
            before[2] + token_bounty,
            before[3] + token_total - token_bounty
        ]
    );
    for subject in [directory, t.h.bond, bond] {
        assert_eq!(t.h.svm.get_account(&subject).unwrap().data[4], 3);
    }
    let final_policy = t.h.svm.get_account(&t.h.economy).unwrap();
    assert_eq!(&final_policy.data[148..164], &[0; 16]);
    assert_eq!(&final_policy.data[176..192], &[0; 16]);
    let final_receipt = t.h.svm.get_account(&receipt).unwrap();
    assert_eq!(final_receipt.data[7], 1);
    snapshots.push(t.snapshot(
        "mixed-proof-settled",
        &[
            (t.h.witness, t.h.bond, usd_pending),
            (witness, bond, pending),
        ],
        Some(receipt),
    ));
    assert!(!t.send(settle));
    assert_eq!(t.h.svm.get_account(&receipt).unwrap(), final_receipt);
    assert_eq!(t.h.svm.get_account(&t.h.economy).unwrap(), final_policy);
    assert!(t.send(prepare));
    let attempted = t.deposit_v2((witness, bond, pending, token_vault, source), 1, 1);
    assert!(
        !t.h.send(&[attempted], true),
        "a slashed lifetime can never activate its historical pending units"
    );
    // A separate local continuation retains collateral to qualify rewards;
    // no production instruction reverses the preceding slash branch.
    t.h.svm = held_collateral_bank;
    let reserve_profile = Address::find_program_address(&[b"reserve-config"], &t.token).0;
    let reserve_allocation = Address::find_program_address(&[b"allocation", &[4]], &t.token).0;
    let reserve_balance = t.h.balance(ata(&reserve_allocation, &t.morse));
    let reserve_configure = Instruction {
        program_id: t.token,
        accounts: vec![
            AccountMeta::new_readonly(t.h.payer.pubkey(), true),
            signer(t.h.payer.pubkey()),
            ro(t.token_config),
            ro(t.morse),
            rw(reserve_profile),
            ro(t.h.program),
            ro(pd(t.h.program)),
            ro(t.h.log),
            ro(t.h.economy),
            ro(t.binding),
            ro(t.rewards),
            ro(pd(t.rewards)),
            ro(t.pool),
            ro(t.h.mint),
            ro(t.oracle),
            ro(t.token),
            ro(pd(t.token)),
            ro(Address::default()),
        ],
        data: vec![11],
    };
    for (role, wrong) in [
        (5, t.rewards),
        (11, pd(t.token)),
        (13, t.morse),
        (16, pd(t.h.program)),
    ] {
        let mut swapped = reserve_configure.clone();
        swapped.accounts[role].pubkey = wrong;
        assert!(!t.send(swapped));
        assert!(t.h.svm.get_account(&reserve_profile).is_none());
    }
    assert!(
        t.send(reserve_configure.clone()),
        "the reserve is pinned to one authenticated judge/rewards pool before any floor funding"
    );
    let configured = t.h.svm.get_account(&reserve_profile).unwrap();
    assert_eq!(&configured.data[..4], b"MRS\x02");
    assert_eq!(&configured.data[228..260], t.pool.as_ref());
    let ready = i64::from_le_bytes(configured.data[292..300].try_into().unwrap());
    assert_eq!(
        ready,
        t.h.svm.get_sysvar::<Clock>().unix_timestamp + morse_judge::state::TIMELOCK_SECONDS
    );
    assert_eq!(
        t.h.balance(ata(&reserve_allocation, &t.morse)),
        reserve_balance
    );
    let token_member = Address::find_program_address(&[b"member", witness.as_ref()], &t.rewards).0;
    assert!(t.send(Instruction {
        program_id: t.rewards,
        accounts: vec![
            signer(t.h.payer.pubkey()),
            signer(t.h.payer.pubkey()),
            ro(t.pool),
            ro(witness),
            rw(token_member),
            ro(Address::default())
        ],
        data: vec![3, 1]
    }));
    let configured_at = t.h.svm.get_sysvar::<Clock>().unix_timestamp;
    t.h.clock(configured_at + 61);
    assert!(t.send(reserve_configure.clone()));
    assert_eq!(
        t.h.svm.get_account(&reserve_profile).unwrap().data,
        configured.data
    );
    snapshots.push(t.snapshot(
        "reserve-profile-proposed",
        &[
            (t.h.witness, t.h.bond, usd_pending),
            (witness, bond, pending),
        ],
        None,
    ));
    let pending_source = Address::new_unique();
    let stamp = t.h.svm.get_sysvar::<Clock>().unix_timestamp;
    Harness::account(&mut t.h.svm, pending_source, PYTH, source_update(stamp));
    assert!(t.send(Instruction {
        program_id: t.token,
        accounts: vec![
            signer(t.h.payer.pubkey()),
            ro(t.token_config),
            ro(t.morse),
            rw(t.oracle),
            ro(PYTH),
            ro(pending_source)
        ],
        data: [vec![6], pending_source.as_ref().to_vec(), vec![9; 32]].concat()
    }));
    let token_pool = Address::find_program_address(&[b"token-pool"], &t.rewards).0;
    let pool_morse = ata(&t.pool, &t.morse);
    assert!(t.send(Instruction {
        program_id: ATA,
        accounts: vec![
            signer(t.h.payer.pubkey()),
            rw(pool_morse),
            ro(t.pool),
            ro(t.morse),
            ro(Address::default()),
            ro(TOKEN)
        ],
        data: vec![1],
    }));
    assert!(t.h.send(
        &[solana_instruction::Instruction {
            program_id: TOKEN,
            accounts: vec![
                rw(source),
                ro(t.morse),
                rw(pool_morse),
                signer(t.h.operator.pubkey())
            ],
            data: [vec![12], 19u64.to_le_bytes().to_vec(), vec![6]].concat(),
        }],
        true
    ));
    let enable = Instruction {
        program_id: t.rewards,
        accounts: vec![
            AccountMeta::new_readonly(t.h.payer.pubkey(), true),
            signer(t.h.payer.pubkey()),
            rw(t.pool),
            rw(token_pool),
            rw(pool_morse),
            ro(t.h.program),
            ro(pd(t.h.program)),
            ro(t.h.log),
            ro(t.h.economy),
            ro(t.binding),
            ro(t.token),
            ro(pd(t.token)),
            ro(t.token_config),
            ro(t.morse),
            ro(t.oracle),
            ro(reserve_profile),
            ro(t.rewards),
            ro(pd(t.rewards)),
            ro(TOKEN),
            ro(ATA),
            ro(Address::default()),
        ],
        data: vec![13],
    };
    assert!(
        !t.send(enable.clone()),
        "reserve profile timelock cannot be bypassed"
    );
    assert!(t.h.svm.get_account(&token_pool).is_none());
    assert_eq!(&t.h.svm.get_account(&t.pool).unwrap().data[..4], b"MRP\x01");
    t.h.clock(ready);
    assert!(t.send(Instruction {
        program_id: t.rewards,
        accounts: vec![ro(t.pool), rw(token_member)],
        data: vec![4]
    }));
    assert!(
        t.send(enable.clone()),
        "versioned rewards activation preserves USD accounting"
    );
    let enabled = t.h.svm.get_account(&t.pool).unwrap();
    assert_eq!(&enabled.data[..4], b"MRP\x02");
    let companion = t.h.svm.get_account(&token_pool).unwrap();
    assert_eq!(&companion.data[..4], b"MRT\x02");
    assert_eq!(
        &companion.data[260..276],
        &[0; 16],
        "direct donations never become liabilities"
    );
    assert_eq!(t.h.balance(pool_morse), 19);
    assert_eq!(
        t.h.balance(ata(&reserve_allocation, &t.morse)),
        reserve_balance
    );
    assert!(t.send(enable.clone()));
    assert_eq!(t.h.svm.get_account(&token_pool).unwrap(), companion);
    assert_eq!(t.h.svm.get_account(&t.pool).unwrap(), enabled);
    let mut unauthorized = enable.clone();
    unauthorized.accounts[0] = signer(t.h.operator.pubkey());
    assert!(!t.h.send(&[unauthorized], true));
    let main_bank = t.h.svm.clone();
    t.h.svm = unclaimed_legacy_bank;
    assert!(t.send(reserve_configure.clone()));
    let old_profile = t.h.svm.get_account(&reserve_profile).unwrap();
    let old_ready = i64::from_le_bytes(old_profile.data[292..300].try_into().unwrap());
    t.h.clock(old_ready);
    assert!(t.send(enable.clone()));
    let old_payout = t.h.balance(payout);
    assert!(
        t.send(legacy_claim.clone()),
        "MRP2 must still pay finalized MRE1 USDC claims"
    );
    assert_eq!(t.h.balance(payout) - old_payout, 100_000_000);
    assert!(!t.send(legacy_claim));
    t.h.svm = main_bank;
    eprintln!("MORSE_REWARDS_V2_ACTIVATION legacy_claim=100000000 donation_unaccounted=19");
    let dollar_donation = t.reward_fund(1, 0, [91; 32]);
    assert!(
        t.h.send(&[dollar_donation], true),
        "MRF1 retries remain idempotent under MRP2"
    );
    let target = (ready / WEEK) as u64 + 1;
    t.observe_price_until((target + 1) as i64 * WEEK + 3600, 100);
    let next = u64::from_le_bytes(
        t.h.svm.get_account(&t.pool).unwrap().data[180..188]
            .try_into()
            .unwrap(),
    );
    let mut reward_subjects = vec![
        (t.h.witness, t.h.bond, usd_pending),
        (witness, bond, pending),
    ];
    let last_eligible = t.h.witness.max(witness);
    for index in 0..10_000 {
        if reward_subjects.len() == 64 {
            break;
        }
        let id = format!("capacity-{index:04}");
        let seed = 65 + (index % 180) as u8;
        let public = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let identity = solana_sha256_hasher::hashv(&[
            b"morse-witness-record-v1",
            &[id.len() as u8],
            id.as_bytes(),
            &public,
        ])
        .to_bytes();
        let candidate =
            Address::find_program_address(&[b"witness", &t.h.log_id, &identity], &t.h.program).0;
        if candidate >= last_eligible {
            continue;
        }
        let (w, b, p, _) = token_fork::register(&mut t.h, id.as_bytes(), seed);
        assert_eq!(w, candidate);
        reward_subjects.push((w, b, p));
    }
    assert_eq!(reward_subjects.len(), 64);
    let absent_witness = reward_subjects[2].0;
    reward_subjects.sort_by_key(|subject| subject.0);
    let paid_row = reward_subjects
        .iter()
        .position(|subject| subject.0 == t.h.witness)
        .unwrap() as u8;
    let token_paid_row = reward_subjects
        .iter()
        .position(|subject| subject.0 == witness)
        .unwrap() as u8;
    let absent_row = reward_subjects
        .iter()
        .position(|subject| subject.0 == absent_witness)
        .unwrap() as u8;
    for epoch in next..=target {
        let context = t.token_reward_context(epoch);
        let week = context[6].pubkey;
        let ledger = context[2].pubkey;
        let token_epoch = context[3].pubkey;
        assert!(t.send(t.h.ix(
            vec![
                signer(t.h.payer.pubkey()),
                ro(t.h.log),
                ro(t.clock),
                rw(week),
                ro(Address::default())
            ],
            [vec![28], epoch.to_le_bytes().to_vec()].concat()
        )));
        if epoch == target {
            let mut state = t.h.svm.get_account(&week).unwrap();
            state.data[44..52].copy_from_slice(&1u64.to_le_bytes());
            state.data[52..60].copy_from_slice(&77u64.to_le_bytes());
            state.data[60..62].copy_from_slice(&64u16.to_le_bytes());
            for (i, (w, _, _)) in reward_subjects.iter().enumerate() {
                let at = 80 + i * 40;
                state.data[at..at + 32].copy_from_slice(w.as_ref());
                state.data[at + 32..at + 40].copy_from_slice(&1u64.to_le_bytes());
            }
            t.h.svm.set_account(week, state).unwrap();
            let mut clock = t.h.svm.get_account(&t.clock).unwrap();
            clock.data[60..68].copy_from_slice(&epoch.to_le_bytes());
            clock.data[80..88].copy_from_slice(&(epoch + 1).to_le_bytes());
            clock.data[88..96].copy_from_slice(&77u64.to_le_bytes());
            t.h.svm.set_account(t.clock, clock).unwrap();
        }
        assert!(t.send(t.h.ix(vec![ro(t.h.log), rw(week)], vec![29])));
        assert!(
            t.send(Instruction {
                program_id: t.rewards,
                accounts: vec![
                    signer(t.h.payer.pubkey()),
                    ro(t.pool),
                    ro(token_pool),
                    rw(ledger),
                    rw(token_epoch),
                    ro(Address::default())
                ],
                data: [vec![14], epoch.to_le_bytes().to_vec()].concat()
            }),
            "token epochs open without reinterpreting USD revenue"
        );
        if epoch == target {
            snapshots.push(t.reward_snapshot(
                "token-rewards-open",
                epoch,
                &[
                    (t.h.witness, t.h.bond, usd_pending),
                    (witness, bond, pending),
                ],
            ));
        }
        assert!(t.send(Instruction {
            program_id: t.rewards,
            accounts: context.clone(),
            data: vec![15]
        }));
        if epoch != target {
            let reserve_before = t.h.balance(ata(&reserve_allocation, &t.morse));
            assert!(t.send(t.token_reward_finalize(epoch)));
            assert_eq!(
                t.h.balance(ata(&reserve_allocation, &t.morse)),
                reserve_before,
                "no eligible rows consume no reserve"
            );
            if epoch == next {
                snapshots.push(t.reward_snapshot(
                    "token-rewards-empty-finalized",
                    epoch,
                    &[
                        (t.h.witness, t.h.bond, usd_pending),
                        (witness, bond, pending),
                    ],
                ));
            }
            continue;
        }
        assert!(
            !t.send(t.token_reward_finalize(epoch)),
            "keeper cannot omit any attendance rows"
        );
        let mut rows = context.clone();
        for &(w, b, p) in &reward_subjects {
            rows.extend([
                ro(w),
                ro(b),
                ro(p),
                ro(Address::find_program_address(&[b"member", w.as_ref()], &t.rewards).0),
            ]);
        }
        let mut needs_assessment = false;
        for chunk in rows[19..].chunks(12) {
            let mut batch = context.clone();
            batch.extend_from_slice(chunk);
            if !t.send(Instruction {
                program_id: t.rewards,
                accounts: batch,
                data: vec![16],
            }) {
                needs_assessment = true;
                break;
            }
        }
        assert!(
            needs_assessment,
            "unrecorded MORSE grace requires an authenticated assessment"
        );
        let assessment = t.h.ix(
            vec![
                ro(t.h.log),
                rw(t.h.economy),
                ro(t.binding),
                rw(bond),
                ro(pending),
                rw(token_vault),
                ro(t.token),
                ro(pd(t.token)),
                ro(t.token_config),
                ro(t.morse),
                ro(t.oracle),
                ro(t.rewards),
                ro(pd(t.rewards)),
                ro(t.pool),
                ro(witness),
            ],
            vec![45, 1],
        );
        assert!(t.send(assessment));
        assert!(
            !t.send(t.token_reward_finalize(epoch)),
            "genuine grace transition invalidates collecting revision"
        );
        assert!(t.send(Instruction {
            program_id: t.rewards,
            accounts: context.clone(),
            data: vec![19]
        }));
        assert!(t.send(Instruction {
            program_id: t.rewards,
            accounts: context.clone(),
            data: vec![15]
        }));
        let mut first = rows[..19].to_vec();
        first.extend_from_slice(&rows[19..23]);
        assert!(t.send(Instruction {
            program_id: t.rewards,
            accounts: first,
            data: vec![16]
        }));
        let collecting_bank = t.h.svm.clone();
        snapshots.push(t.reward_snapshot(
            "token-rewards-collecting",
            epoch,
            &[
                (t.h.witness, t.h.bond, usd_pending),
                (witness, bond, pending),
            ],
        ));
        let cancellation = Instruction {
            program_id: t.rewards,
            accounts: context.clone(),
            data: vec![19],
        };
        assert!(
            !t.send(cancellation.clone()),
            "same-revision stage cannot be cheaply cancelled early"
        );
        let unbond = t.h.ix(
            vec![
                signer(t.h.operator.pubkey()),
                ro(t.h.log),
                rw(t.h.economy),
                ro(t.binding),
                rw(t.h.bond),
                ro(usd_pending),
                rw(t.h.witness),
            ],
            vec![37, 1],
        );
        assert!(t.h.send(std::slice::from_ref(&unbond), true));
        snapshots.push(t.reward_snapshot(
            "token-rewards-invalidated",
            epoch,
            &[
                (t.h.witness, t.h.bond, usd_pending),
                (witness, bond, pending),
            ],
        ));
        assert!(!t.send(t.token_reward_finalize(epoch)));
        assert!(
            t.send(cancellation.clone()),
            "eligibility change after an early append permits reset"
        );
        let reset = t.h.svm.get_account(&t.pool).unwrap();
        let old = collecting_bank.get_account(&t.pool).unwrap();
        assert_eq!(
            &reset.data[180..220],
            &old.data[180..220],
            "cancel preserves next epoch, subsidy,carry and USD liabilities/accounted"
        );
        assert_eq!(
            t.h.svm.get_account(&token_pool).unwrap(),
            collecting_bank.get_account(&token_pool).unwrap()
        );
        assert_eq!(t.h.balance(pool_morse), 19);
        t.h.svm = collecting_bank;
        let mut rest = rows[..19].to_vec();
        rest.extend_from_slice(&rows[23..]);
        for chunk in rest[19..].chunks(12) {
            let mut batch = context.clone();
            batch.extend_from_slice(chunk);
            assert!(t.send(Instruction {
                program_id: t.rewards,
                accounts: batch,
                data: vec![16]
            }));
        }
        let appended_bank = t.h.svm.clone();
        assert!(t.h.send(&[unbond], true));
        assert!(!t.send(t.token_reward_finalize(epoch)));
        assert!(
            t.send(cancellation.clone()),
            "eligibility change after final append invalidates snapshot"
        );
        t.h.svm = appended_bank.clone();
        let stamp = t.h.svm.get_sysvar::<Clock>().unix_timestamp;
        Harness::account(&mut t.h.svm, pending_source, PYTH, source_update(stamp));
        assert!(t.send(Instruction {
            program_id: t.token,
            accounts: vec![
                ro(t.token_config),
                ro(t.morse),
                rw(t.oracle),
                ro(PYTH),
                ro(pending_source)
            ],
            data: vec![7]
        }));
        assert!(
            !t.send(t.token_reward_finalize(epoch)),
            "source revision cannot change after snapshot"
        );
        snapshots.push(t.reward_snapshot(
            "token-rewards-source-changed",
            epoch,
            &[
                (t.h.witness, t.h.bond, usd_pending),
                (witness, bond, pending),
            ],
        ));
        assert!(t.send(cancellation.clone()));
        t.h.svm = appended_bank.clone();
        t.h.clock(stamp + 3600);
        snapshots.push(t.reward_snapshot(
            "token-rewards-expired",
            epoch,
            &[
                (t.h.witness, t.h.bond, usd_pending),
                (witness, bond, pending),
            ],
        ));
        assert!(
            !t.send(t.token_reward_finalize(epoch)),
            "stage expiration prevents finalization"
        );
        assert!(
            t.send(cancellation),
            "abandoned stage can be cancelled after its fixed deadline"
        );
        assert_eq!(t.h.balance(pool_morse), 19);
        // An alternative local continuation proves price-unavailable USDC
        // liveness, without pretending stale MORSE coverage is a zero-valued feed.
        t.h.svm = appended_bank.clone();
        t.h.clock(stamp + 3600);
        assert!(t.send(Instruction {
            program_id: t.rewards,
            accounts: context.clone(),
            data: vec![19]
        }));
        assert!(t.send(Instruction {
            program_id: t.rewards,
            accounts: context.clone(),
            data: vec![15]
        }));
        assert_eq!(
            &t.h.svm.get_account(&token_epoch).unwrap().data[76..84],
            &[0; 8]
        );
        for chunk in rows[19..].chunks(12) {
            let mut batch = context.clone();
            batch.extend_from_slice(chunk);
            assert!(t.send(Instruction {
                program_id: t.rewards,
                accounts: batch,
                data: vec![16]
            }));
        }
        assert!(
            !t.send(t.token_reward_finalize(epoch)),
            "missing coverage cannot pay a MORSE shortfall"
        );
        snapshots.push(t.reward_snapshot(
            "token-rewards-stale-floor-unfunded",
            epoch,
            &[
                (t.h.witness, t.h.bond, usd_pending),
                (witness, bond, pending),
            ],
        ));
        let dollar_floor = u64::from_le_bytes(
            t.h.svm.get_account(&ledger).unwrap().data[112..120]
                .try_into()
                .unwrap(),
        );
        let dollar_topup = t.reward_fund(dollar_floor - 1, 1, [93; 32]);
        assert!(t.h.send(&[dollar_topup], true));
        let reserve_before = t.h.balance(ata(&reserve_allocation, &t.morse));
        assert!(
            t.send(t.token_reward_finalize(epoch)),
            "fully funded USD earnings remain available with authenticated stale TWAP"
        );
        assert_eq!(
            t.h.balance(ata(&reserve_allocation, &t.morse)),
            reserve_before
        );
        assert_eq!(
            &t.h.svm.get_account(&token_epoch).unwrap().data[100..132],
            &[0; 32]
        );
        assert_eq!(
            u64::from_le_bytes(
                t.h.svm.get_account(&ledger).unwrap().data[144..152]
                    .try_into()
                    .unwrap()
            ),
            dollar_floor
        );
        eprintln!("MORSE_REWARDS_STALE_USD_FALLBACK floor={dollar_floor} morse=0");
        snapshots.push(t.reward_snapshot(
            "token-rewards-usdc-only-finalized",
            epoch,
            &[
                (t.h.witness, t.h.bond, usd_pending),
                (witness, bond, pending),
            ],
        ));
        t.h.svm = appended_bank;
        let revision = t.h.svm.get_account(&t.h.economy).unwrap();
        let topup = t.deposit_v2(
            (t.h.witness, t.h.bond, usd_pending, t.h.vault, t.h.source),
            0,
            1,
        );
        assert!(t.h.send(&[topup], true));
        assert_eq!(
            t.h.svm.get_account(&t.h.economy).unwrap(),
            revision,
            "one-unit pending topup cannot invalidate unchanged eligibility"
        );

        let subjects = [
            t.h.economy,
            t.h.bond,
            bond,
            directory_vault,
            t.h.vault,
            token_vault,
        ];
        let custody = subjects.map(|key| t.h.svm.get_account(&key).unwrap());
        let state_keys = [
            t.pool,
            token_pool,
            ledger,
            token_epoch,
            reserve_allocation,
            pool_morse,
            ata(&reserve_allocation, &t.morse),
        ];
        let before = state_keys.map(|key| t.h.svm.get_account(&key).unwrap());
        assert!(
            !t.send(t.token_reward_finalize(epoch)),
            "underfunded floor beyond original-supply epoch cap is atomic"
        );
        assert_eq!(
            state_keys.map(|key| t.h.svm.get_account(&key).unwrap()),
            before
        );
        snapshots.push(t.reward_snapshot(
            "token-rewards-floor-unfunded",
            epoch,
            &[
                (t.h.witness, t.h.bond, usd_pending),
                (witness, bond, pending),
            ],
        ));
        let floor = u64::from_le_bytes(before[2].data[112..120].try_into().unwrap());
        assert!(floor > 50_000_001);
        let topup = t.reward_fund(floor - 50_000_001, 1, [92; 32]);
        assert!(t.h.send(&[topup], true));
        snapshots.push(t.reward_snapshot(
            "token-rewards-ready",
            epoch,
            &[
                (t.h.witness, t.h.bond, usd_pending),
                (witness, bond, pending),
            ],
        ));
        let finalize = t.token_reward_finalize(epoch);
        for (role, wrong) in [
            (3, ledger),
            (8, t.pool),
            (10, pd(t.rewards)),
            (12, t.h.mint),
            (18, t.binding),
            (19, t.pool),
            (20, source),
            (21, token_vault),
            (22, pending),
            (24, ATA),
        ] {
            let mut substituted = finalize.clone();
            substituted.accounts[role].pubkey = wrong;
            assert!(!t.send(substituted), "wrong reserve context role {role}");
        }
        let authentic_oracle = t.h.svm.get_account(&t.oracle).unwrap();
        let mut foreign = authentic_oracle.clone();
        foreign.owner = Address::default();
        t.h.svm.set_account(t.oracle, foreign).unwrap();
        assert!(
            !t.send(finalize.clone()),
            "wrong oracle owner must never become price-unavailable fallback"
        );
        t.h.svm.set_account(t.oracle, authentic_oracle).unwrap();
        let direct_accounts = vec![
            ro(t.pool),
            ro(token_pool),
            ro(ledger),
            ro(token_epoch),
            ro(reserve_profile),
            ro(t.token_config),
            ro(t.morse),
            ro(t.oracle),
            rw(reserve_allocation),
            rw(ata(&reserve_allocation, &t.morse)),
            rw(pool_morse),
            rw(finalize.accounts[22].pubkey),
            signer(t.h.payer.pubkey()),
            ro(t.rewards),
            ro(pd(t.rewards)),
            ro(t.h.program),
            ro(pd(t.h.program)),
            ro(t.h.economy),
            ro(t.binding),
            ro(t.token),
            ro(pd(t.token)),
            ro(TOKEN),
            ro(Address::default()),
        ];
        assert!(
            !t.send(Instruction {
                program_id: t.token,
                accounts: direct_accounts,
                data: vec![12]
            }),
            "no direct caller can sign the rewards Pool PDA"
        );
        let reserve_vault = ata(&reserve_allocation, &t.morse);
        let reserve_source = t.h.svm.get_account(&reserve_vault).unwrap();
        let mut insufficient = reserve_source.clone();
        insufficient.data[64..72].copy_from_slice(&1u64.to_le_bytes());
        t.h.svm
            .set_account(reserve_vault, insufficient.clone())
            .unwrap();
        let receipt_key = finalize.accounts[22].pubkey;
        t.h.svm.airdrop(&receipt_key, 1_000_000).unwrap();
        let prefunded = t.h.svm.get_account(&receipt_key).unwrap();
        let late_keys = [
            t.pool,
            token_pool,
            ledger,
            token_epoch,
            reserve_allocation,
            pool_morse,
        ];
        let late_before = late_keys.map(|key| t.h.svm.get_account(&key).unwrap());
        let instruction = t.prepared_instruction(finalize.clone());
        t.h.svm.expire_blockhash();
        let budget = Instruction {
            program_id: Address::from_str_const("ComputeBudget111111111111111111111111111111"),
            accounts: vec![],
            data: [vec![2], 1_000_000u32.to_le_bytes().to_vec()].concat(),
        };
        let packet = solana_transaction::Transaction::new(
            &[&t.h.payer],
            solana_message::Message::new(&[budget, instruction], Some(&t.h.payer.pubkey())),
            t.h.svm.latest_blockhash(),
        );
        let failure = t.h.svm.send_transaction(packet).unwrap_err();
        let token_invocations = failure
            .meta
            .logs
            .iter()
            .filter(|line| line.starts_with(&format!("Program {TOKEN} invoke")))
            .count();
        assert!(
            token_invocations > 0,
            "reserve rejection must reach the actual SPL transfer: {failure:?}"
        );
        assert_eq!(
            late_keys.map(|key| t.h.svm.get_account(&key).unwrap()),
            late_before
        );
        assert_eq!(
            t.h.svm.get_account(&receipt_key).unwrap(),
            prefunded,
            "late token failure restores prefunded receipt and all rent transfer/accounting"
        );
        assert_eq!(t.h.svm.get_account(&reserve_vault).unwrap(), insufficient);
        t.h.svm.set_account(reserve_vault, reserve_source).unwrap();
        eprintln!("MORSE_REWARDS_RESERVE_LATE_CPI token_invocations={token_invocations} prefunded_receipt_restored=1");
        let reserve_before = t.h.balance(ata(&reserve_allocation, &t.morse));
        let stage_time = t.h.svm.get_sysvar::<Clock>().unix_timestamp;
        t.h.clock(stage_time + 61);
        assert!(
            t.send(t.token_reward_finalize(epoch)),
            "real reserve CPI covers only USD floor shortfall"
        );
        assert_eq!(
            reserve_before - t.h.balance(ata(&reserve_allocation, &t.morse)),
            500_000_000_000
        );
        let final_usd = t.h.svm.get_account(&ledger).unwrap();
        let final_token = t.h.svm.get_account(&token_epoch).unwrap();
        assert_eq!(
            u64::from_le_bytes(final_usd.data[144..152].try_into().unwrap()),
            floor - 50_000_000
        );
        assert_eq!(
            u64::from_le_bytes(final_token.data[100..108].try_into().unwrap()),
            50_000_000
        );
        assert_eq!(
            u64::from_le_bytes(final_token.data[108..116].try_into().unwrap()),
            500_000_000_000
        );
        assert_eq!(t.h.balance(pool_morse), 500_000_000_019);
        assert_eq!(
            subjects.map(|key| t.h.svm.get_account(&key).unwrap()),
            custody,
            "reward funding cannot touch judge custody"
        );
        assert!(!t.send(t.token_reward_finalize(epoch)));
        snapshots.push(t.reward_snapshot(
            "token-rewards-finalized",
            epoch,
            &[
                (t.h.witness, t.h.bond, usd_pending),
                (witness, bond, pending),
            ],
        ));
        let payout_morse = ata(&t.h.payer.pubkey(), &t.morse);
        let payout_before = t.h.balance(payout_morse);
        let token_claim = Instruction {
            program_id: t.rewards,
            accounts: vec![
                ro(t.pool),
                rw(token_pool),
                ro(ledger),
                rw(token_epoch),
                rw(pool_morse),
                rw(payout_morse),
                ro(t.morse),
                ro(TOKEN),
            ],
            data: vec![18, paid_row],
        };
        let existing_payout_bank = t.h.svm.clone();
        t.h.svm
            .set_account(payout_morse, solana_account::Account::default())
            .unwrap();
        assert!(
            !t.send(token_claim.clone()),
            "missing registered payout ATA cannot redirect a claim"
        );
        let setup = Instruction {
            program_id: ATA,
            accounts: vec![
                signer(t.h.payer.pubkey()),
                rw(payout_morse),
                ro(t.h.payer.pubkey()),
                ro(t.morse),
                ro(Address::default()),
                ro(TOKEN),
            ],
            data: vec![1],
        };
        assert!(t.send(setup));
        assert!(t.send(token_claim.clone()));
        assert!(!t.send(token_claim.clone()));
        t.h.svm = existing_payout_bank;
        let mut wrong = token_claim.clone();
        wrong.accounts[5].pubkey = source;
        assert!(!t.send(wrong));
        let request = t.h.ix(
            vec![
                signer(t.h.operator.pubkey()),
                ro(t.h.log),
                rw(t.h.economy),
                ro(t.binding),
                rw(t.h.bond),
                ro(usd_pending),
                rw(t.h.witness),
            ],
            vec![37, 1],
        );
        assert!(t.h.send(&[request], true));
        assert!(
            t.send(token_claim.clone()),
            "later unbond cannot revoke finalized entitlement"
        );
        let row_amount = u64::from_le_bytes(
            final_token.data[256 + paid_row as usize * 16 + 8..256 + paid_row as usize * 16 + 16]
                .try_into()
                .unwrap(),
        );
        assert_eq!(t.h.balance(payout_morse) - payout_before, row_amount);
        let mut other = token_claim.clone();
        other.data[1] = token_paid_row;
        assert!(t.send(other.clone()));
        assert!(!t.send(other));
        assert_eq!(t.h.balance(payout_morse) - payout_before, 500_000_000_000);
        assert_eq!(t.h.balance(pool_morse), 19);
        assert_eq!(
            &t.h.svm.get_account(&token_pool).unwrap().data[260..276],
            &[0; 16]
        );
        assert!(!t.send(token_claim));
        let existing_usdc_payout_bank = t.h.svm.clone();
        t.h.svm
            .set_account(payout, solana_account::Account::default())
            .unwrap();
        let usd_claim = Instruction {
            program_id: t.rewards,
            accounts: vec![
                rw(t.pool),
                rw(ledger),
                rw(ata(&t.pool, &t.h.mint)),
                rw(payout),
                ro(t.h.mint),
                ro(TOKEN),
            ],
            data: vec![8, paid_row],
        };
        assert!(!t.send(usd_claim.clone()));
        assert!(t.send(Instruction {
            program_id: ATA,
            accounts: vec![
                signer(t.h.payer.pubkey()),
                rw(payout),
                ro(t.h.payer.pubkey()),
                ro(t.h.mint),
                ro(Address::default()),
                ro(TOKEN)
            ],
            data: vec![1]
        }));
        assert!(t.send(usd_claim.clone()));
        assert!(!t.send(usd_claim));
        t.h.svm = existing_usdc_payout_bank;
        let usd_before = t.h.balance(payout);
        for row in [paid_row, token_paid_row] {
            let claim = Instruction {
                program_id: t.rewards,
                accounts: vec![
                    rw(t.pool),
                    rw(ledger),
                    rw(ata(&t.pool, &t.h.mint)),
                    rw(payout),
                    ro(t.h.mint),
                    ro(TOKEN),
                ],
                data: vec![8, row],
            };
            assert!(t.send(claim.clone()));
            assert!(!t.send(claim));
        }
        assert_eq!(t.h.balance(payout) - usd_before, floor - 50_000_000);
        assert_eq!(
            &t.h.svm.get_account(&t.pool).unwrap().data[204..220],
            &[0; 16]
        );
        {
            let row = absent_row;
            assert!(!t.send(Instruction {
                program_id: t.rewards,
                accounts: vec![
                    ro(t.pool),
                    rw(token_pool),
                    ro(ledger),
                    rw(token_epoch),
                    rw(pool_morse),
                    rw(payout_morse),
                    ro(t.morse),
                    ro(TOKEN)
                ],
                data: vec![18, row]
            }));
        }
        assert_eq!(
            paid_row.max(token_paid_row),
            63,
            "highest replay bit belongs to a paid snapshot row"
        );
        let claims = t.h.svm.get_account(&token_epoch).unwrap();
        assert_ne!(
            u64::from_le_bytes(claims.data[116..124].try_into().unwrap()) & (1u64 << 63),
            0
        );
        snapshots.push(t.reward_snapshot(
            "token-rewards-claimed",
            epoch,
            &[
                (t.h.witness, t.h.bond, usd_pending),
                (witness, bond, pending),
            ],
        ));
        eprintln!("MORSE_REWARDS_RESERVE gap=50000000 morse=500000000000 untouched_donation=19 attendance_rows=64 paid_bit63=1");
    }
    if !t.replay_instructions.is_empty() {
        for tag in [1, 8, 11, 13, 14, 15, 16, 17, 18, 19] {
            assert!(
                t.replayed_tags[tag] > 0,
                "compiled Mesh instruction tag {tag} did not reach actual SBF"
            );
        }
        eprintln!("MORSE_TOKEN_MESH_WRITE_REPLAY {:?}", t.replayed_tags);
    }
    if std::env::var_os("MORSE_PUBLIC_HISTORY_JUDGE_EXPORT").is_some() {
        public_history_index::export(
            &t.h.svm,
            &[t.h.program, t.token, t.rewards],
            t.snapshot(
                "public-history-final-bank",
                &[
                    (t.h.witness, t.h.bond, usd_pending),
                    (witness, bond, pending),
                ],
                None,
            ),
            "MORSE_PUBLIC_HISTORY_JUDGE_EXPORT",
        );
    }
    if let Ok(path) = std::env::var("MORSE_TOKEN_CUSTODY_FIXTURES_PATH") {
        let write_vectors =
            t.reward_write_vectors(target, &reward_subjects, &reserve_configure, &enable);
        std::fs::write(path,serde_json::to_vec_pretty(&serde_json::json!({"schema_version":2,"scope":"actual-local-sbf-collateral-mixed-proof-and-token-rewards","snapshots":snapshots,"write_vectors":write_vectors})).unwrap()).unwrap();
    }
}

#[test]
fn obsolete_upload_owner_can_close_after_withdrawal_without_current_oracle_or_binding() {
    let mut t = TokenHarness::new();
    assert!(t.send(t.binding_instruction(31)));
    let owner = t.h.operator.pubkey();
    let bytes = b"retired-unsupported-fork-format-owned-cleanup";
    let digest = hash(bytes);
    let stage =
        Address::find_program_address(&[b"stage", owner.as_ref(), digest.as_ref()], &t.h.program).0;
    assert!(t.h.send(
        &[t.h.ix(
            vec![
                signer(owner),
                ro(t.h.log),
                rw(stage),
                ro(Address::default())
            ],
            [
                vec![10],
                (bytes.len() as u16).to_le_bytes().to_vec(),
                digest.as_ref().to_vec()
            ]
            .concat()
        )],
        true
    ));
    assert!(t.h.send(
        &[t.h.ix(
            vec![signer(owner), rw(stage)],
            [vec![11, 0, 0], bytes.to_vec()].concat()
        )],
        true
    ));
    assert!(
        !t.h.send(
            &[t.h.ix(vec![signer(owner), ro(t.h.log), rw(stage)], vec![12])],
            true
        ),
        "unsupported staged wire cannot seal"
    );
    assert!(t.h.send(&[t.h.request()], true));
    t.h.clock(t.h.svm.get_sysvar::<Clock>().unix_timestamp + 40 * 86400);
    assert!(t.h.send(&[t.h.withdraw(t.h.source)], true));
    assert_eq!(t.h.svm.get_account(&t.h.bond).unwrap().data[4], 4);
    let before = t.h.svm.get_account(&stage).unwrap();
    assert!(
        !t.h.send(
            &[t.h.ix(vec![signer(t.h.payer.pubkey()), rw(stage)], vec![14])],
            false
        ),
        "governance/fee payer cannot close somebody else's upload"
    );
    assert_eq!(t.h.svm.get_account(&stage).unwrap(), before);
    assert!(
        t.h.send(&[t.h.ix(vec![signer(owner), rw(stage)], vec![14])], true),
        "stale oracle/withdrawn bond/obsolete bytes cannot trap owner stage rent"
    );
    assert!(t
        .h
        .svm
        .get_account(&stage)
        .is_none_or(|a| a.data.is_empty()));
    eprintln!("MORSE_OWNER_STAGE_CLOSE unsupported_wire=1 withdrawn_witness=1 oracle_stale_40d=1 governance_refused=1 distinct_fee_payer=1 owner_only=1");
}

#[test]
fn fresh_readonly_bonds_v2_snapshots() {
    let now = std::env::var("MORSE_BONDS_FIXTURE_NOW")
        .unwrap()
        .parse::<i64>()
        .unwrap();
    let span = 3 * WEEK + morse_judge::state::TIMELOCK_SECONDS;
    let aligned = now / 3600 * 3600;
    let mut t = TokenHarness::new_at(aligned - span);
    let mut snapshots = Vec::new();
    let legacy_pending =
        Address::find_program_address(&[b"bond-pending", t.h.bond.as_ref()], &t.h.program).0;
    snapshots.push(t.snapshot(
        "legacy-v1",
        &[(t.h.witness, t.h.bond, legacy_pending)],
        None,
    ));
    assert!(t.send(t.binding_instruction(31)));
    t.observe_until(aligned);
    let current = (aligned / WEEK) as u64;
    for epoch in (t.started / WEEK + 1) as u64..current {
        t.drain_week(epoch, false);
    }
    assert!(t.send(t.binding_instruction(32)));
    t.observe_until(now);
    snapshots.push(t.snapshot(
        "v2-context-legacy-rows",
        &[(t.h.witness, t.h.bond, legacy_pending)],
        None,
    ));
    let directory =
        Address::find_program_address(&[b"bond", &t.h.log_id, b"directory"], &t.h.program).0;
    assert!(t.send(t.h.ix(
        vec![
            ro(t.h.log),
            rw(t.h.economy),
            ro(t.binding),
            rw(t.h.bond),
            ro(t.h.witness)
        ],
        vec![33, 1]
    )));
    assert!(t.send(t.h.ix(
        vec![ro(t.h.log), rw(t.h.economy), ro(t.binding), rw(directory)],
        vec![33, 0]
    )));
    let (witness, bond, pending, vault, source) = t.token_witness();
    assert!(t.h.send(
        &[t.deposit_v2((witness, bond, pending, vault, source), 1, 50_000_000)],
        true
    ));
    snapshots.push(t.snapshot(
        "fresh-active-mixed",
        &[
            (t.h.witness, t.h.bond, legacy_pending),
            (witness, bond, pending),
        ],
        None,
    ));
    assert!(t.h.send(
        &[t.deposit_v2((witness, bond, pending, vault, source), 1, 1)],
        true
    ));
    snapshots.push(t.snapshot(
        "fresh-pending-mixed",
        &[
            (t.h.witness, t.h.bond, legacy_pending),
            (witness, bond, pending),
        ],
        None,
    ));
    assert_eq!(t.h.balance(vault), 50_000_018);
    let path = std::env::var("MORSE_BONDS_FIXTURE_OUTPUT").unwrap();
    std::fs::write(path,serde_json::to_vec_pretty(&serde_json::json!({"schema_version":1,"scope":"fresh-owned-sbf-readonly-cli-qualification","clock_basis":"explicit coherent owned SBF base; no production clock override","snapshots":snapshots})).unwrap()).unwrap();
}
