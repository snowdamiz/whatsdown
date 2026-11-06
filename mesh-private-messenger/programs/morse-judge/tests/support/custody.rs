//! Real token CPIs and SBF execution; all wallets/mints are disposable fixtures.
#[path = "collateral_operator.rs"]
pub(super) mod collateral_operator;
use ed25519_dalek::SigningKey;
use litesvm::LiteSVM;
use morse_judge::state::{CONFIG_LEN, LOG_LEN};
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

pub const TOKEN: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const ATA: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const UNBOND: i64 = 30 * 24 * 60 * 60;
pub fn ro(key: Address) -> AccountMeta {
    AccountMeta::new_readonly(key, false)
}
pub fn rw(key: Address) -> AccountMeta {
    AccountMeta::new(key, false)
}
pub fn signer(key: Address) -> AccountMeta {
    AccountMeta::new(key, true)
}
pub fn ata(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()], &ATA).0
}
pub struct Harness {
    pub svm: LiteSVM,
    pub payer: Keypair,
    pub operator: Keypair,
    pub program: Address,
    pub config: Address,
    pub log: Address,
    pub log_id: [u8; 32],
    pub mint: Address,
    pub economy: Address,
    pub source: Address,
    pub witness: Address,
    pub bond: Address,
    pub vault: Address,
}
impl Harness {
    pub fn new() -> Self {
        Self::with_keys(Keypair::new(), Keypair::new())
    }
    /// Disposable deterministic keys are used only by cross-language SBF replay.
    pub fn with_keys(payer: Keypair, operator: Keypair) -> Self {
        let mut svm = LiteSVM::new();
        let program = Address::new_unique();
        svm.airdrop(&payer.pubkey(), 20_000_000_000).unwrap();
        svm.airdrop(&operator.pubkey(), 20_000_000_000).unwrap();
        svm.add_program_from_file(
            program,
            std::env::var_os("MORSE_JUDGE_SBF_PATH").map_or_else(
                || {
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../target/deploy/morse_judge.so")
                },
                PathBuf::from,
            ),
        )
        .expect("build judge SBF");
        let config = Address::find_program_address(&[b"config"], &program).0;
        let mut data = vec![0; CONFIG_LEN];
        data[..4].copy_from_slice(b"MCF\x01");
        data[4..36].copy_from_slice(payer.pubkey().as_ref());
        Self::account(&mut svm, config, program, data);
        // An explicit fixture-only selector creates genuine morse-main PDA/account
        // state. Unset preserves every existing custody/replay corpus.
        let counter_name = std::env::var("MORSE_NETWORK_COUNTER_FIXTURE_LOG").ok();
        let name: &[u8] = match counter_name.as_deref() {
            None => b"custody-test",
            Some("morse-main") => b"morse-main",
            Some(_) => panic!("network counter fixture log must be exactly morse-main"),
        };
        let log_id = hash(name).to_bytes();
        let log = Address::find_program_address(&[b"log", name], &program).0;
        let ring = Address::find_program_address(&[b"ring", name], &program).0;
        let mut data = vec![0; LOG_LEN];
        data[..4].copy_from_slice(b"MLG\x01");
        data[4] = 1;
        data[6] = name.len() as u8;
        data[8..8 + name.len()].copy_from_slice(name);
        data[40..72].copy_from_slice(&log_id);
        data[72..104]
            .copy_from_slice(&SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes());
        data[104..136].copy_from_slice(payer.pubkey().as_ref());
        data[136..168].copy_from_slice(ring.as_ref());
        Self::account(&mut svm, log, program, data);
        let id = b"outside";
        let key = SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes();
        let identity = hashv(&[b"morse-witness-record-v1", &[id.len() as u8], id, &key]);
        let witness =
            Address::find_program_address(&[b"witness", &log_id, identity.as_ref()], &program).0;
        let mut data = vec![0; 320];
        data[..4].copy_from_slice(b"MWI\x01");
        data[4] = id.len() as u8;
        data[8..8 + id.len()].copy_from_slice(id);
        data[72..104].copy_from_slice(&key);
        data[104..136].copy_from_slice(operator.pubkey().as_ref());
        data[136..168].copy_from_slice(payer.pubkey().as_ref());
        data[200..232].copy_from_slice(&log_id);
        Self::account(&mut svm, witness, program, data);
        let mint = Address::new_unique();
        Self::account(&mut svm, mint, TOKEN, vec![0; 82]);
        let economy = Address::find_program_address(&[b"economics", &log_id], &program).0;
        let source = ata(&operator.pubkey(), &mint);
        let bond =
            Address::find_program_address(&[b"bond", &log_id, identity.as_ref()], &program).0;
        let vault = ata(&bond, &mint);
        let mut h = Self {
            svm,
            payer,
            operator,
            program,
            config,
            log,
            log_id,
            mint,
            economy,
            source,
            witness,
            bond,
            vault,
        };
        let initialize = Instruction {
            program_id: TOKEN,
            accounts: vec![rw(mint)],
            data: [vec![20, 6], h.payer.pubkey().as_ref().to_vec(), vec![0]].concat(),
        };
        let create = Instruction {
            program_id: ATA,
            accounts: vec![
                signer(h.payer.pubkey()),
                rw(source),
                ro(h.operator.pubkey()),
                ro(mint),
                ro(Address::default()),
                ro(TOKEN),
            ],
            data: vec![1],
        };
        let mint_to = Instruction {
            program_id: TOKEN,
            accounts: vec![rw(mint), rw(source), signer(h.payer.pubkey())],
            data: [vec![7], 1_000_000_000u64.to_le_bytes().to_vec()].concat(),
        };
        assert!(h.send(&[initialize, create, mint_to], false));
        let source = ata(&h.payer.pubkey(), &h.mint);
        let create = Instruction {
            program_id: ATA,
            accounts: vec![
                signer(h.payer.pubkey()),
                rw(source),
                ro(h.payer.pubkey()),
                ro(h.mint),
                ro(Address::default()),
                ro(TOKEN),
            ],
            data: vec![1],
        };
        let mint = Instruction {
            program_id: TOKEN,
            accounts: vec![rw(h.mint), rw(source), signer(h.payer.pubkey())],
            data: [vec![7], 500_000_000u64.to_le_bytes().to_vec()].concat(),
        };
        assert!(h.send(&[create, mint], false));
        h
    }
    pub fn account(svm: &mut LiteSVM, address: Address, owner: Address, data: Vec<u8>) {
        svm.set_account(
            address,
            Account {
                lamports: svm.minimum_balance_for_rent_exemption(data.len()),
                data,
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }
    pub fn send(&mut self, instructions: &[Instruction], operator: bool) -> bool {
        let observation = collateral_operator::begin(self, instructions);
        let replay = observation
            .as_ref()
            .map(|value| value.instructions.as_slice());
        let instructions = replay.unwrap_or(instructions);
        self.svm.expire_blockhash();
        let mut keys = vec![&self.payer];
        if operator {
            keys.push(&self.operator);
        }
        let tx = Transaction::new(
            &keys,
            Message::new(instructions, Some(&self.payer.pubkey())),
            self.svm.latest_blockhash(),
        );
        assert!(bincode::serialize(&tx).unwrap().len() <= 1232);
        let success = match self.svm.send_transaction(tx) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("refusal {:?}", e.err);
                false
            }
        };
        if let Some(value) = observation {
            collateral_operator::finish(self, value, success);
        }
        success
    }
    pub fn ix(&self, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
        Instruction {
            program_id: self.program,
            accounts,
            data,
        }
    }
    pub fn configure(&self) -> Instruction {
        self.ix(
            vec![
                signer(self.payer.pubkey()),
                signer(self.payer.pubkey()),
                ro(self.config),
                ro(self.log),
                rw(self.economy),
                ro(self.mint),
                ro(Address::default()),
            ],
            [
                vec![15],
                100_000_000u64.to_le_bytes().to_vec(),
                500_000_000u64.to_le_bytes().to_vec(),
                self.payer.pubkey().as_ref().to_vec(),
            ]
            .concat(),
        )
    }
    pub fn clock(&mut self, now: i64) {
        let mut clock = self.svm.get_sysvar::<Clock>();
        clock.unix_timestamp = now;
        self.svm.set_sysvar(&clock);
    }
    pub fn deposit(&self, amount: u64) -> Instruction {
        self.ix(
            vec![
                signer(self.operator.pubkey()),
                ro(self.log),
                rw(self.economy),
                rw(self.witness),
                rw(self.bond),
                rw(self.vault),
                rw(self.source),
                ro(self.mint),
                ro(TOKEN),
                ro(ATA),
                ro(Address::default()),
            ],
            [vec![18], amount.to_le_bytes().to_vec()].concat(),
        )
    }
    pub fn directory_deposit(&self) -> Instruction {
        let source = ata(&self.payer.pubkey(), &self.mint);
        let bond =
            Address::find_program_address(&[b"bond", &self.log_id, b"directory"], &self.program).0;
        let vault = ata(&bond, &self.mint);
        self.ix(
            vec![
                signer(self.payer.pubkey()),
                signer(self.payer.pubkey()),
                ro(self.config),
                rw(self.log),
                rw(self.economy),
                rw(bond),
                rw(vault),
                rw(source),
                ro(self.mint),
                ro(TOKEN),
                ro(ATA),
                ro(Address::default()),
            ],
            [vec![19], 500_000_000u64.to_le_bytes().to_vec()].concat(),
        )
    }
    pub fn fund_directory(&mut self) {
        assert!(self.send(&[self.directory_deposit()], false));
    }
    pub fn request(&self) -> Instruction {
        self.ix(
            vec![
                signer(self.operator.pubkey()),
                ro(self.log),
                rw(self.witness),
                rw(self.bond),
                rw(self.economy),
            ],
            vec![20, 1],
        )
    }
    pub fn withdraw(&self, destination: Address) -> Instruction {
        self.ix(
            vec![
                signer(self.operator.pubkey()),
                ro(self.log),
                rw(self.economy),
                rw(self.witness),
                rw(self.bond),
                rw(self.vault),
                rw(destination),
                ro(self.mint),
                ro(TOKEN),
            ],
            vec![21, 1],
        )
    }
    pub fn snapshot(&self, label: &str, expected: serde_json::Value) -> serde_json::Value {
        let directory_bond =
            Address::find_program_address(&[b"bond", &self.log_id, b"directory"], &self.program).0;
        let directory_vault = ata(&directory_bond, &self.mint);
        let addresses = [
            self.log,
            self.economy,
            self.mint,
            directory_bond,
            directory_vault,
            self.witness,
            self.bond,
            self.vault,
        ];
        let accounts: Vec<_> = addresses
            .iter()
            .map(|address| {
                let account = self.svm.get_account(address).unwrap();
                serde_json::json!({
                    "address":address.to_string(), "data_hex":hex::encode(account.data),
                    "owner":account.owner.to_string(), "lamports":account.lamports.to_string(),
                    "executable":account.executable,
                })
            })
            .collect();
        serde_json::json!({
            "name": label, "program": self.program.to_string(), "log_id": hex::encode(self.log_id),
            "log_name":"custody-test", "accounts":accounts,
            "service_key":hex::encode(SigningKey::from_bytes(&[11;32]).verifying_key().to_bytes()),
            "mint": self.mint.to_string(), "witness_id": "outside",
            "signing_key": hex::encode(SigningKey::from_bytes(&[12;32]).verifying_key().to_bytes()),
            "economics_address": self.economy.to_string(), "bond_address": self.bond.to_string(),
            "vault_address": self.vault.to_string(),
            "economics_hex": hex::encode(self.svm.get_account(&self.economy).unwrap().data),
            "bond_hex": hex::encode(self.svm.get_account(&self.bond).unwrap().data),
            "expected": expected,
        })
    }
    pub fn balance(&self, address: Address) -> u64 {
        self.svm.get_account(&address).map_or(0, |a| {
            u64::from_le_bytes(a.data[64..72].try_into().unwrap())
        })
    }
}
