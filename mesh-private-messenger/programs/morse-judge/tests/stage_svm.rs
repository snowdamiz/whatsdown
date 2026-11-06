//! Exercise the deployed SBF program, real transactions, and Ed25519 precompiles.
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use litesvm::LiteSVM;
use morse_judge::{
    checkpoint::Checkpoint,
    fork::{Fork, Target},
    state::LOG_LEN,
};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_sha256_hasher::{hash, hashv};
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::{path::PathBuf, str::FromStr};

const HEADER: usize = 1152;
fn ro(key: Address) -> AccountMeta {
    AccountMeta::new_readonly(key, false)
}
fn rw(key: Address) -> AccountMeta {
    AccountMeta::new(key, false)
}
fn signer(key: Address) -> AccountMeta {
    AccountMeta::new(key, true)
}
fn instructions() -> AccountMeta {
    ro(Address::from_str("Sysvar1nstructions1111111111111111111111111").unwrap())
}
fn oracle(name: &str) -> Vec<u8> {
    let root: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/fork-v1/vectors.json")).unwrap();
    let case = root["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap();
    hex::decode(case["wire_hex"].as_str().unwrap()).unwrap()
}
fn ed(key: &[u8], signature: &[u8], message: &[u8]) -> Instruction {
    let mut data = vec![1, 0];
    for n in [
        48u16,
        u16::MAX,
        16,
        u16::MAX,
        112,
        message.len() as u16,
        u16::MAX,
    ] {
        data.extend_from_slice(&n.to_le_bytes());
    }
    data.extend_from_slice(key);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    Instruction {
        program_id: Address::from_str("Ed25519SigVerify111111111111111111111111111").unwrap(),
        accounts: vec![],
        data,
    }
}
struct Harness {
    svm: LiteSVM,
    payer: Keypair,
    outsider: Keypair,
    program: Address,
    log: Address,
    log_id: [u8; 32],
}
impl Harness {
    fn new() -> Self {
        Self::with_identity(Address::new_unique(), Keypair::new())
    }
    fn with_identity(program: Address, payer: Keypair) -> Self {
        let mut svm = LiteSVM::new();
        let outsider = Keypair::new();
        svm.airdrop(&payer.pubkey(), 20_000_000_000).unwrap();
        svm.airdrop(&outsider.pubkey(), 20_000_000_000).unwrap();
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
        // The separate anchor SBF suite covers actual registration/governance.
        // Here a correctly registered immutable legacy log isolates stage abuse.
        let name = b"stage-test";
        let log = Address::find_program_address(&[b"log", name], &program).0;
        let log_id = hash(name).to_bytes();
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
        svm.set_account(
            log,
            Account {
                lamports: svm.minimum_balance_for_rent_exemption(data.len()),
                data,
                owner: program,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
        Self {
            svm,
            payer,
            outsider,
            program,
            log,
            log_id,
        }
    }
    fn ix(&self, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
        Instruction {
            program_id: self.program,
            accounts,
            data,
        }
    }
    fn send(&mut self, ixs: &[Instruction]) -> bool {
        self.svm.expire_blockhash();
        let tx = Transaction::new(
            &[&self.payer],
            Message::new(ixs, Some(&self.payer.pubkey())),
            self.svm.latest_blockhash(),
        );
        assert!(
            bincode::serialize(&tx).unwrap().len() <= 1232,
            "each stage transaction must fit the network packet"
        );
        match self.svm.send_transaction(tx) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("refusal {:?}", e.err);
                false
            }
        }
    }
    fn stage(&self, wire: &[u8]) -> Address {
        Address::find_program_address(
            &[b"stage", self.payer.pubkey().as_ref(), hash(wire).as_ref()],
            &self.program,
        )
        .0
    }
    fn init(&self, wire: &[u8]) -> Instruction {
        self.ix(
            vec![
                signer(self.payer.pubkey()),
                ro(self.log),
                rw(self.stage(wire)),
                ro(Address::default()),
            ],
            [
                vec![10],
                (wire.len() as u16).to_le_bytes().to_vec(),
                hash(wire).as_ref().to_vec(),
            ]
            .concat(),
        )
    }
    fn append(&self, stage: Address, offset: usize, bytes: &[u8]) -> Instruction {
        self.ix(
            vec![signer(self.payer.pubkey()), rw(stage)],
            [
                vec![11],
                (offset as u16).to_le_bytes().to_vec(),
                bytes.to_vec(),
            ]
            .concat(),
        )
    }
    fn seal(&self, stage: Address) -> Instruction {
        self.ix(
            vec![signer(self.payer.pubkey()), ro(self.log), rw(stage)],
            vec![12],
        )
    }
    fn load(&mut self, wire: &[u8]) -> Address {
        let stage = self.stage(wire);
        assert!(self.send(&[self.init(wire)]));
        for (index, bytes) in wire.chunks(900).enumerate() {
            assert!(self.send(&[self.append(stage, index * 900, bytes)]));
        }
        assert!(self.send(&[self.seal(stage)]));
        stage
    }
    fn verify(&self, stage: Address, ordinal: u8, witness: Option<Address>) -> Instruction {
        let mut accounts = vec![ro(self.log), rw(stage), instructions()];
        if let Some(witness) = witness {
            accounts.push(ro(witness));
            accounts.push(signer(self.payer.pubkey()));
        }
        self.ix(accounts, vec![13, ordinal, 0, 0])
    }
    fn witness(&mut self, id: &[u8], key: &[u8]) -> Address {
        let identity = hashv(&[b"morse-witness-record-v1", &[id.len() as u8], id, key]);
        let address = Address::find_program_address(
            &[b"witness", &self.log_id, identity.as_ref()],
            &self.program,
        )
        .0;
        let mut data = vec![0; 320];
        data[..4].copy_from_slice(b"MWI\x01");
        data[4] = id.len() as u8;
        data[8..8 + id.len()].copy_from_slice(id);
        data[72..104].copy_from_slice(key);
        data[104..136].copy_from_slice(self.payer.pubkey().as_ref());
        data[136..168].copy_from_slice(self.payer.pubkey().as_ref());
        data[200..232].copy_from_slice(&self.log_id);
        self.svm
            .set_account(
                address,
                Account {
                    lamports: self.svm.minimum_balance_for_rent_exemption(320),
                    data,
                    owner: self.program,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        address
    }
    fn bits(&self, stage: Address) -> u64 {
        u64::from_le_bytes(
            self.svm.get_account(&stage).unwrap().data[112..120]
                .try_into()
                .unwrap(),
        )
    }
}

// Run explicitly after Mesh has generated fresh plans. The ordinary Rust-only
// gate cannot produce these application bytes; CI carries this test executable
// alongside its SBF artifact into the Mesh job.
#[test]
#[ignore = "requires fresh Mesh relay stage plans; run scripts/prove-relay-stage.sh"]
fn mesh_prepared_stage_transactions_execute_in_sbf() {
    fn bytes(value: &serde_json::Value) -> Vec<u8> {
        hex::decode(value.as_str().unwrap()).unwrap()
    }
    fn address(value: &serde_json::Value) -> Address {
        Address::new_from_array(bytes(value).try_into().unwrap())
    }
    let path = std::env::var("MORSE_RELAY_STAGE_FIXTURES_PATH").expect("fresh Mesh plans required");
    let fixtures = std::fs::read_to_string(path).unwrap();
    let fixtures: Vec<serde_json::Value> = fixtures
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(fixtures.len(), 6, "legacy/RFC native/C2SP, signed/anchor");
    for fixture in fixtures {
        // Public deterministic fixture identity, shared with relay_stage.test.mpl.
        let mut h = Harness::with_identity(
            Address::new_from_array([42; 32]),
            Keypair::new_from_array([11; 32]),
        );
        let wire = bytes(&fixture["wire"]);
        let proof = Fork::parse(&wire).unwrap();
        let first = Checkpoint::parse(proof.first).unwrap();
        let mut log = h.svm.get_account(&h.log).unwrap();
        log.data[4] = first.version;
        log.data[72..104].copy_from_slice(&first.service_key);
        if first.version == 2 {
            let origin = b"morseapp.io/log/main/v2";
            log.data[210..212].copy_from_slice(&(origin.len() as u16).to_le_bytes());
            log.data[212..212 + origin.len()].copy_from_slice(origin);
        }
        h.svm.set_account(h.log, log).unwrap();
        let stage = address(&fixture["stage"]);
        assert_eq!(stage, h.stage(&wire));
        let init = Instruction {
            data: bytes(&fixture["initialize"]),
            ..h.init(&wire)
        };
        assert!(h.send(&[init]));
        for chunk in fixture["append"].as_array().unwrap() {
            let append = h.ix(vec![signer(h.payer.pubkey()), rw(stage)], bytes(chunk));
            assert!(h.send(std::slice::from_ref(&append)));
            assert!(h.send(&[append]), "identical uploads can resume safely");
        }
        assert!(h.send(&[Instruction {
            data: bytes(&fixture["seal"]),
            ..h.seal(stage)
        }]));
        assert_eq!(&h.svm.get_account(&stage).unwrap().data[HEADER..], &wire);
        for witness in fixture["witnesses"].as_array().unwrap() {
            let id = witness["id"].as_str().unwrap().as_bytes();
            assert_eq!(
                h.witness(id, &bytes(&witness["key"])),
                address(&witness["address"])
            );
        }
        let mut expected_bits = 0;
        for step in fixture["signatures"].as_array().unwrap() {
            let ordinal = u8::try_from(step["ordinal"].as_u64().unwrap()).unwrap();
            let witness = (!step["witness"].is_null()).then(|| address(&step["witness"]));
            let precompile = Instruction {
                program_id: Address::from_str("Ed25519SigVerify111111111111111111111111111")
                    .unwrap(),
                accounts: vec![],
                data: bytes(&step["ed25519"]),
            };
            let verify = Instruction {
                data: bytes(&step["judge"]),
                ..h.verify(stage, ordinal, witness)
            };
            let mut corrupted = precompile.clone();
            corrupted.data[48] ^= 1;
            assert!(!h.send(&[corrupted, verify.clone()]));
            assert_eq!(
                h.bits(stage),
                expected_bits,
                "failed precompile cannot set a bit"
            );
            assert!(h.send(&[precompile.clone(), verify]));
            expected_bits |= 1u64 << ordinal;
            assert_eq!(h.bits(stage), expected_bits);
            if ordinal >= 2 {
                let offset = 120 + (ordinal as usize - 2) * 32;
                assert_eq!(
                    &h.svm.get_account(&stage).unwrap().data[offset..offset + 32],
                    &precompile.data[16..48]
                );
            }
        }
        let count = fixture["signatures"].as_array().unwrap().len();
        assert_eq!(
            count,
            if matches!(proof.second, Target::Anchor(_)) {
                17
            } else {
                34
            }
        );
        assert!(h.send(&[h.ix(
            vec![signer(h.payer.pubkey()), rw(stage)],
            bytes(&fixture["close"])
        )]));
        assert!(h
            .svm
            .get_account(&stage)
            .is_none_or(|account| account.lamports == 0));
    }
}

#[test]
fn stage_is_bounded_append_only_sealed_and_refunded_only_to_its_submitter() {
    let mut h = Harness::new();
    let wire = oracle("v3-sixteen-double-signers");
    let stage = h.stage(&wire);
    assert!(!h.send(&[h.init(&vec![0; 8010])]));
    h.svm
        .airdrop(&stage, h.svm.minimum_balance_for_rent_exemption(0))
        .unwrap();
    assert!(h.send(&[h.init(&wire)]));
    assert!(!h.send(&[h.init(&wire)]));
    assert_eq!(
        h.svm.get_account(&stage).unwrap().data.len(),
        HEADER + wire.len()
    );
    assert!(!h.send(&[h.seal(stage)]));
    assert!(!h.send(&[h.append(stage, 1, &wire[..900])]));
    assert!(!h.send(&[h.append(stage, 0, &wire[..901])]));
    let mut unauthorized = h.append(stage, 0, &wire[..900]);
    unauthorized.accounts[0] = ro(h.outsider.pubkey());
    assert!(!h.send(&[unauthorized]));
    assert!(h.send(&[h.append(stage, 0, &wire[..900])]));
    assert!(h.send(&[h.append(stage, 0, &wire[..900])]));
    assert!(!h.send(&[h.append(stage, 899, &wire[899..1000])]));
    assert!(!h.send(&[h.append(stage, 0, &[9; 32])]));
    for (i, chunk) in wire[900..].chunks(900).enumerate() {
        assert!(h.send(&[h.append(stage, (i + 1) * 900, chunk)]));
    }
    assert!(h.send(&[h.seal(stage)]));
    assert!(h.send(&[h.seal(stage)]));
    assert!(!h.send(&[h.append(stage, 0, &wire[..32])]));
    assert_eq!(
        &h.svm.get_account(&stage).unwrap().data[HEADER..],
        wire.as_slice()
    );
    let close = h.ix(vec![signer(h.payer.pubkey()), rw(stage)], vec![14]);
    let mut steal = close.clone();
    steal.accounts[0] = ro(h.outsider.pubkey());
    assert!(!h.send(&[steal]));
    let rent = h.svm.get_account(&stage).unwrap().lamports;
    let before = h.svm.get_balance(&h.payer.pubkey()).unwrap();
    assert!(h.send(&[close]));
    assert_eq!(
        h.svm.get_balance(&h.payer.pubkey()).unwrap(),
        before + rent - 5000
    );
    assert!(h.svm.get_account(&stage).is_none_or(|a| a.lamports == 0));
    let maximal = oracle("v3-maximal-framing-invalid-paths");
    let max_stage = h.load(&maximal);
    assert_eq!(
        h.svm.get_account(&max_stage).unwrap().data.len(),
        HEADER + 8009
    );
    // Sealing attests only byte integrity/canonical framing, not a fork verdict.
    assert_eq!(h.bits(max_stage), 0);
}

#[test]
fn all_34_signatures_are_bound_to_sealed_bytes_exact_keys_and_executed_precompiles() {
    for name in ["v3-sixteen-double-signers", "rfc-v3-sixteen-double-signers"] {
        let mut h = Harness::new();
        let wire = oracle(name);
        if name.starts_with("rfc-") {
            let mut log = h.svm.get_account(&h.log).unwrap();
            log.data[4] = 2;
            let origin = b"morseapp.io/log/main/v2";
            log.data[210..212].copy_from_slice(&(origin.len() as u16).to_le_bytes());
            log.data[212..212 + origin.len()].copy_from_slice(origin);
            h.svm.set_account(h.log, log).unwrap();
        }
        let proof = Fork::parse(&wire).unwrap();
        let stage = h.load(&wire);
        let second = match proof.second {
            Target::Checkpoint(cp) => cp,
            _ => unreachable!(),
        };
        for (ordinal, cp) in [proof.first, second].into_iter().enumerate() {
            let cp = Checkpoint::parse(cp).unwrap();
            let precompile = ed(&cp.service_key, &cp.signature, &cp.statement());
            let verify = h.verify(stage, ordinal as u8, None);
            assert!(!h.send(std::slice::from_ref(&verify)));
            assert!(h.send(std::slice::from_ref(&precompile)));
            assert!(
                !h.send(std::slice::from_ref(&verify)),
                "earlier transaction is not evidence"
            );
            assert!(
                !h.send(&[verify.clone(), precompile.clone()]),
                "future precompile is not evidence"
            );
            assert!(h.send(&[precompile, verify]));
        }
        for index in 0..32 {
            let att = proof.attestation(index).unwrap();
            let key = SigningKey::from_bytes(&[40 + index / 2; 32])
                .verifying_key()
                .to_bytes();
            let witness = h.witness(att.id, &key);
            let message = [
                b"mesh-msg/v1/transparency-witness".as_slice(),
                att.id,
                att.checkpoint_hash,
            ]
            .concat();
            let precompile = ed(&key, att.signature, &message);
            let verify = h.verify(stage, index + 2, Some(witness));
            if index == 0 {
                let mut bad_message = precompile.clone();
                *bad_message.data.last_mut().unwrap() ^= 1;
                assert!(!h.send(&[bad_message, verify.clone()]));
                assert_eq!(h.bits(stage), 3);
                let wrong = h.witness(
                    att.id,
                    &SigningKey::from_bytes(&[91; 32]).verifying_key().to_bytes(),
                );
                assert!(!h.send(&[precompile.clone(), h.verify(stage, 2, Some(wrong))]));
            }
            assert!(h.send(&[precompile.clone(), verify.clone()]));
            assert!(h.send(&[precompile, verify]));
            let account = h.svm.get_account(&stage).unwrap();
            assert_eq!(
                &account.data[120 + index as usize * 32..152 + index as usize * 32],
                key.as_slice()
            );
        }
        assert_eq!(h.bits(stage), (1u64 << 34) - 1);
        // The finder is included in stage identity even though fork pay-once identity
        // excludes it. A relayer cannot replace the named finder after verification.
        let mut named = wire.clone();
        named[5..37].fill(42);
        assert_ne!(h.stage(&named), stage);
        assert_eq!(Fork::parse(&named).unwrap().hash(), proof.hash());
    }
}

#[test]
fn seal_refuses_wrong_hash_malformed_frames_and_unregistered_log_keys() {
    let mut h = Harness::new();
    let wire = oracle("same-size-service-only");
    let stage = h.stage(&wire);
    assert!(h.send(&[h.init(&wire)]));
    let mut changed = wire.clone();
    changed[5] = 1;
    assert!(h.send(&[h.append(stage, 0, &changed)]));
    assert!(!h.send(&[h.seal(stage)]));
    for bytes in [
        oracle("wrong-log"),
        oracle("v3-downgrade-to-v2"),
        oracle("trailing"),
    ] {
        let stage = h.stage(&bytes);
        assert!(h.send(&[h.init(&bytes)]));
        for (i, chunk) in bytes.chunks(900).enumerate() {
            assert!(h.send(&[h.append(stage, i * 900, chunk)]));
        }
        assert!(!h.send(&[h.seal(stage)]));
        assert_eq!(h.bits(stage), 0);
    }
}

fn checkpoint_wire(cp: &Checkpoint) -> Vec<u8> {
    [
        vec![cp.version, b'K', b'T', b'K'],
        cp.sequence.to_be_bytes().to_vec(),
        cp.tree_size.to_be_bytes().to_vec(),
        cp.tree_root.to_vec(),
        cp.previous_hash.to_vec(),
        cp.timestamp.to_be_bytes().to_vec(),
        cp.service_key.to_vec(),
        cp.signature.to_vec(),
    ]
    .concat()
}

#[test]
fn c2sp_verification_binds_timestamp_origin_and_checkpoint_but_never_attributes_metadata_rollback()
{
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut h = Harness::new();
    let origin = b"morseapp.io/log/main/v2";
    let mut log = h.svm.get_account(&h.log).unwrap();
    log.data[4] = 2;
    log.data[210..212].copy_from_slice(&(origin.len() as u16).to_le_bytes());
    log.data[212..212 + origin.len()].copy_from_slice(origin);
    h.svm.set_account(h.log, log).unwrap();
    let service = SigningKey::from_bytes(&[11; 32]);
    let witness_key = SigningKey::from_bytes(&[93; 32]);
    let witness = h.witness(b"outside", &witness_key.verifying_key().to_bytes());
    let mut cp = Checkpoint {
        version: 2,
        sequence: 1,
        tree_size: 1,
        tree_root: [3; 32],
        previous_hash: [0; 32],
        timestamp: 1000,
        service_key: service.verifying_key().to_bytes(),
        signature: [0; 64],
    };
    cp.signature = service.sign(&cp.statement()).to_bytes();
    let first = checkpoint_wire(&cp);
    let mut other = cp.clone();
    other.sequence = 2;
    other.tree_root = [4; 32];
    other.signature = service.sign(&other.statement()).to_bytes();
    // Historic evidence accepts an old timestamp, preserving it exactly. The
    // application freshness gate and the judge's proof-age gate are separate.
    let seconds = 1_679_315_147u64;
    let message = format!(
        "cosignature/v1\ntime {seconds}\nmorseapp.io/log/main/v2\n1\n{}\nmorse-checkpoint {}\n",
        STANDARD.encode(cp.tree_root),
        STANDARD.encode(&first)
    );
    let signature = witness_key.sign(message.as_bytes()).to_bytes();
    let prefix = [
        vec![2, b'F', b'R', b'K', 1],
        vec![0; 32],
        cp.service_key.to_vec(),
        first.clone(),
        vec![0],
        checkpoint_wire(&other),
        vec![1, 7],
        b"outside".to_vec(),
        cp.hash().to_vec(),
        vec![4],
    ]
    .concat();
    let wire = [prefix, seconds.to_be_bytes().to_vec(), signature.to_vec()].concat();
    let stage = h.load(&wire);
    let verify = h.verify(stage, 2, Some(witness));
    let precompile = ed(
        &witness_key.verifying_key().to_bytes(),
        &signature,
        message.as_bytes(),
    );
    let foreign = message.replace("main/v2", "canary/v2");
    let foreign_signature = witness_key.sign(foreign.as_bytes()).to_bytes();
    assert!(!h.send(&[
        ed(
            &witness_key.verifying_key().to_bytes(),
            &foreign_signature,
            foreign.as_bytes()
        ),
        verify.clone()
    ]));
    let later = message.replace(&seconds.to_string(), &(seconds + 1).to_string());
    assert!(!h.send(&[
        ed(
            &witness_key.verifying_key().to_bytes(),
            &witness_key.sign(later.as_bytes()).to_bytes(),
            later.as_bytes()
        ),
        verify.clone()
    ]));
    assert_eq!(h.bits(stage), 0);
    assert!(h.send(&[precompile.clone(), verify]));
    assert_eq!(h.bits(stage), 4);
    let mut metadata = wire.clone();
    metadata[4] = 3;
    let metadata_stage = h.load(&metadata);
    assert!(!h.send(&[precompile, h.verify(metadata_stage, 2, Some(witness))]));
    assert_eq!(h.bits(metadata_stage), 0);
}

#[test]
fn anchor_reference_has_no_second_checkpoint_signature_and_unsigned_uploads_cannot_verify() {
    let mut h = Harness::new();
    let wire = oracle("anchored-same-size");
    let stage = h.stage(&wire);
    let cp = Checkpoint::parse(Fork::parse(&wire).unwrap().first).unwrap();
    let precompile = ed(&cp.service_key, &cp.signature, &cp.statement());
    assert!(h.send(&[h.init(&wire)]));
    assert!(h.send(&[h.append(stage, 0, &wire)]));
    assert!(!h.send(&[precompile.clone(), h.verify(stage, 0, None)]));
    assert!(h.send(&[h.seal(stage)]));
    assert!(!h.send(&[precompile.clone(), h.verify(stage, 1, None)]));
    let mut fake_sysvar = h.verify(stage, 0, None);
    fake_sysvar.accounts[2] = ro(h.log);
    assert!(!h.send(&[precompile.clone(), fake_sysvar]));
    let mut readonly = h.verify(stage, 0, None);
    readonly.accounts[1] = ro(stage);
    assert!(!h.send(&[precompile.clone(), readonly]));
    assert!(h.send(&[precompile, h.verify(stage, 0, None)]));
    assert_eq!(h.bits(stage), 1);
    let forged = oracle("bad-checkpoint-signature");
    let stage = h.load(&forged);
    let cp = Checkpoint::parse(Fork::parse(&forged).unwrap().first).unwrap();
    assert!(!h.send(&[
        ed(&cp.service_key, &cp.signature, &cp.statement()),
        h.verify(stage, 0, None)
    ]));
    assert_eq!(h.bits(stage), 0);
}
