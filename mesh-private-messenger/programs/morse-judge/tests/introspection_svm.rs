use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use litesvm::LiteSVM;
use morse_judge::checkpoint::Checkpoint;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::{path::PathBuf, str::FromStr};

fn precompile(key: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Instruction {
    let mut data = vec![1, 0];
    for value in [
        48,
        u16::MAX,
        16,
        u16::MAX,
        112,
        message.len() as u16,
        u16::MAX,
    ] {
        data.extend_from_slice(&value.to_le_bytes());
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

fn succeeds(svm: &mut LiteSVM, payer: &Keypair, instructions: &[Instruction]) -> bool {
    svm.expire_blockhash();
    let tx = Transaction::new(
        &[payer],
        Message::new(instructions, Some(&payer.pubkey())),
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).is_ok()
}

#[test]
fn sbf_introspection_requires_the_exact_earlier_verified_statement() {
    let probe = std::env::var_os("MORSE_JUDGE_PROBE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../target/deploy/morse_judge_introspection_probe.so")
        });
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();
    let program = Address::new_unique();
    svm.add_program_from_file(program, probe)
        .expect("build the test SBF probe before --features svm");
    let sysvar = Address::from_str("Sysvar1nstructions1111111111111111111111111").unwrap();
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/fork-v1/anchor-checkpoints.json"
    ))
    .unwrap();
    for fixture in fixtures.as_array().unwrap() {
        let wire = hex::decode(fixture["wire"].as_str().unwrap()).unwrap();
        let checkpoint = Checkpoint::parse(&wire).unwrap();
        let ed = precompile(
            &checkpoint.service_key,
            &checkpoint.signature,
            &checkpoint.statement(),
        );
        let mut data = vec![0, 0];
        data.extend_from_slice(&wire);
        let check = Instruction {
            program_id: program,
            accounts: vec![AccountMeta::new_readonly(sysvar, false)],
            data,
        };
        assert!(succeeds(&mut svm, &payer, &[ed.clone(), check.clone()]));
        // Prior transactions do not confer authority. A future instruction is
        // also rejected even if its signature is cryptographically valid.
        assert!(succeeds(&mut svm, &payer, std::slice::from_ref(&ed)));
        assert!(!succeeds(&mut svm, &payer, std::slice::from_ref(&check)));
        assert!(!succeeds(&mut svm, &payer, &[check.clone(), ed.clone()]));
        let mut fake_sysvar = check.clone();
        fake_sysvar.accounts[0].pubkey = payer.pubkey();
        assert!(!succeeds(&mut svm, &payer, &[ed.clone(), fake_sysvar]));
        let mut bad_signature = ed.clone();
        bad_signature.data[48] ^= 1;
        assert!(!succeeds(&mut svm, &payer, &[bad_signature, check.clone()]));
        let mut wrong_message = checkpoint.statement();
        wrong_message[26] ^= 1;
        let signing_key = SigningKey::from_bytes(&[11; 32]);
        let other = precompile(
            &checkpoint.service_key,
            &signing_key.sign(&wrong_message).to_bytes(),
            &wrong_message,
        );
        // A valid signature over a different statement reaches the judge and
        // fails its byte-for-byte comparison, rather than precompile crypto.
        assert!(succeeds(&mut svm, &payer, std::slice::from_ref(&other)));
        assert!(!succeeds(&mut svm, &payer, &[other, check.clone()]));
        // This Ed25519 instruction verifies using fields in a *different*
        // instruction. Solana accepts it; the judge requires self containment.
        let mut redirected = ed.clone();
        for offset in [4, 8, 14] {
            redirected.data[offset..offset + 2].copy_from_slice(&0u16.to_le_bytes());
        }
        assert!(succeeds(
            &mut svm,
            &payer,
            &[ed.clone(), redirected.clone()]
        ));
        let mut redirected_check = check.clone();
        redirected_check.data[..2].copy_from_slice(&1u16.to_le_bytes());
        assert!(!succeeds(
            &mut svm,
            &payer,
            &[ed, redirected, redirected_check]
        ));
    }
}
