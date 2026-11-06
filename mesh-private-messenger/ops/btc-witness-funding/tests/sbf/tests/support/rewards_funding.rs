//! Conversion-only output bridge: actual rewards initialization/fund_once SBF.
//! Judge log/clock are canonical judge-owned fixtures, not a claim of attendance
//! or judge custody execution. No scheduling, member, claim or keeper behavior.
use super::*;
pub struct Context {
    pub program: Address,
    pub pool: Address,
    pub vault: Address,
    pub judge: Address,
}
fn put(svm: &mut LiteSVM, key: Address, owner: Address, data: Vec<u8>) {
    svm.set_account(
        key,
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
pub fn setup(svm: &mut LiteSVM, payer: &Keypair, mint: Address, now: i64) -> Context {
    let program = Address::new_from_array(
        solana_sha256_hasher::hash(b"owned-output-bridge-program").to_bytes(),
    );
    let elf = PathBuf::from(
        std::env::var_os("MORSE_SOL_CONVERSION_REWARDS_ELF").expect("explicit owned rewards ELF"),
    );
    svm.add_program_from_file(program, &elf).unwrap();
    let pd = metadata(program);
    let mut image = svm.get_account(&pd).unwrap();
    image.data[12] = 1;
    image.data[13..45].copy_from_slice(payer.pubkey().as_ref());
    svm.set_account(pd, image).unwrap();
    let judge =
        Address::new_from_array(solana_sha256_hasher::hash(b"owned-conversion-judge").to_bytes());
    svm.set_account(judge, svm.get_account(&TOKEN).unwrap())
        .unwrap();
    let name = b"sol-conversion";
    let id = solana_sha256_hasher::hash(name).to_bytes();
    let log = Address::find_program_address(&[b"log", name], &judge).0;
    let clock = Address::find_program_address(&[b"attendance", &id], &judge).0;
    let started = now - 604800;
    let first = (started / 604800) as u64 + 1;
    let mut data = vec![0; 352];
    data[..4].copy_from_slice(b"MLG\x01");
    data[4] = 1;
    data[6] = name.len() as u8;
    data[7] = 1;
    data[8..8 + name.len()].copy_from_slice(name);
    data[40..72].copy_from_slice(&id);
    put(svm, log, judge, data);
    let mut data = vec![0; 80 + 4096 * 16];
    data[..4].copy_from_slice(b"MAC\x01");
    data[4..36].copy_from_slice(&id);
    data[36..44].copy_from_slice(&started.to_le_bytes());
    data[44..52].copy_from_slice(&1000u64.to_le_bytes());
    data[52..60].copy_from_slice(&first.to_le_bytes());
    data[60..68].copy_from_slice(&((started / 604800) as u64).to_le_bytes());
    put(svm, clock, judge, data);
    let pool = Address::find_program_address(&[b"pool"], &program).0;
    let vault = ata(pool, mint);
    let initialize = Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new(payer.pubkey(), true),
            rw(pool),
            rw(vault),
            ro(program),
            ro(pd),
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
            solana_sha256_hasher::hash(b"owned-unused-morse-witness")
                .to_bytes()
                .to_vec(),
        ]
        .concat(),
    };
    send(svm, payer, &[], &[initialize]);
    let epoch_number = (now / 604800) as u64;
    let epoch = Address::find_program_address(&[b"epoch", &epoch_number.to_le_bytes()], &program).0;
    send(
        svm,
        payer,
        &[],
        &[Instruction {
            program_id: program,
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                ro(pool),
                rw(epoch),
                ro(Address::default()),
            ],
            data: [vec![1], epoch_number.to_le_bytes().to_vec()].concat(),
        }],
    );
    Context {
        program,
        pool,
        vault,
        judge,
    }
}
