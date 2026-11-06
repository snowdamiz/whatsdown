//! Conversion-only output bridge: actual rewards initialization/fund_once SBF.
//! Judge log/clock are canonical judge-owned fixtures, not a claim of attendance
//! or judge custody execution. No scheduling, member, claim or keeper behavior.
use super::*;
pub struct Context {
    pub program: Address,
    pub pool: Address,
    pub vault: Address,
    pub judge: Address,
    pub log: Address,
    pub epoch: Address,
    pub epoch_number: u64,
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
        log,
        epoch,
        epoch_number,
    }
}
pub fn execute(
    svm: &mut LiteSVM,
    dir: &Path,
    ctx: &Context,
    payer: &Keypair,
    owner: &Keypair,
    mint: Address,
    id: [u8; 32],
    profile_hash: [u8; 32],
    conversion: &Transaction,
    conversion_wire: &[u8],
    received: u64,
    spent: u64,
    fee: u64,
) {
    let clock = svm.get_sysvar::<Clock>();
    let receipt = [
        b"MCS1".to_vec(),
        id.to_vec(),
        profile_hash.to_vec(),
        conversion.signatures[0].as_ref().to_vec(),
        solana_sha256_hasher::hash(conversion_wire)
            .to_bytes()
            .to_vec(),
        clock.slot.to_le_bytes().to_vec(),
        spent.to_le_bytes().to_vec(),
        received.to_le_bytes().to_vec(),
        fee.to_le_bytes().to_vec(),
        vec![1],
    ]
    .concat();
    assert_eq!(receipt.len(), 197);
    let funding_id = solana_sha256_hasher::hashv(&[
        b"morse-sol-witness-funding-v1",
        &id,
        solana_sha256_hasher::hash(&receipt).as_ref(),
        &ctx.epoch_number.to_le_bytes(),
        ctx.program.as_ref(),
        ctx.pool.as_ref(),
    ])
    .to_bytes();
    let permanent = Address::find_program_address(
        &[b"funding", owner.pubkey().as_ref(), &funding_id],
        &ctx.program,
    )
    .0;
    let source = ata(owner.pubkey(), mint);
    let fund = Instruction {
        program_id: ctx.program,
        accounts: vec![
            AccountMeta::new_readonly(owner.pubkey(), true),
            AccountMeta::new(payer.pubkey(), true),
            rw(ctx.pool),
            rw(ctx.epoch),
            rw(ctx.vault),
            rw(source),
            ro(mint),
            ro(TOKEN),
            rw(permanent),
            ro(Address::default()),
        ],
        data: [
            vec![12, 0],
            received.to_le_bytes().to_vec(),
            funding_id.to_vec(),
        ]
        .concat(),
    };
    let budget = Instruction {
        program_id: Address::from_str_const("ComputeBudget111111111111111111111111111111"),
        accounts: vec![],
        data: [vec![2], 300000u32.to_le_bytes().to_vec()].concat(),
    };
    svm.expire_blockhash();
    let expected = Message::new_with_blockhash(
        &[budget, fund.clone()],
        Some(&payer.pubkey()),
        &svm.latest_blockhash(),
    );
    write(
        &dir.join("funding-ready.json"),
        &json!({"funding_id":hex::encode(funding_id),"conversion_receipt":hex::encode(receipt),"epoch":ctx.epoch_number.to_string(),"blockhash":svm.latest_blockhash().to_string(),"judge":ctx.judge.to_string(),"log_name":"sol-conversion","log":ctx.log.to_string(),"program":ctx.program.to_string(),"pool":ctx.pool.to_string(),"amount":received.to_string(),"boundary":"Actual rewards fund_once; canonical judge-owned log/clock fixtures only, no keeper/attendance qualification"}),
    );
    let raw = B64
        .decode(wait(&dir.join("funding.message.base64")))
        .unwrap();
    let supplied: Message = wincode::deserialize(&raw).unwrap();
    assert_eq!(supplied.serialize(), raw);
    equivalent_message(&supplied, &expected);
    let tx = Transaction::new(&[payer, owner], supplied, svm.latest_blockhash());
    let packet = wincode::serialize(&tx).unwrap();
    assert!(packet.len() <= 1232);
    std::fs::write(
        dir.join("funding.signed.packet.base64"),
        B64.encode(&packet),
    )
    .unwrap();
    assert_eq!(
        B64.decode(wait(&dir.join("funding.send.packet.base64")))
            .unwrap(),
        packet
    );
    let source_before = amount(svm, source);
    let vault_before = amount(svm, ctx.vault);
    let result = svm
        .send_transaction(tx)
        .unwrap_or_else(|e| panic!("{:?}\n{}", e.err, e.meta.logs.join("\n")));
    assert_eq!(source_before - amount(svm, source), received);
    assert_eq!(amount(svm, ctx.vault) - vault_before, received);
    let proof = svm.get_account(&permanent).unwrap();
    assert_eq!(proof.owner, ctx.program);
    assert_eq!(proof.data.len(), 192);
    assert_eq!(&proof.data[68..100], &funding_id);
    assert_eq!(
        u64::from_le_bytes(proof.data[112..120].try_into().unwrap()),
        received
    );
    // Fresh blockhash retries reach the permanent exact-intent receipt branch,
    // rather than merely relying on duplicate transaction rejection.
    send(svm, payer, &[owner], &[fund.clone()]);
    send(svm, payer, &[owner], &[fund]);
    assert_eq!(source_before - amount(svm, source), received);
    assert_eq!(amount(svm, ctx.vault) - vault_before, received);
    let keys = [
        permanent,
        Address::from_str_const("SysvarC1ock11111111111111111111111111111111"),
        ctx.pool,
        ctx.vault,
        source,
        mint,
        ctx.program,
        metadata(ctx.program),
    ];
    write(
        &dir.join("funding.json"),
        &json!({"funding_id":hex::encode(funding_id),"conversion_id":hex::encode(id),"amount":received.to_string(),"receipt":hex::encode(proof.data),"accounts":keys.iter().map(|k|json!({"address":k.to_string(),"account":account_json(svm,*k)})).collect::<Vec<_>>(),"packet":B64.encode(packet),"units":result.compute_units_consumed,"exact_intent_replays":2,"source_remaining":amount(svm,source).to_string(),"vault_received":(amount(svm,ctx.vault)-vault_before).to_string()}),
    );
}
