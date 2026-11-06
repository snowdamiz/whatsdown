//! Genuine failed ExactIn attempt followed by a fresh observation and signed
//! retry on the same retained owned bank. No absence/expiry replacement path.
use super::*;
pub fn run(
    svm: &mut LiteSVM,
    dir: &Path,
    payer: &Keypair,
    owner: &Keypair,
    mint: Address,
    oracle: Address,
    keys: &[Address],
    instructions: &[Instruction],
    principal: u64,
) {
    let mut clock = svm.get_sysvar::<Clock>();
    clock.slot += 2;
    clock.unix_timestamp += 2;
    svm.set_sysvar(&clock);
    let mut price = svm.get_account(&oracle).unwrap();
    price.data[73..81].copy_from_slice(&15_000_000_000i64.to_le_bytes());
    price.data[93..101].copy_from_slice(&clock.unix_timestamp.to_le_bytes());
    price.data[101..109].copy_from_slice(&(clock.unix_timestamp - 1).to_le_bytes());
    price.data[125..133].copy_from_slice(&clock.slot.to_le_bytes());
    svm.set_account(oracle, price).unwrap();
    let minimum = (u128::from(principal) * 150_000_000 * 9900).div_ceil(10_000_000_000_000) as u64;
    let mut updated = instructions.to_vec();
    updated[5].data[16..24].copy_from_slice(&minimum.to_le_bytes());
    svm.expire_blockhash();
    let expected =
        Message::new_with_blockhash(&updated, Some(&payer.pubkey()), &svm.latest_blockhash());
    let mut ready: Value =
        serde_json::from_slice(&std::fs::read(dir.join("initial.json")).unwrap()).unwrap();
    ready["slot"] = json!(clock.slot.to_string());
    ready["now"] = json!(clock.unix_timestamp.to_string());
    ready["minimum"] = json!(minimum.to_string());
    ready["blockhash"] = json!(svm.latest_blockhash().to_string());
    ready["accounts"] = json!(keys
        .iter()
        .map(|k| json!({"address":k.to_string(),"account":account_json(svm,*k)}))
        .collect::<Vec<_>>());
    ready["message"] = json!(B64.encode(expected.serialize()));
    ready.as_object_mut().unwrap().remove("wire");
    write(&dir.join("retry-ready.json"), &ready);
    let raw = B64.decode(wait(&dir.join("retry.message.base64"))).unwrap();
    let supplied: Message = wincode::deserialize(&raw).unwrap();
    assert_eq!(supplied.serialize(), raw);
    equivalent_message(&supplied, &expected);
    let tx = Transaction::new(&[payer, owner], supplied.clone(), svm.latest_blockhash());
    let wire = wincode::serialize(&tx).unwrap();
    std::fs::write(dir.join("retry.signed.packet.base64"), B64.encode(&wire)).unwrap();
    assert_eq!(
        B64.decode(wait(&dir.join("retry.send.packet.base64")))
            .unwrap(),
        wire
    );
    let destination = ata(owner.pubkey(), mint);
    let pre = amount(svm, destination);
    let owner_before = svm.get_balance(&owner.pubkey()).unwrap();
    let payer_before = svm.get_balance(&payer.pubkey()).unwrap();
    let pre_balances: Vec<_> = supplied
        .account_keys
        .iter()
        .map(|k| svm.get_balance(k).unwrap_or(0))
        .collect();
    let pre_tokens = token_rows(svm, &supplied.account_keys, mint);
    let result = svm
        .send_transaction(tx.clone())
        .unwrap_or_else(|e| panic!("{:?}\n{}", e.err, e.meta.logs.join("\n")));
    let received = amount(svm, destination) - pre;
    assert!(received >= minimum);
    assert_eq!(
        owner_before - svm.get_balance(&owner.pubkey()).unwrap(),
        principal
    );
    assert_eq!(
        payer_before - svm.get_balance(&payer.pubkey()).unwrap(),
        result.fee
    );
    let paid_balance = svm.get_balance(&payer.pubkey());
    assert!(svm.send_transaction(tx.clone()).is_err());
    assert!(svm.send_transaction(tx.clone()).is_err());
    assert_eq!(svm.get_balance(&payer.pubkey()), paid_balance);
    assert_eq!(amount(svm, destination) - pre, received);
    let post_balances: Vec<_> = supplied
        .account_keys
        .iter()
        .map(|k| svm.get_balance(k).unwrap_or(0))
        .collect();
    write(
        &dir.join("retry.execution.json"),
        &json!({"signature":tx.signatures[0].to_string(),"message":B64.encode(supplied.serialize()),"wire":B64.encode(wire),"execution_error":Value::Null,"slot":clock.slot,"block_time":clock.unix_timestamp,"fee":result.fee,"received_usdc":received.to_string(),"spent_lamports":principal.to_string(),"pre_usdc":pre.to_string(),"pre_balances":pre_balances,"post_balances":post_balances,"pre_tokens":pre_tokens,"post_tokens":token_rows(svm,&supplied.account_keys,mint),"units":result.compute_units_consumed,"logs":result.logs,"duplicate_refusals":2,"accounts":keys.iter().map(|k|json!({"address":k.to_string(),"account":account_json(svm,*k)})).collect::<Vec<_>>()}),
    );
}
