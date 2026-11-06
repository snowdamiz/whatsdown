use morse_rewards::{state::*, validate_instruction};
#[test]
fn malformed_account_headers_cannot_be_used_as_reward_money() {
    let mut pool = vec![0; POOL_LEN];
    assert!(Pool::parse(&pool).is_err());
    pool[..4].copy_from_slice(b"MRP\x01");
    assert!(Pool::parse(&pool).is_err());
    assert!(Ledger::parse(&vec![0; LEDGER_LEN]).is_err());
    assert!(Member::parse(&[0; MEMBER_LEN]).is_err());
}
#[test]
fn instruction_tags_and_lengths_are_closed() {
    for data in [
        vec![],
        vec![255],
        vec![2],
        vec![2, 2, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![4, 1],
        vec![8],
    ] {
        assert!(validate_instruction(&data).is_err(), "{data:?}");
    }
    assert!(validate_instruction(&[4]).is_ok());
    assert!(validate_instruction(&[5]).is_ok());
    assert!(validate_instruction(&[6]).is_ok());
}

#[test]
fn reward_account_pdas_match_cross_language_u64_max_vectors() {
    use solana_address::Address;
    let program = Address::from([0x66; 32]);
    let witness = Address::from([1; 32]);
    let mint = Address::from([0x77; 32]);
    let pool = Address::find_program_address(&[b"pool"], &program).0;
    let member = Address::find_program_address(&[b"member", witness.as_ref()], &program).0;
    let epoch = Address::find_program_address(&[b"epoch", &u64::MAX.to_le_bytes()], &program).0;
    let funding =
        Address::find_program_address(&[b"funding", &[0x88; 32], &[0x99; 32]], &program).0;
    assert_eq!(
        funding.to_string(),
        "NeSNbrQasxwPFQ4DCRVvWKvrTsM4DTUNo9keQrspbEH"
    );
    let token = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    let ata = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
    let vault =
        Address::find_program_address(&[pool.as_ref(), token.as_ref(), mint.as_ref()], &ata).0;
    assert_eq!(
        pool.to_string(),
        "AYEAZnLGHzjV95vMtRu4StknBBRtmZUGLwK297Na1jqK"
    );
    assert_eq!(
        member.to_string(),
        "5ve21kaazCkupZwgYTuD9phMcJYEy5Uojrz4jJdpXCTW"
    );
    assert_eq!(
        epoch.to_string(),
        "Da7kLkGX3ykmYgJ5Q1TGKQm3EM1hLw5beynx8QgMSUqH"
    );
    assert_eq!(
        vault.to_string(),
        "EmXsPprSeSwqUmzD8sfTZdhxZxeeat74NwAAma9eZpPW"
    );
}

#[test]
fn funding_receipts_reject_partial_or_ambiguous_intent_encodings() {
    let mut d = vec![0; FUNDING_LEN];
    d[..4].copy_from_slice(b"MRF\x01");
    d[4..36].fill(1);
    d[36..68].fill(2);
    d[68..100].fill(3);
    put64(&mut d, 100, 99);
    put64(&mut d, 112, 1);
    d[120..152].fill(4);
    d[152..184].fill(5);
    d[184..192].copy_from_slice(&100i64.to_le_bytes());
    assert_eq!(FundingReceipt::parse(&d).unwrap().amount, 1);
    for offset in [108, 109] {
        let mut wrong = d.clone();
        wrong[offset] = 2;
        assert!(FundingReceipt::parse(&wrong).is_err());
    }
    let mut wrong = d.clone();
    wrong[68..100].fill(0);
    assert!(FundingReceipt::parse(&wrong).is_err());
    let mut wrong = d.clone();
    wrong[184..192].fill(0);
    assert!(FundingReceipt::parse(&wrong).is_err());
    assert!(FundingReceipt::parse(&d[..191]).is_err());
}
