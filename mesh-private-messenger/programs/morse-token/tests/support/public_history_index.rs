//! Optional public-account fixture export only; no keys, instructions or mutations.
use litesvm::LiteSVM;
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;

fn account(address: Address, value: &Account, maximum: Option<usize>) -> serde_json::Value {
    let length = maximum.map_or(value.data.len(), |limit| value.data.len().min(limit));
    serde_json::json!({"address":address.to_string(),"owner":value.owner.to_string(),
        "space":value.data.len().to_string(),"lamports":value.lamports.to_string(),
        "rent_epoch":value.rent_epoch.to_string(),"executable":value.executable,
        "data_hex":hex::encode(&value.data[..length])})
}

pub(super) fn export(
    svm: &LiteSVM,
    programs: &[Address],
    metadata: serde_json::Value,
    variable: &str,
) {
    let Some(path) = std::env::var_os(variable) else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    assert!(
        !path.exists(),
        "fixture export must use a fresh output path"
    );
    let mut values = std::collections::BTreeMap::new();
    let mut owned = Vec::new();
    let mut known_absent = Vec::new();
    let mut extra = Vec::new();
    let mut total = 0usize;
    for program in programs {
        let mut accounts = svm.get_program_accounts(program);
        accounts.sort_by_key(|(address, _)| address.to_bytes());
        assert!(
            accounts.len() <= 1000,
            "actual fixture enumeration exceeds bounded export"
        );
        let rows: Vec<_> = accounts
            .iter()
            .map(|(address, value)| {
                total = total.checked_add(value.data.len()).unwrap();
                assert!(
                    total <= 16 * 1024 * 1024,
                    "actual fixture bytes exceed export bound"
                );
                values.insert(address.to_bytes(), (*address, value.clone()));
                account(*address, value, None)
            })
            .collect();
        owned.push(
            serde_json::json!({"program":program.to_string(),"count":rows.len(),"accounts":rows}),
        );
    }
    // Metadata roles and canonical pending/opposite-asset vault keys are looked
    // up in the same real bank. Missing observations are explicit, never guessed
    // from the enumeration of a different owner.
    let roles: Vec<_> = match &metadata["accounts"] {
        serde_json::Value::Array(rows) => rows.iter().collect(),
        serde_json::Value::Object(rows) => rows.values().collect(),
        _ => Vec::new(),
    };
    for row in &roles {
        if let Some(text) = row["address"].as_str() {
            extra.push(text.parse::<Address>().unwrap());
        }
    }
    let mints: Vec<Address> = [
        metadata["usdc"].as_str(),
        metadata["accounts"]["usdc"]["address"].as_str(),
        metadata["accounts"]["morse"]["address"].as_str(),
    ]
    .into_iter()
    .flatten()
    .map(|text| text.parse().unwrap())
    .collect();
    let token = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    let ata = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
    for program in programs {
        for (address, value) in svm.get_program_accounts(program) {
            if value.data.starts_with(b"MBD") {
                extra.push(
                    Address::find_program_address(&[b"bond-pending", address.as_ref()], program).0,
                );
                for mint in &mints {
                    extra.push(
                        Address::find_program_address(
                            &[address.as_ref(), token.as_ref(), mint.as_ref()],
                            &ata,
                        )
                        .0,
                    );
                }
            }
        }
    }
    extra.sort_by_key(|address| address.to_bytes());
    extra.dedup();
    for address in extra {
        match svm.get_account(&address) {
            Some(value) => {
                values.insert(address.to_bytes(), (address, value));
            }
            None => known_absent.push(address.to_string()),
        }
    }

    for (address, value) in svm.get_program_accounts(&token) {
        values.insert(address.to_bytes(), (address, value));
    }
    let loader = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
    for address in programs
        .iter()
        .copied()
        .chain(
            programs
                .iter()
                .map(|program| Address::find_program_address(&[program.as_ref()], &loader).0),
        )
        .chain([Address::from_str_const(
            "SysvarC1ock11111111111111111111111111111111",
        )])
    {
        if let Some(value) = svm.get_account(&address) {
            values.insert(address.to_bytes(), (address, value));
        }
    }
    let values: Vec<_> = values
        .values()
        .map(|(address, value)| account(*address, value, Some(8416)))
        .collect();
    let clock = svm.get_sysvar::<Clock>();
    let output = serde_json::json!({"schema_version":1,"scope":"complete-actual-owned-accounts-local-sbf-bank",
        "context_slot":clock.slot.to_string(),"source_time_unix":clock.unix_timestamp.to_string(),
        "owned":owned,"value_data_slice_length":8416,"value_accounts":values,"absent_accounts":known_absent,"metadata":metadata,
        "limits":["Clock/slot are controlled local SBF observations, not ledger finality.",
        "Owned lists are complete actual get_program_accounts output; value-role bodies are genuine bounded prefixes.",
        "No private signer bytes or invented accepted accounts are exported."]});
    std::fs::write(path, serde_json::to_vec_pretty(&output).unwrap()).unwrap();
    // Optional second genuine bank: clone the real account state and advance
    // only its controlled Clock. This proves cross-bank read semantics without
    // mutating the original test bank or fabricating accepted account bytes.
    let later_variable = format!("{variable}_LATER");
    if !variable.ends_with("_LATER") && std::env::var_os(&later_variable).is_some() {
        let mut later = svm.clone();
        let mut later_clock = later.get_sysvar::<Clock>();
        later_clock.slot = later_clock.slot.checked_add(7).unwrap();
        later_clock.unix_timestamp = later_clock.unix_timestamp.checked_add(7).unwrap();
        later.warp_to_slot(later_clock.slot);
        later.set_sysvar(&later_clock);
        export(&later, programs, output["metadata"].clone(), &later_variable);
    }
}
