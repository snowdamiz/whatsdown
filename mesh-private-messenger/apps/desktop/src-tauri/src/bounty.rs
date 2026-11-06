// Trusted host orchestration only. Mesh owns the retained proof and every
// immutable decision; the wallet SDK alone supplies the40-byte reservation.
fn packet(fields: &[&[u8]]) -> Vec<u8> {
    let mut bytes = (fields.len() as u32).to_be_bytes().to_vec();
    for field in fields {
        bytes.extend((field.len() as u32).to_be_bytes());
        bytes.extend(*field);
    }
    bytes
}

struct View {
    enabled: bool,
    status: u8,
    proof: Vec<u8>,
}
fn view(input: &[u8]) -> Result<View, String> {
    let invalid = || "invalid_bounty_response".to_owned();
    if input.len() > 160 || input.get(..4) != Some(&6u32.to_be_bytes()) {
        return Err(invalid());
    }
    let mut fields = Vec::with_capacity(6);
    let mut at = 4;
    for _ in 0..6 {
        let length = u32::from_be_bytes(
            input
                .get(at..at + 4)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize;
        at += 4;
        let field = input.get(at..at + length).ok_or_else(invalid)?;
        at += length;
        fields.push(field);
    }
    if at != input.len()
        || fields[0] != b"\x01BFP"
        || fields[1].len() != 1
        || fields[1][0] > 1
        || fields[2].len() != 1
        || fields[2][0] > 5
        || fields[5].len() != 8
    {
        return Err(invalid());
    }
    let status = fields[2][0];
    let index = u64::from_be_bytes(fields[5].try_into().map_err(|_| invalid())?);
    if (if status == 0 {
        !fields[3].is_empty()
    } else {
        fields[3].len() != 32
    }) || (if status < 2 {
        !fields[4].is_empty()
    } else {
        fields[4].len() != 32
    }) || (if status == 3 {
        index >= 2147483648 || fields[4].iter().all(|n| *n == 0)
    } else {
        index != 0
    }) || (matches!(status, 2 | 4) && fields[4].iter().any(|n| *n != 0))
    {
        return Err(invalid());
    }
    Ok(View {
        enabled: fields[1][0] == 1,
        status,
        proof: fields[3].to_vec(),
    })
}

pub fn preflight<M, S>(database: &[u8], mut mesh: M, mut sdk: S) -> Result<(), String>
where
    M: FnMut(&str, &[u8]) -> Result<Vec<u8>, String>,
    S: FnMut(u32, &[u8]) -> Result<Vec<u8>, String>,
{
    for _ in 0..3 {
        let state = view(&mesh("mesh_messenger_bounty_status", database)?)?;
        if state.status != 1 {
            return Ok(());
        }
        let (symbol, request) = match sdk(4, &[]) {
            Ok(reservation) => {
                if reservation.len() != 40 {
                    return Err("invalid_bounty_wallet_response".into());
                }
                (
                    "mesh_messenger_bounty_commit",
                    packet(&[database, &state.proof, &reservation]),
                )
            }
            // Only an actual SDK failure can select the no-wallet fallback.
            Err(_) => (
                "mesh_messenger_bounty_unavailable",
                packet(&[database, &state.proof]),
            ),
        };
        if let Ok(result) = mesh(symbol, &request) {
            if view(&result)?.status == 1 {
                return Err("invalid_bounty_response".into());
            }
            return Ok(());
        }
        // CAS/frozen races reread before another reservation. Never abandon
        // a proof merely because its commit lost to another native writer.
    }
    if view(&mesh("mesh_messenger_bounty_status", database)?)?.status != 1 {
        return Ok(());
    }
    Err("bounty_selection_pending".into())
}
pub fn set_enabled<M, S>(
    database: &[u8],
    enabled: u8,
    mut mesh: M,
    mut sdk: S,
) -> Result<Vec<u8>, String>
where
    M: FnMut(&str, &[u8]) -> Result<Vec<u8>, String>,
    S: FnMut(u32, &[u8]) -> Result<Vec<u8>, String>,
{
    if enabled > 1 {
        return Err("invalid_bounty_request".into());
    }
    if enabled == 1 {
        let address = sdk(2, &[])?;
        if address.len() != 32 || address.iter().all(|n| *n == 0) {
            return Err("invalid_bounty_wallet_response".into());
        }
    }
    let result = mesh(
        "mesh_messenger_bounty_set_enabled",
        &packet(&[database, &[enabled]]),
    )?;
    if view(&result)?.enabled != (enabled == 1) {
        return Err("invalid_bounty_response".into());
    }
    Ok(result)
}

pub fn invoke_proof<M, S>(
    symbol: &str,
    database: &[u8],
    mut mesh: M,
    mut sdk: S,
) -> Result<Vec<u8>, String>
where
    M: FnMut(&str, &[u8]) -> Result<Vec<u8>, String>,
    S: FnMut(u32, &[u8]) -> Result<Vec<u8>, String>,
{
    if !matches!(
        symbol,
        "mesh_messenger_transparency_fork" | "mesh_messenger_fork_filing"
    ) {
        return Err("invalid_bounty_request".into());
    }
    for _ in 0..3 {
        preflight(database, &mut mesh, &mut sdk)?;
        match mesh(symbol, database) {
            Err(error) if error.contains("bounty_selection_pending") => continue,
            result => return result,
        }
    }
    Err("bounty_selection_pending".into())
}

fn movement_fields(input: &[u8], count: usize, maximum: usize) -> Result<Vec<&[u8]>, String> {
    let invalid = || "invalid_bounty_transfer_response".to_owned();
    if input.len() > maximum || input.get(..4) != Some(&(count as u32).to_be_bytes()) {
        return Err(invalid());
    }
    let mut at = 4;
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let length = u32::from_be_bytes(
            input
                .get(at..at + 4)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize;
        at += 4;
        let field = input.get(at..at + length).ok_or_else(invalid)?;
        at += length;
        fields.push(field);
    }
    if at != input.len() {
        return Err(invalid());
    }
    Ok(fields)
}
fn movement_result(input: &[u8], identity: &[u8], destination: &[u8]) -> Result<u8, String> {
    let fields = movement_fields(input, 12, 2048)?;
    if fields[0] != b"\x01BMW"
        || fields[1] != identity
        || fields[2].len() != 1
        || fields[2][0] > 5
        || fields[4].len() != 32
        || fields[5] != destination
        || fields[6].len() != 32
        || fields[7].len() != 8
        || fields[8].len() != 1
        || fields[8][0] > 18
        || fields[9].len() != 8
        || fields[10].len() != 8
        || fields[11].len() > 256
        || std::str::from_utf8(fields[11]).is_err()
        || (if fields[2][0] < 2 {
            !fields[3].is_empty()
        } else {
            fields[3].len() != 64
        })
    {
        return Err("invalid_bounty_transfer_response".into());
    }
    Ok(fields[2][0])
}

// Host wallet operation8. JS supplies only a destination owner. Native Mesh
// authenticates receipt/amount/mint/index and the SDK confirms its exact BWT.
pub fn movement<M, S>(
    input: &[u8],
    database: &[u8],
    mut mesh: M,
    mut sdk: S,
) -> Result<Vec<u8>, String>
where
    M: FnMut(&str, &[u8]) -> Result<Vec<u8>, String>,
    S: FnMut(u32, &[u8]) -> Result<Vec<u8>, String>,
{
    let request = movement_fields(input, 2, 8192)?;
    if request[0] != database || request[1].len() != 32 || request[1].iter().all(|n| *n == 0) {
        return Err("invalid_bounty_transfer_request".into());
    }
    let payer = sdk(2, &[])?;
    if payer.len() != 32 || payer.iter().all(|n| *n == 0) {
        return Err("invalid_bounty_wallet_response".into());
    }
    let raw = mesh(
        "mesh_messenger_bounty_transfer_prepare",
        &packet(&[database, request[1], &payer]),
    )?;
    let plan = movement_fields(&raw, 6, 512)?;
    if plan[0] != b"\x01BMP"
        || plan[1].len() != 32
        || plan[1].iter().all(|n| *n == 0)
        || plan[2].len() != 1
        || plan[3].len() != 166
        || &plan[3][..4] != b"\x01BWT"
        || &plan[3][44..76] != request[1]
        || plan[5].len() != 1
        || !(1..=5).contains(&plan[5][0])
        || plan[2][0] != u8::from(plan[5][0] == 1)
        || (if plan[5][0] < 2 {
            !plan[4].is_empty()
        } else {
            plan[4].len() != 64
        })
    {
        return Err("invalid_bounty_transfer_response".into());
    }
    let identity = plan[1];
    if plan[2][0] == 1 {
        let wire = sdk(5, plan[3])?;
        if wire.is_empty() || wire.len() > 1232 {
            return Err("invalid_bounty_wallet_response".into());
        }
        let committed = mesh(
            "mesh_messenger_bounty_transfer_commit",
            &packet(&[database, identity, &wire]),
        )?;
        let status = movement_result(&committed, identity, request[1])?;
        if status >= 4 {
            return Ok(committed);
        }
        if status < 2 {
            return Err("invalid_bounty_transfer_response".into());
        }
    } else if plan[5][0] >= 4 {
        let output = mesh("mesh_messenger_bounty_transfer_status", database)?;
        movement_result(&output, identity, request[1])?;
        return Ok(output);
    }
    let output = mesh(
        "mesh_messenger_bounty_transfer_submit",
        &packet(&[database, identity]),
    )?;
    let status = movement_result(&output, identity, request[1])?;
    if status < 2 {
        return Err("invalid_bounty_transfer_response".into());
    }
    Ok(output)
}

#[cfg(test)]
mod movement_tests {
    use super::*;
    use std::cell::RefCell;
    fn fixture(status: u8) -> Vec<u8> {
        packet(&[
            b"\x01BMW",
            &[7; 32],
            &[status],
            if status >= 2 { &[9; 64] } else { &[] },
            &[4; 32],
            &[6; 32],
            &[5; 32],
            &100u64.to_be_bytes(),
            &[6],
            &0u64.to_be_bytes(),
            &0u64.to_be_bytes(),
            b"",
        ])
    }
    fn prepared(status: u8) -> Vec<u8> {
        let mut intent = vec![1; 166];
        intent[..4].copy_from_slice(b"\x01BWT");
        intent[44..76].fill(6);
        packet(&[
            b"\x01BMP",
            &[7; 32],
            &[u8::from(status == 1)],
            &intent,
            if status >= 2 { &[9; 64] } else { &[] },
            &[status],
        ])
    }
    #[test]
    fn signing_uses_only_native_intent_and_commits_before_submit() {
        let calls = RefCell::new(Vec::new());
        let output = movement(
            &packet(&[b"/db", &[6; 32]]),
            b"/db",
            |name, input| {
                calls.borrow_mut().push(name.to_string());
                if name.ends_with("_prepare") {
                    assert_eq!(input, packet(&[b"/db", &[6; 32], &[2; 32]]));
                    Ok(prepared(1))
                } else if name.ends_with("_commit") {
                    assert_eq!(input, packet(&[b"/db", &[7; 32], &[8; 200]]));
                    Ok(fixture(2))
                } else {
                    assert!(name.ends_with("_submit"));
                    Ok(fixture(3))
                }
            },
            |op, input| {
                calls.borrow_mut().push(format!("sdk{op}"));
                if op == 2 {
                    assert!(input.is_empty());
                    Ok(vec![2; 32])
                } else {
                    assert_eq!(op, 5);
                    assert_eq!(input.len(), 166);
                    assert_eq!(&input[..4], b"\x01BWT");
                    Ok(vec![8; 200])
                }
            },
        )
        .unwrap();
        assert_eq!(output, fixture(3));
        assert_eq!(
            *calls.borrow(),
            [
                "sdk2",
                "mesh_messenger_bounty_transfer_prepare",
                "sdk5",
                "mesh_messenger_bounty_transfer_commit",
                "mesh_messenger_bounty_transfer_submit"
            ]
        );
    }
    #[test]
    fn signed_unknown_and_completed_never_sign_again() {
        for status in [2, 3, 4, 5] {
            let output = movement(
                &packet(&[b"/db", &[6; 32]]),
                b"/db",
                |name, _| {
                    if name.ends_with("_prepare") {
                        Ok(prepared(status))
                    } else if name.ends_with("_status") {
                        Ok(fixture(status))
                    } else {
                        assert!(name.ends_with("_submit") && status < 4);
                        Ok(fixture(3))
                    }
                },
                |op, _| {
                    assert_eq!(op, 2);
                    Ok(vec![2; 32])
                },
            )
            .unwrap();
            assert_eq!(output, fixture(if status < 4 { 3 } else { status }));
        }
    }
    #[test]
    fn forged_database_or_malformed_native_intent_never_reaches_signer() {
        assert!(movement(
            &packet(&[b"/other", &[6; 32]]),
            b"/db",
            |_, _| panic!(),
            |_, _| panic!()
        )
        .is_err());
        assert!(movement(
            &packet(&[b"/db", &[6; 32]]),
            b"/db",
            |_, _| {
                let mut v = prepared(1);
                v.push(1);
                Ok(v)
            },
            |op, _| {
                assert_eq!(op, 2);
                Ok(vec![2; 32])
            }
        )
        .is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    fn view(enabled: bool, status: u8) -> Vec<u8> {
        let proof = if status == 0 { vec![] } else { vec![7; 32] };
        let finder = match status {
            0 | 1 => vec![],
            2 | 4 => vec![0; 32],
            _ => vec![8; 32],
        };
        packet(&[
            b"\x01BFP",
            &[u8::from(enabled)],
            &[status],
            &proof,
            &finder,
            &0u64.to_be_bytes(),
        ])
    }
    #[test]
    fn both_exports_retry_if_detection_races_the_initial_empty_view() {
        for symbol in [
            "mesh_messenger_transparency_fork",
            "mesh_messenger_fork_filing",
        ] {
            let calls = Cell::new(0);
            let committed = Cell::new(false);
            let result = invoke_proof(
                symbol,
                b"/db",
                |name, _| {
                    if name.ends_with("_status") {
                        return Ok(view(
                            true,
                            if committed.get() {
                                3
                            } else if calls.get() == 0 {
                                0
                            } else {
                                1
                            },
                        ));
                    }
                    if name.ends_with("_commit") {
                        committed.set(true);
                        return Ok(view(true, 3));
                    }
                    assert_eq!(name, symbol);
                    calls.set(calls.get() + 1);
                    if !committed.get() {
                        Err("Mesh7: bounty_selection_pending".into())
                    } else {
                        Ok(vec![42])
                    }
                },
                |operation, _| {
                    assert_eq!(operation, 4);
                    Ok([0; 8].into_iter().chain([9; 32]).collect())
                },
            )
            .unwrap();
            assert_eq!(result, vec![42]);
            assert_eq!(calls.get(), 2);
        }
    }
    #[test]
    fn terminal_proofs_never_reserve_an_address() {
        for status in [0, 2, 3, 4, 5] {
            preflight(
                b"/db",
                |name, input| {
                    assert_eq!(name, "mesh_messenger_bounty_status");
                    assert_eq!(input, b"/db");
                    Ok(view(false, status))
                },
                |_, _| panic!("SDK must remain unused"),
            )
            .unwrap();
        }
    }
    #[test]
    fn only_sdk_output_is_committed_to_the_exact_pending_raw_proof() {
        let sdk_calls = Cell::new(0);
        let raw = [0; 8].into_iter().chain([9; 32]).collect::<Vec<_>>();
        preflight(
            b"/db",
            |name, input| {
                if name.ends_with("_status") {
                    Ok(view(true, 1))
                } else {
                    assert_eq!(name, "mesh_messenger_bounty_commit");
                    assert_eq!(input, packet(&[b"/db", &[7; 32], &raw]));
                    Ok(view(true, 3))
                }
            },
            |operation, input| {
                assert_eq!(operation, 4);
                assert!(input.is_empty());
                sdk_calls.set(sdk_calls.get() + 1);
                Ok(raw.clone())
            },
        )
        .unwrap();
        assert_eq!(sdk_calls.get(), 1);
    }
    #[test]
    fn sdk_failure_falls_back_but_a_commit_race_never_overwrites_the_winner() {
        preflight(
            b"/db",
            |name, input| {
                if name.ends_with("_status") {
                    Ok(view(true, 1))
                } else {
                    assert_eq!(name, "mesh_messenger_bounty_unavailable");
                    assert_eq!(input, packet(&[b"/db", &[7; 32]]));
                    Ok(view(true, 4))
                }
            },
            |_, _| Err("wallet_locked".into()),
        )
        .unwrap();
        let reads = Cell::new(0);
        let sdk_calls = Cell::new(0);
        preflight(
            b"/db",
            |name, _| {
                if name.ends_with("_status") {
                    reads.set(reads.get() + 1);
                    Ok(view(true, if reads.get() == 1 { 1 } else { 3 }))
                } else {
                    assert!(name.ends_with("_commit"));
                    Err("bounty_selection_frozen".into())
                }
            },
            |_, _| {
                sdk_calls.set(sdk_calls.get() + 1);
                Ok([0; 8].into_iter().chain([9; 32]).collect())
            },
        )
        .unwrap();
        assert_eq!(sdk_calls.get(), 1);
    }
    #[test]
    fn malformed_native_view_cannot_reach_the_sdk_and_retries_are_bounded() {
        let mut corrupt = view(true, 1);
        corrupt.push(0);
        assert!(preflight(
            b"/db",
            |_, _| Ok(corrupt.clone()),
            |_, _| panic!("bad view reached SDK")
        )
        .is_err());
        let sdk_calls = Cell::new(0);
        assert!(preflight(
            b"/db",
            |name, _| if name.ends_with("_status") {
                Ok(view(true, 1))
            } else {
                Err("local_state_changed".into())
            },
            |_, _| {
                sdk_calls.set(sdk_calls.get() + 1);
                Ok([0; 8].into_iter().chain([9; 32]).collect())
            }
        )
        .is_err());
        assert_eq!(sdk_calls.get(), 3);
    }
    #[test]
    fn disabling_needs_no_wallet_but_enabling_proves_existing_custody_first() {
        let result = set_enabled(
            b"/db",
            0,
            |name, input| {
                assert_eq!(name, "mesh_messenger_bounty_set_enabled");
                assert_eq!(input, packet(&[b"/db", &[0]]));
                Ok(view(false, 0))
            },
            |_, _| panic!("disable must not require config or custody"),
        );
        assert_eq!(result.unwrap(), view(false, 0));
        assert!(set_enabled(
            b"/db",
            1,
            |_, _| panic!("failed wallet must not change preference"),
            |operation, _| {
                assert_eq!(operation, 2);
                Err("wallet_missing".into())
            }
        )
        .is_err());
        assert_eq!(
            set_enabled(
                b"/db",
                1,
                |_, input| {
                    assert_eq!(input, packet(&[b"/db", &[1]]));
                    Ok(view(true, 0))
                },
                |operation, input| {
                    assert_eq!(operation, 2);
                    assert!(input.is_empty());
                    Ok(vec![9; 32])
                }
            )
            .unwrap(),
            view(true, 0)
        );
    }
}
