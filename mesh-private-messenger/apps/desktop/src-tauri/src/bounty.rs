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
struct MovementSignature([u8; 64]);
impl MovementSignature {
    fn stored(bytes: &[u8]) -> Result<Self, String> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| "invalid_bounty_transfer_response".into())
    }
    fn signed_wire(wire: &[u8]) -> Result<Self, String> {
        // SDK5 uses a canonical one-byte count followed by two signatures and a message.
        // Core authenticates the full packet; the host retains only its first signature.
        if !(130..=1232).contains(&wire.len()) || wire[0] != 2 {
            return Err("invalid_bounty_wallet_response".into());
        }
        Self::stored(&wire[1..65])
    }
}
fn movement_result(
    input: &[u8],
    identity: &[u8],
    destination: &[u8],
    expected: &MovementSignature,
) -> Result<u8, String> {
    let fields = movement_fields(input, 12, 2048)?;
    if fields[0] != b"\x01BMW"
        || fields[1] != identity
        || fields[3] != expected.0
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

// These decoders check the native ABI, not bounty eligibility or economics.
fn movement_row(input: &[u8]) -> Result<Vec<&[u8]>, String> {
    let f = movement_fields(input, 12, 2048)?;
    let invalid = || "invalid_bounty_transfer_response".to_owned();
    if f[0] != b"\x01BMW"
        || f[2].len() != 1
        || f[2][0] > 5
        || f[7].len() != 8
        || f[8].len() != 1
        || f[8][0] > 18
        || f[9].len() != 8
        || f[10].len() != 8
        || f[11].len() > 256
        || std::str::from_utf8(f[11]).is_err()
    {
        return Err(invalid());
    }
    let status = f[2][0];
    if f[1].is_empty() {
        if status != 0 || [3, 4, 5, 6].iter().any(|&i| !f[i].is_empty()) {
            return Err(invalid());
        }
    } else if f[1].len() != 32
        || f[1].iter().all(|n| *n == 0)
        || [4, 5, 6].iter().any(|&i| f[i].len() != 32)
        || (if status < 2 {
            !f[3].is_empty()
        } else {
            f[3].len() != 64
        })
    {
        return Err(invalid());
    }
    Ok(f)
}
fn movement_aggregate(input: &[u8], asset: u8) -> Result<Option<Vec<&[u8]>>, String> {
    let f = movement_fields(input, 6, 8192)?;
    let invalid = || "invalid_bounty_transfer_response".to_owned();
    if f[0] != b"\x02BMW"
        || f[1].len() != 1
        || f[1][0] > 2
        || f[2].len() > 256
        || std::str::from_utf8(f[2]).is_err()
    {
        return Err(invalid());
    }
    match f[1][0] {
        0 => {
            if f[3..].iter().any(|v| !v.is_empty()) {
                return Err(invalid());
            }
            Ok(None)
        }
        1 => {
            if f[3].is_empty() || !f[4].is_empty() || !f[5].is_empty() {
                return Err(invalid());
            }
            let row = movement_row(f[3])?;
            Ok(if asset == 0 && !row[1].is_empty() {
                Some(row)
            } else {
                None
            })
        }
        2 => {
            if !f[3].is_empty() {
                return Err(invalid());
            }
            let mut selected = None;
            for selector in [1u8, 2] {
                let leg = movement_fields(f[selector as usize + 3], 7, 4096)?;
                if leg[0] != b"\x02BML"
                    || leg[1] != [selector]
                    || leg[2].len() != 1
                    || leg[2][0] > 3
                    || leg[3].len() != 32
                    || leg[4].len() != 8
                    || leg[5].len() != 1
                    || (leg[5][0] > 18 && !(leg[5][0] == 255 && leg[2][0] != 3))
                {
                    return Err(invalid());
                }
                if leg[2][0] == 3 {
                    let row = movement_row(leg[6])?;
                    if row[1].is_empty() || row[6] != leg[3] || row[7] != leg[4] || row[8] != leg[5] {
                        return Err(invalid());
                    }
                    if selector == asset {
                        selected = Some(row);
                    }
                } else if !leg[6].is_empty() {
                    return Err(invalid());
                }
            }
            Ok(selected)
        }
        _ => unreachable!(),
    }
}
fn movement_matches(row: &[&[u8]], identity: &[u8], intent: &[u8]) -> bool {
    row[1] == identity
        && row[4] == &intent[12..44]
        && row[5] == &intent[44..76]
        && row[6] == &intent[76..108]
        && row[7] == &intent[108..116]
        && row[8] == &intent[165..166]
}
fn movement_v2<M, S>(
    request: &[&[u8]],
    database: &[u8],
    mesh: &mut M,
    sdk: &mut S,
) -> Result<Vec<u8>, String>
where
    M: FnMut(&str, &[u8]) -> Result<Vec<u8>, String>,
    S: FnMut(u32, &[u8]) -> Result<Vec<u8>, String>,
{
    let invalid = || "invalid_bounty_transfer_response".to_owned();
    if request.len() != 4
        || request[1] != database
        || request[2].len() != 1
        || request[2][0] > 2
        || request[3].len() != 32
        || request[3].iter().all(|n| *n == 0)
    {
        return Err("invalid_bounty_transfer_request".into());
    }
    let asset = request[2][0];
    let payer = sdk(2, &[])?;
    if payer.len() != 32 || payer.iter().all(|n| *n == 0) {
        return Err("invalid_bounty_wallet_response".into());
    }
    let raw = mesh(
        "mesh_messenger_bounty_transfer_prepare",
        &packet(&[b"\x02BMR", database, request[2], request[3], &payer]),
    )?;
    let p = movement_fields(&raw, 8, 8192)?;
    if p[0] != b"\x02BMP"
        || p[1] != request[2]
        || p[3].len() != 1
        || p[3][0] > 1
        || p[6].len() != 1
        || p[6][0] > 5
    {
        return Err(invalid());
    }
    let selected = movement_aggregate(p[7], asset)?;
    let status = p[6][0];
    if status == 0 {
        if !p[2].is_empty()
            || p[3] != [0]
            || !p[4].is_empty()
            || !p[5].is_empty()
            || selected.is_some()
        {
            return Err(invalid());
        }
        return Ok(p[7].to_vec());
    }
    if p[2].len() != 32
        || p[2].iter().all(|n| *n == 0)
        || p[4].len() != 166
        || &p[4][..4] != b"\x01BWT"
        || (if status < 2 {
            !p[5].is_empty()
        } else {
            p[5].len() != 64
        })
    {
        return Err(invalid());
    }
    let row = selected.ok_or_else(invalid)?;
    let identity = row[1];
    if row[2] != p[6] || row[3] != p[5] || !movement_matches(&row, identity, p[4]) {
        return Err(invalid());
    }
    let same_destination = &p[4][44..76] == request[3];
    if p[3][0] != u8::from(status == 1 && same_destination) {
        return Err(invalid());
    }
    if !same_destination || status >= 4 {
        return Ok(p[7].to_vec());
    }
    let expected = if p[3][0] == 1 {
        let wire = sdk(5, p[4])?;
        let expected = MovementSignature::signed_wire(&wire)?;
        let committed = mesh(
            "mesh_messenger_bounty_transfer_commit",
            &packet(&[b"\x02BMR", database, request[2], p[2], &wire]),
        )?;
        let row = movement_aggregate(&committed, asset)?.ok_or_else(invalid)?;
        if row[2][0] < 2 || row[3] != expected.0 || !movement_matches(&row, identity, p[4]) {
            return Err(invalid());
        }
        if row[2][0] >= 4 {
            return Ok(committed);
        }
        expected
    } else {
        MovementSignature::stored(p[5])?
    };
    let output = mesh(
        "mesh_messenger_bounty_transfer_submit",
        &packet(&[b"\x02BMR", database, request[2], identity, &expected.0]),
    )?;
    let row = movement_aggregate(&output, asset)?.ok_or_else(invalid)?;
    if row[2][0] < 2 || row[3] != expected.0 || !movement_matches(&row, identity, p[4]) {
        return Err(invalid());
    }
    Ok(output)
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
    let count = input
        .get(..4)
        .and_then(|v| v.try_into().ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0) as usize;
    if count != 2 && count != 4 {
        return Err("invalid_bounty_transfer_request".into());
    }
    let request = movement_fields(input, count, 8192)?;
    if request[0] == b"\x02BMR" {
        return movement_v2(&request, database, &mut mesh, &mut sdk);
    }
    if count != 2 || (request[0].len() == 4 && &request[0][1..] == b"BMR") {
        return Err("invalid_bounty_transfer_request".into());
    }
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
    let expected = if plan[2][0] == 1 {
        let wire = sdk(5, plan[3])?;
        let expected = MovementSignature::signed_wire(&wire)?;
        let committed = mesh(
            "mesh_messenger_bounty_transfer_commit",
            &packet(&[database, identity, &wire]),
        )?;
        let status = movement_result(&committed, identity, request[1], &expected)?;
        if status >= 4 {
            return Ok(committed);
        }
        if status < 2 {
            return Err("invalid_bounty_transfer_response".into());
        }
        expected
    } else {
        let expected = MovementSignature::stored(plan[4])?;
        if plan[5][0] >= 4 {
            let output = mesh("mesh_messenger_bounty_transfer_status", database)?;
            movement_result(&output, identity, request[1], &expected)?;
            return Ok(output);
        }
        expected
    };
    let output = mesh(
        "mesh_messenger_bounty_transfer_submit",
        &packet(&[database, identity, &expected.0]),
    )?;
    let status = movement_result(&output, identity, request[1], &expected)?;
    if status < 2 {
        return Err("invalid_bounty_transfer_response".into());
    }
    Ok(output)
}

#[cfg(test)]
fn sdk_wire() -> Vec<u8> {
    [vec![2], vec![9; 64], vec![3; 135]].concat()
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
                    assert_eq!(input, packet(&[b"/db", &[7; 32], &sdk_wire()]));
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
                    Ok(sdk_wire())
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

#[cfg(test)]
mod mixed_movement_tests {
    use super::*;
    use std::cell::RefCell;
    fn intent(destination: u8) -> Vec<u8> {
        let mut v = vec![0; 166];
        v[..4].copy_from_slice(b"\x01BWT");
        v[12..44].fill(4);
        v[44..76].fill(destination);
        v[76..108].fill(5);
        v[108..116].copy_from_slice(&100u64.to_be_bytes());
        v[165] = 6;
        v
    }
    fn row(status: u8, destination: u8) -> Vec<u8> {
        packet(&[
            b"\x01BMW",
            &[7; 32],
            &[status],
            if status >= 2 { &[9; 64] } else { &[] },
            &[4; 32],
            &[destination; 32],
            &[5; 32],
            &100u64.to_be_bytes(),
            &[6],
            &0u64.to_be_bytes(),
            &0u64.to_be_bytes(),
            b"",
        ])
    }
    fn aggregate(asset: u8, status: u8, destination: u8, availability: u8) -> Vec<u8> {
        if asset == 0 {
            return packet(&[
                b"\x02BMW",
                &[1],
                b"",
                &row(status.max(1), destination),
                b"",
                b"",
            ]);
        }
        let leg = |selector| {
            packet(&[
                b"\x02BML",
                &[selector],
                &[if selector == asset { availability } else { 1 }],
                &[5; 32],
                &(if selector == asset && availability != 1 {
                    100u64
                } else {
                    0
                })
                .to_be_bytes(),
                &[if selector == asset && availability == 3 {
                    6
                } else {
                    255
                }],
                &if selector == asset && availability == 3 {
                    row(status, destination)
                } else {
                    vec![]
                },
            ])
        };
        packet(&[b"\x02BMW", &[2], b"", b"", &leg(1), &leg(2)])
    }
    fn plan(asset: u8, status: u8, destination: u8, availability: u8) -> Vec<u8> {
        let active = status != 0;
        packet(&[
            b"\x02BMP",
            &[asset],
            if active { &[8; 32] } else { b"" },
            &[u8::from(status == 1 && destination == 6)],
            &if active { intent(destination) } else { vec![] },
            if status >= 2 { &[9; 64] } else { b"" },
            &[status],
            &aggregate(asset, status, destination, availability),
        ])
    }
    fn request(asset: u8) -> Vec<u8> {
        packet(&[b"\x02BMR", b"/db", &[asset], &[6; 32]])
    }
    fn replace(input: &[u8], count: usize, index: usize, value: &[u8]) -> Vec<u8> {
        let mut f = movement_fields(input, count, 8192).unwrap();
        f[index] = value;
        packet(&f)
    }
    #[test]
    fn v2_morse_signs_with_a_cancelled_usdc_sibling() {
        let cancelled = aggregate(1, 0, 6, 3);
        let leg = movement_fields(&cancelled, 6, 8192).unwrap()[4];
        let with_cancelled = |value: Vec<u8>| replace(&value, 6, 4, leg);
        let calls = RefCell::new(Vec::new());
        let output = movement(&request(2), b"/db", |name, _| {
            calls.borrow_mut().push(name.to_owned());
            if name.ends_with("_prepare") {
                Ok(replace(&plan(2, 1, 6, 3), 8, 7, &with_cancelled(aggregate(2, 1, 6, 3))))
            } else if name.ends_with("_commit") { Ok(with_cancelled(aggregate(2, 2, 6, 3))) }
            else { assert!(name.ends_with("_submit")); Ok(with_cancelled(aggregate(2, 3, 6, 3))) }
        }, |op, input| {
            calls.borrow_mut().push(format!("sdk{op}"));
            if op == 2 { Ok(vec![2; 32]) } else { assert_eq!(op, 5); assert_eq!(input, intent(6)); Ok(sdk_wire()) }
        }).unwrap();
        assert_eq!(output, with_cancelled(aggregate(2, 3, 6, 3)));
        assert_eq!(*calls.borrow(), ["sdk2", "mesh_messenger_bounty_transfer_prepare", "sdk5", "mesh_messenger_bounty_transfer_commit", "mesh_messenger_bounty_transfer_submit"]);
    }

    #[test]
    fn cancelled_identity_is_preserved_and_cannot_masquerade_as_no_attempt() {
        let cancelled = row(0, 6);
        let legacy = packet(&[b"\x02BMW", &[1], b"", &cancelled, b"", b""]);
        assert!(movement_aggregate(&legacy, 0).unwrap().is_some());
        assert!(movement_aggregate(&legacy, 1).unwrap().is_none());
        let no_attempt = replace(&plan(0, 0, 6, 3), 8, 7, &legacy);
        let result = movement(&request(0), b"/db", |name, _| { assert!(name.ends_with("_prepare")); Ok(no_attempt.clone()) }, |op, _| { assert_eq!(op, 2); Ok(vec![2; 32]) });
        assert!(result.is_err());
    }

    #[test]
    fn v2_signs_each_asset_and_commits_handle_before_submitting_leg_identity() {
        for asset in [0, 1, 2] {
            let calls = RefCell::new(Vec::new());
            let output = movement(
                &request(asset),
                b"/db",
                |name, input| {
                    calls.borrow_mut().push(name.to_owned());
                    if name.ends_with("_prepare") {
                        assert_eq!(
                            input,
                            packet(&[b"\x02BMR", b"/db", &[asset], &[6; 32], &[2; 32]])
                        );
                        Ok(plan(asset, 1, 6, 3))
                    } else if name.ends_with("_commit") {
                        assert_eq!(
                            input,
                            packet(&[b"\x02BMR", b"/db", &[asset], &[8; 32], &sdk_wire()])
                        );
                        Ok(aggregate(asset, 2, 6, 3))
                    } else {
                        assert!(name.ends_with("_submit"));
                        assert_eq!(input, packet(&[b"\x02BMR", b"/db", &[asset], &[7; 32], &[9; 64]]));
                        Ok(aggregate(asset, 3, 6, 3))
                    }
                },
                |op, input| {
                    calls.borrow_mut().push(format!("sdk{op}"));
                    match op {
                        2 => {
                            assert!(input.is_empty());
                            Ok(vec![2; 32])
                        }
                        5 => {
                            assert_eq!(input, intent(6));
                            Ok(sdk_wire())
                        }
                        _ => panic!(),
                    }
                },
            )
            .unwrap();
            assert_eq!(output, aggregate(asset, 3, 6, 3));
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
    }
    #[test]
    fn v2_pending_other_destination_and_terminal_return_embedded_state_without_send() {
        for asset in [1, 2] {
            for (status, dest) in [(1, 10), (2, 10), (3, 10), (4, 6), (5, 6)] {
                let output = movement(
                    &request(asset),
                    b"/db",
                    |name, _| {
                        assert!(name.ends_with("_prepare"));
                        Ok(plan(asset, status, dest, 3))
                    },
                    |op, _| {
                        assert_eq!(op, 2);
                        Ok(vec![2; 32])
                    },
                )
                .unwrap();
                assert_eq!(output, aggregate(asset, status, dest, 3));
            }
        }
    }
    #[test]
    fn v2_ready_zero_and_unavailable_are_read_only() {
        for asset in [1, 2] {
            for availability in [0, 1, 2] {
                let output = movement(
                    &request(asset),
                    b"/db",
                    |name, _| {
                        assert!(name.ends_with("_prepare"));
                        Ok(plan(asset, 0, 6, availability))
                    },
                    |op, _| {
                        assert_eq!(op, 2);
                        Ok(vec![2; 32])
                    },
                )
                .unwrap();
                assert_eq!(output, aggregate(asset, 0, 6, availability));
            }
        }
        let unavailable = packet(&[b"\x02BMW", &[0], b"not configured", b"", b"", b""]);
        let raw = packet(&[b"\x02BMP", &[1], b"", &[0], b"", b"", &[0], &unavailable]);
        assert_eq!(
            movement(
                &request(1),
                b"/db",
                |_, _| Ok(raw.clone()),
                |op, _| {
                    assert_eq!(op, 2);
                    Ok(vec![2; 32])
                }
            )
            .unwrap(),
            unavailable
        );
    }
    #[test]
    fn v2_signed_same_destination_submits_without_resigning() {
        for asset in [1, 2] {
            for status in [2, 3] {
                let calls = RefCell::new(Vec::new());
                movement(
                    &request(asset),
                    b"/db",
                    |name, input| {
                        calls.borrow_mut().push(name.to_owned());
                        if name.ends_with("_prepare") {
                            Ok(plan(asset, status, 6, 3))
                        } else {
                            assert!(name.ends_with("_submit"));
                            assert_eq!(input, packet(&[b"\x02BMR", b"/db", &[asset], &[7; 32], &[9; 64]]));
                            Ok(aggregate(asset, 3, 6, 3))
                        }
                    },
                    |op, _| {
                        assert_eq!(op, 2);
                        Ok(vec![2; 32])
                    },
                )
                .unwrap();
                assert_eq!(calls.borrow().len(), 2);
            }
        }
    }
    #[test]
    fn malformed_v2_requests_are_closed_before_sdk_or_mesh() {
        let base = request(1);
        for bad in [
            replace(&base, 4, 0, b"\x03BMR"),
            replace(&base, 4, 2, &[3]),
            replace(&base, 4, 2, &[1, 2]),
            replace(&base, 4, 1, b"/other"),
            replace(&base, 4, 3, &[0; 32]),
            packet(&[b"\x02BMR", b"/db", &[1], &[6; 32], b"extra"]),
            packet(&[b"\x03BMR", &[6; 32]]),
            [base.clone(), vec![0]].concat(),
            vec![0; 8193],
        ] {
            assert!(movement(
                &bad,
                b"/db",
                |_, _| panic!("bad request reached Mesh"),
                |_, _| panic!("bad request reached SDK")
            )
            .is_err());
        }
    }
    #[test]
    fn v2_wrong_selector_identity_status_and_intent_terms_never_reach_signer() {
        let base = plan(1, 1, 6, 3);
        let agg = aggregate(1, 1, 6, 3);
        let leg = movement_fields(&agg, 6, 8192).unwrap()[4];
        let wrong_identity = replace(&row(2, 6), 12, 1, &[11; 32]);
        let bad_leg = replace(leg, 7, 6, &wrong_identity);
        let bad_agg = replace(&agg, 6, 4, &bad_leg);
        let mut bad_plans = vec![
            replace(&base, 8, 0, b"\x01BMP"),
            replace(&base, 8, 1, &[2]),
            replace(&base, 8, 6, &[2]),
            replace(&base, 8, 7, &replace(&agg, 6, 4, &replace(leg, 7, 1, &[2]))),
            replace(
                &base,
                8,
                7,
                &replace(&agg, 6, 4, &replace(leg, 7, 5, &[255])),
            ),
            replace(&base, 8, 7, &replace(&agg, 6, 2, &[255])),
            replace(&base, 8, 7, &[agg.clone(), vec![0]].concat()),
            replace(&base, 8, 3, &[0]),
            replace(&base, 8, 2, b""),
            replace(&base, 8, 5, &[9; 64]),
        ];
        for offset in [0, 12, 44, 76, 108, 165] {
            let mut bwt = intent(6);
            bwt[offset] ^= 1;
            bad_plans.push(replace(&base, 8, 4, &bwt));
        }
        for raw in bad_plans {
            assert!(movement(
                &request(1),
                b"/db",
                |name, _| {
                    assert!(name.ends_with("_prepare"));
                    Ok(raw.clone())
                },
                |op, _| {
                    assert_eq!(op, 2);
                    Ok(vec![2; 32])
                }
            )
            .is_err());
        }
        for bad in [
            replace(
                &aggregate(1, 2, 6, 3),
                6,
                4,
                &replace(leg, 7, 6, &row(2, 10)),
            ),
            bad_agg,
            aggregate(1, 1, 6, 3),
        ] {
            assert!(movement(
                &request(1),
                b"/db",
                |name, _| {
                    if name.ends_with("_prepare") {
                        Ok(base.clone())
                    } else {
                        assert!(name.ends_with("_commit"));
                        Ok(bad.clone())
                    }
                },
                |op, _| { Ok(if op == 2 { vec![2; 32] } else { sdk_wire() }) }
            )
            .is_err());
        }
    }
    fn correlated_request(asset: Option<u8>) -> Vec<u8> {
        asset
            .map(request)
            .unwrap_or_else(|| packet(&[b"/db", &[6; 32]]))
    }
    fn correlated_result(asset: Option<u8>, status: u8, signature: u8, dest: u8) -> Vec<u8> {
        let row = replace(&row(status, dest), 12, 3, &[signature; 64]);
        match asset {
            None => row,
            Some(0) => replace(&aggregate(0, status, dest, 3), 6, 3, &row),
            Some(a) => {
                let agg = aggregate(a, status, dest, 3);
                let leg = movement_fields(&agg, 6, 8192).unwrap()[a as usize + 3];
                replace(&agg, 6, a as usize + 3, &replace(leg, 7, 6, &row))
            }
        }
    }
    fn correlated_plan(asset: Option<u8>, status: u8, signature: u8) -> Vec<u8> {
        let sig = if status >= 2 {
            vec![signature; 64]
        } else {
            vec![]
        };
        match asset {
            None => packet(&[
                b"\x01BMP",
                &[7; 32],
                &[u8::from(status == 1)],
                &intent(6),
                &sig,
                &[status],
            ]),
            Some(a) if status == 1 => plan(a, status, 6, 3),
            Some(a) => replace(
                &replace(&plan(a, status, 6, 3), 8, 5, &sig),
                8,
                7,
                &correlated_result(asset, status, signature, 6),
            ),
        }
    }
    fn bound_submit(asset: Option<u8>, signature: u8) -> Vec<u8> {
        match asset {
            None => packet(&[b"/db", &[7; 32], &[signature; 64]]),
            Some(a) => packet(&[b"\x02BMR", b"/db", &[a], &[7; 32], &[signature; 64]]),
        }
    }
    #[test]
    fn submit_binds_sdk_or_prepared_signature_for_every_route() {
        for asset in [None, Some(0), Some(1), Some(2)] {
            for status in [1, 2, 3] {
                let sig = if status == 1 { 9 } else { 11 };
                let mut sends = 0;
                movement(
                    &correlated_request(asset),
                    b"/db",
                    |name, input| {
                        if name.ends_with("_prepare") {
                            Ok(correlated_plan(asset, status, sig))
                        } else if name.ends_with("_commit") {
                            Ok(correlated_result(asset, 2, sig, 6))
                        } else {
                            assert!(name.ends_with("_submit"));
                            assert_eq!(
                                input,
                                bound_submit(asset, sig),
                                "unbound submit for {asset:?} status {status}"
                            );
                            sends += 1;
                            Ok(correlated_result(asset, 3, sig, 6))
                        }
                    },
                    |op, _| {
                        if op == 2 {
                            Ok(vec![2; 32])
                        } else {
                            assert_eq!(status, 1);
                            assert_eq!(op, 5);
                            Ok(sdk_wire())
                        }
                    },
                )
                .unwrap();
                assert_eq!(sends, 1);
            }
        }
    }
    #[test]
    fn wrong_commit_signature_refuses_before_submit_including_terminal_commit() {
        for asset in [None, Some(0), Some(1), Some(2)] {
            for status in [2, 3, 4, 5] {
                let mut sends = 0;
                let result = movement(
                    &correlated_request(asset),
                    b"/db",
                    |name, _| {
                        if name.ends_with("_prepare") {
                            Ok(correlated_plan(asset, 1, 9))
                        } else if name.ends_with("_commit") {
                            Ok(correlated_result(asset, status, 11, 6))
                        } else {
                            sends += 1;
                            Ok(correlated_result(asset, 3, 11, 6))
                        }
                    },
                    |op, _| Ok(if op == 2 { vec![2; 32] } else { sdk_wire() }),
                );
                assert!(
                    result.is_err() && sends == 0,
                    "wrong commit signature accepted for {asset:?} status {status}; sends={sends}"
                );
            }
        }
    }
    #[test]
    fn final_response_must_keep_expected_signature() {
        for asset in [None, Some(0), Some(1), Some(2)] {
            for prepared_status in [1, 2, 3] {
                for final_status in [2, 3, 4, 5] {
                    let mut sends = 0;
                    let result = movement(
                        &correlated_request(asset),
                        b"/db",
                        |name, _| {
                            if name.ends_with("_prepare") {
                                Ok(correlated_plan(asset, prepared_status, 9))
                            } else if name.ends_with("_commit") {
                                Ok(correlated_result(asset, 2, 9, 6))
                            } else {
                                sends += 1;
                                Ok(correlated_result(asset, final_status, 11, 6))
                            }
                        },
                        |op, _| {
                            if op == 2 {
                                Ok(vec![2; 32])
                            } else {
                                assert_eq!(prepared_status, 1);
                                Ok(sdk_wire())
                            }
                        },
                    );
                    assert!(
                        result.is_err() && sends == 1,
                        "wrong final signature accepted for {asset:?}"
                    );
                }
            }
        }
    }
    #[test]
    fn stale_continuation_cannot_send_replacement_attempt() {
        for asset in [None, Some(0), Some(1), Some(2)] {
            for status in [1, 2, 3] {
                let mut stored_signature = 9;
                let mut attempts = 0;
                let mut sends = 0;
                let result = movement(
                    &correlated_request(asset),
                    b"/db",
                    |name, input| {
                        if name.ends_with("_prepare") {
                            let response = correlated_plan(asset, status, 9);
                            if status >= 2 {
                                stored_signature = 11;
                            }
                            Ok(response)
                        } else if name.ends_with("_commit") {
                            let response = correlated_result(asset, 2, 9, 6);
                            // Simulate another explicit operation replacing A before its callback returns.
                            stored_signature = 11;
                            Ok(response)
                        } else {
                            attempts += 1;
                            if input == bound_submit(asset, 9) && stored_signature != 9 {
                                return Err("bounty_attempt_changed".into());
                            }
                            sends += 1;
                            Ok(correlated_result(asset, 3, stored_signature, 10))
                        }
                    },
                    |op, _| {
                        if op == 2 {
                            Ok(vec![2; 32])
                        } else {
                            assert_eq!(status, 1);
                            Ok(sdk_wire())
                        }
                    },
                );
                assert!(result.is_err());
                assert_eq!(
                    (attempts, sends),
                    (1, 0),
                    "replacement sent before host rejection for {asset:?}"
                );
            }
        }
    }
    #[test]
    fn malformed_sdk_signature_prefix_never_reaches_commit() {
        let mut bad_wires: Vec<Vec<u8>> =
            [0, 1, 64, 65, 128, 129, 1233].map(|n| vec![2; n]).to_vec();
        for prefix in [0, 1, 3, 130] {
            let mut wire = sdk_wire();
            wire[0] = prefix;
            bad_wires.push(wire);
        }
        for asset in [None, Some(0), Some(1), Some(2)] {
            for wire in &bad_wires {
                let mut commits = 0;
                let result = movement(
                    &correlated_request(asset),
                    b"/db",
                    |name, _| {
                        if name.ends_with("_prepare") {
                            Ok(correlated_plan(asset, 1, 9))
                        } else {
                            commits += 1;
                            Err("unexpected_commit".into())
                        }
                    },
                    |op, _| Ok(if op == 2 { vec![2; 32] } else { wire.clone() }),
                );
                assert!(
                    result.is_err() && commits == 0,
                    "malformed SDK packet reached commit for {asset:?}: {} bytes",
                    wire.len()
                );
            }
        }
    }
}
