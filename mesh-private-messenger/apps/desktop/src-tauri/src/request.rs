pub const MAX_REQUEST: usize = 8 * 1024 * 1024;

pub fn maximum_response(symbol: &str) -> usize {
    if symbol == "mesh_messenger_load_history" {
        16_794_632
    } else {
        MAX_REQUEST
    }
}

pub fn maximum_request(symbol: &str) -> usize {
    if symbol == "mesh_messenger_fanout_send" {
        88_740
    } else if symbol == "mesh_messenger_attachment_upload" {
        16_782_000
    } else {
        MAX_REQUEST
    }
}

fn typed_fields<'a>(
    request: &'a [u8],
    counted: bool,
    bounds: &[usize],
) -> Result<&'a [u8], String> {
    typed_fields_optional(request, counted, bounds, &[])
}

fn typed_fields_optional<'a>(
    request: &'a [u8],
    counted: bool,
    bounds: &[usize],
    optional: &[usize],
) -> Result<&'a [u8], String> {
    let mut offset = 0usize;
    let read = |offset: &mut usize| -> Result<usize, String> {
        let value = request
            .get(*offset..*offset + 4)
            .ok_or("invalid_native_request")?;
        *offset += 4;
        Ok(u32::from_be_bytes(value.try_into().map_err(|_| "invalid_native_request")?) as usize)
    };
    if counted && read(&mut offset)? != bounds.len() {
        return Err("invalid_native_request".into());
    }
    let mut path = &request[..0];
    for (index, maximum) in bounds.iter().enumerate() {
        let length = read(&mut offset)?;
        if length > *maximum || (!counted && length == 0 && !optional.contains(&index)) {
            return Err("invalid_native_request".into());
        }
        let value = request
            .get(offset..offset + length)
            .ok_or("invalid_native_request")?;
        if index == 0 {
            path = value;
        }
        offset += length;
    }
    if offset != request.len() {
        return Err("invalid_native_request".into());
    }
    Ok(path)
}

pub fn binary_body(body: &tauri::ipc::InvokeBody, error: &'static str) -> Result<Vec<u8>, String> {
    bounded_binary_body(body, 0, MAX_REQUEST, error)
}

// Tauri's postMessage transport represents a binary request as a JSON array.
// Keep the same bounds as raw IPC and accept only exact unsigned byte values.
pub fn bounded_binary_body(
    body: &tauri::ipc::InvokeBody,
    minimum: usize,
    maximum: usize,
    error: &'static str,
) -> Result<Vec<u8>, String> {
    match body {
        tauri::ipc::InvokeBody::Raw(bytes) if bytes.len() >= minimum && bytes.len() <= maximum => {
            Ok(bytes.clone())
        }
        tauri::ipc::InvokeBody::Json(serde_json::Value::Array(values))
            if values.len() >= minimum && values.len() <= maximum =>
        {
            values
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|value| u8::try_from(value).ok())
                        .ok_or_else(|| error.to_owned())
                })
                .collect()
        }
        _ => Err(error.into()),
    }
}

#[cfg(test)]
mod binary_body_tests {
    use super::*;
    use tauri::ipc::InvokeBody;

    #[test]
    fn raw_and_postmessage_attachment_chunks_share_the_same_exact_bounds() {
        for length in [0, 1, 4, 5] {
            let bytes = vec![255; length];
            for body in [
                InvokeBody::Raw(bytes.clone()),
                InvokeBody::Json(serde_json::json!(bytes)),
            ] {
                let result = bounded_binary_body(&body, 1, 4, "invalid");
                if (1..=4).contains(&length) {
                    assert_eq!(result, Ok(vec![255; length]));
                } else {
                    assert_eq!(result, Err("invalid".into()));
                }
            }
        }
    }

    #[test]
    fn postmessage_binary_preserves_all_bytes_and_rejects_noncanonical_values() {
        let raw = vec![0, 1, 127, 128, 255];
        assert_eq!(
            binary_body(&InvokeBody::Raw(raw.clone()), "invalid"),
            Ok(raw.clone())
        );
        assert_eq!(
            binary_body(&InvokeBody::Json(serde_json::json!(raw)), "invalid"),
            Ok(raw)
        );
        assert_eq!(
            binary_body(&InvokeBody::Json(serde_json::json!([])), "invalid"),
            Ok(vec![])
        );
        for value in [
            serde_json::json!([-1]),
            serde_json::json!([256]),
            serde_json::json!([1.5]),
            serde_json::json!([true]),
            serde_json::json!(["1"]),
            serde_json::json!([[1]]),
            serde_json::json!({"0": 1}),
            serde_json::json!(null),
        ] {
            assert_eq!(
                binary_body(&InvokeBody::Json(value), "invalid"),
                Err("invalid".into())
            );
        }
    }
}
// Header values are ASCII, so the web view percent-encodes the suggested name.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let decoded = if bytes[index] == b'%' && index + 2 < bytes.len() {
            std::str::from_utf8(&bytes[index + 1..index + 3])
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        } else {
            None
        };
        match decoded {
            Some(byte) => {
                output.push(byte);
                index += 3;
            }
            None => {
                output.push(bytes[index]);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

// The suggested name in a save dialog comes from the sender: keep only a plain
// leaf name and fall back to a neutral one for anything else.
pub fn safe_file_name(name: &str) -> String {
    let cleaned: String = percent_decode(name)
        .chars()
        .filter(|character| !character.is_control() && !matches!(character, '/' | '\\' | ':'))
        .collect();
    let trimmed = cleaned.trim().trim_start_matches('.');
    if trimmed.is_empty() || trimmed.chars().count() > 255 {
        "attachment".to_owned()
    } else {
        trimmed.to_owned()
    }
}

// The generated C header is the export allowlist, shared with the mobile bridge.
const HEADER: &str =
    include_str!("../../../mobile/modules/mesh-messenger/generated/libmessenger_mobile.h");

pub fn public_export(symbol: &str) -> bool {
    !matches!(
        symbol,
        "mesh_messenger_prepare_fanout_prekeys"
            | "mesh_messenger_send_fanout"
            | "mesh_messenger_group_invite"
            | "mesh_messenger_group_invitation_accept"
            | "mesh_messenger_journal_load"
            | "mesh_messenger_journal_save"
            | "mesh_messenger_push_intent"
            | "mesh_messenger_push_action_complete"
            | "mesh_messenger_push_flow_validate"
            | "mesh_messenger_push_flow_intent"
            | "mesh_messenger_account_deletion"
            | "mesh_messenger_device_departure"
            | "mesh_messenger_create_device_revocation"
            | "mesh_messenger_renew_devices"
            | "mesh_messenger_erase_account"
            | "mesh_messenger_forget_on_proof"
            | "mesh_messenger_mailbox_fetch"
            | "mesh_messenger_process_delivery_batch"
            | "mesh_messenger_credit_wallet_prepare"
            | "mesh_messenger_credit_payment_handoff"
            | "mesh_messenger_credit_wallet_commit"
            | "mesh_messenger_credit_wallet_submit"
            | "mesh_messenger_bounty_transfer_prepare"
            | "mesh_messenger_bounty_transfer_commit"
            | "mesh_messenger_bounty_transfer_submit"
            | "mesh_messenger_bounty_set_enabled"
            | "mesh_messenger_bounty_commit"
            | "mesh_messenger_bounty_unavailable"
            | "mesh_messenger_register_request"
            | "mesh_messenger_register_signup_policy"
            | "mesh_messenger_replenish_prekeys"
            | "mesh_messenger_reconcile_prekeys"
            | "mesh_messenger_directory_lookup"
            | "mesh_messenger_transparency_lookup"
            | "mesh_messenger_resolve_request"
            | "mesh_messenger_resolve_plan"
            | "mesh_messenger_verify_transparency"
            | "mesh_messenger_outbox_list"
            | "mesh_messenger_outbox_page"
            | "mesh_messenger_outbox_ack"
            | "mesh_messenger_outbox_fail"
            | "mesh_messenger_privacy_submission"
            | "mesh_messenger_attachment_prepare"
            | "mesh_messenger_attachment_seal_chunk"
            | "mesh_messenger_attachment_open_chunk"
            | "mesh_messenger_view_once_consume"
    )
}

pub fn validate_public(symbol: &str, request: &[u8], database: &[u8]) -> Result<(), String> {
    if !public_export(symbol) {
        return Err("private_native_export".into());
    }
    validate(symbol, request, database)
}

pub fn validate(symbol: &str, request: &[u8], database: &[u8]) -> Result<(), String> {
    if !symbol.starts_with("mesh_messenger_")
        || !HEADER
            .lines()
            .any(|line| line.starts_with(&format!("int32_t {symbol}(")))
        || request.len() > maximum_request(symbol)
    {
        return Err("invalid_native_request".into());
    }
    let name = &symbol[15..];
    // These exports consume wire payloads, without opening a database.
    if matches!(
        name,
        "validate_outer"
            | "device_link_sas"
            | "import_contact"
            | "directory_lookup"
            | "privacy_submission"
    ) {
        return Ok(());
    }
    let path = if name == "fanout_send" {
        typed_fields_optional(
            request,
            false,
            &[4096, 36134, 65, 1, 32000, 32, 16384],
            &[4, 5, 6],
        )?
    } else if name == "attachment_upload" {
        typed_fields(request, true, &[4096, 255, 127, 16_777_216])?
    } else if name == "attachment_discard" {
        typed_fields(request, true, &[4096, 4096])?
    } else if name == "push_flow_begin" {
        typed_fields(request, false, &[4096, 36134, 1])?
    } else if matches!(
        name,
        "account_delete" | "account_discard" | "account_capabilities"
    ) {
        typed_fields(request, false, &[4096, 36134])?
    } else if name == "journal_load_bound" {
        typed_fields(request, false, &[4096, 36134, 256])?
    } else if name == "journal_save_bound" {
        typed_fields(request, false, &[4096, 36134, 256, 262144])?
    } else if name == "devices_renew" {
        typed_fields(request, false, &[4096, 305260])?
    } else if name == "device_revoke" {
        typed_fields(request, false, &[4096, 305260, 16])?
    } else if name == "push_flow_complete" {
        typed_fields(request, false, &[4096, 50, 1])?
    } else if name == "push_flow_send" {
        typed_fields(request, false, &[4096, 50])?
    } else if name == "outbox_drain" || name == "push_flow_intent" {
        typed_fields(request, false, &[4096, 1])?
    } else if name == "directory_resolve" {
        typed_fields(request, false, &[4096, 65])?
    } else if name.starts_with("credit_")
        || matches!(
            name,
            "signup_draft_rename"
                | "bounty_set_enabled"
                | "bounty_commit"
                | "bounty_unavailable"
                | "signup_draft_free"
                | "signup_draft_free_complete"
                | "register_signup_policy"
                | "bounty_transfer_prepare"
                | "bounty_transfer_commit"
                | "bounty_transfer_submit"
                | "bounty_transfer_recover"
                | "bounty_transfer_cancel"
                | "postage_policy_view"
                | "postage_policy_prepare"
                | "postage_policy_publish"
                | "attachment_download_plan"
                | "attachment_fetch_chunk"
                | "mailbox_stream_poll"
                | "mailbox_stream_close"
        )
    {
        let count = request.get(..4).ok_or("invalid_credit_request")?;
        let count = u32::from_be_bytes(count.try_into().map_err(|_| "invalid_credit_request")?);
        let maximum_fields = match name {
            "credit_attachment_prepare" => 5,
            "credit_attachment_part" | "credit_postage_prepare" | "postage_policy_publish" => 4,
            _ => 3,
        };
        if !(1..=maximum_fields).contains(&count) {
            return Err("invalid_credit_request".into());
        }
        let length = request.get(4..8).ok_or("invalid_database_path")?;
        let length =
            u32::from_be_bytes(length.try_into().map_err(|_| "invalid_database_path")?) as usize;
        request.get(8..8 + length).ok_or("invalid_database_path")?
    } else if matches!(
        name,
        "initialize"
            | "load_profile"
            | "signup_draft_state"
            | "bounty_status"
            | "create_link_request"
            | "group_key_package"
            | "group_invitations"
            | "group_create"
            | "group_list"
            | "push_status"
            | "list_conversations"
            | "transparency_fork"
            | "network_counter"
            | "anchor_check"
            | "fork_filing"
            | "directory_entry"
            | "register_request"
            | "mailbox_fetch"
            | "mailbox_synchronize"
            | "directory_register"
            | "prekeys_synchronize"
            | "mailbox_stream_open"
            | "outbox_list"
            | "account_deletion"
            | "erase_account"
            | "device_departure"
    ) {
        request
    } else {
        let length = request.get(..4).ok_or("invalid_database_path")?;
        let length =
            u32::from_be_bytes(length.try_into().map_err(|_| "invalid_database_path")?) as usize;
        request.get(4..4 + length).ok_or("invalid_database_path")?
    };
    if path != database {
        return Err("invalid_database_path".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn typed_upload_and_resolution_bound_the_whole_frame() {
        let database = b"/native/morse.db";
        let frame = |counted: bool, fields: &[&[u8]]| {
            let mut bytes = Vec::new();
            if counted {
                bytes.extend((fields.len() as u32).to_be_bytes());
            }
            for field in fields {
                bytes.extend((field.len() as u32).to_be_bytes());
                bytes.extend(*field);
            }
            bytes
        };
        let file = vec![7; 16_777_216];
        let upload = frame(
            true,
            &[database, b"file.bin", b"application/octet-stream", &file],
        );
        assert!(
            super::validate_public("mesh_messenger_attachment_upload", &upload, database).is_ok()
        );
        assert!(
            super::validate_public("mesh_messenger_attachment_upload", &upload, b"/wrong.db")
                .is_err()
        );
        assert!(
            super::validate_public("mesh_messenger_attachment_discard", &upload, database).is_err()
        );
        let oversized = frame(
            true,
            &[
                database,
                b"file.bin",
                b"application/octet-stream",
                &vec![7; 16_777_217],
            ],
        );
        assert!(
            super::validate_public("mesh_messenger_attachment_upload", &oversized, database)
                .is_err()
        );
        for name in ["attachment_discard", "directory_resolve"] {
            let symbol = format!("mesh_messenger_{name}");
            let counted = name == "attachment_discard";
            let request = frame(counted, &[database, b"opaque"]);
            assert!(super::validate_public(&symbol, &request, database).is_ok());
            assert!(super::validate_public(&symbol, &request, b"/wrong.db").is_err());
            let mut trailing = request.clone();
            trailing.push(0);
            assert!(super::validate_public(&symbol, &trailing, database).is_err());
            assert!(super::validate_public(
                &symbol,
                &frame(!counted, &[database, b"opaque"]),
                database
            )
            .is_err());
        }
        assert!(super::validate_public(
            "mesh_messenger_directory_resolve",
            &frame(false, &[database, &[b'a'; 66]]),
            database
        )
        .is_err());
        assert!(super::validate_public(
            "mesh_messenger_directory_resolve",
            &frame(false, &[database, b""]),
            database
        )
        .is_err());
        assert_eq!(
            super::maximum_request("mesh_messenger_credit_prepare"),
            super::MAX_REQUEST
        );
    }

    #[test]
    fn native_push_frames_are_opaque_and_bound_to_the_native_database() {
        let database = b"/native/morse.db";
        let ordinary = |fields: &[&[u8]]| {
            let mut bytes = Vec::new();
            for field in fields {
                bytes.extend((field.len() as u32).to_be_bytes());
                bytes.extend(*field);
            }
            bytes
        };
        for (symbol, fields) in [
            (
                "mesh_messenger_push_flow_begin",
                vec![database.as_slice(), &[7; 36134], &[1]],
            ),
            (
                "mesh_messenger_push_flow_complete",
                vec![database.as_slice(), &[7; 50], &[0]],
            ),
            (
                "mesh_messenger_push_flow_send",
                vec![database.as_slice(), &[7; 50]],
            ),
            (
                "mesh_messenger_account_delete",
                vec![database.as_slice(), &[7; 36134]],
            ),
            (
                "mesh_messenger_account_discard",
                vec![database.as_slice(), &[7; 36134]],
            ),
            (
                "mesh_messenger_account_capabilities",
                vec![database.as_slice(), &[7; 36134]],
            ),
            (
                "mesh_messenger_journal_load_bound",
                vec![database.as_slice(), &[7; 36134], &[7; 256]],
            ),
            (
                "mesh_messenger_journal_save_bound",
                vec![database.as_slice(), &[7; 36134], &[7; 256], &[7; 262144]],
            ),
            (
                "mesh_messenger_devices_renew",
                vec![database.as_slice(), &[7; 305260]],
            ),
            (
                "mesh_messenger_device_revoke",
                vec![database.as_slice(), &[7; 305260], &[7; 16]],
            ),
        ] {
            let frame = ordinary(&fields);
            assert!(validate_public(symbol, &frame, database).is_ok());
            assert!(validate_public(symbol, &frame, b"/other.db").is_err());
            let mut trailing = frame.clone();
            trailing.push(0);
            assert!(validate_public(symbol, &trailing, database).is_err());
            assert!(validate_public(symbol, &frame[..frame.len() - 1], database).is_err());
            let mut empty = fields.clone();
            empty[1] = b"";
            assert!(validate_public(symbol, &ordinary(&empty), database).is_err());
            let mut wide = fields.clone();
            let over = vec![7; fields[1].len() + 1];
            wide[1] = &over;
            assert!(validate_public(symbol, &ordinary(&wide), database).is_err());
            let mut counted = (fields.len() as u32).to_be_bytes().to_vec();
            counted.extend(frame);
            assert!(validate_public(symbol, &counted, database).is_err());
        }
        for symbol in [
            "mesh_messenger_push_intent",
            "mesh_messenger_push_action_complete",
            "mesh_messenger_push_flow_intent",
            "mesh_messenger_push_flow_validate",
            "mesh_messenger_account_deletion",
            "mesh_messenger_device_departure",
            "mesh_messenger_create_device_revocation",
            "mesh_messenger_renew_devices",
            "mesh_messenger_erase_account",
            "mesh_messenger_forget_on_proof",
        ] {
            assert_eq!(
                validate_public(symbol, &ordinary(&[database, &[1]]), database),
                Err("private_native_export".into())
            );
        }
    }

    #[test]
    fn legacy_mailbox_wire_exports_are_private() {
        for symbol in [
            "mesh_messenger_mailbox_fetch",
            "mesh_messenger_process_delivery_batch",
        ] {
            assert!(!super::public_export(symbol));
            assert_eq!(
                super::validate_public(symbol, b"/native/morse.db", b"/native/morse.db"),
                Err("private_native_export".into())
            );
        }
    }

    #[test]
    fn legacy_directory_wire_exports_are_private() {
        for symbol in [
            "mesh_messenger_register_request",
            "mesh_messenger_register_signup_policy",
            "mesh_messenger_replenish_prekeys",
            "mesh_messenger_reconcile_prekeys",
            "mesh_messenger_directory_lookup",
            "mesh_messenger_transparency_lookup",
            "mesh_messenger_resolve_request",
            "mesh_messenger_resolve_plan",
            "mesh_messenger_verify_transparency",
            "mesh_messenger_attachment_prepare",
            "mesh_messenger_attachment_seal_chunk",
            "mesh_messenger_attachment_open_chunk",
        ] {
            assert_eq!(
                super::validate_public(symbol, b"/native/morse.db", b"/native/morse.db"),
                Err("private_native_export".into())
            );
        }
    }

    #[test]
    fn directory_operations_accept_only_the_exact_native_database_path() {
        let database = b"/native/morse.db";
        for symbol in [
            "mesh_messenger_directory_register",
            "mesh_messenger_prekeys_synchronize",
        ] {
            assert!(super::validate_public(symbol, database, database).is_ok());
            for input in [b"/other.db".as_slice(), b"/native/morse.db\0", b""] {
                assert!(super::validate_public(symbol, input, database).is_err());
            }
            let mut framed = (database.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(database);
            assert!(super::validate_public(symbol, &framed, database).is_err());
        }
    }

    #[test]
    fn mailbox_stream_exports_are_bound_to_the_native_database() {
        let database = b"/native/morse.db";
        assert!(
            super::validate_public("mesh_messenger_mailbox_synchronize", database, database)
                .is_ok()
        );
        assert!(super::validate_public(
            "mesh_messenger_mailbox_synchronize",
            b"/other.db",
            database
        )
        .is_err());
        assert!(
            super::validate_public("mesh_messenger_mailbox_stream_open", database, database)
                .is_ok()
        );
        assert!(super::validate_public(
            "mesh_messenger_mailbox_stream_open",
            b"/other.db",
            database
        )
        .is_err());
        let mut request = 2u32.to_be_bytes().to_vec();
        request.extend_from_slice(&(database.len() as u32).to_be_bytes());
        request.extend_from_slice(database);
        request.extend_from_slice(&32u32.to_be_bytes());
        request.extend_from_slice(&[7; 32]);
        for symbol in [
            "mesh_messenger_mailbox_stream_poll",
            "mesh_messenger_mailbox_stream_close",
        ] {
            assert!(super::validate_public(symbol, &request, database).is_ok());
            assert!(super::validate_public(symbol, &request, b"/other.db").is_err());
        }
    }

    #[test]
    fn bounty_authority_exports_are_private_even_when_the_generated_abi_contains_them() {
        for symbol in [
            "mesh_messenger_bounty_set_enabled",
            "mesh_messenger_bounty_commit",
            "mesh_messenger_bounty_unavailable",
        ] {
            assert!(!super::public_export(symbol), "{symbol}");
        }
        assert!(super::public_export("mesh_messenger_bounty_status"));
        assert!(super::public_export("mesh_messenger_transparency_fork"));
    }
    use super::*;

    #[test]
    fn native_credit_packets_cannot_select_another_database() {
        let database = b"/app/private.db";
        let mut packet = 1u32.to_be_bytes().to_vec();
        packet.extend((database.len() as u32).to_be_bytes());
        packet.extend(database);
        assert!(validate("mesh_messenger_credit_balance", &packet, database).is_ok());
        assert!(validate("mesh_messenger_credit_balance", &packet, b"/app/other.db").is_err());
        assert!(validate("mesh_messenger_credit_balance", &[0; 4], database).is_err());
        assert!(validate("mesh_messenger_credit_balance", &[255; 8], database).is_err());
    }

    #[test]
    fn signup_and_paid_attachment_exports_preserve_the_native_database_pin() {
        let database = b"/app/private.db";
        let frame = |counted: bool, fields: &[&[u8]]| {
            let mut bytes = Vec::new();
            if counted {
                bytes.extend((fields.len() as u32).to_be_bytes());
            }
            for field in fields {
                bytes.extend((field.len() as u32).to_be_bytes());
                bytes.extend(*field);
            }
            bytes
        };
        for (name, input) in [
            ("signup_draft_state", database.to_vec()),
            ("create_signup_draft", frame(false, &[database, b"alice"])),
            (
                "signup_draft_rename",
                frame(true, &[database, b"alice_again"]),
            ),
            ("signup_draft_free", frame(true, &[database])),
            ("signup_draft_free_complete", frame(true, &[database])),
            ("register_signup_policy", frame(true, &[database, &[1; 88]])),
            (
                "attachment_download_plan",
                frame(true, &[database, &[1; 128]]),
            ),
            (
                "credit_attachment_prepare",
                frame(
                    true,
                    &[
                        database,
                        &[7; 32],
                        b"a.bin",
                        b"application/octet-stream",
                        &[1, 0, 0, 1],
                    ],
                ),
            ),
            (
                "credit_attachment_part",
                frame(true, &[database, &[7; 32], &[0; 4], &[5; 65_536]]),
            ),
        ] {
            let symbol = format!("mesh_messenger_{name}");
            assert!(validate(&symbol, &input, database).is_ok(), "{name}");
            assert!(
                validate(&symbol, &input, b"/app/other.db").is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn suggested_save_names_are_plain_leaf_names() {
        assert_eq!(safe_file_name("photo.jpg"), "photo.jpg");
        assert_eq!(
            safe_file_name("../../.ssh/authorized_keys"),
            "sshauthorized_keys"
        );
        assert_eq!(safe_file_name("..\\..\\evil.exe"), "evil.exe");
        assert_eq!(safe_file_name(".hidden"), "hidden");
        assert_eq!(safe_file_name("a\u{0}b\n.txt"), "ab.txt");
        assert_eq!(safe_file_name("   "), "attachment");
        assert_eq!(safe_file_name(""), "attachment");
        assert_eq!(safe_file_name(&"x".repeat(256)), "attachment");
        assert_eq!(safe_file_name("caf%C3%A9%20menu.pdf"), "café menu.pdf");
        assert_eq!(safe_file_name("%2E%2E%2Fetc%2Fpasswd"), "etcpasswd");
        assert_eq!(safe_file_name("100%25.txt"), "100%.txt");
        assert_eq!(safe_file_name("odd%zz%4"), "odd%zz%4");
    }

    #[test]
    fn only_the_app_database_and_known_exports_can_be_invoked() {
        let db = b"C:\\Users\\Alice\\Morse\\morse.db";
        let mut account = (db.len() as u32).to_be_bytes().to_vec();
        account.extend(db);
        account.extend([0, 0, 0, 5]);
        account.extend(b"alice");
        assert!(validate("mesh_messenger_create_account", &account, db).is_ok());
        assert!(validate("mesh_messenger_attachment_prepare", &account, db).is_ok());
        assert!(validate("mesh_messenger_attachment_seal_chunk", &account, b"other").is_err());
        assert!(validate("mesh_messenger_load_profile", db, db).is_ok());
        assert!(validate("mesh_messenger_transparency_fork", db, db).is_ok());
        assert!(validate("mesh_messenger_transparency_fork", b"/tmp/other.db", db).is_err());
        assert!(validate("mesh_messenger_anchor_check", db, db).is_ok());
        assert!(validate("mesh_messenger_anchor_check", b"/tmp/other.db", db).is_err());
        assert!(validate("mesh_messenger_fork_filing", db, db).is_ok());
        assert!(validate("mesh_messenger_fork_filing", b"/tmp/other.db", db).is_err());
        // The two stamped directory requests keep their unstamped twins' shapes:
        // a bare database path, and a path-prefixed lookup.
        assert!(validate("mesh_messenger_register_request", db, db).is_ok());
        assert!(validate("mesh_messenger_register_request", b"/tmp/other.db", db).is_err());
        assert!(validate("mesh_messenger_resolve_request", &account, db).is_ok());
        assert!(validate("mesh_messenger_resolve_request", &account, b"other").is_err());
        assert!(validate("mesh_messenger_resolve_plan", &account, db).is_ok());
        assert!(validate("mesh_messenger_resolve_plan", &account, b"other").is_err());
        // Deleting the account, leaving it, and erasing this device name only the app database.
        for symbol in [
            "mesh_messenger_account_deletion",
            "mesh_messenger_erase_account",
            "mesh_messenger_device_departure",
        ] {
            assert!(validate(symbol, db, db).is_ok());
            assert!(validate(symbol, b"/tmp/other.db", db).is_err());
        }
        assert!(validate("mesh_messenger_forget_on_proof", &account, db).is_ok());
        assert!(validate("mesh_messenger_forget_on_proof", &account, b"other").is_err());
        // Settling and paging the outbox carry the database path like any other call.
        // So do the sealed journals: which record they name is the core's to check.
        for symbol in [
            "mesh_messenger_outbox_fail",
            "mesh_messenger_outbox_page",
            "mesh_messenger_journal_load",
            "mesh_messenger_journal_save",
        ] {
            assert!(validate(symbol, &account, db).is_ok());
            assert!(validate(symbol, &account, b"other").is_err());
        }
        assert!(validate("mesh_messenger_load_profile", b"/tmp/other.db", db).is_err());
        assert!(validate("mesh_messenger_create_account", &account, b"other").is_err());
        assert!(validate("mesh_messenger_create_account", &[255; 4], db).is_err());
        assert!(validate("mesh_library_shutdown", &[], db).is_err());
        assert!(validate("mesh_messenger_unknown", db, db).is_err());
        assert!(validate(
            "mesh_messenger_validate_outer",
            &vec![0; MAX_REQUEST + 1],
            db
        )
        .is_err());
    }

    #[test]
    fn fanout_keeps_empty_optional_fields_and_bounds_every_vector() {
        let frame = |parts: &[Vec<u8>]| -> Vec<u8> {
            parts
                .iter()
                .flat_map(|part| {
                    let mut field = (part.len() as u32).to_be_bytes().to_vec();
                    field.extend_from_slice(part);
                    field
                })
                .collect()
        };
        let bounds = [4096, 36134, 65, 1, 32000, 32, 16384];
        let parts = vec![
            b"/app/db".to_vec(),
            vec![1; 8],
            b"bob".to_vec(),
            vec![1],
            b"hello".to_vec(),
            vec![],
            vec![],
        ];
        let parse = |wire: &[u8]| {
            typed_fields_optional(wire, false, &bounds, &[4, 5, 6]).map(|path| path.to_vec())
        };
        let valid = frame(&parts);
        assert_eq!(parse(&valid).unwrap(), b"/app/db");
        assert!(validate_public("mesh_messenger_fanout_send", &valid, b"/app/db").is_ok());
        assert!(validate_public("mesh_messenger_fanout_send", &valid, b"/other/db").is_err());
        let mut attachment = parts.clone();
        attachment[4].clear();
        attachment[6] = vec![7; 16];
        assert!(parse(&frame(&attachment)).is_ok());
        for index in 0..bounds.len() {
            let mut over = parts.clone();
            over[index] = vec![1; bounds[index] + 1];
            assert!(parse(&frame(&over)).is_err(), "oversized field {index}");
            if index < 4 {
                let mut empty = parts.clone();
                empty[index].clear();
                assert!(parse(&frame(&empty)).is_err(), "empty field {index}");
            }
        }
        let maximum: Vec<Vec<u8>> = bounds.iter().map(|bound| vec![1; *bound]).collect();
        assert_eq!(frame(&maximum).len(), 88740);
        assert!(parse(&frame(&maximum)).is_ok());
        assert!(parse(&[7u32.to_be_bytes().as_slice(), valid.as_slice()].concat()).is_err());
        assert!(parse(&[valid.as_slice(), &[0]].concat()).is_err());
        assert!(parse(&valid[..valid.len() - 1]).is_err());
        let mut extra = parts.clone();
        extra.push(vec![]);
        assert!(parse(&frame(&extra)).is_err());
        assert_eq!(maximum_request("mesh_messenger_fanout_send"), 88740);
    }

    #[test]
    fn private_wallet_journals_never_enter_generic_js_dispatch() {
        for name in [
            "journal_load",
            "journal_save",
            "prepare_fanout_prekeys",
            "send_fanout",
            "group_invite",
            "group_invitation_accept",
            "credit_wallet_prepare",
            "credit_payment_handoff",
            "credit_wallet_commit",
            "credit_wallet_submit",
            "bounty_transfer_prepare",
            "bounty_transfer_commit",
            "bounty_transfer_submit",
        ] {
            assert!(!public_export(&format!("mesh_messenger_{name}")));
        }
    }
    #[test]
    fn postage_requests_and_policy_are_confined_to_native_database() {
        let database = b"/canonical/messages.db";
        for (name, count) in [
            ("credit_postage_prepare", 4),
            ("postage_policy_view", 2),
            ("postage_policy_prepare", 2),
        ] {
            let mut request = (count as u32).to_be_bytes().to_vec();
            request.extend_from_slice(&(database.len() as u32).to_be_bytes());
            request.extend_from_slice(database);
            for _ in 1..count {
                request.extend_from_slice(&0u32.to_be_bytes());
            }
            assert!(validate_public(&format!("mesh_messenger_{name}"), &request, database).is_ok());
            assert!(
                validate_public(&format!("mesh_messenger_{name}"), &request, b"/other.db").is_err()
            );
        }
    }
}

#[cfg(test)]
mod network_counter_boundary {
    #[test]
    fn network_counter_requires_the_native_database_without_vector_or_caller_path_override() {
        let database = b"/native/morse.db";
        let symbol = "mesh_messenger_network_counter";
        assert!(super::validate_public(symbol, database, database).is_ok());
        for input in [b"/other/morse.db".as_slice(), b"", b"/native/morse.db\0"] {
            assert_eq!(
                super::validate_public(symbol, input, database),
                Err("invalid_database_path".into())
            );
        }
        let mut framed = (database.len() as u32).to_be_bytes().to_vec();
        framed.extend(database);
        assert_eq!(
            super::validate_public(symbol, &framed, database),
            Err("invalid_database_path".into())
        );
    }
}

#[cfg(test)]
#[test]
fn view_once_consume_is_native_only_independent_of_generated_header_discovery() {
    assert!(!public_export("mesh_messenger_view_once_consume"));
    assert!(public_export("mesh_messenger_load_profile"));
}
