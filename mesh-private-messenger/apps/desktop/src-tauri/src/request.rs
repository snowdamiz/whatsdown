pub const MAX_REQUEST: usize = 8 * 1024 * 1024;
// One opaque object part: a sealed 64 KiB attachment chunk plus its framing.
pub const MAX_OBJECT_PART: usize = 65_608;
// Part indices span the manifest plus 256 chunks.
const MAX_PART_INDEX: u32 = 256;

pub struct Routes<'a> {
    pub base_url: &'a str,
    pub edge_url: &'a str,
    pub object_url: &'a str,
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_part_index(value: &str) -> bool {
    (value == "0" || (!value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit())))
        && value
            .parse::<u32>()
            .is_ok_and(|index| index <= MAX_PART_INDEX)
}

fn is_object_part_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/v1/objects/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let (Some(object_id), Some("parts"), Some(index), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    is_lower_hex(object_id, 64) && is_canonical_part_index(index)
}

// Every service request from the web view must name a known route, and the object
// capability header may only accompany the part transfer it authorizes.
pub fn allowed_request(routes: &Routes, url: &str, method: &str, capability: Option<&str>) -> bool {
    // The object service may share the messenger host, so its routes are checked by path.
    let object_path = url.strip_prefix(routes.object_url);
    if let Some(capability) = capability {
        return matches!(method, "PUT" | "GET")
            && is_lower_hex(capability, 64)
            && object_path.is_some_and(is_object_part_path);
    }
    if method == "POST"
        && object_path.is_some_and(|path| {
            matches!(
                path,
                "/v1/attachments/grant" | "/v1/attachments/complete" | "/v1/attachments/delete"
            )
        })
    {
        return true;
    }
    let base_routes = [
        ("/v1/devices/register", "PUT"),
        ("/v1/prekeys/one-time/batch", "POST"),
        ("/v1/devices/resolve", "POST"),
        ("/v1/devices/revoke", "POST"),
        ("/v1/mailbox/fetch", "POST"),
        ("/v1/mailbox/ack", "POST"),
    ];
    base_routes
        .iter()
        .any(|(path, verb)| method == *verb && url == format!("{}{path}", routes.base_url))
        || (method == "POST" && url == format!("{}/v1/envelopes/batch", routes.edge_url))
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

pub fn validate_prekey_url(mut input: &[u8], base_url: &str) -> Result<(), String> {
    let mut field = &[][..];
    for _ in 0..4 {
        let length = input.get(..4).ok_or("invalid_prekey_request")?;
        let length =
            u32::from_be_bytes(length.try_into().map_err(|_| "invalid_prekey_request")?) as usize;
        field = input.get(4..4 + length).ok_or("invalid_prekey_request")?;
        input = &input[4 + length..];
    }
    if !input.is_empty() || field != base_url.as_bytes() {
        return Err("invalid_prekey_service".into());
    }
    Ok(())
}

// The generated C header is the export allowlist, shared with the mobile bridge.
const HEADER: &str =
    include_str!("../../../mobile/modules/mesh-messenger/generated/libmessenger_mobile.h");

pub fn validate(symbol: &str, request: &[u8], database: &[u8]) -> Result<(), String> {
    if !symbol.starts_with("mesh_messenger_")
        || !HEADER
            .lines()
            .any(|line| line.starts_with(&format!("int32_t {symbol}(")))
        || request.len() > MAX_REQUEST
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
    let path = if matches!(
        name,
        "initialize"
            | "load_profile"
            | "create_link_request"
            | "group_key_package"
            | "group_invitations"
            | "group_create"
            | "group_list"
            | "push_status"
            | "list_conversations"
            | "directory_entry"
            | "register_request"
            | "mailbox_fetch"
            | "outbox_list"
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
    use super::*;

    #[test]
    fn native_prekey_requests_cannot_redirect_credentials_to_another_service() {
        let frame = |url: &[u8]| {
            let mut request = Vec::new();
            for bytes in [b"db".as_slice(), b"peer", b"local", url] {
                request.extend((bytes.len() as u32).to_be_bytes());
                request.extend(bytes);
            }
            request
        };
        assert!(validate_prekey_url(
            &frame(b"https://messenger.example"),
            "https://messenger.example"
        )
        .is_ok());
        assert!(validate_prekey_url(
            &frame(b"https://other.example"),
            "https://messenger.example"
        )
        .is_err());
        assert!(validate_prekey_url(&[255; 4], "https://messenger.example").is_err());
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
    fn service_requests_are_limited_to_known_routes_and_object_capabilities() {
        let routes = Routes {
            base_url: "https://messenger.example",
            edge_url: "https://edge.example",
            object_url: "https://objects.example",
        };
        let object = "https://objects.example/v1/objects/".to_owned() + &"ab".repeat(32);
        let capability = "0f".repeat(32);
        assert!(allowed_request(
            &routes,
            "https://messenger.example/v1/mailbox/fetch",
            "POST",
            None
        ));
        assert!(allowed_request(
            &routes,
            "https://edge.example/v1/envelopes/batch",
            "POST",
            None
        ));
        assert!(allowed_request(
            &routes,
            "https://objects.example/v1/attachments/grant",
            "POST",
            None
        ));
        assert!(allowed_request(
            &routes,
            "https://objects.example/v1/attachments/complete",
            "POST",
            None
        ));
        assert!(allowed_request(
            &routes,
            "https://objects.example/v1/attachments/delete",
            "POST",
            None
        ));
        assert!(allowed_request(
            &routes,
            &format!("{object}/parts/0"),
            "PUT",
            Some(&capability)
        ));
        assert!(allowed_request(
            &routes,
            &format!("{object}/parts/256"),
            "GET",
            Some(&capability)
        ));
        // The capability header never travels to other routes, and part routes always carry it.
        assert!(!allowed_request(
            &routes,
            &format!("{object}/parts/1"),
            "PUT",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://messenger.example/v1/mailbox/fetch",
            "POST",
            Some(&capability)
        ));
        assert!(!allowed_request(
            &routes,
            "https://objects.example/v1/attachments/grant",
            "POST",
            Some(&capability)
        ));
        assert!(!allowed_request(
            &routes,
            &format!("{object}/parts/1"),
            "POST",
            Some(&capability)
        ));
        assert!(!allowed_request(
            &routes,
            &format!("{object}/parts/1"),
            "PUT",
            Some(&capability.to_uppercase())
        ));
        assert!(!allowed_request(
            &routes,
            &format!("{object}/parts/1"),
            "PUT",
            Some(&capability[..62])
        ));
        assert!(!allowed_request(
            &routes,
            &format!("{object}/parts/257"),
            "PUT",
            Some(&capability)
        ));
        assert!(!allowed_request(
            &routes,
            &format!("{object}/parts/01"),
            "PUT",
            Some(&capability)
        ));
        assert!(!allowed_request(
            &routes,
            &format!("{object}/parts/1?x=1"),
            "PUT",
            Some(&capability)
        ));
        assert!(!allowed_request(
            &routes,
            &format!("{object}/parts/1/extra"),
            "PUT",
            Some(&capability)
        ));
        assert!(!allowed_request(
            &routes,
            &format!("{object}AB/parts/1"),
            "PUT",
            Some(&capability)
        ));
        assert!(!allowed_request(
            &routes,
            "https://objects.example.evil/v1/attachments/grant",
            "POST",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://messenger.example/v1/attachments/grant",
            "POST",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://messenger.example/v1/mailbox/fetch",
            "GET",
            None
        ));
        // Deployments that serve objects from the messenger host keep both route sets.
        let shared = Routes {
            object_url: "https://messenger.example",
            ..routes
        };
        assert!(allowed_request(
            &shared,
            "https://messenger.example/v1/mailbox/fetch",
            "POST",
            None
        ));
        assert!(allowed_request(
            &shared,
            "https://messenger.example/v1/attachments/grant",
            "POST",
            None
        ));
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
        // The two stamped directory requests keep their unstamped twins' shapes:
        // a bare database path, and a path-prefixed lookup.
        assert!(validate("mesh_messenger_register_request", db, db).is_ok());
        assert!(validate("mesh_messenger_register_request", b"/tmp/other.db", db).is_err());
        assert!(validate("mesh_messenger_resolve_request", &account, db).is_ok());
        assert!(validate("mesh_messenger_resolve_request", &account, b"other").is_err());
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
}
