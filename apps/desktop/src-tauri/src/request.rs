pub const MAX_REQUEST: usize = 8 * 1024 * 1024;
// One opaque object part: a sealed 64 KiB attachment chunk plus its framing.
pub const MAX_OBJECT_PART: usize = 65_608;
// Part indices span the manifest plus up to 8,192 chunks (512 MiB, paid with
// credits above 16 MiB).
const MAX_PART_INDEX: u32 = 8192;

pub struct Routes<'a> {
    pub base_url: &'a str,
    pub edge_url: &'a str,
    pub object_url: &'a str,
    pub pinned: &'a Pinned,
}

// The public-record services this build pins in its security config v2: the
// RPC providers the phone reads the chain from (never through Morse) and the
// relays it files fork evidence with, and the OHTTP relay its stateless
// requests go through (protocol/ohttp-v1.md). A v1 or unreadable frame pins
// none.
#[derive(Default)]
pub struct Pinned {
    pub rpc_urls: Vec<String>,
    pub relays: Vec<String>,
    pub ohttp_relay: Option<String>,
}

impl Pinned {
    pub fn from_frame(frame: &str) -> Pinned {
        Self::parse(frame).unwrap_or_default()
    }

    fn parse(frame: &str) -> Option<Pinned> {
        let lines: Vec<&str> = frame.split('\n').collect();
        if lines.first() != Some(&"2") {
            return None;
        }
        let witnesses: usize = lines.get(5)?.parse().ok()?;
        let rpc_at = 7 + witnesses;
        let rpc_count: usize = lines.get(rpc_at)?.parse().ok()?;
        let relay_at = rpc_at + 1 + rpc_count;
        let relay_count: usize = lines.get(relay_at)?.parse().ok()?;
        let rpc_urls: Vec<String> = lines
            .get(rpc_at + 1..relay_at)?
            .iter()
            .filter(|url| url.starts_with("https://"))
            .map(|url| url.to_string())
            .collect();
        let relays: Vec<String> = lines
            .get(relay_at + 1..relay_at + 1 + relay_count)?
            .iter()
            .filter(|url| url.starts_with("https://"))
            .map(|url| url.to_string())
            .collect();
        // The optional last line: the gateway's key configuration and the relay.
        let ohttp_relay = lines
            .get(relay_at + 1 + relay_count + 3)
            .map(|line| line.split(' ').collect::<Vec<_>>())
            .filter(|fields| fields.len() == 2)
            .map(|fields| fields[1].to_string());
        Some(Pinned {
            rpc_urls,
            relays,
            ohttp_relay,
        })
    }
}

fn is_ohttp_relay(routes: &Routes, url: &str) -> bool {
    routes
        .pinned
        .ohttp_relay
        .as_ref()
        .is_some_and(|relay| url == format!("{relay}/v1/ohttp"))
}

// JSON-RPC to a pinned provider, OHTTP to the pinned relay; everything else is
// Morse's binary framing.
pub fn content_type(routes: &Routes, url: &str) -> &'static str {
    if routes.pinned.rpc_urls.iter().any(|pinned| pinned == url) {
        "application/json"
    } else if is_ohttp_relay(routes, url) {
        "message/ohttp-req"
    } else {
        "application/octet-stream"
    }
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
        ("/v1/accounts/delete", "POST"),
        ("/v1/devices/leave", "POST"),
        ("/v1/mailbox/fetch", "POST"),
        ("/v1/mailbox/ack", "POST"),
        ("/v1/transparency/consistency", "POST"),
        ("/v1/transparency/leaf", "POST"),
        // A device's signed price for message requests (credits-v1.md "Postage").
        ("/v1/mailbox/policy", "PUT"),
    ];
    let public_record = method == "POST"
        && (routes.pinned.rpc_urls.iter().any(|pinned| pinned == url)
            || routes
                .pinned
                .relays
                .iter()
                .any(|relay| url == format!("{relay}/v1/fork-evidence")));
    base_routes
        .iter()
        .any(|(path, verb)| method == *verb && url == format!("{}{path}", routes.base_url))
        || (method == "POST" && url == format!("{}/v1/envelopes/batch", routes.edge_url))
        || (method == "POST" && url == format!("{}/v1/mailbox/retention", routes.edge_url))
        || (method == "POST" && is_ohttp_relay(routes, url))
        || public_record
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

// The credit exports that make their own requests (issuer keys from the
// directory; quotes and issuing through the privacy edge) name the service in
// their second vector: it must be the one this build is configured with.
pub fn validate_service_url(input: &[u8], expected: &str) -> Result<(), String> {
    let mut rest = input;
    let mut field = &[][..];
    for _ in 0..2 {
        let length = rest.get(..4).ok_or("invalid_service_request")?;
        let length =
            u32::from_be_bytes(length.try_into().map_err(|_| "invalid_service_request")?) as usize;
        field = rest.get(4..4 + length).ok_or("invalid_service_request")?;
        rest = &rest[4 + length..];
    }
    if field != expected.as_bytes() {
        return Err("invalid_credits_service".into());
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
            | "wallet_rpc_urls"
            | "oblivious_encapsulate"
            | "oblivious_decapsulate"
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
            | "account_deletion"
            | "erase_account"
            | "device_departure"
            | "network_status"
            | "transparency_anchor_requests"
            | "trust_alarm_details"
            | "expiry_purge"
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
    fn credit_exports_reach_only_the_configured_services() {
        let frame = |url: &[u8]| {
            let mut request = Vec::new();
            for bytes in [b"db".as_slice(), url, b"\x01", b"\x01"] {
                request.extend((bytes.len() as u32).to_be_bytes());
                request.extend(bytes);
            }
            request
        };
        assert!(
            validate_service_url(&frame(b"https://edge.example"), "https://edge.example").is_ok()
        );
        assert!(
            validate_service_url(&frame(b"https://other.example"), "https://edge.example").is_err()
        );
        assert!(validate_service_url(b"\x00\x00", "https://edge.example").is_err());
    }

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
        let pinned = Pinned::default();
        let routes = Routes {
            base_url: "https://messenger.example",
            edge_url: "https://edge.example",
            object_url: "https://objects.example",
            pinned: &pinned,
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
        // Credits: a signed inbox price at the directory, longer storage at the edge.
        assert!(allowed_request(
            &routes,
            "https://messenger.example/v1/mailbox/policy",
            "PUT",
            None
        ));
        assert!(allowed_request(
            &routes,
            "https://edge.example/v1/mailbox/retention",
            "POST",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://messenger.example/v1/mailbox/retention",
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
            &format!("{object}/parts/8192"),
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
            &format!("{object}/parts/8193"),
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
        assert!(allowed_request(
            &routes,
            "https://messenger.example/v1/accounts/delete",
            "POST",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://edge.example/v1/accounts/delete",
            "POST",
            None
        ));
        assert!(allowed_request(
            &routes,
            "https://messenger.example/v1/devices/leave",
            "POST",
            None
        ));
        // Consistency proofs for group anchors come from the directory, by POST only.
        assert!(allowed_request(
            &routes,
            "https://messenger.example/v1/transparency/consistency",
            "POST",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://messenger.example/v1/transparency/consistency",
            "GET",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://edge.example/v1/transparency/consistency",
            "POST",
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

    const FRAME: &str = "2\n\
        6b734a8eff246fe734b38d4046c148eee5f04fe87b3a0a423955a77956de066b\n\
        77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a\n\
        8\n2\n2\n\
        witness-a d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a Morse\n\
        witness-b 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c Morse\n\
        Judge111111111111111111111111111111111111111 Log1111111111111111111111111111111111111111\n\
        3\nhttps://rpc-1.test/v1\nhttps://rpc-2.test\nhttps://rpc-3.test\n\
        2\nhttps://relay-a.test\nhttps://relay-b.test\n\
        -\n-\n1";

    // §22 M3: a frame that pins the OHTTP gateway ends with its key
    // configuration and the relay (protocol/ohttp-v1.md).
    #[test]
    fn oblivious_requests_reach_only_the_pinned_relay() {
        let frame = format!(
            "{FRAME}\n01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155000400010003 https://edge.example"
        );
        let pinned = Pinned::from_frame(&frame);
        assert_eq!(pinned.ohttp_relay.as_deref(), Some("https://edge.example"));
        assert_eq!(pinned.relays.len(), 2);
        let routes = Routes {
            base_url: "https://messenger.example",
            edge_url: "https://edge.example",
            object_url: "https://objects.example",
            pinned: &pinned,
        };
        assert!(allowed_request(
            &routes,
            "https://edge.example/v1/ohttp",
            "POST",
            None
        ));
        assert_eq!(
            content_type(&routes, "https://edge.example/v1/ohttp"),
            "message/ohttp-req"
        );
        for (url, method) in [
            ("https://edge.example/v1/ohttp", "GET"),
            ("https://messenger.example/v1/ohttp", "POST"),
            ("https://edge.example/v1/ohttp/other", "POST"),
        ] {
            assert!(
                !allowed_request(&routes, url, method, None),
                "{method} {url}"
            );
        }
        assert!(!allowed_request(
            &routes,
            "https://edge.example/v1/ohttp",
            "POST",
            Some(&"0f".repeat(32))
        ));
        // A frame without the line pins no relay.
        let unpinned = Pinned::from_frame(FRAME);
        assert_eq!(unpinned.ohttp_relay, None);
        let routes = Routes {
            pinned: &unpinned,
            ..routes
        };
        assert!(!allowed_request(
            &routes,
            "https://edge.example/v1/ohttp",
            "POST",
            None
        ));
        // The two exports carry wire bytes and open no database.
        assert!(validate(
            "mesh_messenger_oblivious_encapsulate",
            b"\0\0\0\x04POST",
            b"db"
        )
        .is_ok());
        assert!(validate(
            "mesh_messenger_oblivious_decapsulate",
            b"\0\0\0\x01k",
            b"db"
        )
        .is_ok());
    }

    #[test]
    fn public_record_requests_reach_only_the_pinned_providers_and_relays() {
        let pinned = Pinned::from_frame(FRAME);
        assert_eq!(pinned.rpc_urls.len(), 3);
        assert_eq!(pinned.relays.len(), 2);
        let routes = Routes {
            base_url: "https://messenger.example",
            edge_url: "https://edge.example",
            object_url: "https://objects.example",
            pinned: &pinned,
        };
        // The chain is read from pinned providers, as JSON-RPC, by POST only.
        assert!(allowed_request(
            &routes,
            "https://rpc-1.test/v1",
            "POST",
            None
        ));
        assert!(allowed_request(&routes, "https://rpc-3.test", "POST", None));
        assert_eq!(
            content_type(&routes, "https://rpc-1.test/v1"),
            "application/json"
        );
        assert!(!allowed_request(
            &routes,
            "https://rpc-1.test/v1",
            "GET",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://rpc-1.test/v1/other",
            "POST",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://rpc-1.test",
            "POST",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://rpc-9.test",
            "POST",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://rpc-1.test/v1",
            "POST",
            Some(&"0f".repeat(32))
        ));
        // Fork evidence goes to a pinned relay's one route.
        assert!(allowed_request(
            &routes,
            "https://relay-a.test/v1/fork-evidence",
            "POST",
            None
        ));
        assert_eq!(
            content_type(&routes, "https://relay-a.test/v1/fork-evidence"),
            "application/octet-stream"
        );
        assert!(!allowed_request(
            &routes,
            "https://relay-a.test",
            "POST",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://relay-a.test/v1/other",
            "POST",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://relay-z.test/v1/fork-evidence",
            "POST",
            None
        ));
        // The public side of a contradiction proof comes from the directory.
        assert!(allowed_request(
            &routes,
            "https://messenger.example/v1/transparency/leaf",
            "POST",
            None
        ));
        assert!(!allowed_request(
            &routes,
            "https://rpc-1.test/v1/transparency/leaf",
            "POST",
            None
        ));
        // A v1 frame pins no public-record services at all.
        let legacy = Pinned::from_frame("1\nab\ncd\nef\n01\n8");
        assert!(legacy.rpc_urls.is_empty() && legacy.relays.is_empty());
        assert!(Pinned::from_frame("2\nbroken").rpc_urls.is_empty());
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
        // Deleting the account, leaving it, and erasing this device name only the app database.
        for symbol in [
            "mesh_messenger_account_deletion",
            "mesh_messenger_erase_account",
            "mesh_messenger_device_departure",
        ] {
            assert!(validate(symbol, db, db).is_ok());
            assert!(validate(symbol, b"/tmp/other.db", db).is_err());
        }
        // The network status and the pending anchor proofs name only the app database;
        // an anchor proof arrives path-prefixed like any other call.
        for symbol in [
            "mesh_messenger_network_status",
            "mesh_messenger_transparency_anchor_requests",
            "mesh_messenger_expiry_purge",
        ] {
            assert!(validate(symbol, db, db).is_ok());
            assert!(validate(symbol, b"/tmp/other.db", db).is_err());
        }
        // The public-record check runs path-prefixed; its details name only the database.
        assert!(validate("mesh_messenger_anchor_check", &account, db).is_ok());
        assert!(validate("mesh_messenger_anchor_check", &account, b"other").is_err());
        assert!(validate("mesh_messenger_trust_alarm_details", db, db).is_ok());
        assert!(validate("mesh_messenger_trust_alarm_details", b"/tmp/other.db", db).is_err());
        assert!(validate("mesh_messenger_transparency_anchor_proof", &account, db).is_ok());
        assert!(validate(
            "mesh_messenger_transparency_anchor_proof",
            &account,
            b"other"
        )
        .is_err());
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
        // The wallet's pinned RPC list names no database.
        assert!(validate("mesh_messenger_wallet_rpc_urls", &[], db).is_ok());
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
