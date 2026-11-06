pub fn allowed(url: &tauri::Url) -> bool {
    let origin = if cfg!(windows) {
        matches!(url.scheme(), "http" | "https") && url.host_str() == Some("tauri.localhost")
    } else {
        url.scheme() == "tauri" && url.host_str() == Some("localhost")
    };
    origin && url.port().is_none() && url.username().is_empty() && url.password().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_packaged_app_origin_can_navigate() {
        let app = if cfg!(windows) {
            "http://tauri.localhost"
        } else {
            "tauri://localhost"
        };
        for path in ["/", "/index.html", "/settings?tab=network#details"] {
            assert!(allowed(&format!("{app}{path}").parse().unwrap()));
        }
        for url in [
            "https://example.invalid/",
            "http://127.0.0.1/",
            "https://localhost/",
            "tauri://localhost.evil/",
            "tauri://localhost:1234/",
            "tauri://user@localhost/",
            "file:///tmp/probe.html",
            "data:text/html,probe",
            "javascript:void(0)",
            "about:blank",
        ] {
            assert!(!allowed(&url.parse().unwrap()), "{url}");
        }
    }
}
