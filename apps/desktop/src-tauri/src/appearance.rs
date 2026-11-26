//! The user's choice of light or dark. The shell reads it, rather than the
//! web view, because the window has to open in the right scheme before any
//! script has run. It is sealed by the core in the app's journal
//! (`settings/appearance`), like the phone's.

use std::path::{Path, PathBuf};

use tauri::{webview::Color, Theme};

/// What the user picked: a scheme, or whatever the desktop is set to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Appearance {
    System,
    Light,
    Dark,
}

impl Appearance {
    /// Anything that is not an explicit scheme follows the system, so a
    /// missing, empty or garbled file never locks the window into one look.
    pub fn parse(saved: &str) -> Self {
        match saved.trim() {
            "light" => Self::Light,
            "dark" => Self::Dark,
            _ => Self::System,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    /// The window theme override this choice asks for: none when it follows the system.
    pub fn theme(self) -> Option<Theme> {
        match self {
            Self::System => None,
            Self::Light => Some(Theme::Light),
            Self::Dark => Some(Theme::Dark),
        }
    }
}

/// The canvas colour of each scheme, painted behind the web view so the window
/// never shows the other scheme while the page loads. Mirrors the `canvas`
/// token in the app's palettes (apps/mobile/src/appearance.ts).
pub fn canvas(theme: Theme) -> Color {
    match theme {
        Theme::Light => Color(0xFF, 0xFF, 0xFF, 0xFF),
        _ => Color(0x0A, 0x0A, 0x0C, 0xFF),
    }
}

/// Where an older build kept the choice in the clear.
fn file(directory: &Path) -> PathBuf {
    directory.join("appearance")
}

/// The sealed choice, from `sealed`. A clear copy left by an older build is
/// sealed with `seal` the first time it is found, and removed once it is.
pub fn load(
    directory: &Path,
    sealed: impl FnOnce() -> Option<String>,
    seal: impl FnOnce(&str) -> Result<(), String>,
) -> Appearance {
    let legacy = file(directory);
    let kept = sealed().filter(|value| !value.is_empty());
    let clear = std::fs::read_to_string(&legacy).ok();
    if let (None, Some(value)) = (&kept, &clear) {
        if seal(Appearance::parse(value).as_str()).is_err() {
            return Appearance::parse(value);
        }
    }
    if clear.is_some() {
        let _ = std::fs::remove_file(&legacy);
    }
    kept.or(clear)
        .map(|value| Appearance::parse(&value))
        .unwrap_or(Appearance::System)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_schemes_and_falls_back_to_system() {
        assert_eq!(Appearance::parse("light"), Appearance::Light);
        assert_eq!(Appearance::parse(" dark\n"), Appearance::Dark);
        assert_eq!(Appearance::parse("system"), Appearance::System);
        assert_eq!(Appearance::parse(""), Appearance::System);
        assert_eq!(Appearance::parse("sepia"), Appearance::System);
    }

    #[test]
    fn a_clear_copy_is_sealed_once_and_removed() {
        use std::cell::RefCell;
        let directory =
            std::env::temp_dir().join(format!("morse-appearance-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let journal = RefCell::new(None::<String>);
        let sealed = || journal.borrow().clone();
        let seal = |value: &str| {
            *journal.borrow_mut() = Some(value.to_owned());
            Ok(())
        };
        assert_eq!(load(&directory, sealed, seal), Appearance::System);
        // An older build's file moves into the journal, and goes.
        std::fs::write(file(&directory), "light").unwrap();
        assert_eq!(load(&directory, sealed, seal), Appearance::Light);
        assert_eq!(journal.borrow().as_deref(), Some("light"));
        assert!(!file(&directory).exists());
        // The sealed choice wins over a clear copy found later, which goes too.
        std::fs::write(file(&directory), "dark").unwrap();
        assert_eq!(load(&directory, sealed, seal), Appearance::Light);
        assert!(!file(&directory).exists());
        // A copy that could not be sealed stays, and still applies.
        *journal.borrow_mut() = None;
        std::fs::write(file(&directory), "dark").unwrap();
        let refused = |_: &str| Err("database_write_failed".to_owned());
        assert_eq!(load(&directory, sealed, refused), Appearance::Dark);
        assert!(file(&directory).exists());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn only_explicit_schemes_override_the_window_theme() {
        assert_eq!(Appearance::System.theme(), None);
        assert_eq!(Appearance::Light.theme(), Some(Theme::Light));
        assert_eq!(Appearance::Dark.theme(), Some(Theme::Dark));
    }

    #[test]
    fn canvas_matches_each_scheme() {
        assert_eq!(canvas(Theme::Light), Color(0xFF, 0xFF, 0xFF, 0xFF));
        assert_eq!(canvas(Theme::Dark), Color(0x0A, 0x0A, 0x0C, 0xFF));
    }
}
