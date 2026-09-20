//! The user's choice of light or dark. The shell keeps it, rather than the
//! web view, because the window has to open in the right scheme before any
//! script has run.

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

fn file(directory: &Path) -> PathBuf {
    directory.join("appearance")
}

pub fn load(directory: &Path) -> Appearance {
    std::fs::read_to_string(file(directory))
        .map(|saved| Appearance::parse(&saved))
        .unwrap_or(Appearance::System)
}

pub fn save(directory: &Path, appearance: Appearance) -> std::io::Result<()> {
    std::fs::write(file(directory), appearance.as_str())
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
    fn round_trips_through_the_file_and_reads_absence_as_system() {
        let directory =
            std::env::temp_dir().join(format!("morse-appearance-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        assert_eq!(load(&directory), Appearance::System);
        save(&directory, Appearance::Light).unwrap();
        assert_eq!(load(&directory), Appearance::Light);
        save(&directory, Appearance::System).unwrap();
        assert_eq!(load(&directory), Appearance::System);
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
