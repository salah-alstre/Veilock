//! Product naming, read from the single `branding.json` at the repository root so the Rust side
//! never hardcodes the app name (the frontend imports the same file).

use std::sync::OnceLock;

use serde::Deserialize;

const RAW: &str = include_str!("../../branding.json");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Branding {
    pub app_name: String,
    pub file_extension: String,
}

pub fn get() -> &'static Branding {
    static CELL: OnceLock<Branding> = OnceLock::new();
    CELL.get_or_init(|| serde_json::from_str(RAW).expect("branding.json is valid"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branding_parses_and_matches_container_extension() {
        let b = get();
        assert!(!b.app_name.is_empty());
        assert_eq!(b.file_extension, crate::filesystem::ops::CONTAINER_EXT);
    }
}
