//! Global search. It only ever looks at what the app may show right now: vault names (always
//! visible), recent items, items of vaults that are *unlocked*, and saved-password entries only
//! while the credential vault is unlocked. A locked vault or locked credential vault contributes
//! nothing, so search cannot be used to probe their contents.

use serde::Serialize;

use crate::errors::{AppError, Result};

use super::{blocking, St};

const MAX_QUERY_CHARS: usize = 100;
const PER_SOURCE: u32 = 20;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHit {
    /// "item" | "vault" | "vaultItem" | "password"
    pub kind: &'static str,
    pub id: String,
    pub title: String,
    /// Owning vault for `vaultItem`.
    pub vault_id: Option<String>,
    /// Encrypted path for `item`.
    pub path: Option<String>,
}

fn matches(haystack: &str, needle_lower: &str) -> bool {
    haystack.to_lowercase().contains(needle_lower)
}

#[tauri::command]
pub async fn search_all(state: St<'_>, query: String) -> Result<Vec<SearchHit>> {
    let needle = query.trim();
    if needle.is_empty() {
        return Ok(Vec::new());
    }
    if needle.chars().count() > MAX_QUERY_CHARS {
        return Err(AppError::InvalidInput("query too long".into()));
    }
    let needle = needle.to_owned();
    blocking(&state, move |s| {
        let lower = needle.to_lowercase();
        let mut hits = Vec::new();

        for rec in s.db.search_items(&needle, PER_SOURCE)? {
            hits.push(SearchHit {
                kind: "item",
                id: rec.id,
                title: rec.name,
                vault_id: None,
                path: Some(rec.encrypted_path),
            });
        }

        for v in s.vaults.list()? {
            if matches(&v.record.name, &lower) {
                hits.push(SearchHit {
                    kind: "vault",
                    id: v.record.id.clone(),
                    title: v.record.name.clone(),
                    vault_id: None,
                    path: None,
                });
            }
            if v.unlocked {
                for it in s.vaults.list_items(&v.record.id)? {
                    if matches(&it.name, &lower) {
                        hits.push(SearchHit {
                            kind: "vaultItem",
                            id: it.id,
                            title: it.name,
                            vault_id: Some(v.record.id.clone()),
                            path: None,
                        });
                    }
                }
            }
        }

        if s.creds.is_unlocked() {
            // Entries holding a vault's own password are reachable through the vault itself.
            for e in s.creds.list()? {
                if e.kind != "vault" && matches(&e.name, &lower) {
                    hits.push(SearchHit {
                        kind: "password",
                        id: e.id,
                        title: e.name,
                        vault_id: None,
                        path: None,
                    });
                }
            }
        }
        Ok(hits)
    })
    .await
}
