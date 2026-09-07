//! `search_runbooks` — keyword search over the markdown runbook docs.
//!
//! The docs are deliberately inconsistent (bulleted vs. prose, `#` headers vs.
//! plain caps), so matching strips markdown punctuation and case before
//! comparing rather than relying on exact formatting.

use std::fs;
use std::io;
use std::path::Path;

const RUNBOOKS_DIR: &str = "runbooks";

#[derive(Debug, PartialEq, serde::Serialize)]
pub struct RunbookMatch {
    pub file: String,
    pub score: usize,
    /// First line that contains a query keyword, for a quick preview.
    pub snippet: String,
}

/// Ranks runbook docs by how many query keywords they contain.
/// Returns only docs with at least one match, highest score first.
pub fn search_runbooks(query: &str) -> io::Result<Vec<RunbookMatch>> {
    search_runbooks_in(query, Path::new(RUNBOOKS_DIR))
}

fn search_runbooks_in(query: &str, dir: &Path) -> io::Result<Vec<RunbookMatch>> {
    let keywords: Vec<String> = normalize(query)
        .split_whitespace()
        .map(str::to_string)
        .collect();

    let mut matches = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let content = fs::read_to_string(&path)?;
        let normalized = normalize(&content);
        let score: usize = keywords
            .iter()
            .map(|k| normalized.matches(k.as_str()).count())
            .sum();
        if score == 0 {
            continue;
        }
        matches.push(RunbookMatch {
            file: path.file_name().unwrap().to_string_lossy().into_owned(),
            score,
            snippet: best_snippet(&content, &keywords),
        });
    }

    matches.sort_by(|a, b| b.score.cmp(&a.score));
    Ok(matches)
}

/// Lowercases and strips markdown punctuation so "connection pool exhaustion"
/// matches regardless of `#`/`*`/`-`/backtick formatting around it.
fn normalize(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| if "#*-`_".contains(c) { ' ' } else { c })
        .collect()
}

fn best_snippet(content: &str, keywords: &[String]) -> String {
    content
        .lines()
        .map(str::trim)
        .find(|line| {
            let normalized = normalize(line);
            keywords.iter().any(|k| normalized.contains(k.as_str()))
        })
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_pool_exhaustion_runbook_for_the_seeded_incident() {
        let results =
            search_runbooks_in("connection pool exhausted payment-gateway timeout", Path::new("runbooks"))
                .unwrap();
        assert_eq!(results[0].file, "connection-pool-exhaustion.md");
    }

    #[test]
    fn finds_rollback_runbook_for_a_bad_deploy() {
        let results = search_runbooks_in("errors after deploy rollback", Path::new("runbooks")).unwrap();
        assert_eq!(results[0].file, "elevated-error-rate-bad-deploy.md");
    }

    #[test]
    fn matches_regardless_of_markdown_formatting() {
        // "high cpu scaling" query should hit high-cpu-scaling.md even though
        // that file is plain lowercase prose with no headers/bullets at all.
        let results = search_runbooks_in("high cpu scaling", Path::new("runbooks")).unwrap();
        assert!(results.iter().any(|m| m.file == "high-cpu-scaling.md"));
    }

    #[test]
    fn no_keyword_matches_returns_empty() {
        let results = search_runbooks_in("quantum flux capacitor", Path::new("runbooks")).unwrap();
        assert!(results.is_empty());
    }
}
