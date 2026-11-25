//! Fast zero-dependency secret & credential scanner with mandatory preview redaction.
//!
//! Never outputs raw secret material in findings or JSON output; every detection carries
//! a strictly redacted preview plus a truncated SHA-256 fingerprint for deduplication.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crate::json;
use crate::sha256;

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".venv",
    "dist",
    "build",
    "__pycache__",
];

#[derive(Debug, Clone)]
pub struct SecretsConfig {
    pub max_file_bytes: u64,
    pub min_entropy: f64,
    pub include_hidden: bool,
    pub concurrency: usize,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: 2 * 1024 * 1024,
            min_entropy: 4.2,
            include_hidden: false,
            concurrency: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFinding {
    pub rule_id: String,
    pub severity: &'static str,
    pub path: String,
    pub line: usize,
    pub redacted_preview: String,
    pub fingerprint: String,
    pub entropy_x100: u32,
}

#[derive(Debug, Clone)]
pub struct SecretsReport {
    pub root: String,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub findings_count: usize,
    pub duration_ms: u64,
    pub findings: Vec<SecretFinding>,
}

impl SecretsReport {
    pub fn to_json(&self) -> String {
        let mut out = String::from("{");
        out.push_str(&format!("\"root\":{},", json::quote(&self.root)));
        out.push_str(&format!("\"files_scanned\":{},", self.files_scanned));
        out.push_str(&format!("\"files_skipped\":{},", self.files_skipped));
        out.push_str(&format!("\"findings_count\":{},", self.findings_count));
        out.push_str(&format!("\"duration_ms\":{},", self.duration_ms));
        out.push_str("\"redacted\":true,");
        out.push_str("\"findings\":[");
        for (i, f) in self.findings.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"rule_id\":{},\"severity\":{},\"path\":{},\"line\":{},\"redacted_preview\":{},\"fingerprint\":{},\"entropy\":{:.2}}}",
                json::quote(&f.rule_id),
                json::quote(f.severity),
                json::quote(&f.path),
                f.line,
                json::quote(&f.redacted_preview),
                json::quote(&f.fingerprint),
                (f.entropy_x100 as f64) / 100.0,
            ));
        }
        out.push_str("]}");
        out
    }
}

/// Strictly redacts a secret value so raw credential bytes are never exposed.
pub fn redact_secret(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.contains("PRIVATE KEY") && trimmed.starts_with("-----BEGIN") {
        let header = trimmed
            .lines()
            .next()
            .unwrap_or("-----BEGIN PRIVATE KEY-----");
        return format!("{header} [REDACTED]");
    }

    let chars: Vec<char> = trimmed.chars().collect();
    let len = chars.len();
    if len <= 10 {
        return format!("***[REDACTED len={len}]***");
    }
    let head: String = chars.iter().take(4).collect();
    let tail: String = chars.iter().skip(len.saturating_sub(2)).collect();
    format!("{head}…[REDACTED len={len}]…{tail}")
}

/// Computes Shannon entropy (bits per byte) of an ASCII slice.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b'+' | b'=')
}

fn is_alnum_underscore_dash(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_base64url_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_upper_alnum(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}

fn is_word_boundary(bytes: &[u8], idx: usize) -> bool {
    if idx == 0 || idx >= bytes.len() {
        return true;
    }
    !bytes[idx].is_ascii_alphanumeric() && bytes[idx] != b'_'
}

fn scan_prefix_tokens<'a>(
    line: &'a str,
    prefixes: &[&str],
    min_suffix_len: usize,
    char_pred: fn(u8) -> bool,
) -> Vec<&'a str> {
    let bytes = line.as_bytes();
    let mut matches = Vec::new();
    for &prefix in prefixes {
        let mut search_from = 0usize;
        while let Some(rel) = line[search_from..].find(prefix) {
            let start = search_from + rel;
            let before_ok = start == 0 || is_word_boundary(bytes, start - 1);
            let mut end = start + prefix.len();
            while end < bytes.len() && char_pred(bytes[end]) {
                end += 1;
            }
            let suffix_len = end - (start + prefix.len());
            let after_ok = end == bytes.len() || is_word_boundary(bytes, end);
            if before_ok && after_ok && suffix_len >= min_suffix_len {
                matches.push(&line[start..end]);
                search_from = end;
            } else {
                search_from = start + prefix.len();
            }
        }
    }
    matches
}

fn scan_aws_access_keys(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    for prefix in ["AKIA", "ASIA", "AIDA", "AROA"] {
        let mut pos = 0usize;
        while let Some(rel) = line[pos..].find(prefix) {
            let start = pos + rel;
            let end = start + 20;
            if end <= bytes.len() {
                let before_ok = start == 0 || is_word_boundary(bytes, start - 1);
                let after_ok = end == bytes.len() || is_word_boundary(bytes, end);
                if before_ok && after_ok && bytes[start + 4..end].iter().all(|&b| is_upper_alnum(b)) {
                    out.push(&line[start..end]);
                    pos = end;
                    continue;
                }
            }
            pos = start + 4;
        }
    }
    out
}

fn scan_jwts(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some(rel) = line[pos..].find("eyJ") {
        let start = pos + rel;
        let before_ok = start == 0 || !is_base64url_byte(bytes[start - 1]);
        if !before_ok {
            pos = start + 3;
            continue;
        }
        let mut idx = start;
        let mut dot_positions = [0usize; 2];
        let mut dots = 0usize;
        while idx < bytes.len() {
            let b = bytes[idx];
            if b == b'.' {
                if dots < 2 {
                    dot_positions[dots] = idx;
                    dots += 1;
                    idx += 1;
                    continue;
                } else {
                    break;
                }
            } else if is_base64url_byte(b) {
                idx += 1;
            } else {
                break;
            }
        }
        if dots == 2 {
            let p1 = dot_positions[0] - start;
            let p2 = dot_positions[1] - (dot_positions[0] + 1);
            let p3 = idx - (dot_positions[1] + 1);
            if p1 >= 8 && p2 >= 8 && p3 >= 16 && line[dot_positions[0] + 1..].starts_with("eyJ") {
                out.push(&line[start..idx]);
                pos = idx;
                continue;
            }
        }
        pos = start + 3;
    }
    out
}

fn looks_like_placeholder(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("changeme")
        || lower.contains("redacted")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("sha256:")
}

fn has_mixed_classes(token: &str) -> bool {
    let mut upper = false;
    let mut lower = false;
    let mut digit = false;
    let mut sym = false;
    for b in token.bytes() {
        if b.is_ascii_uppercase() {
            upper = true;
        } else if b.is_ascii_lowercase() {
            lower = true;
        } else if b.is_ascii_digit() {
            digit = true;
        } else {
            sym = true;
        }
    }
    let classes = (upper as u8) + (lower as u8) + (digit as u8) + (sym as u8);
    classes >= 3
}

fn is_pure_hex(token: &str) -> bool {
    token.bytes().all(|b| b.is_ascii_hexdigit())
}

fn scan_high_entropy_assignments<'a>(line: &'a str, min_entropy: f64) -> Vec<(&'static str, &'a str)> {
    let lower_line = line.to_ascii_lowercase();
    let sensitive_hint = [
        "secret",
        "token",
        "apikey",
        "api_key",
        "api-key",
        "password",
        "passwd",
        "auth",
        "bearer",
        "credential",
        "private",
        "aws_secret",
    ]
    .iter()
    .any(|kw| lower_line.contains(kw));

    if !sensitive_hint {
        return Vec::new();
    }

    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && !is_token_byte(bytes[i]) {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && is_token_byte(bytes[i]) {
            i += 1;
        }
        let tok = &line[start..i];
        let trimmed = tok.trim_matches(|c| c == '"' || c == '\'' || c == '.' || c == '/');
        let len = trimmed.len();
        if len < 24 || len > 256 || looks_like_placeholder(trimmed) {
            continue;
        }
        // Skip file paths like /usr/local/something/secret/foo
        if trimmed.matches('/').count() >= 3 && !trimmed.contains('+') && !trimmed.ends_with('=') {
            continue;
        }
        // Check AWS secret access key pattern (40 base64-ish chars on an aws_secret line)
        if lower_line.contains("aws_secret") && len == 40 && shannon_entropy(trimmed) >= 3.8 {
            out.push(("aws-secret-access-key", trimmed));
            continue;
        }
        // Skip pure 64-char sha256 hashes unless entropy + mixed case indicate real secret
        if is_pure_hex(trimmed) && (len == 32 || len == 40 || len == 64) {
            continue;
        }
        let ent = shannon_entropy(trimmed);
        if ent >= min_entropy && has_mixed_classes(trimmed) {
            out.push(("high-entropy-secret", trimmed));
        }
    }
    out
}

/// Scans an in-memory text buffer for secrets and returns strictly redacted findings.
pub fn scan_text(rel_path: &str, content: &str, min_entropy: f64) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    let mut seen_on_line = HashSet::<(usize, String)>::new();

    for (idx, line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let mut push_match = |rule_id: &str, severity: &'static str, raw: &str| {
            let fp_full = sha256::digest_hex(format!("{rule_id}:{rel_path}:{line_no}:{raw}").as_bytes());
            let fingerprint = fp_full[..16].to_string();
            let dedup_key = (line_no, raw.to_string());
            if !seen_on_line.insert(dedup_key) {
                return;
            }
            let ent = (shannon_entropy(raw) * 100.0).round() as u32;
            findings.push(SecretFinding {
                rule_id: rule_id.to_string(),
                severity,
                path: rel_path.to_string(),
                line: line_no,
                redacted_preview: redact_secret(raw),
                fingerprint,
                entropy_x100: ent,
            });
        };

        // 1. Private key headers
        if line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----") {
            push_match("private-key-pem", "critical", line.trim());
        }

        // 2. AWS Access Key IDs
        for tok in scan_aws_access_keys(line) {
            push_match("aws-access-key-id", "high", tok);
        }

        // 3. GitHub tokens
        for tok in scan_prefix_tokens(
            line,
            &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
            24,
            is_alnum_underscore_dash,
        ) {
            push_match("github-token", "critical", tok);
        }

        // 4. Hanzo / AI provider API keys
        for tok in scan_prefix_tokens(
            line,
            &["hz_live_", "hz_test_", "hz_sk_", "hanzo_sk_", "sk-ant-", "sk-proj-"],
            16,
            is_alnum_underscore_dash,
        ) {
            push_match("hanzo-api-key", "critical", tok);
        }

        // 5. JWTs
        for tok in scan_jwts(line) {
            push_match("jwt-token", "medium", tok);
        }

        // 6. AWS secret keys & high-entropy secret assignments
        for (rule, tok) in scan_high_entropy_assignments(line, min_entropy) {
            let sev = if rule == "aws-secret-access-key" {
                "critical"
            } else {
                "medium"
            };
            push_match(rule, sev, tok);
        }
    }

    findings
}

fn collect_files(
    base: &Path,
    dir: &Path,
    include_hidden: bool,
    out: &mut Vec<(String, PathBuf)>,
) -> std::io::Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        if SKIP_DIRS.iter().any(|&skip| skip == name) {
            continue;
        }
        if !include_hidden && name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let _ = collect_files(base, &path, include_hidden, out);
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((rel, path));
        }
    }
    Ok(())
}

/// Scans a single file or directory tree concurrently for secrets.
pub fn scan_path(root: &Path, config: &SecretsConfig) -> Result<SecretsReport, String> {
    let started = Instant::now();
    let meta = fs::metadata(root)
        .map_err(|e| format!("cannot access '{}': {e}", root.display()))?;

    let mut targets: Vec<(String, PathBuf)> = Vec::new();
    if meta.is_file() {
        let rel = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| root.to_string_lossy().into_owned());
        targets.push((rel, root.to_path_buf()));
    } else if meta.is_dir() {
        collect_files(root, root, config.include_hidden, &mut targets)
            .map_err(|e| format!("failed walking '{}': {e}", root.display()))?;
        targets.sort_by(|a, b| a.0.cmp(&b.0));
    } else {
        return Err(format!("unsupported file type: '{}'", root.display()));
    }

    let targets = Arc::new(targets);
    let next_idx = Arc::new(AtomicUsize::new(0));
    let files_scanned = Arc::new(AtomicUsize::new(0));
    let files_skipped = Arc::new(AtomicUsize::new(0));
    let findings = Arc::new(Mutex::new(Vec::<SecretFinding>::new()));

    let workers = config.concurrency.clamp(1, 32).min(targets.len().max(1));
    let max_bytes = config.max_file_bytes;
    let min_entropy = config.min_entropy;

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let targets = Arc::clone(&targets);
        let next_idx = Arc::clone(&next_idx);
        let files_scanned = Arc::clone(&files_scanned);
        let files_skipped = Arc::clone(&files_skipped);
        let findings = Arc::clone(&findings);

        handles.push(thread::spawn(move || {
            loop {
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                if idx >= targets.len() {
                    break;
                }
                let (ref rel, ref full) = targets[idx];
                let Ok(meta) = fs::metadata(full) else {
                    files_skipped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if meta.len() > max_bytes || meta.len() == 0 {
                    files_skipped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Ok(mut f) = File::open(full) else {
                    files_skipped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let mut buf = Vec::with_capacity(meta.len() as usize);
                if f.read_to_end(&mut buf).is_err() {
                    files_skipped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                // Skip binary files (NUL byte in first 8 KiB)
                let probe_len = buf.len().min(8192);
                if buf[..probe_len].contains(&0u8) {
                    files_skipped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let text = String::from_utf8_lossy(&buf);
                let found = scan_text(rel, &text, min_entropy);
                files_scanned.fetch_add(1, Ordering::Relaxed);
                if !found.is_empty() {
                    if let Ok(mut guard) = findings.lock() {
                        guard.extend(found);
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }

    let mut all_findings = findings.lock().map(|g| g.clone()).unwrap_or_default();
    all_findings.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    Ok(SecretsReport {
        root: root.to_string_lossy().into_owned(),
        files_scanned: files_scanned.load(Ordering::Relaxed),
        files_skipped: files_skipped.load(Ordering::Relaxed),
        findings_count: all_findings.len(),
        duration_ms: started.elapsed().as_millis() as u64,
        findings: all_findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_and_strictly_redacts_secrets_without_leaking_raw_values() {
        // Construct synthetic test fixtures dynamically so static scanners do not trip on test source.
        let aws_key = ["AKIA", "IOSFODNN7", "ZXQ987A"].concat();
        let gh_token = ["ghp_", "9kLmN2pQrStUvWxYz", "0123456789AbCdEfGh"].concat();
        let hanzo_key = ["hz_live_", "9xK2mP7qR4vT8wZ1bN6cY3fH5jL0"].concat();
        let jwt = [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "eyJzdWIiOiJ1c2VyXzQyIiwib3JnIjoiaGFuem8ifQ",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ]
        .join(".");
        let pem_header = ["-----BEGIN ", "RSA PRIVATE KEY-----"].concat();
        let high_ent = ["xK9#mP2qL8vT4wZ7", "nB3cY6fH1jR5sD0gA9k"].concat();

        let sample = format!(
            "aws_access_key_id = \"{aws_key}\"\n\
             GITHUB_TOKEN={gh_token}\n\
             HANZO_API_KEY={hanzo_key}\n\
             authorization = \"Bearer {jwt}\"\n\
             {pem_header}\n\
             api_secret_token = \"{high_ent}\"\n"
        );

        let findings = scan_text("config.env", &sample, 4.2);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rules.contains(&"aws-access-key-id"), "missing aws-access-key-id: {rules:?}");
        assert!(rules.contains(&"github-token"), "missing github-token: {rules:?}");
        assert!(rules.contains(&"hanzo-api-key"), "missing hanzo-api-key: {rules:?}");
        assert!(rules.contains(&"jwt-token"), "missing jwt-token: {rules:?}");
        assert!(rules.contains(&"private-key-pem"), "missing private-key-pem: {rules:?}");
        assert!(rules.contains(&"high-entropy-secret"), "missing high-entropy-secret: {rules:?}");

        // Verify ZERO raw secret material appears in any redacted preview or JSON report.
        let report = SecretsReport {
            root: "config.env".to_string(),
            files_scanned: 1,
            files_skipped: 0,
            findings_count: findings.len(),
            duration_ms: 1,
            findings,
        };
        let serialized = report.to_json();
        for secret in [&aws_key, &gh_token, &hanzo_key, &jwt, &high_ent] {
            assert!(
                !serialized.contains(secret.as_str()),
                "raw secret leaked into JSON output!"
            );
            // Also ensure the middle slice is never leaked.
            let mid = &secret[4..secret.len() - 4];
            assert!(
                !serialized.contains(mid),
                "middle secret bytes leaked into JSON output!"
            );
        }
    }

    #[test]
    fn scans_directory_and_skips_binary_files() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("cyber_probe_sec_{}_{}", std::process::id(), nanos));
        fs::create_dir_all(&dir).unwrap();

        let hanzo_key = ["hz_test_", "7pQ3vN9mK2xR5tW8bL4cY1fH6jD0"].concat();
        fs::write(dir.join("app.env"), format!("HANZO_KEY={hanzo_key}\n")).unwrap();
        fs::write(dir.join("bin.dat"), b"\x00\x01\x02\x03binarydata").unwrap();

        let report = scan_path(&dir, &SecretsConfig::default()).unwrap();
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.findings_count, 1);
        assert_eq!(report.findings[0].rule_id, "hanzo-api-key");
        assert!(!report.findings[0].redacted_preview.contains(&hanzo_key));

        let _ = fs::remove_dir_all(&dir);
    }
}
