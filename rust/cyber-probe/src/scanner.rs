//! Concurrent threaded TCP port & banner scanner with fail-closed scope enforcement.
//!
//! Every target MUST match at least one explicit `--allow-hosts` rule (exact hostname,
//! wildcard domain `*.example.test`, exact IP, or IPv4/IPv6 CIDR). Empty scope always refuses.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::json;

/// Common ports scanned when `--ports top` is requested.
pub const TOP_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 993, 995,
    1433, 1723, 3000, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8787, 9090,
];

const HTTP_LIKE_PORTS: &[u16] = &[80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8787, 8888, 9000];

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScopeRule {
    ExactHost(String),
    WildcardDomain(String), // stores ".example.test"
    Ipv4Cidr { network: u32, mask: u32 },
    Ipv6Cidr { network: u128, mask: u128 },
}

/// Fail-closed target scope allowlist built from `--allow-hosts`.
#[derive(Debug, Clone)]
pub struct ScopePolicy {
    rules: Vec<ScopeRule>,
    raw_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    EmptyScope,
    InvalidRule(String),
    InvalidTarget(String),
    OutOfScope { target: String, reason: String },
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeError::EmptyScope => {
                write!(f, "refused: --allow-hosts is required and cannot be empty (fail-closed)")
            }
            ScopeError::InvalidRule(r) => write!(f, "invalid --allow-hosts rule: {r}"),
            ScopeError::InvalidTarget(t) => write!(f, "invalid scan target: {t}"),
            ScopeError::OutOfScope { target, reason } => {
                write!(f, "refused: target '{target}' is out of authorized scope ({reason})")
            }
        }
    }
}

fn normalize_host(input: &str) -> String {
    let trimmed = input.trim();
    let stripped = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    stripped.trim_end_matches('.').to_ascii_lowercase()
}

fn ipv4_mask(prefix: u32) -> u32 {
    if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u32) -> u128 {
    if prefix == 0 {
        0
    } else {
        !0u128 << (128 - prefix)
    }
}

impl ScopePolicy {
    /// Parses a list of allowed hosts/wildcards/CIDRs.
    pub fn from_allow_hosts<S: AsRef<str>>(items: &[S]) -> Result<Self, ScopeError> {
        let mut rules = Vec::new();
        let mut raw_rules = Vec::new();

        for item in items {
            for part in item.as_ref().split(',') {
                let raw = part.trim();
                if raw.is_empty() {
                    continue;
                }
                raw_rules.push(raw.to_string());
                rules.push(Self::parse_rule(raw)?);
            }
        }

        if rules.is_empty() {
            return Err(ScopeError::EmptyScope);
        }

        Ok(Self { rules, raw_rules })
    }

    fn parse_rule(raw: &str) -> Result<ScopeRule, ScopeError> {
        let norm = normalize_host(raw);
        if norm.is_empty() || norm.chars().any(char::is_whitespace) {
            return Err(ScopeError::InvalidRule(raw.to_string()));
        }

        // CIDR rule?
        if let Some((ip_part, prefix_part)) = norm.split_once('/') {
            let prefix: u32 = prefix_part
                .parse()
                .map_err(|_| ScopeError::InvalidRule(raw.to_string()))?;
            if let Ok(v4) = ip_part.parse::<Ipv4Addr>() {
                if prefix > 32 {
                    return Err(ScopeError::InvalidRule(raw.to_string()));
                }
                let mask = ipv4_mask(prefix);
                let network = u32::from(v4) & mask;
                return Ok(ScopeRule::Ipv4Cidr { network, mask });
            }
            if let Ok(v6) = ip_part.parse::<Ipv6Addr>() {
                if prefix > 128 {
                    return Err(ScopeError::InvalidRule(raw.to_string()));
                }
                let mask = ipv6_mask(prefix);
                let network = u128::from_be_bytes(v6.octets()) & mask;
                return Ok(ScopeRule::Ipv6Cidr { network, mask });
            }
            return Err(ScopeError::InvalidRule(raw.to_string()));
        }

        // Exact IP address?
        if let Ok(ip) = norm.parse::<IpAddr>() {
            return Ok(match ip {
                IpAddr::V4(v4) => ScopeRule::Ipv4Cidr {
                    network: u32::from(v4),
                    mask: !0u32,
                },
                IpAddr::V6(v6) => ScopeRule::Ipv6Cidr {
                    network: u128::from_be_bytes(v6.octets()),
                    mask: !0u128,
                },
            });
        }

        // Wildcard domain `*.example.test` (never allow bare `*`)
        if let Some(rest) = norm.strip_prefix("*.") {
            if rest.is_empty() || rest.contains('*') || !rest.contains('.') {
                return Err(ScopeError::InvalidRule(raw.to_string()));
            }
            return Ok(ScopeRule::WildcardDomain(format!(".{rest}")));
        }

        if norm.contains('*') {
            return Err(ScopeError::InvalidRule(raw.to_string()));
        }

        Ok(ScopeRule::ExactHost(norm))
    }

    /// Checks whether an IP matches any IP/CIDR rule in the policy.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        for rule in &self.rules {
            match (rule, ip) {
                (ScopeRule::Ipv4Cidr { network, mask }, IpAddr::V4(v4)) => {
                    if (u32::from(v4) & *mask) == *network {
                        return true;
                    }
                }
                (ScopeRule::Ipv6Cidr { network, mask }, IpAddr::V6(v6)) => {
                    if (u128::from_be_bytes(v6.octets()) & *mask) == *network {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Checks whether a host string is explicitly authorized by hostname or IP/CIDR rules.
    pub fn matches_host(&self, target: &str) -> Result<bool, ScopeError> {
        let norm = normalize_host(target);
        if norm.is_empty() || norm.chars().any(char::is_whitespace) || norm.contains('/') {
            return Err(ScopeError::InvalidTarget(target.to_string()));
        }

        if let Ok(ip) = norm.parse::<IpAddr>() {
            return Ok(self.matches_ip(ip));
        }

        for rule in &self.rules {
            match rule {
                ScopeRule::ExactHost(h) if h == &norm => return Ok(true),
                ScopeRule::WildcardDomain(suffix)
                    if norm.ends_with(suffix) && norm.len() > suffix.len() =>
                {
                    return Ok(true);
                }
                _ => {}
            }
        }
        Ok(false)
    }

    /// Enforces scope on a target string before any socket is opened.
    pub fn check_target(&self, target: &str) -> Result<(), ScopeError> {
        if self.matches_host(target)? {
            return Ok(());
        }
        Err(ScopeError::OutOfScope {
            target: target.to_string(),
            reason: format!("does not match allowlist [{}]", self.raw_rules.join(", ")),
        })
    }
}

/// Parses a port specification (`80`, `22,80,443`, `8000-8010`, `top`).
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("top") {
        return Ok(TOP_PORTS.to_vec());
    }

    let mut ports = Vec::new();
    for token in trimmed.split(',') {
        let part = token.trim();
        if part.is_empty() {
            continue;
        }
        if part.eq_ignore_ascii_case("top") {
            ports.extend_from_slice(TOP_PORTS);
            continue;
        }
        if let Some((start_s, end_s)) = part.split_once('-') {
            let start: u16 = start_s
                .trim()
                .parse()
                .map_err(|_| format!("invalid port range start: '{part}'"))?;
            let end: u16 = end_s
                .trim()
                .parse()
                .map_err(|_| format!("invalid port range end: '{part}'"))?;
            if start == 0 || end == 0 || start > end {
                return Err(format!("invalid port range: '{part}'"));
            }
            for p in start..=end {
                ports.push(p);
            }
        } else {
            let p: u16 = part
                .parse()
                .map_err(|_| format!("invalid port number: '{part}'"))?;
            if p == 0 {
                return Err("port 0 is invalid".to_string());
            }
            ports.push(p);
        }
    }

    if ports.is_empty() {
        return Err("no valid ports specified".to_string());
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: String,
    pub ports: Vec<u16>,
    pub allow_hosts: Vec<String>,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub grab_banner: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortResult {
    pub port: u16,
    pub state: &'static str,
    pub service: String,
    pub banner: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ScanReport {
    pub target: String,
    pub resolved_ip: String,
    pub scanned_ports: usize,
    pub open_count: usize,
    pub duration_ms: u64,
    pub open: Vec<PortResult>,
}

impl ScanReport {
    pub fn to_json(&self) -> String {
        let mut out = String::from("{");
        out.push_str(&format!("\"target\":{},", json::quote(&self.target)));
        out.push_str(&format!("\"resolved_ip\":{},", json::quote(&self.resolved_ip)));
        out.push_str(&format!("\"scanned_ports\":{},", self.scanned_ports));
        out.push_str(&format!("\"open_count\":{},", self.open_count));
        out.push_str(&format!("\"duration_ms\":{},", self.duration_ms));
        out.push_str("\"untrusted_target_output\":true,");
        out.push_str("\"open\":[");
        for (i, item) in self.open.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"port\":{},\"state\":{},\"service\":{},\"banner\":{},\"latency_ms\":{}}}",
                item.port,
                json::quote(item.state),
                json::quote(&item.service),
                json::quote(&item.banner),
                item.latency_ms,
            ));
        }
        out.push_str("]}");
        out
    }
}

#[derive(Debug, Clone)]
pub enum ScanError {
    Scope(ScopeError),
    InvalidConfig(String),
    ResolveFailed(String),
}

impl ScanError {
    pub fn code(&self) -> &'static str {
        match self {
            ScanError::Scope(_) => "SCOPE_REFUSED",
            ScanError::InvalidConfig(_) => "INVALID_CONFIG",
            ScanError::ResolveFailed(_) => "RESOLVE_FAILED",
        }
    }
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Scope(e) => write!(f, "{e}"),
            ScanError::InvalidConfig(m) => write!(f, "{m}"),
            ScanError::ResolveFailed(m) => write!(f, "{m}"),
        }
    }
}

fn sanitize_banner(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len().min(256));
    let mut prev_space = false;
    for &b in raw.iter().take(512) {
        if out.len() >= 256 {
            break;
        }
        match b {
            0x20..=0x7e => {
                let ch = b as char;
                if ch == ' ' {
                    if !prev_space && !out.is_empty() {
                        out.push(' ');
                    }
                    prev_space = true;
                } else {
                    out.push(ch);
                    prev_space = false;
                }
            }
            b'\r' | b'\n' | b'\t' => {
                if !prev_space && !out.is_empty() {
                    out.push(' ');
                    prev_space = true;
                }
            }
            _ => {}
        }
    }
    out.trim().to_string()
}

fn infer_service(port: u16, banner: &str) -> String {
    let lower = banner.to_ascii_lowercase();
    if lower.starts_with("ssh-") {
        return "ssh".to_string();
    }
    if lower.starts_with("http/") {
        return if port == 443 || port == 8443 {
            "https".to_string()
        } else {
            "http".to_string()
        };
    }
    if lower.starts_with("220 ") && lower.contains("ftp") {
        return "ftp".to_string();
    }
    if lower.starts_with("220 ") && (lower.contains("smtp") || lower.contains("esmtp")) {
        return "smtp".to_string();
    }
    if lower.contains("redis") || lower.starts_with("-err") || lower.starts_with("+pong") {
        return "redis".to_string();
    }
    if lower.contains("mysql") || lower.contains("mariadb") {
        return "mysql".to_string();
    }
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 => "smtp",
        53 => "dns",
        80 | 8000 | 8080 | 8081 | 8787 => "http",
        110 => "pop3",
        143 => "imap",
        443 | 8443 => "https",
        445 => "smb",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        6379 => "redis",
        9090 => "metrics",
        _ => "tcp",
    }
    .to_string()
}

fn probe_port(
    ip: IpAddr,
    target_host: &str,
    port: u16,
    timeout: Duration,
    grab_banner: bool,
) -> Option<PortResult> {
    let addr = SocketAddr::new(ip, port);
    let started = Instant::now();
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    let latency_ms = started.elapsed().as_millis() as u64;

    let mut banner = String::new();
    if grab_banner {
        let banner_timeout = timeout.min(Duration::from_millis(500));
        let _ = stream.set_read_timeout(Some(banner_timeout));
        let _ = stream.set_write_timeout(Some(banner_timeout));

        let mut buf = [0u8; 512];
        match stream.read(&mut buf) {
            Ok(n) if n > 0 => {
                banner = sanitize_banner(&buf[..n]);
            }
            _ => {
                if HTTP_LIKE_PORTS.contains(&port) {
                    let req = format!("HEAD / HTTP/1.0\r\nHost: {target_host}\r\nConnection: close\r\n\r\n");
                    if stream.write_all(req.as_bytes()).is_ok() {
                        if let Ok(n) = stream.read(&mut buf) {
                            if n > 0 {
                                banner = sanitize_banner(&buf[..n]);
                            }
                        }
                    }
                }
            }
        }
    }

    let service = infer_service(port, &banner);
    Some(PortResult {
        port,
        state: "open",
        service,
        banner,
        latency_ms,
    })
}

/// Runs a strictly scoped concurrent TCP port & banner scan.
pub fn scan_ports(config: &ScanConfig) -> Result<ScanReport, ScanError> {
    let policy = ScopePolicy::from_allow_hosts(&config.allow_hosts).map_err(ScanError::Scope)?;

    if config.ports.is_empty() {
        return Err(ScanError::InvalidConfig("ports list cannot be empty".to_string()));
    }

    // Check literal target first before doing any DNS resolution or socket connect.
    let direct_match = policy.matches_host(&config.target).map_err(ScanError::Scope)?;

    let target_norm = normalize_host(&config.target);
    let resolved_ips: Vec<IpAddr> = if let Ok(ip) = target_norm.parse::<IpAddr>() {
        if !direct_match {
            policy.check_target(&config.target).map_err(ScanError::Scope)?;
        }
        vec![ip]
    } else {
        // Hostname target: if it doesn't match hostname/wildcard allowlist, only allow if
        // allowlist contains IP/CIDR rules AND every resolved IP falls inside them.
        if !direct_match {
            let has_ip_rule = policy
                .rules
                .iter()
                .any(|r| matches!(r, ScopeRule::Ipv4Cidr { .. } | ScopeRule::Ipv6Cidr { .. }));
            if !has_ip_rule {
                policy.check_target(&config.target).map_err(ScanError::Scope)?;
            }
        }
        let addrs: Vec<IpAddr> = (target_norm.as_str(), config.ports[0])
            .to_socket_addrs()
            .map_err(|e| ScanError::ResolveFailed(format!("DNS lookup failed for '{}': {e}", config.target)))?
            .map(|sa| sa.ip())
            .collect();
        if addrs.is_empty() {
            return Err(ScanError::ResolveFailed(format!(
                "no IP addresses resolved for '{}'",
                config.target
            )));
        }
        if !direct_match && !addrs.iter().all(|ip| policy.matches_ip(*ip)) {
            return Err(ScanError::Scope(ScopeError::OutOfScope {
                target: config.target.clone(),
                reason: "resolved IP falls outside --allow-hosts CIDR/IP allowlist".to_string(),
            }));
        }
        addrs
    };

    let target_ip = resolved_ips[0];
    let timeout = Duration::from_millis(config.timeout_ms.clamp(50, 10_000));
    let workers = config.concurrency.clamp(1, 256).min(config.ports.len());
    let ports = Arc::new(config.ports.clone());
    let next_idx = Arc::new(AtomicUsize::new(0));
    let results: Arc<Mutex<Vec<PortResult>>> = Arc::new(Mutex::new(Vec::new()));
    let target_host = Arc::new(target_norm);
    let grab_banner = config.grab_banner;

    let started = Instant::now();
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let ports = Arc::clone(&ports);
        let next_idx = Arc::clone(&next_idx);
        let results = Arc::clone(&results);
        let target_host = Arc::clone(&target_host);
        handles.push(thread::spawn(move || {
            loop {
                let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                if idx >= ports.len() {
                    break;
                }
                let port = ports[idx];
                if let Some(found) = probe_port(target_ip, &target_host, port, timeout, grab_banner) {
                    if let Ok(mut guard) = results.lock() {
                        guard.push(found);
                    }
                }
            }
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    let mut open = results
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();
    open.sort_by_key(|r| r.port);

    Ok(ScanReport {
        target: config.target.clone(),
        resolved_ip: target_ip.to_string(),
        scanned_ports: config.ports.len(),
        open_count: open.len(),
        duration_ms: started.elapsed().as_millis() as u64,
        open,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn refuses_empty_scope_and_out_of_scope_targets() {
        // Empty scope always fails closed.
        let empty = ScopePolicy::from_allow_hosts::<&str>(&[]);
        assert_eq!(empty.unwrap_err(), ScopeError::EmptyScope);

        // Out-of-scope IP/hostname is strictly refused before any socket call.
        let err = scan_ports(&ScanConfig {
            target: "198.51.100.10".to_string(),
            ports: vec![80, 443],
            allow_hosts: vec!["127.0.0.1".to_string(), "*.mdtf.test".to_string()],
            timeout_ms: 200,
            concurrency: 4,
            grab_banner: false,
        })
        .unwrap_err();
        assert_eq!(err.code(), "SCOPE_REFUSED");

        // Subdomain suffix spoofing (`evil-mdtf.test`) must NOT match `*.mdtf.test`.
        let policy = ScopePolicy::from_allow_hosts(&["*.mdtf.test", "10.10.0.0/24"]).unwrap();
        assert!(policy.check_target("api.mdtf.test").is_ok());
        assert!(policy.check_target("10.10.0.42").is_ok());
        assert!(policy.check_target("evil-mdtf.test").is_err());
        assert!(policy.check_target("mdtf.test").is_err());
        assert!(policy.check_target("10.10.1.1").is_err());
    }

    #[test]
    fn probes_localhost_tcp_listener_and_grabs_banner() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let open_port = listener.local_addr().unwrap().port();

        // Pick a closed ephemeral port by binding and immediately dropping.
        let closed_port = {
            let tmp = TcpListener::bind("127.0.0.1:0").unwrap();
            tmp.local_addr().unwrap().port()
        };

        let server = thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let _ = conn.write_all(b"SSH-2.0-HanzoCyberTest_1.0\r\n");
                let _ = conn.flush();
            }
        });

        let report = scan_ports(&ScanConfig {
            target: "127.0.0.1".to_string(),
            ports: vec![closed_port, open_port],
            allow_hosts: vec!["127.0.0.0/8".to_string()],
            timeout_ms: 500,
            concurrency: 4,
            grab_banner: true,
        })
        .expect("localhost scan succeeds under 127.0.0.0/8 scope");

        let _ = server.join();

        assert_eq!(report.scanned_ports, 2);
        assert_eq!(report.open_count, 1);
        assert_eq!(report.open[0].port, open_port);
        assert_eq!(report.open[0].service, "ssh");
        assert!(report.open[0].banner.contains("SSH-2.0-HanzoCyberTest_1.0"));
    }

    #[test]
    fn parses_port_lists_and_ranges() {
        assert_eq!(parse_ports("80,22,80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("8000-8002").unwrap(), vec![8000, 8001, 8002]);
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("90-80").is_err());
    }
}
