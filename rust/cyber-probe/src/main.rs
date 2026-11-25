//! `cyber-probe`: zero-dependency Rust scanner CLI for Hanzo Cyber.
//!
//! Subcommands:
//!   cyber-probe ports   --target <HOST> --allow-hosts <LIST> [--ports top|22,80|1-1024]
//!   cyber-probe secrets --path <PATH> [--min-entropy 4.2] [--max-bytes 2097152]
//!   cyber-probe hash    --path <PATH> [--exclude .git,target]
//!   cyber-probe version

mod json;
mod scanner;
mod secrets;
mod sha256;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn print_usage() {
    let usage = "\
cyber-probe — zero-dependency Rust scanner for Hanzo Cyber

Usage:
  cyber-probe ports   --target <HOST> --allow-hosts <HOSTS> [--ports top|22,80|1-1024] [--timeout-ms 400] [--concurrency 64] [--no-banner]
  cyber-probe secrets --path <PATH> [--min-entropy 4.2] [--max-bytes 2097152] [--include-hidden]
  cyber-probe hash    --path <PATH> [--exclude .git,target]
  cyber-probe version

All subcommands emit deterministic JSON envelopes on stdout.";
    eprintln!("{usage}");
}

fn run_version() -> ExitCode {
    let data = format!(
        "{{\"name\":\"cyber-probe\",\"version\":{},\"os\":{},\"arch\":{}}}",
        json::quote(json::VERSION),
        json::quote(env::consts::OS),
        json::quote(env::consts::ARCH),
    );
    println!("{}", json::envelope_ok("version", &data));
    ExitCode::SUCCESS
}

fn next_flag_value(args: &[String], idx: &mut usize, flag: &str) -> Result<String, String> {
    *idx += 1;
    args.get(*idx)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn run_ports(args: &[String]) -> ExitCode {
    let mut target = String::new();
    let mut allow_hosts: Vec<String> = Vec::new();
    let mut ports_spec = String::from("top");
    let mut timeout_ms = 400u64;
    let mut concurrency = 64usize;
    let mut grab_banner = true;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "-t" => match next_flag_value(args, &mut i, "--target") {
                Ok(v) => target = v,
                Err(e) => {
                    println!("{}", json::envelope_err("ports", "INVALID_ARGS", &e));
                    return ExitCode::from(2);
                }
            },
            "--allow-hosts" => match next_flag_value(args, &mut i, "--allow-hosts") {
                Ok(v) => allow_hosts.push(v),
                Err(e) => {
                    println!("{}", json::envelope_err("ports", "INVALID_ARGS", &e));
                    return ExitCode::from(2);
                }
            },
            "--ports" | "-p" => match next_flag_value(args, &mut i, "--ports") {
                Ok(v) => ports_spec = v,
                Err(e) => {
                    println!("{}", json::envelope_err("ports", "INVALID_ARGS", &e));
                    return ExitCode::from(2);
                }
            },
            "--timeout-ms" => match next_flag_value(args, &mut i, "--timeout-ms") {
                Ok(v) => match v.parse::<u64>() {
                    Ok(ms) => timeout_ms = ms,
                    Err(_) => {
                        println!(
                            "{}",
                            json::envelope_err("ports", "INVALID_ARGS", "invalid --timeout-ms integer")
                        );
                        return ExitCode::from(2);
                    }
                },
                Err(e) => {
                    println!("{}", json::envelope_err("ports", "INVALID_ARGS", &e));
                    return ExitCode::from(2);
                }
            },
            "--concurrency" | "-c" => match next_flag_value(args, &mut i, "--concurrency") {
                Ok(v) => match v.parse::<usize>() {
                    Ok(c) => concurrency = c,
                    Err(_) => {
                        println!(
                            "{}",
                            json::envelope_err("ports", "INVALID_ARGS", "invalid --concurrency integer")
                        );
                        return ExitCode::from(2);
                    }
                },
                Err(e) => {
                    println!("{}", json::envelope_err("ports", "INVALID_ARGS", &e));
                    return ExitCode::from(2);
                }
            },
            "--no-banner" => grab_banner = false,
            other => {
                if !other.starts_with('-') && target.is_empty() {
                    target = other.to_string();
                } else {
                    println!(
                        "{}",
                        json::envelope_err("ports", "INVALID_ARGS", &format!("unknown argument: {other}"))
                    );
                    return ExitCode::from(2);
                }
            }
        }
        i += 1;
    }

    if target.trim().is_empty() {
        println!(
            "{}",
            json::envelope_err("ports", "INVALID_ARGS", "--target is required")
        );
        return ExitCode::from(2);
    }

    let ports = match scanner::parse_ports(&ports_spec) {
        Ok(p) => p,
        Err(e) => {
            println!("{}", json::envelope_err("ports", "INVALID_PORTS", &e));
            return ExitCode::from(2);
        }
    };

    let cfg = scanner::ScanConfig {
        target,
        ports,
        allow_hosts,
        timeout_ms,
        concurrency,
        grab_banner,
    };

    match scanner::scan_ports(&cfg) {
        Ok(report) => {
            println!("{}", json::envelope_ok("ports", &report.to_json()));
            ExitCode::SUCCESS
        }
        Err(err) => {
            println!("{}", json::envelope_err("ports", err.code(), &err.to_string()));
            ExitCode::from(2)
        }
    }
}

fn run_secrets(args: &[String]) -> ExitCode {
    let mut path: Option<PathBuf> = None;
    let mut cfg = secrets::SecretsConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" | "-p" => match next_flag_value(args, &mut i, "--path") {
                Ok(v) => path = Some(PathBuf::from(v)),
                Err(e) => {
                    println!("{}", json::envelope_err("secrets", "INVALID_ARGS", &e));
                    return ExitCode::from(2);
                }
            },
            "--max-bytes" => match next_flag_value(args, &mut i, "--max-bytes") {
                Ok(v) => match v.parse::<u64>() {
                    Ok(n) => cfg.max_file_bytes = n,
                    Err(_) => {
                        println!(
                            "{}",
                            json::envelope_err("secrets", "INVALID_ARGS", "invalid --max-bytes integer")
                        );
                        return ExitCode::from(2);
                    }
                },
                Err(e) => {
                    println!("{}", json::envelope_err("secrets", "INVALID_ARGS", &e));
                    return ExitCode::from(2);
                }
            },
            "--min-entropy" => match next_flag_value(args, &mut i, "--min-entropy") {
                Ok(v) => match v.parse::<f64>() {
                    Ok(e) => cfg.min_entropy = e,
                    Err(_) => {
                        println!(
                            "{}",
                            json::envelope_err("secrets", "INVALID_ARGS", "invalid --min-entropy float")
                        );
                        return ExitCode::from(2);
                    }
                },
                Err(e) => {
                    println!("{}", json::envelope_err("secrets", "INVALID_ARGS", &e));
                    return ExitCode::from(2);
                }
            },
            "--include-hidden" => cfg.include_hidden = true,
            other => {
                if !other.starts_with('-') && path.is_none() {
                    path = Some(PathBuf::from(other));
                } else {
                    println!(
                        "{}",
                        json::envelope_err("secrets", "INVALID_ARGS", &format!("unknown argument: {other}"))
                    );
                    return ExitCode::from(2);
                }
            }
        }
        i += 1;
    }

    let target_path = path.unwrap_or_else(|| PathBuf::from("."));
    match secrets::scan_path(&target_path, &cfg) {
        Ok(report) => {
            println!("{}", json::envelope_ok("secrets", &report.to_json()));
            ExitCode::SUCCESS
        }
        Err(err) => {
            println!("{}", json::envelope_err("secrets", "SCAN_ERROR", &err));
            ExitCode::from(2)
        }
    }
}

fn run_hash(args: &[String]) -> ExitCode {
    let mut path: Option<PathBuf> = None;
    let mut excludes: Vec<String> = vec![".git".to_string(), "target".to_string()];

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--path" | "-p" => match next_flag_value(args, &mut i, "--path") {
                Ok(v) => path = Some(PathBuf::from(v)),
                Err(e) => {
                    println!("{}", json::envelope_err("hash", "INVALID_ARGS", &e));
                    return ExitCode::from(2);
                }
            },
            "--exclude" => match next_flag_value(args, &mut i, "--exclude") {
                Ok(v) => {
                    excludes = v
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                Err(e) => {
                    println!("{}", json::envelope_err("hash", "INVALID_ARGS", &e));
                    return ExitCode::from(2);
                }
            },
            other => {
                if !other.starts_with('-') && path.is_none() {
                    path = Some(PathBuf::from(other));
                } else {
                    println!(
                        "{}",
                        json::envelope_err("hash", "INVALID_ARGS", &format!("unknown argument: {other}"))
                    );
                    return ExitCode::from(2);
                }
            }
        }
        i += 1;
    }

    let target_path = match path {
        Some(p) => p,
        None => {
            println!(
                "{}",
                json::envelope_err("hash", "INVALID_ARGS", "--path is required")
            );
            return ExitCode::from(2);
        }
    };

    match sha256::hash_tree(&target_path, &excludes) {
        Ok(report) => {
            println!("{}", json::envelope_ok("hash", &report.to_json()));
            ExitCode::SUCCESS
        }
        Err(err) => {
            println!("{}", json::envelope_err("hash", "IO_ERROR", &err.to_string()));
            ExitCode::from(2)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        print_usage();
        return ExitCode::from(2);
    };

    match cmd {
        "version" | "--version" | "-V" => run_version(),
        "ports" => run_ports(&args[1..]),
        "secrets" => run_secrets(&args[1..]),
        "hash" => run_hash(&args[1..]),
        "help" | "--help" | "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        other => {
            println!(
                "{}",
                json::envelope_err(other, "UNKNOWN_COMMAND", &format!("unknown subcommand: {other}"))
            );
            ExitCode::from(2)
        }
    }
}
