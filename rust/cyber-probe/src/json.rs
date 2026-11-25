//! Minimal RFC 8259 JSON serialization helpers (zero external dependencies).

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Escapes a string into a valid JSON string literal (without surrounding quotes).
pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Returns a double-quoted JSON string literal.
pub fn quote(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    out.push_str(&escape(input));
    out.push('"');
    out
}

/// Wraps a JSON value payload inside a standard cyber-probe success envelope.
pub fn envelope_ok(command: &str, data_json: &str) -> String {
    format!(
        "{{\"ok\":true,\"tool\":\"cyber-probe\",\"command\":{},\"version\":{},\"data\":{}}}",
        quote(command),
        quote(VERSION),
        data_json,
    )
}

/// Wraps an error code and message inside a standard cyber-probe error envelope.
pub fn envelope_err(command: &str, code: &str, message: &str) -> String {
    format!(
        "{{\"ok\":false,\"tool\":\"cyber-probe\",\"command\":{},\"version\":{},\"error\":{{\"code\":{},\"message\":{}}}}}",
        quote(command),
        quote(VERSION),
        quote(code),
        quote(message),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_quote_characters() {
        assert_eq!(escape("a\"b\\c\nd\te\u{0001}"), "a\\\"b\\\\c\\nd\\te\\u0001");
        assert_eq!(quote("ok"), "\"ok\"");
    }
}
