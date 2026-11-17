//! `.env` text and path rules. Pure functions only.

pub type Pairs = Vec<(String, String)>;

pub fn valid_key(k: &str) -> bool {
    let mut b = k.bytes();
    k.len() <= 128
        && matches!(b.next(), Some(c) if c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// Reads `KEY=value` lines. Comments and blank lines are dropped, an `export ` prefix and
/// surrounding quotes are removed. Double-quoted values use JSON escapes (what `format_env` writes).
pub fn parse_env(text: &str) -> Pairs {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_start();
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim();
        if !valid_key(k) {
            continue;
        }
        let v = v.trim();
        let v = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
            serde_json::from_str::<String>(v).unwrap_or_else(|_| v[1..v.len() - 1].to_string())
        } else if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
            v[1..v.len() - 1].to_string()
        } else {
            v.to_string()
        };
        out.push((k.to_string(), v));
    }
    out
}

/// Quotes only values that need it (whitespace, `#`, quotes, backslash, empty).
pub fn format_env(pairs: &[(String, String)], header: Option<&str>) -> String {
    let mut s = String::new();
    if let Some(h) = header {
        for l in h.lines() {
            s.push_str("# ");
            s.push_str(l);
            s.push('\n');
        }
    }
    for (k, v) in pairs {
        let needs = v.is_empty() || v.chars().any(|c| c.is_whitespace() || matches!(c, '#' | '"' | '\'' | '\\'));
        let v = if needs { serde_json::to_string(v).unwrap() } else { v.clone() };
        s.push_str(&format!("{k}={v}\n"));
    }
    s
}

/// A vault path is the file's path relative to its repository (`deploy/app/.env`). Leading `./`
/// and `/` are trimmed; empty, `.`/`..` and odd characters are rejected.
pub fn normalize_path(raw: &str) -> Result<String, String> {
    let p = raw.trim();
    let p = p.strip_prefix("./").unwrap_or(p).trim_start_matches('/').trim_end_matches('/');
    if p.is_empty() || p.len() > 300 {
        return Err("path is empty or too long".into());
    }
    let ok = p.split('/').all(|s| {
        !s.is_empty() && s != "." && s != ".." && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'-'))
    });
    if ok { Ok(p.to_string()) } else { Err(format!("invalid path: {raw}")) }
}

/// Token scope: `*` is everything, `dir/` is everything below it, otherwise one exact path.
pub fn in_scope(scope: &str, path: &str) -> bool {
    scope == "*" || if scope.ends_with('/') { path.starts_with(scope) } else { path == scope }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format_round_trip() {
        let text = "# c\nexport A=1\nB = 'two words'\nC=\"x\\ny\"\n\nbad line\n1X=no\nD=\n";
        let p = parse_env(text);
        assert_eq!(p, vec![
            ("A".into(), "1".into()),
            ("B".into(), "two words".into()),
            ("C".into(), "x\ny".into()),
            ("D".into(), "".into()),
        ]);
        assert_eq!(parse_env(&format_env(&p, Some("hdr"))), p);
    }

    #[test]
    fn paths() {
        assert_eq!(normalize_path("./deploy/a/.env").unwrap(), "deploy/a/.env");
        assert_eq!(normalize_path("/x/.env.local/").unwrap(), "x/.env.local");
        for bad in ["", "../x", "a//b", "a/./b", "a b", "a/../b"] {
            assert!(normalize_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn scopes() {
        assert!(in_scope("*", "a/b"));
        assert!(in_scope("deploy/", "deploy/x/.env"));
        assert!(!in_scope("deploy/", "deployx/.env"));
        assert!(in_scope("a/.env", "a/.env"));
        assert!(!in_scope("a/.env", "a/.env.local"));
    }
}
