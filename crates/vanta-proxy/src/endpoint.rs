//! Proxy endpoints and the bulk-import line grammar (F04 Proxy Hub).
//!
//! Accepted line forms (one proxy per line, blank lines and `#` comments skipped):
//!
//! ```text
//! host:port
//! host:port:user:pass
//! user:pass@host:port
//! scheme://host:port
//! scheme://user:pass@host:port        scheme = http | https | socks5 (socks5h accepted)
//! [2001:db8::1]:1080                  IPv6 hosts must be bracketed
//! ```
//!
//! Lines without a scheme take the caller's default scheme. Passwords are held in
//! [`zeroize::Zeroizing`] memory, are never part of `Debug`/`Display` output, and are never
//! echoed in import error messages.

use std::fmt;
use std::net::IpAddr;
use vanta_types::{Result, VantaError};
use zeroize::Zeroizing;

/// Protocol spoken to the upstream proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyScheme {
    Http,
    Https,
    Socks5,
}

impl ProxyScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyScheme::Http => "http",
            ProxyScheme::Https => "https",
            ProxyScheme::Socks5 => "socks5",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            "socks5" | "socks5h" => Ok(Self::Socks5),
            _ => Err(VantaError::Invalid(
                "unsupported scheme (use http, https or socks5)".into(),
            )),
        }
    }
}

/// Proxy login. The password lives in zeroizing memory and is redacted from `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    password: Zeroizing<String>,
}

impl Credentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: Zeroizing::new(password.into()),
        }
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// One upstream proxy.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub scheme: ProxyScheme,
    /// Lower-cased host name or IP literal (IPv6 without brackets).
    pub host: String,
    pub port: u16,
    pub auth: Option<Credentials>,
}

impl ProxyEndpoint {
    pub fn new(scheme: ProxyScheme, host: &str, port: u16, auth: Option<Credentials>) -> Self {
        Self {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
            auth,
        }
    }

    /// The host as an IP address, when it is a literal.
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    /// `host:port`, with brackets around IPv6 literals.
    pub fn host_port(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Redacted form: `socks5://user:***@host:port`.
impl fmt::Display for ProxyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.auth {
            Some(c) => write!(
                f,
                "{}://{}:***@{}",
                self.scheme.as_str(),
                c.username,
                self.host_port()
            ),
            None => write!(f, "{}://{}", self.scheme.as_str(), self.host_port()),
        }
    }
}

impl fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyEndpoint({self})")
    }
}

fn invalid(msg: &str) -> VantaError {
    VantaError::Invalid(msg.into())
}

fn parse_port(s: &str) -> Result<u16> {
    match s.parse::<u16>() {
        Ok(p) if p != 0 && !s.starts_with('+') => Ok(p),
        _ => Err(invalid("port must be a number from 1 to 65535")),
    }
}

fn validate_host(h: &str) -> Result<String> {
    if h.is_empty() || h.len() > 253 {
        return Err(invalid("missing or overlong host"));
    }
    if h.parse::<IpAddr>().is_ok() {
        return Ok(h.to_ascii_lowercase());
    }
    let ok = h.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    if !ok {
        return Err(invalid("host is not a valid name or IP address"));
    }
    Ok(h.to_ascii_lowercase())
}

/// Split `host:port`, accepting `[v6]:port`.
fn split_host_port(s: &str) -> Result<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest
            .split_once(']')
            .ok_or_else(|| invalid("unclosed '[' in IPv6 host"))?;
        if h.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(invalid("bracketed host is not an IPv6 address"));
        }
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| invalid("missing port"))?;
        return Ok((h.to_ascii_lowercase(), parse_port(port)?));
    }
    let (h, p) = s.rsplit_once(':').ok_or_else(|| invalid("missing port"))?;
    Ok((validate_host(h)?, parse_port(p)?))
}

fn percent_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| invalid("bad %-escape in login"))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| invalid("login is not UTF-8"))
}

fn credentials(user: &str, pass: &str, url_form: bool) -> Result<Credentials> {
    let (user, pass) = if url_form {
        (percent_decode(user)?, percent_decode(pass)?)
    } else {
        (user.to_string(), pass.to_string())
    };
    if user.is_empty() {
        return Err(invalid("empty username"));
    }
    if user.chars().any(char::is_whitespace) {
        return Err(invalid("username contains whitespace"));
    }
    Ok(Credentials::new(user, pass))
}

/// Parse one import line. Error messages describe the problem, never the line itself.
pub fn parse_line(line: &str, default_scheme: ProxyScheme) -> Result<ProxyEndpoint> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err(invalid("empty line"));
    }
    if line.chars().any(char::is_whitespace) {
        return Err(invalid("whitespace inside the proxy line"));
    }
    let (scheme, rest, has_scheme) = match line.split_once("://") {
        Some((s, r)) => (ProxyScheme::parse(s)?, r.trim_end_matches('/'), true),
        None => (default_scheme, line, false),
    };
    if let Some((userinfo, hostport)) = rest.rsplit_once('@') {
        let at_form = (|| {
            let (user, pass) = userinfo
                .split_once(':')
                .ok_or_else(|| invalid("login must be user:pass"))?;
            let (host, port) = split_host_port(hostport)?;
            let auth = credentials(user, pass, has_scheme)?;
            Ok(ProxyEndpoint::new(scheme, &host, port, Some(auth)))
        })();
        // `host:port:user:pass` where the login itself contains '@' (e.g. an e-mail).
        if at_form.is_err() && !has_scheme {
            if let Ok(e) = parse_colon_form(scheme, rest, has_scheme) {
                return Ok(e);
            }
        }
        return at_form;
    }
    if rest.starts_with('[') {
        // [v6]:port or [v6]:port:user:pass
        let close = rest.find(']').ok_or_else(|| invalid("unclosed '['"))?;
        let after = &rest[close + 1..];
        let mut parts = after.strip_prefix(':').unwrap_or("").splitn(3, ':');
        let port = parts.next().unwrap_or("");
        let hostport = format!("{}:{}", &rest[..=close], port);
        let (host, port) = split_host_port(&hostport)?;
        let auth = match (parts.next(), parts.next()) {
            (None, _) => None,
            (Some(u), Some(p)) if !has_scheme => Some(credentials(u, p, false)?),
            _ => return Err(invalid("expected [host]:port or [host]:port:user:pass")),
        };
        return Ok(ProxyEndpoint::new(scheme, &host, port, auth));
    }
    parse_colon_form(scheme, rest, has_scheme)
}

fn parse_colon_form(scheme: ProxyScheme, rest: &str, has_scheme: bool) -> Result<ProxyEndpoint> {
    let parts: Vec<&str> = rest.splitn(4, ':').collect();
    match parts.as_slice() {
        [h, p] => {
            let (host, port) = split_host_port(&format!("{h}:{p}"))?;
            Ok(ProxyEndpoint::new(scheme, &host, port, None))
        }
        [h, p, u, pw] if !has_scheme => {
            let (host, port) = split_host_port(&format!("{h}:{p}"))?;
            let auth = credentials(u, pw, false)?;
            Ok(ProxyEndpoint::new(scheme, &host, port, Some(auth)))
        }
        _ => Err(invalid(
            "expected host:port, host:port:user:pass, user:pass@host:port or scheme://user:pass@host:port",
        )),
    }
}

/// A successfully parsed import line (1-based line number).
#[derive(Debug, Clone)]
pub struct ImportedProxy {
    pub line: usize,
    pub endpoint: ProxyEndpoint,
}

/// A rejected import line (1-based). `message` never contains the line's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportError {
    pub line: usize,
    pub message: String,
}

/// Result of a bulk import: good lines and bad lines, kept apart for the UI.
#[derive(Debug, Clone, Default)]
pub struct ImportReport {
    pub proxies: Vec<ImportedProxy>,
    pub errors: Vec<ImportError>,
}

/// Parse a pasted list. Blank lines and `#` comments are skipped silently.
pub fn parse_list(text: &str, default_scheme: ProxyScheme) -> ImportReport {
    let mut report = ImportReport::default();
    for (i, raw) in text.lines().enumerate() {
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        match parse_line(t, default_scheme) {
            Ok(endpoint) => report.proxies.push(ImportedProxy {
                line: i + 1,
                endpoint,
            }),
            Err(e) => report.errors.push(ImportError {
                line: i + 1,
                message: match e {
                    VantaError::Invalid(m) => m,
                    other => other.to_string(),
                },
            }),
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use ProxyScheme::*;

    fn p(s: &str) -> ProxyEndpoint {
        parse_line(s, Http).unwrap()
    }

    #[test]
    fn host_port() {
        let e = p("Proxy.Example.com:8080");
        assert_eq!(
            (e.scheme, e.host.as_str(), e.port),
            (Http, "proxy.example.com", 8080)
        );
        assert!(e.auth.is_none());
    }

    #[test]
    fn host_port_user_pass() {
        let e = p("192.0.2.10:1080:alice:s3cr:et");
        assert_eq!(e.host, "192.0.2.10");
        let a = e.auth.unwrap();
        assert_eq!(a.username, "alice");
        assert_eq!(a.password(), "s3cr:et");
    }

    #[test]
    fn user_pass_at_host() {
        let e = p("alice:p@ss@gw.example.net:22225");
        assert_eq!(e.host, "gw.example.net");
        assert_eq!(e.port, 22225);
        assert_eq!(e.auth.unwrap().password(), "p@ss");
    }

    #[test]
    fn url_forms() {
        let e = parse_line("socks5://bob:pa%3Ass@10.0.0.1:1080", Http).unwrap();
        assert_eq!(e.scheme, Socks5);
        assert_eq!(e.auth.as_ref().unwrap().password(), "pa:ss");
        assert_eq!(
            parse_line("SOCKS5H://h.example:1", Http).unwrap().scheme,
            Socks5
        );
        assert_eq!(
            parse_line("https://h.example:443/", Http).unwrap().scheme,
            Https
        );
        assert_eq!(
            parse_line("http://h.example:3128", Socks5).unwrap().scheme,
            Http
        );
    }

    #[test]
    fn default_scheme_applies() {
        assert_eq!(parse_line("h.example:1080", Socks5).unwrap().scheme, Socks5);
    }

    #[test]
    fn ipv6() {
        let e = p("[2001:DB8::1]:1080:u:p");
        assert_eq!(e.host, "2001:db8::1");
        assert_eq!(e.host_port(), "[2001:db8::1]:1080");
        assert!(e.auth.is_some());
        assert!(parse_line("2001:db8::1:1080", Http).is_err());
    }

    #[test]
    fn email_login_in_colon_form() {
        let e = p("h.example:8000:me@mail.example:pw");
        assert_eq!(e.host, "h.example");
        assert_eq!(e.auth.unwrap().username, "me@mail.example");
    }

    #[test]
    fn rejects_bad_lines() {
        for bad in [
            "host",
            "host:0",
            "host:70000",
            "host:abc",
            "host:1:user",
            "socks4://h:1",
            "ftp://h:1",
            ":@h:1",
            "u:p@h",
            "bad host:1",
            "h..x:1",
            "socks5://h:1:u:p",
        ] {
            assert!(parse_line(bad, Http).is_err(), "{bad}");
        }
    }

    #[test]
    fn password_never_shown() {
        let e = p("alice:hunter2@h.example:1");
        assert_eq!(e.to_string(), "http://alice:***@h.example:1");
        assert!(!format!("{e:?}").contains("hunter2"));
        assert!(!format!("{:?}", e.auth).contains("hunter2"));
    }

    #[test]
    fn list_separates_errors_without_echoing_secrets() {
        let text = "# comment\n\nh1.example:1\nbroken-line-hunter2\nu:p@h2.example:2\nh3:1:u\n";
        let r = parse_list(text, Socks5);
        assert_eq!(r.proxies.len(), 2);
        assert_eq!(r.proxies[0].line, 3);
        assert_eq!(r.proxies[1].line, 5);
        assert_eq!(r.errors.iter().map(|e| e.line).collect::<Vec<_>>(), [4, 6]);
        assert!(r.errors.iter().all(|e| !e.message.contains("hunter2")));
    }

    #[test]
    fn thousand_lines_parse_fast() {
        let text: String = (0..1000)
            .map(|i| {
                format!(
                    "10.0.{}.{}:{}:user{i}:pass{i}\n",
                    i / 250,
                    i % 250,
                    1000 + i
                )
            })
            .collect();
        let t = std::time::Instant::now();
        let r = parse_list(&text, Http);
        assert_eq!(r.proxies.len(), 1000);
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
    }
}
