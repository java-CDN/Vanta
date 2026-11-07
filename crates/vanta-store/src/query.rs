//! Profile search language (F01).
//!
//! `tag:shop os:win11 health:<80 status:running folder:"QA Lab" proxy:DE frankfurt`
//! Terms are AND-ed; the word `OR` separates alternative groups.

use vanta_types::{Result, VantaError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Tag(String),
    Os(String),
    Status(String),
    Health(Cmp, i64),
    Folder(String),
    /// Country code (2 letters) or exit-IP prefix.
    Proxy(String),
    Text(String),
}

/// OR of AND-groups.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Query {
    pub groups: Vec<Vec<Term>>,
}

fn tokenize(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in s.chars() {
        match c {
            '"' => in_q = !in_q,
            c if c.is_whitespace() && !in_q => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if in_q {
        return Err(VantaError::Invalid("unclosed quote in search".into()));
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

fn os_alias(v: &str) -> Result<String> {
    Ok(match v.to_ascii_lowercase().as_str() {
        "win11" | "windows11" | "w11" => "windows11",
        "win10" | "windows10" | "w10" => "windows10",
        other => {
            return Err(VantaError::Invalid(format!(
                "unknown os '{other}' (use win10 or win11)"
            )))
        }
    }
    .to_string())
}

fn health(v: &str) -> Result<Term> {
    let (cmp, num) = if let Some(r) = v.strip_prefix("<=") {
        (Cmp::Le, r)
    } else if let Some(r) = v.strip_prefix(">=") {
        (Cmp::Ge, r)
    } else if let Some(r) = v.strip_prefix('<') {
        (Cmp::Lt, r)
    } else if let Some(r) = v.strip_prefix('>') {
        (Cmp::Gt, r)
    } else if let Some(r) = v.strip_prefix('=') {
        (Cmp::Eq, r)
    } else {
        (Cmp::Eq, v)
    };
    let n: i64 = num
        .parse()
        .map_err(|_| VantaError::Invalid(format!("health value '{v}'")))?;
    if !(0..=100).contains(&n) {
        return Err(VantaError::Invalid("health must be 0-100".into()));
    }
    Ok(Term::Health(cmp, n))
}

pub fn parse(s: &str) -> Result<Query> {
    let mut q = Query::default();
    let mut group = Vec::new();
    for tok in tokenize(s)? {
        if tok == "OR" {
            if !group.is_empty() {
                q.groups.push(std::mem::take(&mut group));
            }
            continue;
        }
        let term = match tok.split_once(':') {
            Some((k, v)) if !v.is_empty() => match k.to_ascii_lowercase().as_str() {
                "tag" => Term::Tag(v.to_lowercase()),
                "os" => Term::Os(os_alias(v)?),
                "status" => {
                    let v = v.to_lowercase();
                    v.parse::<vanta_types::ProfileStatus>()?;
                    Term::Status(v)
                }
                "health" => health(v)?,
                "folder" => Term::Folder(v.to_string()),
                "proxy" => Term::Proxy(v.to_string()),
                _ => Term::Text(tok.clone()),
            },
            _ => Term::Text(tok.clone()),
        };
        group.push(term);
    }
    if !group.is_empty() {
        q.groups.push(group);
    }
    Ok(q)
}

/// Build a SQL WHERE clause (without the keyword) and its parameters.
pub fn to_sql(q: &Query) -> (String, Vec<rusqlite::types::Value>) {
    use rusqlite::types::Value;
    if q.groups.is_empty() {
        return ("1".into(), vec![]);
    }
    let mut params: Vec<Value> = Vec::new();
    let mut ors = Vec::new();
    for g in &q.groups {
        let mut ands = Vec::new();
        for t in g {
            match t {
                Term::Tag(v) => {
                    ands.push("(' ' || tags || ' ') LIKE ? ESCAPE '\\'".to_string());
                    params.push(Value::Text(format!("% {} %", like_escape(v))));
                }
                Term::Os(v) => {
                    ands.push("os = ?".into());
                    params.push(Value::Text(v.clone()));
                }
                Term::Status(v) => {
                    ands.push("status = ?".into());
                    params.push(Value::Text(v.clone()));
                }
                Term::Health(c, n) => {
                    let op = match c {
                        Cmp::Lt => "<",
                        Cmp::Le => "<=",
                        Cmp::Gt => ">",
                        Cmp::Ge => ">=",
                        Cmp::Eq => "=",
                    };
                    ands.push(format!("health {op} ?"));
                    params.push(Value::Integer(*n));
                }
                Term::Folder(v) => {
                    ands.push("folder = ? COLLATE NOCASE".into());
                    params.push(Value::Text(v.clone()));
                }
                Term::Proxy(v) => {
                    if v.len() == 2 && v.chars().all(|c| c.is_ascii_alphabetic()) {
                        ands.push("country = ?".into());
                        params.push(Value::Text(v.to_ascii_uppercase()));
                    } else {
                        ands.push("exit_ip LIKE ? ESCAPE '\\'".into());
                        params.push(Value::Text(format!("{}%", like_escape(v))));
                    }
                }
                Term::Text(v) => {
                    ands.push(
                        "rowid IN (SELECT rowid FROM profiles_fts WHERE profiles_fts MATCH ?)"
                            .into(),
                    );
                    params.push(Value::Text(fts_prefix(v)));
                }
            }
        }
        ors.push(format!("({})", ands.join(" AND ")));
    }
    (ors.join(" OR "), params)
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Quote a user word for FTS5 and make it a prefix search; quotes stop FTS syntax injection.
fn fts_prefix(s: &str) -> String {
    format!("\"{}\"*", s.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_filters() {
        let q =
            parse("tag:shop os:win11 health:<80 status:running folder:\"QA Lab\" proxy:de frank")
                .unwrap();
        assert_eq!(
            q.groups,
            vec![vec![
                Term::Tag("shop".into()),
                Term::Os("windows11".into()),
                Term::Health(Cmp::Lt, 80),
                Term::Status("running".into()),
                Term::Folder("QA Lab".into()),
                Term::Proxy("de".into()),
                Term::Text("frank".into()),
            ]]
        );
    }

    #[test]
    fn or_groups() {
        let q = parse("tag:shop OR tag:ads").unwrap();
        assert_eq!(q.groups.len(), 2);
    }

    #[test]
    fn errors_are_clear() {
        assert!(parse("os:beos").is_err());
        assert!(parse("os:mac").is_err());
        assert!(parse("os:linux").is_err());
        assert!(parse("health:<abc").is_err());
        assert!(parse("health:>101").is_err());
        assert!(parse("status:flying").is_err());
        assert!(parse("folder:\"open").is_err());
    }

    #[test]
    fn unknown_key_is_text() {
        assert_eq!(
            parse("foo:bar").unwrap().groups[0][0],
            Term::Text("foo:bar".into())
        );
    }

    #[test]
    fn fts_quoting_blocks_injection() {
        assert_eq!(fts_prefix("a\" OR \"b"), "\"a\"\" OR \"\"b\"*");
    }
}
