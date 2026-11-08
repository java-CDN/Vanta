//! vanta-store: SQLite + FTS5 profile database (F01).
//!
//! Only non-secret metadata is stored in clear (name, tags, folder, status...), so the
//! profile table can be searched without unlocking each profile. Fingerprint config,
//! cookies and the like live in `config` as vault-sealed blobs. Deleting a row also
//! deletes the profile's wrapped key, so the profile's files can no longer be decrypted.
//!
//! Schema 2 adds:
//! - `proxies`: the Proxy Hub list. A row holds scheme, host, port, user name and the last
//!   check state, never a password: the password is a vault secret and the row keeps only
//!   its reference (`secret_ref`).
//! - `vault_secrets`: opaque sealed blobs (`vanta-vault` `Vault::seal_secret`) by
//!   reference: proxy passwords, the launcher signing key, the activity-log head. The store
//!   never sees a key or a plaintext.
//! - `health_reports`: the summary of each profile's last health run (F03).
//!
//! Schema 3 adds `proxies.preset`: the provider preset (JSON of
//! `vanta_proxy::ProviderPreset`, no password) a Proxy Hub entry's username is built from.
//!
//! Before schema 2 a profile's `proxy_id` could hold an inline proxy line (with its
//! password). [`Store::legacy_inline_proxies`] lists such rows so the app can move the
//! password into the vault on the next unlock; [`Store::compact`] then rewrites the file so
//! no freed page or WAL frame keeps the old text.

pub mod query;

use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::path::Path;
use vanta_types::{OsKind, ProfileId, ProfileStatus, Result, VantaError};

const SCHEMA_VERSION: i64 = 3;

const MIGRATION_1: &str = r#"
CREATE TABLE profiles (
  rowid       INTEGER PRIMARY KEY,
  id          TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
  folder      TEXT NOT NULL DEFAULT '',
  tags        TEXT NOT NULL DEFAULT '',
  os          TEXT NOT NULL,
  proxy_id    TEXT,
  exit_ip     TEXT NOT NULL DEFAULT '',
  country     TEXT NOT NULL DEFAULT '',
  health      INTEGER NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'stopped',
  color       TEXT NOT NULL DEFAULT '',
  notes       TEXT NOT NULL DEFAULT '',
  created_ms  INTEGER NOT NULL,
  last_opened_ms INTEGER,
  config      BLOB,
  wrapped_key BLOB
);
CREATE INDEX profiles_folder ON profiles(folder);
CREATE INDEX profiles_status ON profiles(status);
CREATE INDEX profiles_last ON profiles(last_opened_ms DESC);
CREATE VIRTUAL TABLE profiles_fts USING fts5(
  name, tags, notes, exit_ip, folder,
  content='profiles', content_rowid='rowid', tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER profiles_ai AFTER INSERT ON profiles BEGIN
  INSERT INTO profiles_fts(rowid, name, tags, notes, exit_ip, folder)
  VALUES (new.rowid, new.name, new.tags, new.notes, new.exit_ip, new.folder);
END;
CREATE TRIGGER profiles_ad AFTER DELETE ON profiles BEGIN
  INSERT INTO profiles_fts(profiles_fts, rowid, name, tags, notes, exit_ip, folder)
  VALUES ('delete', old.rowid, old.name, old.tags, old.notes, old.exit_ip, old.folder);
END;
CREATE TRIGGER profiles_au AFTER UPDATE OF name, tags, notes, exit_ip, folder ON profiles BEGIN
  INSERT INTO profiles_fts(profiles_fts, rowid, name, tags, notes, exit_ip, folder)
  VALUES ('delete', old.rowid, old.name, old.tags, old.notes, old.exit_ip, old.folder);
  INSERT INTO profiles_fts(rowid, name, tags, notes, exit_ip, folder)
  VALUES (new.rowid, new.name, new.tags, new.notes, new.exit_ip, new.folder);
END;
"#;

const MIGRATION_2: &str = r#"
CREATE TABLE proxies (
  id          TEXT PRIMARY KEY,
  scheme      TEXT NOT NULL,
  host        TEXT NOT NULL,
  port        INTEGER NOT NULL,
  username    TEXT,
  secret_ref  TEXT,
  label       TEXT NOT NULL DEFAULT '',
  state       TEXT NOT NULL DEFAULT '{"state":"unknown"}',
  created_ms  INTEGER NOT NULL
);
CREATE TABLE vault_secrets (
  ref   TEXT PRIMARY KEY,
  blob  BLOB NOT NULL
);
CREATE TABLE health_reports (
  profile_id  TEXT PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
  score       INTEGER NOT NULL,
  blocked     INTEGER NOT NULL,
  failing     TEXT NOT NULL DEFAULT '',
  engine      TEXT NOT NULL,
  proxy_id    TEXT,
  ts_ms       INTEGER NOT NULL
);
"#;

const MIGRATION_3: &str = "ALTER TABLE proxies ADD COLUMN preset TEXT;";

/// One Proxy Hub entry. Holds no password: `secret_ref` names the vault secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRecord {
    pub id: String,
    /// `http`, `https` or `socks5`.
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    /// Reference of the sealed password in `vault_secrets`.
    pub secret_ref: Option<String>,
    pub label: String,
    /// Last check, JSON of `vanta_proxy::ProxyState`.
    pub state: String,
    pub created_ms: i64,
    /// Provider preset the username is built from (JSON of `vanta_proxy::ProviderPreset`).
    #[serde(default)]
    pub preset: Option<String>,
}

/// Summary of a profile's last health run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSummary {
    pub profile_id: ProfileId,
    pub score: u8,
    pub blocked: bool,
    /// Ids of checks that failed (H01...).
    pub failing: Vec<String>,
    /// Engine version the run used.
    pub engine: String,
    /// Proxy the run went through.
    pub proxy_id: Option<String>,
    pub ts_ms: i64,
}

/// Searchable, non-secret part of a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMeta {
    pub id: ProfileId,
    pub name: String,
    pub folder: String,
    pub tags: Vec<String>,
    pub os: OsKind,
    pub proxy_id: Option<String>,
    pub exit_ip: String,
    pub country: String,
    pub health: u8,
    pub status: ProfileStatus,
    pub color: String,
    pub notes: String,
    pub created_ms: i64,
    pub last_opened_ms: Option<i64>,
}

impl ProfileMeta {
    pub fn new(name: impl Into<String>, os: OsKind, now_ms: i64) -> Self {
        Self {
            id: ProfileId::new(),
            name: name.into(),
            folder: String::new(),
            tags: vec![],
            os,
            proxy_id: None,
            exit_ip: String::new(),
            country: String::new(),
            health: 0,
            status: ProfileStatus::Stopped,
            color: String::new(),
            notes: String::new(),
            created_ms: now_ms,
            last_opened_ms: None,
        }
    }
}

/// Encrypted parts, stored as opaque bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileSecrets {
    pub config: Option<Vec<u8>>,
    pub wrapped_key: Option<Vec<u8>>,
}

fn os_str(o: OsKind) -> &'static str {
    match o {
        OsKind::Windows10 => "windows10",
        OsKind::Windows11 => "windows11",
    }
}

fn os_from(s: &str) -> Result<OsKind> {
    Ok(match s {
        "windows10" => OsKind::Windows10,
        "windows11" => OsKind::Windows11,
        _ => {
            return Err(VantaError::Storage(format!(
                "unsupported profile os '{s}': Vanta personas are Windows 10/11 only"
            )))
        }
    })
}

fn normalize_tags(tags: &[String]) -> String {
    let mut t: Vec<String> = tags
        .iter()
        .map(|t| t.trim().to_lowercase().replace(char::is_whitespace, "-"))
        .filter(|t| !t.is_empty())
        .collect();
    t.sort();
    t.dedup();
    t.join(" ")
}

fn db(e: rusqlite::Error) -> VantaError {
    VantaError::Storage(e.to_string())
}

const COLS: &str = "id,name,folder,tags,os,proxy_id,exit_ip,country,health,status,color,notes,created_ms,last_opened_ms";

fn row_meta(r: &Row) -> rusqlite::Result<(String, ProfileMetaRaw)> {
    Ok((
        r.get(0)?,
        ProfileMetaRaw {
            name: r.get(1)?,
            folder: r.get(2)?,
            tags: r.get(3)?,
            os: r.get(4)?,
            proxy_id: r.get(5)?,
            exit_ip: r.get(6)?,
            country: r.get(7)?,
            health: r.get(8)?,
            status: r.get(9)?,
            color: r.get(10)?,
            notes: r.get(11)?,
            created_ms: r.get(12)?,
            last_opened_ms: r.get(13)?,
        },
    ))
}

struct ProfileMetaRaw {
    name: String,
    folder: String,
    tags: String,
    os: String,
    proxy_id: Option<String>,
    exit_ip: String,
    country: String,
    health: i64,
    status: String,
    color: String,
    notes: String,
    created_ms: i64,
    last_opened_ms: Option<i64>,
}

fn finish((id, r): (String, ProfileMetaRaw)) -> Result<ProfileMeta> {
    Ok(ProfileMeta {
        id: id.parse()?,
        name: r.name,
        folder: r.folder,
        tags: r.tags.split_whitespace().map(String::from).collect(),
        os: os_from(&r.os)?,
        proxy_id: r.proxy_id,
        exit_ip: r.exit_ip,
        country: r.country,
        health: r.health.clamp(0, 100) as u8,
        status: r.status.parse()?,
        color: r.color,
        notes: r.notes,
        created_ms: r.created_ms,
        last_opened_ms: r.last_opened_ms,
    })
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(db)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(db)?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(db)?;
        conn.pragma_update(None, "secure_delete", "ON")
            .map_err(db)?;
        let v: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(db)?;
        if v > SCHEMA_VERSION {
            return Err(VantaError::Storage(format!(
                "database is from a newer Vanta (schema {v})"
            )));
        }
        if v < 1 {
            conn.execute_batch(MIGRATION_1).map_err(db)?;
            conn.pragma_update(None, "user_version", 1).map_err(db)?;
        }
        if v < 2 {
            conn.execute_batch(MIGRATION_2).map_err(db)?;
            conn.pragma_update(None, "user_version", 2).map_err(db)?;
        }
        if v < 3 {
            conn.execute_batch(MIGRATION_3).map_err(db)?;
            conn.pragma_update(None, "user_version", 3).map_err(db)?;
        }
        Ok(Self { conn })
    }

    pub fn insert(&mut self, m: &ProfileMeta, s: &ProfileSecrets) -> Result<()> {
        self.insert_many(std::iter::once((m, s))).map(|_| ())
    }

    /// One transaction for the whole batch: all or nothing (used by import/migrations and tests).
    pub fn insert_many<'a>(
        &mut self,
        items: impl IntoIterator<Item = (&'a ProfileMeta, &'a ProfileSecrets)>,
    ) -> Result<usize> {
        let tx = self.conn.transaction().map_err(db)?;
        let mut n = 0;
        {
            let mut st = tx
                .prepare(&format!("INSERT INTO profiles ({COLS},config,wrapped_key) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)"))
                .map_err(db)?;
            for (m, s) in items {
                if m.name.trim().is_empty() {
                    return Err(VantaError::Invalid("profile name is empty".into()));
                }
                st.execute(params![
                    m.id.to_string(),
                    m.name.trim(),
                    m.folder,
                    normalize_tags(&m.tags),
                    os_str(m.os),
                    m.proxy_id,
                    m.exit_ip,
                    m.country.to_ascii_uppercase(),
                    m.health as i64,
                    m.status.as_str(),
                    m.color,
                    m.notes,
                    m.created_ms,
                    m.last_opened_ms,
                    s.config,
                    s.wrapped_key
                ])
                .map_err(|e| match e {
                    rusqlite::Error::SqliteFailure(f, _)
                        if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        VantaError::Invalid(format!("a profile named '{}' already exists", m.name))
                    }
                    e => db(e),
                })?;
                n += 1;
            }
        }
        tx.commit().map_err(db)?;
        Ok(n)
    }

    pub fn get(&self, id: ProfileId) -> Result<ProfileMeta> {
        self.conn
            .query_row(
                &format!("SELECT {COLS} FROM profiles WHERE id = ?"),
                [id.to_string()],
                row_meta,
            )
            .optional()
            .map_err(db)?
            .map(finish)
            .unwrap_or_else(|| Err(VantaError::NotFound(format!("profile {id}"))))
    }

    pub fn secrets(&self, id: ProfileId) -> Result<ProfileSecrets> {
        self.conn
            .query_row(
                "SELECT config, wrapped_key FROM profiles WHERE id = ?",
                [id.to_string()],
                |r| {
                    Ok(ProfileSecrets {
                        config: r.get(0)?,
                        wrapped_key: r.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(db)?
            .ok_or_else(|| VantaError::NotFound(format!("profile {id}")))
    }

    pub fn set_config(&self, id: ProfileId, config: &[u8]) -> Result<()> {
        self.exec1(
            "UPDATE profiles SET config = ? WHERE id = ?",
            params![config, id.to_string()],
            id,
        )
    }

    pub fn update_meta(&self, m: &ProfileMeta) -> Result<()> {
        self.exec1(
            "UPDATE profiles SET name=?, folder=?, tags=?, os=?, proxy_id=?, exit_ip=?, country=?, health=?, color=?, notes=? WHERE id=?",
            params![
                m.name.trim(),
                m.folder,
                normalize_tags(&m.tags),
                os_str(m.os),
                m.proxy_id,
                m.exit_ip,
                m.country.to_ascii_uppercase(),
                m.health as i64,
                m.color,
                m.notes,
                m.id.to_string()
            ],
            m.id,
        )
    }

    /// Status comes only from the launcher's real process state.
    pub fn set_status(&self, id: ProfileId, status: ProfileStatus, now_ms: i64) -> Result<()> {
        if status == ProfileStatus::Running {
            self.exec1(
                "UPDATE profiles SET status=?, last_opened_ms=? WHERE id=?",
                params![status.as_str(), now_ms, id.to_string()],
                id,
            )
        } else {
            self.exec1(
                "UPDATE profiles SET status=? WHERE id=?",
                params![status.as_str(), id.to_string()],
                id,
            )
        }
    }

    /// On app start every profile is stopped (no engine survives the app; Job Object kill-on-close).
    pub fn reset_all_status(&self) -> Result<usize> {
        self.conn
            .execute(
                "UPDATE profiles SET status='stopped' WHERE status != 'stopped'",
                [],
            )
            .map_err(db)
    }

    pub fn move_to_folder(&mut self, ids: &[ProfileId], folder: &str) -> Result<usize> {
        let tx = self.conn.transaction().map_err(db)?;
        let mut n = 0;
        {
            let mut st = tx
                .prepare("UPDATE profiles SET folder=? WHERE id=?")
                .map_err(db)?;
            for id in ids {
                n += st.execute(params![folder, id.to_string()]).map_err(db)?;
            }
        }
        tx.commit().map_err(db)?;
        Ok(n)
    }

    /// Deletes metadata, sealed config and the wrapped key. `secure_delete`
    /// makes SQLite overwrite freed pages.
    pub fn delete(&mut self, ids: &[ProfileId]) -> Result<usize> {
        let tx = self.conn.transaction().map_err(db)?;
        let mut n = 0;
        {
            let mut st = tx.prepare("DELETE FROM profiles WHERE id=?").map_err(db)?;
            for id in ids {
                n += st.execute([id.to_string()]).map_err(db)?;
            }
        }
        tx.commit().map_err(db)?;
        Ok(n)
    }

    pub fn count(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM profiles", [], |r| r.get(0))
            .map_err(db)
    }

    /// Folder names with profile counts, for the sidebar.
    pub fn folders(&self) -> Result<Vec<(String, i64)>> {
        let mut st = self
            .conn
            .prepare("SELECT folder, COUNT(*) FROM profiles GROUP BY folder ORDER BY folder")
            .map_err(db)?;
        let rows = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(db)?;
        rows.collect::<rusqlite::Result<_>>().map_err(db)
    }

    /// Run a search-language query. Newest-opened first.
    pub fn search(&self, q: &str, limit: usize, offset: usize) -> Result<(Vec<ProfileMeta>, i64)> {
        let parsed = query::parse(q)?;
        let (wh, mut params) = query::to_sql(&parsed);
        let total: i64 = self
            .conn
            .query_row(
                &format!("SELECT COUNT(*) FROM profiles WHERE {wh}"),
                params_from_iter(params.iter()),
                |r| r.get(0),
            )
            .map_err(db)?;
        params.push(rusqlite::types::Value::Integer(limit as i64));
        params.push(rusqlite::types::Value::Integer(offset as i64));
        let sql = format!(
            "SELECT {COLS} FROM profiles WHERE {wh} ORDER BY last_opened_ms IS NULL, last_opened_ms DESC, name LIMIT ? OFFSET ?"
        );
        let mut st = self.conn.prepare_cached(&sql).map_err(db)?;
        let rows = st
            .query_map(params_from_iter(params.iter()), row_meta)
            .map_err(db)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(finish(r.map_err(db)?)?);
        }
        Ok((out, total))
    }

    /// Point a profile at a proxy (or none).
    pub fn set_proxy_id(&self, id: ProfileId, proxy_id: Option<&str>) -> Result<()> {
        self.exec1(
            "UPDATE profiles SET proxy_id=? WHERE id=?",
            params![proxy_id, id.to_string()],
            id,
        )
    }

    /// Every profile with a proxy: `(profile, proxy id)`.
    pub fn assignments(&self) -> Result<Vec<(ProfileId, String)>> {
        let mut st = self
            .conn
            .prepare("SELECT id, proxy_id FROM profiles WHERE proxy_id IS NOT NULL")
            .map_err(db)?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(db)?;
        let mut out = Vec::new();
        for r in rows {
            let (id, p) = r.map_err(db)?;
            out.push((id.parse()?, p));
        }
        Ok(out)
    }

    // ---- proxies -------------------------------------------------------------------

    pub fn insert_proxies(&mut self, items: &[ProxyRecord]) -> Result<usize> {
        let tx = self.conn.transaction().map_err(db)?;
        {
            let mut st = tx
                .prepare("INSERT INTO proxies (id,scheme,host,port,username,secret_ref,label,state,created_ms,preset) VALUES (?,?,?,?,?,?,?,?,?,?)")
                .map_err(db)?;
            for p in items {
                st.execute(params![
                    p.id,
                    p.scheme,
                    p.host,
                    p.port as i64,
                    p.username,
                    p.secret_ref,
                    p.label,
                    p.state,
                    p.created_ms,
                    p.preset
                ])
                .map_err(db)?;
            }
        }
        tx.commit().map_err(db)?;
        Ok(items.len())
    }

    fn row_proxy(r: &Row) -> rusqlite::Result<ProxyRecord> {
        Ok(ProxyRecord {
            id: r.get(0)?,
            scheme: r.get(1)?,
            host: r.get(2)?,
            port: r.get::<_, i64>(3)?.clamp(0, 65535) as u16,
            username: r.get(4)?,
            secret_ref: r.get(5)?,
            label: r.get(6)?,
            state: r.get(7)?,
            created_ms: r.get(8)?,
            preset: r.get(9)?,
        })
    }

    pub fn get_proxy(&self, id: &str) -> Result<ProxyRecord> {
        self.conn
            .query_row(
                "SELECT id,scheme,host,port,username,secret_ref,label,state,created_ms,preset FROM proxies WHERE id=?",
                [id],
                Self::row_proxy,
            )
            .optional()
            .map_err(db)?
            .ok_or_else(|| VantaError::NotFound(format!("proxy {id}")))
    }

    pub fn list_proxies(&self) -> Result<Vec<ProxyRecord>> {
        let mut st = self
            .conn
            .prepare("SELECT id,scheme,host,port,username,secret_ref,label,state,created_ms,preset FROM proxies ORDER BY created_ms, id")
            .map_err(db)?;
        let rows = st.query_map([], Self::row_proxy).map_err(db)?;
        rows.collect::<rusqlite::Result<_>>().map_err(db)
    }

    pub fn set_proxy_state(&self, id: &str, state_json: &str) -> Result<()> {
        match self
            .conn
            .execute(
                "UPDATE proxies SET state=? WHERE id=?",
                params![state_json, id],
            )
            .map_err(db)?
        {
            0 => Err(VantaError::NotFound(format!("proxy {id}"))),
            _ => Ok(()),
        }
    }

    /// Rewrite a proxy's fields (not `created_ms`). A `secret_ref` that is dropped or
    /// replaced has its sealed blob deleted in the same transaction. When the endpoint
    /// (scheme, host, port, username) changes, health reports made through it are dropped.
    pub fn update_proxy(&mut self, p: &ProxyRecord) -> Result<()> {
        let tx = self.conn.transaction().map_err(db)?;
        let old = tx
            .query_row(
                "SELECT id,scheme,host,port,username,secret_ref,label,state,created_ms,preset FROM proxies WHERE id=?",
                [&p.id],
                Self::row_proxy,
            )
            .optional()
            .map_err(db)?
            .ok_or_else(|| VantaError::NotFound(format!("proxy {}", p.id)))?;
        if let Some(r) = old.secret_ref.filter(|r| p.secret_ref.as_ref() != Some(r)) {
            tx.execute("DELETE FROM vault_secrets WHERE ref=?", [r])
                .map_err(db)?;
        }
        if (&old.scheme, &old.host, old.port, &old.username)
            != (&p.scheme, &p.host, p.port, &p.username)
        {
            tx.execute("DELETE FROM health_reports WHERE proxy_id=?", [&p.id])
                .map_err(db)?;
        }
        tx.execute(
            "UPDATE proxies SET scheme=?, host=?, port=?, username=?, secret_ref=?, label=?, state=?, preset=? WHERE id=?",
            params![
                p.scheme,
                p.host,
                p.port as i64,
                p.username,
                p.secret_ref,
                p.label,
                p.state,
                p.preset,
                p.id
            ],
        )
        .map_err(db)?;
        tx.commit().map_err(db)
    }

    /// Delete a proxy, its sealed password, and every profile's link to it.
    pub fn delete_proxy(&mut self, id: &str) -> Result<()> {
        let tx = self.conn.transaction().map_err(db)?;
        let secret: Option<String> = tx
            .query_row("SELECT secret_ref FROM proxies WHERE id=?", [id], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db)?
            .ok_or_else(|| VantaError::NotFound(format!("proxy {id}")))?;
        if let Some(r) = secret {
            tx.execute("DELETE FROM vault_secrets WHERE ref=?", [r])
                .map_err(db)?;
        }
        tx.execute("UPDATE profiles SET proxy_id=NULL WHERE proxy_id=?", [id])
            .map_err(db)?;
        tx.execute("DELETE FROM health_reports WHERE proxy_id=?", [id])
            .map_err(db)?;
        tx.execute("DELETE FROM proxies WHERE id=?", [id])
            .map_err(db)?;
        tx.commit().map_err(db)
    }

    /// Profiles whose `proxy_id` is not a Proxy Hub id: inline proxy lines written before
    /// schema 2 (they may hold a password in clear). `(profile, raw value)`.
    pub fn legacy_inline_proxies(&self) -> Result<Vec<(ProfileId, String)>> {
        let mut st = self
            .conn
            .prepare("SELECT id, proxy_id FROM profiles WHERE proxy_id IS NOT NULL AND proxy_id NOT IN (SELECT id FROM proxies)")
            .map_err(db)?;
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(db)?;
        let mut out = Vec::new();
        for r in rows {
            let (id, raw) = r.map_err(db)?;
            out.push((id.parse()?, raw));
        }
        Ok(out)
    }

    // ---- vault secrets (sealed, opaque) -------------------------------------------

    pub fn put_secret(&self, reference: &str, sealed: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO vault_secrets (ref, blob) VALUES (?, ?) ON CONFLICT(ref) DO UPDATE SET blob=excluded.blob",
                params![reference, sealed],
            )
            .map(|_| ())
            .map_err(db)
    }

    pub fn get_secret(&self, reference: &str) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT blob FROM vault_secrets WHERE ref=?",
                [reference],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)
    }

    pub fn delete_secret(&self, reference: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM vault_secrets WHERE ref=?", [reference])
            .map(|_| ())
            .map_err(db)
    }

    // ---- health --------------------------------------------------------------------

    /// Store a health summary and copy its score to the profile row.
    pub fn put_health(&mut self, h: &HealthSummary) -> Result<()> {
        let tx = self.conn.transaction().map_err(db)?;
        let n = tx
            .execute(
                "UPDATE profiles SET health=? WHERE id=?",
                params![h.score as i64, h.profile_id.to_string()],
            )
            .map_err(db)?;
        if n == 0 {
            return Err(VantaError::NotFound(format!("profile {}", h.profile_id)));
        }
        tx.execute(
            "INSERT OR REPLACE INTO health_reports (profile_id,score,blocked,failing,engine,proxy_id,ts_ms) VALUES (?,?,?,?,?,?,?)",
            params![
                h.profile_id.to_string(),
                h.score as i64,
                h.blocked,
                h.failing.join(" "),
                h.engine,
                h.proxy_id,
                h.ts_ms
            ],
        )
        .map_err(db)?;
        tx.commit().map_err(db)
    }

    pub fn get_health(&self, id: ProfileId) -> Result<Option<HealthSummary>> {
        self.conn
            .query_row(
                "SELECT score,blocked,failing,engine,proxy_id,ts_ms FROM health_reports WHERE profile_id=?",
                [id.to_string()],
                |r| {
                    Ok(HealthSummary {
                        profile_id: id,
                        score: r.get::<_, i64>(0)?.clamp(0, 100) as u8,
                        blocked: r.get(1)?,
                        failing: r
                            .get::<_, String>(2)?
                            .split_whitespace()
                            .map(String::from)
                            .collect(),
                        engine: r.get(3)?,
                        proxy_id: r.get(4)?,
                        ts_ms: r.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(db)
    }

    /// Forget a profile's health run (its proxy or fingerprint changed).
    /// Forget every health run made through a proxy (its login changed).
    pub fn clear_proxy_health(&self, proxy_id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM health_reports WHERE proxy_id=?", [proxy_id])
            .map(|_| ())
            .map_err(db)
    }

    pub fn clear_health(&self, id: ProfileId) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM health_reports WHERE profile_id=?",
                [id.to_string()],
            )
            .map(|_| ())
            .map_err(db)
    }

    /// Fold the WAL into the main file and rebuild it, so no free page or WAL frame keeps
    /// data that was overwritten (used after moving legacy passwords into the vault).
    pub fn compact(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .map_err(db)
    }

    fn exec1(&self, sql: &str, p: impl rusqlite::Params, id: ProfileId) -> Result<()> {
        match self.conn.execute(sql, p).map_err(db)? {
            0 => Err(VantaError::NotFound(format!("profile {id}"))),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(
        name: &str,
        os: OsKind,
        folder: &str,
        tags: &[&str],
        cc: &str,
        ip: &str,
        health: u8,
    ) -> ProfileMeta {
        let mut m = ProfileMeta::new(name, os, 1);
        m.folder = folder.into();
        m.tags = tags.iter().map(|s| s.to_string()).collect();
        m.country = cc.into();
        m.exit_ip = ip.into();
        m.health = health;
        m
    }

    fn sample() -> Store {
        let mut s = Store::open_in_memory().unwrap();
        let rows = [
            p(
                "shop-de-01",
                OsKind::Windows11,
                "E-commerce",
                &["shop", "de"],
                "DE",
                "203.0.113.24",
                96,
            ),
            p(
                "shop-nl-01",
                OsKind::Windows10,
                "E-commerce",
                &["shop", "nl"],
                "NL",
                "198.51.100.12",
                91,
            ),
            p(
                "ads-us-02",
                OsKind::Windows10,
                "Ads",
                &["ads", "us"],
                "US",
                "198.51.100.88",
                88,
            ),
            p(
                "ads-gb-01",
                OsKind::Windows11,
                "Ads",
                &["ads", "gb"],
                "GB",
                "192.0.2.41",
                79,
            ),
            p(
                "social-in-01",
                OsKind::Windows11,
                "Social",
                &["social", "in"],
                "IN",
                "192.0.2.150",
                95,
            ),
            p(
                "qa-jp-01",
                OsKind::Windows11,
                "QA Lab",
                &["qa"],
                "JP",
                "203.0.113.120",
                58,
            ),
        ];
        let empty = ProfileSecrets::default();
        s.insert_many(rows.iter().map(|m| (m, &empty))).unwrap();
        s
    }

    fn names(s: &Store, q: &str) -> Vec<String> {
        let mut v: Vec<String> = s
            .search(q, 100, 0)
            .unwrap()
            .0
            .into_iter()
            .map(|m| m.name)
            .collect();
        v.sort();
        v
    }

    #[test]
    fn filters_work() {
        let s = sample();
        assert_eq!(names(&s, "tag:shop"), ["shop-de-01", "shop-nl-01"]);
        assert_eq!(names(&s, "os:win11 health:<80"), ["ads-gb-01", "qa-jp-01"]);
        assert_eq!(names(&s, "folder:\"qa lab\""), ["qa-jp-01"]);
        assert_eq!(names(&s, "proxy:de"), ["shop-de-01"]);
        assert_eq!(names(&s, "proxy:192.0.2."), ["ads-gb-01", "social-in-01"]);
        assert_eq!(
            names(&s, "tag:shop OR tag:social"),
            ["shop-de-01", "shop-nl-01", "social-in-01"]
        );
        assert_eq!(names(&s, "health:>=95"), ["shop-de-01", "social-in-01"]);
        assert_eq!(s.search("", 100, 0).unwrap().1, 6);
    }

    #[test]
    fn tag_match_is_whole_word() {
        let s = sample();
        assert!(names(&s, "tag:sho").is_empty());
    }

    #[test]
    fn full_text_prefix() {
        let s = sample();
        assert_eq!(names(&s, "social"), ["social-in-01"]);
        assert_eq!(names(&s, "203.0.113"), ["qa-jp-01", "shop-de-01"]);
    }

    #[test]
    fn duplicate_name_is_friendly_error_and_batch_is_atomic() {
        let mut s = sample();
        let a = p("new-1", OsKind::Windows11, "", &[], "", "", 0);
        let b = p("SHOP-DE-01", OsKind::Windows11, "", &[], "", "", 0);
        let e = ProfileSecrets::default();
        let err = s.insert_many([(&a, &e), (&b, &e)]).unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert_eq!(
            s.count().unwrap(),
            6,
            "nothing from the failed batch is kept"
        );
    }

    #[test]
    fn status_and_last_opened() {
        let s = sample();
        let id = s.search("shop-nl", 1, 0).unwrap().0[0].id;
        s.set_status(id, ProfileStatus::Running, 5_000).unwrap();
        let m = s.get(id).unwrap();
        assert_eq!(m.status, ProfileStatus::Running);
        assert_eq!(m.last_opened_ms, Some(5_000));
        assert_eq!(names(&s, "status:running"), ["shop-nl-01"]);
        assert_eq!(s.reset_all_status().unwrap(), 1);
        assert_eq!(s.get(id).unwrap().status, ProfileStatus::Stopped);
    }

    #[test]
    fn move_update_delete_keep_fts_in_sync() {
        let mut s = sample();
        let id = s.search("qa-jp", 1, 0).unwrap().0[0].id;
        s.move_to_folder(&[id], "Archive").unwrap();
        assert_eq!(names(&s, "folder:archive"), ["qa-jp-01"]);
        let mut m = s.get(id).unwrap();
        m.name = "renamed-zz".into();
        s.update_meta(&m).unwrap();
        assert_eq!(names(&s, "renamed"), ["renamed-zz"]);
        assert!(names(&s, "qa-jp").is_empty());
        s.delete(&[id]).unwrap();
        assert!(names(&s, "renamed").is_empty());
        assert!(matches!(s.get(id), Err(VantaError::NotFound(_))));
        assert!(matches!(s.secrets(id), Err(VantaError::NotFound(_))));
    }

    #[test]
    fn secrets_roundtrip() {
        let mut s = Store::open_in_memory().unwrap();
        let m = ProfileMeta::new("x-1", OsKind::Windows11, 1);
        let sec = ProfileSecrets {
            config: Some(vec![1, 2, 3]),
            wrapped_key: Some(vec![9; 72]),
        };
        s.insert(&m, &sec).unwrap();
        assert_eq!(s.secrets(m.id).unwrap(), sec);
        s.set_config(m.id, &[7]).unwrap();
        assert_eq!(s.secrets(m.id).unwrap().config, Some(vec![7]));
    }

    #[test]
    fn os_roundtrip_and_legacy_values_rejected() {
        for o in [OsKind::Windows10, OsKind::Windows11] {
            assert_eq!(os_from(os_str(o)).unwrap(), o);
        }
        for legacy in ["mac_os", "linux", "android", ""] {
            let e = os_from(legacy).unwrap_err().to_string();
            assert!(e.contains("Windows 10/11 only"), "{legacy}: {e}");
        }
    }

    #[test]
    fn tags_are_normalized() {
        let mut s = Store::open_in_memory().unwrap();
        let mut m = ProfileMeta::new("t", OsKind::Windows10, 1);
        m.tags = vec!["Shop".into(), " shop ".into(), "Batch Nov".into()];
        s.insert(&m, &ProfileSecrets::default()).unwrap();
        assert_eq!(s.get(m.id).unwrap().tags, ["batch-nov", "shop"]);
    }

    #[test]
    fn folders_sidebar() {
        let s = sample();
        let f = s.folders().unwrap();
        assert!(f.contains(&("Ads".to_string(), 2)));
    }

    #[test]
    fn persists_on_disk_and_rejects_newer_schema() {
        let dir = std::env::temp_dir().join(format!("vanta-store-{}", ProfileId::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.db");
        {
            let mut s = Store::open(&path).unwrap();
            s.insert(
                &ProfileMeta::new("disk-1", OsKind::Windows11, 1),
                &ProfileSecrets::default(),
            )
            .unwrap();
        }
        assert_eq!(Store::open(&path).unwrap().count().unwrap(), 1);
        {
            let c = Connection::open(&path).unwrap();
            c.pragma_update(None, "user_version", 99).unwrap();
        }
        assert!(Store::open(&path).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    fn proxy(id: &str) -> ProxyRecord {
        ProxyRecord {
            id: id.into(),
            scheme: "socks5".into(),
            host: "198.51.100.9".into(),
            port: 1080,
            username: Some("user".into()),
            secret_ref: Some(format!("proxy/{id}")),
            label: String::new(),
            state: r#"{"state":"unknown"}"#.into(),
            created_ms: 1,
            preset: None,
        }
    }

    #[test]
    fn update_proxy_rewrites_fields_secret_and_health() {
        let mut s = sample();
        s.insert_proxies(&[proxy("p1")]).unwrap();
        s.put_secret("proxy/p1", &[1]).unwrap();
        let id = s.search("qa-jp", 1, 0).unwrap().0[0].id;
        s.set_proxy_id(id, Some("p1")).unwrap();
        let h = HealthSummary {
            profile_id: id,
            score: 90,
            blocked: false,
            failing: vec![],
            engine: "156.0.8078.79".into(),
            proxy_id: Some("p1".into()),
            ts_ms: 5,
        };
        s.put_health(&h).unwrap();
        // Label and preset only: endpoint unchanged, health and secret kept.
        let mut r = s.get_proxy("p1").unwrap();
        r.label = "shop".into();
        r.preset = Some(r#"{"provider":"soax"}"#.into());
        s.update_proxy(&r).unwrap();
        let got = s.get_proxy("p1").unwrap();
        assert_eq!(got, r);
        assert!(s.get_health(id).unwrap().is_some());
        assert_eq!(s.get_secret("proxy/p1").unwrap(), Some(vec![1]));
        // New username and no password: the old sealed blob and the health report go.
        r.username = Some("user-2".into());
        r.secret_ref = None;
        s.update_proxy(&r).unwrap();
        assert_eq!(s.get_secret("proxy/p1").unwrap(), None);
        assert!(s.get_health(id).unwrap().is_none());
        assert_eq!(s.get(id).unwrap().proxy_id.as_deref(), Some("p1"));
        s.put_health(&h).unwrap();
        s.clear_proxy_health("other").unwrap();
        assert!(s.get_health(id).unwrap().is_some());
        s.clear_proxy_health("p1").unwrap();
        assert!(s.get_health(id).unwrap().is_none());
        r.id = "nope".into();
        assert!(matches!(s.update_proxy(&r), Err(VantaError::NotFound(_))));
    }

    #[test]
    fn proxies_secrets_and_links() {
        let mut s = sample();
        s.insert_proxies(&[proxy("p1"), proxy("p2")]).unwrap();
        s.put_secret("proxy/p1", &[1, 2, 3]).unwrap();
        s.put_secret("proxy/p1", &[4, 5]).unwrap();
        assert_eq!(s.get_secret("proxy/p1").unwrap(), Some(vec![4, 5]));
        let id = s.search("shop-de", 1, 0).unwrap().0[0].id;
        s.set_proxy_id(id, Some("p1")).unwrap();
        assert_eq!(s.assignments().unwrap(), vec![(id, "p1".to_string())]);
        s.set_proxy_state("p1", r#"{"state":"online"}"#).unwrap();
        assert!(s.get_proxy("p1").unwrap().state.contains("online"));
        assert_eq!(s.list_proxies().unwrap().len(), 2);
        s.delete_proxy("p1").unwrap();
        assert_eq!(s.get_secret("proxy/p1").unwrap(), None);
        assert_eq!(s.get(id).unwrap().proxy_id, None);
        assert!(matches!(s.get_proxy("p1"), Err(VantaError::NotFound(_))));
        assert!(s.set_proxy_state("p1", "{}").is_err());
    }

    #[test]
    fn legacy_inline_proxy_rows_are_listed() {
        let mut s = sample();
        s.insert_proxies(&[proxy("p1")]).unwrap();
        let a = s.search("shop-de", 1, 0).unwrap().0[0].id;
        let b = s.search("shop-nl", 1, 0).unwrap().0[0].id;
        s.set_proxy_id(a, Some("p1")).unwrap();
        s.set_proxy_id(b, Some("socks5://u:pw@198.51.100.1:1080"))
            .unwrap();
        assert_eq!(
            s.legacy_inline_proxies().unwrap(),
            vec![(b, "socks5://u:pw@198.51.100.1:1080".to_string())]
        );
    }

    #[test]
    fn health_summary_roundtrip_and_cascade() {
        let mut s = sample();
        let id = s.search("qa-jp", 1, 0).unwrap().0[0].id;
        assert_eq!(s.get_health(id).unwrap(), None);
        let h = HealthSummary {
            profile_id: id,
            score: 41,
            blocked: true,
            failing: vec!["H01".into(), "H12".into()],
            engine: "156.0.8078.79".into(),
            proxy_id: Some("p1".into()),
            ts_ms: 9,
        };
        s.put_health(&h).unwrap();
        assert_eq!(s.get_health(id).unwrap(), Some(h));
        assert_eq!(s.get(id).unwrap().health, 41);
        s.clear_health(id).unwrap();
        assert_eq!(s.get_health(id).unwrap(), None);
        s.put_health(&HealthSummary {
            profile_id: id,
            score: 90,
            blocked: false,
            failing: vec![],
            engine: "x".into(),
            proxy_id: None,
            ts_ms: 1,
        })
        .unwrap();
        s.delete(&[id]).unwrap();
        assert_eq!(s.get_health(id).unwrap(), None, "cascade on delete");
        s.compact().unwrap();
    }

    #[test]
    fn schema_1_database_is_migrated() {
        let dir = std::env::temp_dir().join(format!("vanta-store-v1-{}", ProfileId::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(MIGRATION_1).unwrap();
            c.pragma_update(None, "user_version", 1).unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert!(s.list_proxies().unwrap().is_empty());
        let v: i64 = s
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        drop(s);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn schema_2_proxies_survive_migration_3() {
        let dir = std::env::temp_dir().join(format!("vanta-store-v2-{}", ProfileId::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.db");
        {
            let c = Connection::open(&path).unwrap();
            c.execute_batch(MIGRATION_1).unwrap();
            c.execute_batch(MIGRATION_2).unwrap();
            c.execute(
                "INSERT INTO proxies (id,scheme,host,port,username,secret_ref,label,state,created_ms) VALUES ('p1','http','192.0.2.1',8080,NULL,NULL,'',?,1)",
                [r#"{"state":"unknown"}"#],
            )
            .unwrap();
            c.pragma_update(None, "user_version", 2).unwrap();
        }
        let s = Store::open(&path).unwrap();
        let p = s.get_proxy("p1").unwrap();
        assert_eq!((p.host.as_str(), p.preset), ("192.0.2.1", None));
        drop(s);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn search_10k_profiles_fast() {
        let mut s = Store::open_in_memory().unwrap();
        let oses = [OsKind::Windows11, OsKind::Windows10];
        let rows: Vec<ProfileMeta> = (0..10_000)
            .map(|i| {
                let mut m = ProfileMeta::new(format!("profile-{i:05}"), oses[i % 2], 1);
                m.tags = vec![["shop", "ads", "social", "qa"][i % 4].into()];
                m.health = (i % 101) as u8;
                m.exit_ip = format!("203.0.{}.{}", i / 250, i % 250);
                m.last_opened_ms = Some(i as i64);
                m
            })
            .collect();
        let e = ProfileSecrets::default();
        s.insert_many(rows.iter().map(|m| (m, &e))).unwrap();
        for q in ["tag:shop health:<50", "profile-0999", "os:win10", "203.0.7"] {
            s.search(q, 50, 0).unwrap(); // warm the statement cache
            let t = std::time::Instant::now();
            let (r, _) = s.search(q, 50, 0).unwrap();
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            assert!(!r.is_empty(), "{q}");
            let budget = if cfg!(debug_assertions) { 250.0 } else { 50.0 };
            assert!(
                ms < budget,
                "search '{q}' took {ms:.1} ms (budget {budget} ms)"
            );
        }
    }
}
