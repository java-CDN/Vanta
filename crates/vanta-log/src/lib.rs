//! vanta-log: the local Activity Log (F08).
//!
//! Append-only, hash-chained, encrypted at rest, kept 90 days, never leaves the machine.
//!
//! # Chain
//! ```text
//! hash[i] = SHA-256( "vanta/log/v1" || prev[i] || canonical_json(entry[i]) )
//! prev[0] = anchor.prev_hash            (all zeros for a log that was never pruned)
//! prev[i] = hash[i-1]
//! seq[i]  = anchor.first_seq + i
//! ```
//! Changing, removing or reordering any entry breaks [`ActivityLog::verify_chain`] at that
//! entry. Removing entries from the *end* cannot be seen from the chain alone, so callers
//! keep [`ActivityLog::head`] elsewhere (e.g. next to the vault header) and check it with
//! [`ActivityLog::verify_head`].
//!
//! # Retention and the anchor
//! [`ActivityLog::prune`] drops the oldest entries older than 90 days. The chain stays
//! verifiable because the log keeps an **anchor**: the `seq` of the first kept entry and
//! that entry's `prev` hash (the hash of the last pruned entry). Verification starts from
//! the anchor instead of from zero. The anchor is encrypted and authenticated like every
//! entry, so it cannot be swapped without the log key.
//!
//! # At rest
//! The file is a sequence of frames `u32-le length || Sealed(nonce || ciphertext)`, each
//! sealed with `vanta-vault`'s XChaCha20-Poly1305 under the vault's log key
//! (`Vault::log_key`, HKDF info `vanta/log/v1`). Frame 0 is the anchor (AAD
//! `vanta/log/v1/anchor`); frame `1 + i` holds entry `seq = first_seq + i` with AAD
//! `vanta/log/v1/entry/<seq>`, so frames cannot be moved between positions. Appends are
//! appended to the file; pruning rewrites it through a temporary file and a rename.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use vanta_types::{ProfileId, Result, VantaError};
use vanta_vault::{Key, Sealed};

/// Entries are kept this many days.
pub const RETENTION_DAYS: i64 = 90;
const DAY_MS: i64 = 86_400_000;
const DOMAIN: &[u8] = b"vanta/log/v1";
const AAD_ANCHOR: &[u8] = b"vanta/log/v1/anchor";
const MAX_FRAME: usize = 1 << 20;

/// Oldest timestamp (ms) that survives pruning at `now_ms`.
pub fn retention_cutoff_ms(now_ms: i64) -> i64 {
    now_ms - RETENTION_DAYS * DAY_MS
}

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogKind {
    ProfileLaunch,
    ProfileStop,
    VaultUnlock,
    VaultLock,
    ProxyFailure,
    /// A leak the guard stopped (non-proxied UDP, LAN, IPv6...).
    BlockedEvent,
    HealthRun,
    /// The Network Guard kill switch tripped (heartbeat or tunnel failure); all relay
    /// connections were cut.
    KillSwitch,
    /// The upstream proxy answered again and the kill switch re-armed.
    ProxyReconnect,
    /// A launch the gate refused, or an engine that refused its config (exit 86/87).
    LaunchBlocked,
    /// An engine that ended on its own with an error.
    ProfileCrash,
}

/// One log entry. `detail` is short free text and must never hold secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub ts_ms: i64,
    pub kind: LogKind,
    pub profile: Option<ProfileId>,
    pub detail: String,
}

/// An entry with its chain links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainRecord {
    pub entry: LogEntry,
    #[serde(with = "hex32")]
    pub prev: [u8; 32],
    #[serde(with = "hex32")]
    pub hash: [u8; 32],
}

/// Where verification starts (see the crate docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub first_seq: u64,
    #[serde(with = "hex32")]
    pub prev_hash: [u8; 32],
    /// Entries before this time were pruned (0 = never pruned).
    pub pruned_before_ms: i64,
}

impl Anchor {
    pub const GENESIS: Anchor = Anchor {
        first_seq: 0,
        prev_hash: [0; 32],
        pruned_before_ms: 0,
    };
}

/// Why the chain does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakReason {
    /// `prev` does not equal the previous hash (or the anchor's).
    PrevMismatch,
    /// The stored hash does not match the entry's contents.
    HashMismatch,
    /// `seq` is not `first_seq + index`.
    SeqGap,
}

/// The chain breaks at `index` (0-based position among the kept entries).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainBreak {
    pub index: usize,
    pub reason: BreakReason,
}

impl std::fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "activity log chain breaks at entry {} ({:?})",
            self.index, self.reason
        )
    }
}

/// `SHA-256(domain || prev || canonical_json(entry))`.
pub fn entry_hash(prev: &[u8; 32], entry: &LogEntry) -> [u8; 32] {
    let json = serde_json::to_vec(entry).expect("log entries always serialize");
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(prev);
    h.update(&json);
    h.finalize().into()
}

/// Filter for [`ActivityLog::query`]. Empty fields match everything; the time range is
/// inclusive of `from_ms` and exclusive of `to_ms`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogFilter {
    pub kinds: Vec<LogKind>,
    pub profile: Option<ProfileId>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
}

impl LogFilter {
    pub fn matches(&self, e: &LogEntry) -> bool {
        (self.kinds.is_empty() || self.kinds.contains(&e.kind))
            && (self.profile.is_none() || e.profile == self.profile)
            && !matches!(self.from_ms, Some(f) if e.ts_ms < f)
            && !matches!(self.to_ms, Some(t) if e.ts_ms >= t)
    }
}

/// The activity log, held decrypted in memory while the vault is unlocked.
pub struct ActivityLog {
    key: Key,
    path: Option<PathBuf>,
    anchor: Anchor,
    records: Vec<ChainRecord>,
}

fn entry_aad(seq: u64) -> Vec<u8> {
    let mut a = b"vanta/log/v1/entry/".to_vec();
    a.extend_from_slice(seq.to_string().as_bytes());
    a
}

fn io(e: std::io::Error) -> VantaError {
    VantaError::Storage(format!("activity log: {e}"))
}

fn frame(sealed: &Sealed) -> Vec<u8> {
    let body = sealed.to_bytes();
    let mut v = (body.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(&body);
    v
}

impl ActivityLog {
    /// A log that lives only in memory (tests, or before a data folder exists).
    pub fn in_memory(key: Key) -> Self {
        Self {
            key,
            path: None,
            anchor: Anchor::GENESIS,
            records: Vec::new(),
        }
    }

    /// Open the log file at `path`, creating it when missing. Fails with a storage error
    /// naming the frame when any frame does not authenticate under `key`.
    pub fn open(path: impl AsRef<Path>, key: Key) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            let mut log = Self::in_memory(key);
            log.path = Some(path);
            log.rewrite()?;
            return Ok(log);
        }
        let mut data = Vec::new();
        File::open(&path)
            .map_err(io)?
            .read_to_end(&mut data)
            .map_err(io)?;
        let mut frames = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let len_bytes = data.get(i..i + 4).ok_or_else(|| {
                VantaError::Storage("activity log: truncated frame header".into())
            })?;
            let len = u32::from_le_bytes(len_bytes.try_into().expect("4 bytes")) as usize;
            if len > MAX_FRAME {
                return Err(VantaError::Storage("activity log: oversized frame".into()));
            }
            let body = data
                .get(i + 4..i + 4 + len)
                .ok_or_else(|| VantaError::Storage("activity log: truncated frame".into()))?;
            frames.push(body);
            i += 4 + len;
        }
        let bad = |n: usize| {
            VantaError::Storage(format!("activity log: frame {n} failed authentication"))
        };
        let first = frames.first().ok_or_else(|| bad(0))?;
        let anchor_pt = Sealed::from_bytes(first)
            .and_then(|s| s.open(&key, AAD_ANCHOR))
            .map_err(|_| bad(0))?;
        let anchor: Anchor = serde_json::from_slice(&anchor_pt).map_err(|_| bad(0))?;
        let mut records = Vec::with_capacity(frames.len() - 1);
        for (n, body) in frames.iter().enumerate().skip(1) {
            let seq = anchor.first_seq + (n as u64 - 1);
            let pt = Sealed::from_bytes(body)
                .and_then(|s| s.open(&key, &entry_aad(seq)))
                .map_err(|_| bad(n))?;
            let rec: ChainRecord = serde_json::from_slice(&pt).map_err(|_| bad(n))?;
            records.push(rec);
        }
        Ok(Self {
            key,
            path: Some(path),
            anchor,
            records,
        })
    }

    pub fn anchor(&self) -> Anchor {
        self.anchor
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Hash of the newest entry (the anchor's hash when empty). Keep it outside the log to
    /// detect truncation.
    pub fn head(&self) -> [u8; 32] {
        self.records
            .last()
            .map_or(self.anchor.prev_hash, |r| r.hash)
    }

    fn next_seq(&self) -> u64 {
        self.records
            .last()
            .map_or(self.anchor.first_seq, |r| r.entry.seq + 1)
    }

    /// Append an entry and persist it. Returns the stored entry.
    pub fn append(
        &mut self,
        ts_ms: i64,
        kind: LogKind,
        profile: Option<ProfileId>,
        detail: impl Into<String>,
    ) -> Result<&LogEntry> {
        let entry = LogEntry {
            seq: self.next_seq(),
            ts_ms,
            kind,
            profile,
            detail: detail.into(),
        };
        let prev = self.head();
        let hash = entry_hash(&prev, &entry);
        let rec = ChainRecord { entry, prev, hash };
        if let Some(p) = &self.path {
            let pt = serde_json::to_vec(&rec).expect("records serialize");
            let sealed = Sealed::seal(&self.key, &entry_aad(rec.entry.seq), &pt);
            let mut f = OpenOptions::new().append(true).open(p).map_err(io)?;
            f.write_all(&frame(&sealed)).map_err(io)?;
            f.flush().map_err(io)?;
        }
        self.records.push(rec);
        Ok(&self.records.last().expect("just pushed").entry)
    }

    /// All kept entries, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &LogEntry> {
        self.records.iter().map(|r| &r.entry)
    }

    pub fn records(&self) -> &[ChainRecord] {
        &self.records
    }

    /// Entries matching `filter`, oldest first.
    pub fn query(&self, filter: &LogFilter) -> Vec<&LogEntry> {
        self.iter().filter(|e| filter.matches(e)).collect()
    }

    /// Check every link from the anchor to the head.
    pub fn verify_chain(&self) -> std::result::Result<(), ChainBreak> {
        verify_records(&self.anchor, &self.records)
    }

    /// Check the chain and that its head equals a hash kept outside the log.
    pub fn verify_head(&self, expected: &[u8; 32]) -> Result<()> {
        self.verify_chain()
            .map_err(|b| VantaError::Invalid(b.to_string()))?;
        if &self.head() != expected {
            return Err(VantaError::Invalid(
                "activity log head does not match (entries removed from the end)".into(),
            ));
        }
        Ok(())
    }

    /// Drop the oldest entries with `ts_ms` before the 90-day cutoff and move the anchor to
    /// the first kept entry. Only a leading run is dropped, so a clock that went backwards
    /// never punches holes into the chain. Refuses to prune a chain that does not verify.
    /// Returns how many entries were removed.
    pub fn prune(&mut self, now_ms: i64) -> Result<usize> {
        self.verify_chain()
            .map_err(|b| VantaError::Invalid(b.to_string()))?;
        let cutoff = retention_cutoff_ms(now_ms);
        let n = self
            .records
            .iter()
            .take_while(|r| r.entry.ts_ms < cutoff)
            .count();
        if n == 0 {
            return Ok(0);
        }
        let last_pruned = &self.records[n - 1];
        self.anchor = Anchor {
            first_seq: last_pruned.entry.seq + 1,
            prev_hash: last_pruned.hash,
            pruned_before_ms: cutoff,
        };
        self.records.drain(..n);
        self.rewrite()?;
        Ok(n)
    }

    /// Rewrite the whole file (anchor + every record) via a temp file and rename.
    fn rewrite(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut buf = Vec::new();
        let anchor = serde_json::to_vec(&self.anchor).expect("anchor serializes");
        buf.extend_from_slice(&frame(&Sealed::seal(&self.key, AAD_ANCHOR, &anchor)));
        for r in &self.records {
            let pt = serde_json::to_vec(r).expect("records serialize");
            buf.extend_from_slice(&frame(&Sealed::seal(
                &self.key,
                &entry_aad(r.entry.seq),
                &pt,
            )));
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp).map_err(io)?;
            f.write_all(&buf).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        fs::rename(&tmp, path).map_err(io)
    }
}

/// Verify `records` against `anchor` (exposed for tests and tools).
pub fn verify_records(
    anchor: &Anchor,
    records: &[ChainRecord],
) -> std::result::Result<(), ChainBreak> {
    let mut prev = anchor.prev_hash;
    for (index, r) in records.iter().enumerate() {
        if r.entry.seq != anchor.first_seq + index as u64 {
            return Err(ChainBreak {
                index,
                reason: BreakReason::SeqGap,
            });
        }
        if r.prev != prev {
            return Err(ChainBreak {
                index,
                reason: BreakReason::PrevMismatch,
            });
        }
        if entry_hash(&r.prev, &r.entry) != r.hash {
            return Err(ChainBreak {
                index,
                reason: BreakReason::HashMismatch,
            });
        }
        prev = r.hash;
    }
    Ok(())
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
        s.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        if s.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 hex chars"));
        }
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(serde::de::Error::custom)?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000_000;

    fn pid(n: u128) -> ProfileId {
        ProfileId(uuid::Uuid::from_u128(n))
    }

    fn tmp_path(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanta-log-test-{}-{name}", std::process::id()));
        let _ = fs::remove_file(&d);
        d
    }

    fn sample(log: &mut ActivityLog) {
        log.append(T0, LogKind::VaultUnlock, None, "unlock")
            .unwrap();
        log.append(T0 + 1, LogKind::ProfileLaunch, Some(pid(1)), "launch")
            .unwrap();
        log.append(T0 + 2, LogKind::BlockedEvent, Some(pid(1)), "UDP ASSOCIATE")
            .unwrap();
        log.append(
            T0 + 3,
            LogKind::ProxyFailure,
            Some(pid(2)),
            "proxy timed out",
        )
        .unwrap();
        log.append(T0 + 4, LogKind::HealthRun, Some(pid(2)), "score 92")
            .unwrap();
        log.append(T0 + 5, LogKind::ProfileStop, Some(pid(1)), "stop")
            .unwrap();
        log.append(T0 + 6, LogKind::VaultLock, None, "idle")
            .unwrap();
    }

    #[test]
    fn append_chains_entries() {
        let mut log = ActivityLog::in_memory(Key::random());
        assert_eq!(log.head(), [0; 32]);
        sample(&mut log);
        assert_eq!(log.len(), 7);
        let r = log.records();
        assert_eq!(r[0].prev, [0; 32]);
        for w in r.windows(2) {
            assert_eq!(w[1].prev, w[0].hash);
            assert_eq!(w[1].entry.seq, w[0].entry.seq + 1);
        }
        assert_eq!(log.verify_chain(), Ok(()));
        assert_eq!(log.head(), r[6].hash);
    }

    #[test]
    fn hash_is_deterministic_and_content_bound() {
        let e = LogEntry {
            seq: 0,
            ts_ms: 1,
            kind: LogKind::VaultLock,
            profile: None,
            detail: "x".into(),
        };
        assert_eq!(entry_hash(&[0; 32], &e), entry_hash(&[0; 32], &e));
        let mut e2 = e.clone();
        e2.detail = "y".into();
        assert_ne!(entry_hash(&[0; 32], &e), entry_hash(&[0; 32], &e2));
        assert_ne!(entry_hash(&[0; 32], &e), entry_hash(&[1; 32], &e));
    }

    #[test]
    fn tampered_entry_breaks_chain_at_its_index() {
        let mut log = ActivityLog::in_memory(Key::random());
        sample(&mut log);
        log.records[3].entry.detail = "nothing happened".into();
        assert_eq!(
            log.verify_chain(),
            Err(ChainBreak {
                index: 3,
                reason: BreakReason::HashMismatch
            })
        );
    }

    #[test]
    fn rehashed_tamper_breaks_next_link() {
        // An attacker who also recomputes the tampered entry's hash breaks the next link.
        let mut log = ActivityLog::in_memory(Key::random());
        sample(&mut log);
        log.records[2].entry.kind = LogKind::HealthRun;
        log.records[2].hash = entry_hash(&log.records[2].prev, &log.records[2].entry);
        assert_eq!(
            log.verify_chain(),
            Err(ChainBreak {
                index: 3,
                reason: BreakReason::PrevMismatch
            })
        );
    }

    #[test]
    fn removed_or_reordered_entries_detected() {
        let mut log = ActivityLog::in_memory(Key::random());
        sample(&mut log);
        let mut removed = log.records.clone();
        removed.remove(2);
        assert_eq!(verify_records(&log.anchor, &removed).unwrap_err().index, 2);
        let mut swapped = log.records.clone();
        swapped.swap(1, 4);
        assert_eq!(verify_records(&log.anchor, &swapped).unwrap_err().index, 1);
    }

    #[test]
    fn truncation_detected_by_head() {
        let mut log = ActivityLog::in_memory(Key::random());
        sample(&mut log);
        let head = log.head();
        assert!(log.verify_head(&head).is_ok());
        log.records.pop();
        assert_eq!(log.verify_chain(), Ok(()));
        assert!(log.verify_head(&head).is_err());
    }

    #[test]
    fn filters() {
        let mut log = ActivityLog::in_memory(Key::random());
        sample(&mut log);
        let by_kind = log.query(&LogFilter {
            kinds: vec![LogKind::VaultLock, LogKind::VaultUnlock],
            ..Default::default()
        });
        assert_eq!(by_kind.len(), 2);
        let by_profile = log.query(&LogFilter {
            profile: Some(pid(1)),
            ..Default::default()
        });
        assert_eq!(
            by_profile.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2, 5]
        );
        let range = log.query(&LogFilter {
            from_ms: Some(T0 + 2),
            to_ms: Some(T0 + 4),
            ..Default::default()
        });
        assert_eq!(
            range.iter().map(|e| e.kind).collect::<Vec<_>>(),
            [LogKind::BlockedEvent, LogKind::ProxyFailure]
        );
        let combo = log.query(&LogFilter {
            kinds: vec![LogKind::HealthRun],
            profile: Some(pid(1)),
            ..Default::default()
        });
        assert!(combo.is_empty());
        assert_eq!(log.query(&LogFilter::default()).len(), 7);
    }

    #[test]
    fn works_with_the_vault_log_key() {
        let (vault, _recovery) = vanta_vault::Vault::create(
            "correct horse battery",
            vanta_vault::KdfParams::insecure_for_tests(),
        )
        .unwrap();
        let path = tmp_path("vault-key");
        {
            let mut log = ActivityLog::open(&path, vault.log_key().unwrap()).unwrap();
            log.append(T0, LogKind::VaultUnlock, None, "unlock")
                .unwrap();
        }
        let log = ActivityLog::open(&path, vault.log_key().unwrap()).unwrap();
        assert_eq!(log.len(), 1);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn retention_cutoff() {
        assert_eq!(retention_cutoff_ms(T0), T0 - 90 * 86_400_000);
    }

    #[test]
    fn prune_keeps_chain_verifiable_from_anchor() {
        let mut log = ActivityLog::in_memory(Key::random());
        let day = 86_400_000;
        for d in 0..100 {
            log.append(T0 + d * day, LogKind::HealthRun, None, format!("day {d}"))
                .unwrap();
        }
        let now = T0 + 99 * day;
        let removed = log.prune(now).unwrap();
        assert_eq!(removed, 9); // days 0..=8 are older than 90 days
        assert_eq!(log.iter().next().unwrap().detail, "day 9");
        let a = log.anchor();
        assert_eq!(a.first_seq, 9);
        assert_eq!(a.pruned_before_ms, retention_cutoff_ms(now));
        assert_eq!(log.verify_chain(), Ok(()));
        // New entries keep chaining after a prune.
        log.append(now + 1, LogKind::VaultLock, None, "after")
            .unwrap();
        assert_eq!(log.iter().last().unwrap().seq, 100);
        assert_eq!(log.verify_chain(), Ok(()));
        // A forged anchor no longer matches the first kept entry.
        log.anchor.prev_hash = [9; 32];
        assert_eq!(
            log.verify_chain().unwrap_err(),
            ChainBreak {
                index: 0,
                reason: BreakReason::PrevMismatch
            }
        );
        assert!(log.prune(now).is_err(), "refuses to prune a broken chain");
    }

    #[test]
    fn prune_only_drops_leading_run() {
        let mut log = ActivityLog::in_memory(Key::random());
        let old = T0 - 200 * 86_400_000;
        log.append(old, LogKind::VaultUnlock, None, "a").unwrap();
        log.append(T0, LogKind::VaultUnlock, None, "b").unwrap();
        log.append(old, LogKind::VaultUnlock, None, "c (clock went back)")
            .unwrap();
        assert_eq!(log.prune(T0).unwrap(), 1);
        assert_eq!(log.len(), 2);
        assert_eq!(log.verify_chain(), Ok(()));
        assert_eq!(log.prune(T0).unwrap(), 0);
    }

    #[test]
    fn file_roundtrip_encrypted() {
        let path = tmp_path("roundtrip");
        let key = Key::random();
        {
            let mut log = ActivityLog::open(&path, key.clone()).unwrap();
            sample(&mut log);
        }
        let raw = fs::read(&path).unwrap();
        for needle in ["UDP ASSOCIATE", "profile_launch", "score 92"] {
            assert!(
                !raw.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "plaintext {needle} on disk"
            );
        }
        let log = ActivityLog::open(&path, key.clone()).unwrap();
        assert_eq!(log.len(), 7);
        assert_eq!(log.verify_chain(), Ok(()));
        assert_eq!(log.iter().nth(2).unwrap().detail, "UDP ASSOCIATE");
        assert!(
            ActivityLog::open(&path, Key::random()).is_err(),
            "wrong key"
        );
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn file_prune_persists_anchor() {
        let path = tmp_path("prune");
        let key = Key::random();
        let day = 86_400_000;
        let now = T0 + 120 * day;
        {
            let mut log = ActivityLog::open(&path, key.clone()).unwrap();
            for d in 0..=120 {
                log.append(T0 + d * day, LogKind::ProfileLaunch, Some(pid(1)), "x")
                    .unwrap();
            }
            assert_eq!(log.prune(now).unwrap(), 30);
        }
        let mut log = ActivityLog::open(&path, key.clone()).unwrap();
        assert_eq!(log.len(), 91);
        assert_eq!(log.anchor().first_seq, 30);
        assert_eq!(log.verify_chain(), Ok(()));
        log.append(now, LogKind::ProfileStop, Some(pid(1)), "y")
            .unwrap();
        let log = ActivityLog::open(&path, key).unwrap();
        assert_eq!(log.len(), 92);
        assert_eq!(log.verify_chain(), Ok(()));
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn file_tamper_and_reorder_rejected() {
        let path = tmp_path("tamper");
        let key = Key::random();
        {
            let mut log = ActivityLog::open(&path, key.clone()).unwrap();
            sample(&mut log);
        }
        let good = fs::read(&path).unwrap();
        // Flip one ciphertext byte near the end (inside the last entry frame).
        let mut bad = good.clone();
        let n = bad.len();
        bad[n - 5] ^= 1;
        fs::write(&path, &bad).unwrap();
        let err = ActivityLog::open(&path, key.clone()).err().unwrap();
        assert!(err.to_string().contains("frame 7"), "{err}");
        // Swap two whole entry frames: AAD binds each frame to its position.
        let frames = split_frames(&good);
        let mut swapped = Vec::new();
        for i in [0, 1, 3, 2, 4, 5, 6, 7] {
            swapped.extend_from_slice(frames[i]);
        }
        fs::write(&path, &swapped).unwrap();
        assert!(ActivityLog::open(&path, key.clone()).is_err());
        // Truncated mid-frame.
        fs::write(&path, &good[..good.len() - 3]).unwrap();
        assert!(ActivityLog::open(&path, key).is_err());
        fs::remove_file(&path).unwrap();
    }

    fn split_frames(b: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            let len = u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
            out.push(&b[i..i + 4 + len]);
            i += 4 + len;
        }
        out
    }

    #[test]
    fn search_over_many_entries_is_fast() {
        let mut log = ActivityLog::in_memory(Key::random());
        for i in 0..100_000i64 {
            let kind = if i % 50 == 0 {
                LogKind::BlockedEvent
            } else {
                LogKind::ProfileLaunch
            };
            log.append(T0 + i, kind, Some(pid((i % 20) as u128)), "e")
                .unwrap();
        }
        let t = std::time::Instant::now();
        let hits = log.query(&LogFilter {
            kinds: vec![LogKind::BlockedEvent],
            profile: Some(pid(0)),
            ..Default::default()
        });
        assert_eq!(hits.len(), 1_000);
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
    }
}
