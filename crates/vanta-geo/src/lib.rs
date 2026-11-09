//! vanta-geo: the offline GeoIP lookup behind Geo Auto-Match (F07).
//!
//! The database is DB-IP "IP to City Lite" (MMDB, CC BY 4.0, monthly; attribution
//! [`ATTRIBUTION`]). It is not in git: the desktop CI downloads the current release,
//! checks it (`scripts/fetch_geoip.py`) and ships it as the app resource `geoip/` with a
//! manifest ([`MANIFEST`]). The app checks the file against the manifest's SHA-256 before
//! the first lookup ([`GeoDb::open_bundle`]). Lookups never leave the PC.
//!
//! A lookup gives country, region, city and coordinates; the time zone is derived from
//! country + coordinates ([`vanta_fingerprint::geo`]), because the Lite database has none.

pub mod testkit;

use maxminddb::geoip2;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Required attribution for DB-IP Lite data (CC BY 4.0).
pub const ATTRIBUTION: &str = "IP geolocation by DB-IP";
pub const ATTRIBUTION_URL: &str = "https://db-ip.com";
/// Manifest written by `scripts/fetch_geoip.py` next to the database.
pub const MANIFEST: &str = "geoip.json";
/// Folder of the database in the app's resources.
pub const RESOURCE_DIR: &str = "geoip";

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum GeoError {
    #[error("the GeoIP database is not installed")]
    NotInstalled,
    #[error("GeoIP manifest: {0}")]
    Manifest(String),
    #[error("GeoIP database failed its integrity check: {0}")]
    Integrity(String),
    #[error("GeoIP database is not usable: {0}")]
    Invalid(String),
    #[error("GeoIP lookup failed: {0}")]
    Lookup(String),
}

/// `geoip.json` next to the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// File name of the database in the same folder.
    pub file: String,
    /// DB-IP release month, `YYYY-MM`.
    pub release: String,
    pub sha256: String,
    /// The SHA-1 DB-IP published for the release (checked at download).
    #[serde(default)]
    pub sha1: String,
    pub source: String,
    pub license: String,
    pub attribution: String,
}

/// What the UI shows about the database (Settings › About, Geo Auto-Match tab).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeoDbInfo {
    pub database_type: String,
    /// Release month from the manifest, else the build date (`YYYY-MM-DD`).
    pub release: String,
    pub license: String,
    pub attribution: String,
}

/// One lookup result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Location {
    /// ISO 3166-1 alpha-2, upper case.
    pub country: String,
    pub country_name: Option<String>,
    /// First-level subdivision (state, province, region).
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    /// IANA zone derived from country + coordinates; `None` for a country outside the
    /// table.
    pub timezone: Option<String>,
}

enum Source {
    Map(memmap2::Mmap),
    Mem(Vec<u8>),
}

impl AsRef<[u8]> for Source {
    fn as_ref(&self) -> &[u8] {
        match self {
            Source::Map(m) => m,
            Source::Mem(v) => v,
        }
    }
}

/// An open, checked database.
pub struct GeoDb {
    reader: maxminddb::Reader<Source>,
    info: GeoDbInfo,
}

impl std::fmt::Debug for GeoDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoDb").field("info", &self.info).finish()
    }
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>())
}

fn read_manifest(dir: &Path) -> Result<(Manifest, PathBuf), GeoError> {
    let mpath = dir.join(MANIFEST);
    let text = match std::fs::read_to_string(&mpath) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(GeoError::NotInstalled),
        Err(e) => return Err(GeoError::Manifest(e.to_string())),
    };
    let m: Manifest = serde_json::from_str(&text).map_err(|e| GeoError::Manifest(e.to_string()))?;
    let plain =
        !m.file.is_empty() && !m.file.contains(['/', '\\', ':']) && m.file != "." && m.file != "..";
    if !plain {
        return Err(GeoError::Manifest(format!("bad file name {:?}", m.file)));
    }
    if m.sha256.len() != 64 || !m.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(GeoError::Manifest(
            "sha256 is not a SHA-256 hex digest".into(),
        ));
    }
    let file = dir.join(&m.file);
    Ok((m, file))
}

impl GeoDb {
    /// Open the bundled database in `dir` (`<resources>/geoip`): manifest, SHA-256 of the
    /// file, then the MMDB itself (memory-mapped). [`GeoError::NotInstalled`] when the
    /// folder has no manifest (a build without the database).
    pub fn open_bundle(dir: &Path) -> Result<Self, GeoError> {
        let (m, file) = read_manifest(dir)?;
        let got = sha256_file(&file).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => GeoError::Integrity(format!("{} is missing", m.file)),
            _ => GeoError::Integrity(e.to_string()),
        })?;
        if !got.eq_ignore_ascii_case(&m.sha256) {
            return Err(GeoError::Integrity(format!(
                "{} has SHA-256 {got}, the manifest says {}",
                m.file, m.sha256
            )));
        }
        let f = std::fs::File::open(&file).map_err(|e| GeoError::Invalid(e.to_string()))?;
        // SAFETY: the file is the read-only database in the app's install folder, checked
        // above; Vanta never writes it. A change by another program while mapped could
        // only make lookups return wrong or garbled data, which the decoder bounds-checks.
        let map =
            unsafe { memmap2::Mmap::map(&f) }.map_err(|e| GeoError::Invalid(e.to_string()))?;
        let mut db = Self::from_source(Source::Map(map))?;
        db.info.release = m.release;
        db.info.license = m.license;
        db.info.attribution = m.attribution;
        Ok(db)
    }

    /// A database held in memory (tests, or a file the caller already checked).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, GeoError> {
        Self::from_source(Source::Mem(bytes))
    }

    fn from_source(src: Source) -> Result<Self, GeoError> {
        let reader =
            maxminddb::Reader::from_source(src).map_err(|e| GeoError::Invalid(e.to_string()))?;
        let md = reader.metadata();
        if !md.database_type.to_ascii_lowercase().contains("city") {
            return Err(GeoError::Invalid(format!(
                "database type {:?} is not a city database",
                md.database_type
            )));
        }
        if md.ip_version != 6 {
            return Err(GeoError::Invalid(
                "database has no IPv6 tree (IPv4-only database)".into(),
            ));
        }
        let info = GeoDbInfo {
            database_type: md.database_type.clone(),
            release: build_date(md.build_epoch),
            license: "CC BY 4.0".into(),
            attribution: ATTRIBUTION.into(),
        };
        Ok(Self { reader, info })
    }

    pub fn info(&self) -> &GeoDbInfo {
        &self.info
    }

    /// Location of `ip`; `Ok(None)` when the database has no country for it (private,
    /// reserved or unknown ranges).
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<Location>, GeoError> {
        // IPv4-mapped IPv6 (::ffff:a.b.c.d) is looked up as IPv4.
        let ip = match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        let res = self
            .reader
            .lookup(ip)
            .map_err(|e| GeoError::Lookup(e.to_string()))?;
        let Some(rec) = res
            .decode::<geoip2::City>()
            .map_err(|e| GeoError::Lookup(e.to_string()))?
        else {
            return Ok(None);
        };
        let Some(cc) = rec.country.iso_code.filter(|c| c.len() == 2) else {
            return Ok(None);
        };
        let country = cc.to_ascii_uppercase();
        let (Some(lat), Some(lon)) = (rec.location.latitude, rec.location.longitude) else {
            return Ok(None);
        };
        let timezone =
            vanta_fingerprint::geo::timezone_at(&country, lat, lon).map(|z| z.to_string());
        Ok(Some(Location {
            country_name: rec.country.names.english.map(String::from),
            region: rec
                .subdivisions
                .first()
                .and_then(|s| s.names.english)
                .map(String::from),
            city: rec.city.names.english.map(String::from),
            latitude: lat,
            longitude: lon,
            timezone,
            country,
        }))
    }
}

/// `YYYY-MM-DD` (UTC) of a Unix time, without a date crate.
fn build_date(epoch: u64) -> String {
    let days = (epoch / 86_400) as i64;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn lookup_country_region_city_coordinates_and_zone() {
        let db = GeoDb::from_bytes(testkit::sample_db()).unwrap();
        assert_eq!(db.info().database_type, "DBIP-City-Lite");
        assert_eq!(db.info().release, "2026-11-01");
        let l = db.lookup(ip("198.51.100.20")).unwrap().unwrap();
        assert_eq!(l.country, "DE");
        assert_eq!(l.country_name.as_deref(), Some("Germany"));
        assert_eq!(l.region.as_deref(), Some("Hesse"));
        assert_eq!(l.city.as_deref(), Some("Frankfurt am Main"));
        assert!((l.latitude - 50.1109).abs() < 1e-9 && (l.longitude - 8.6821).abs() < 1e-9);
        assert_eq!(l.timezone.as_deref(), Some("Europe/Berlin"));

        let us = db.lookup(ip("203.0.113.5")).unwrap().unwrap();
        assert_eq!(
            (us.country.as_str(), us.timezone.as_deref()),
            ("US", Some("America/Los_Angeles"))
        );
        let ca = db.lookup(ip("203.0.113.200")).unwrap().unwrap();
        assert_eq!(ca.timezone.as_deref(), Some("America/Toronto"));
        assert_eq!(ca.region.as_deref(), Some("Quebec"));
        // IPv6, and IPv4-mapped IPv6.
        let nl = db.lookup(ip("2001:db8::1")).unwrap().unwrap();
        assert_eq!(nl.timezone.as_deref(), Some("Europe/Amsterdam"));
        assert_eq!(
            db.lookup(ip("::ffff:198.51.100.7"))
                .unwrap()
                .unwrap()
                .country,
            "DE"
        );
        // Country outside the zone table: located, but no zone.
        let zz = db.lookup(ip("192.0.2.1")).unwrap().unwrap();
        assert_eq!((zz.country.as_str(), zz.timezone), ("ZZ", None));
        // Not in the database.
        assert_eq!(db.lookup(ip("10.0.0.1")).unwrap(), None);
        assert_eq!(db.lookup(ip("2001:db9::1")).unwrap(), None);
    }

    #[test]
    fn rejects_non_city_and_garbage() {
        let mut w = testkit::MmdbWriter::new("DBIP-ASN-Lite");
        w.insert(ip("198.51.100.0"), 24, &testkit::Value::Map(vec![]));
        assert!(matches!(
            GeoDb::from_bytes(w.build()),
            Err(GeoError::Invalid(_))
        ));
        assert!(matches!(
            GeoDb::from_bytes(b"not a database".to_vec()),
            Err(GeoError::Invalid(_))
        ));
    }

    #[test]
    fn bundle_checks_manifest_and_sha256() {
        let dir = std::env::temp_dir().join(format!("vanta-geo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            GeoDb::open_bundle(&dir).unwrap_err(),
            GeoError::NotInstalled
        );
        let bytes = testkit::sample_db();
        std::fs::write(dir.join("dbip-city-lite.mmdb"), &bytes).unwrap();
        let sha = sha256_file(&dir.join("dbip-city-lite.mmdb")).unwrap();
        let manifest = |file: &str, sha: &str| {
            serde_json::to_string(&Manifest {
                file: file.into(),
                release: "2026-11".into(),
                sha256: sha.into(),
                sha1: String::new(),
                source: "https://download.db-ip.com/free/dbip-city-lite-2026-11.mmdb.gz".into(),
                license: "CC BY 4.0".into(),
                attribution: ATTRIBUTION.into(),
            })
            .unwrap()
        };
        std::fs::write(dir.join(MANIFEST), manifest("dbip-city-lite.mmdb", &sha)).unwrap();
        let db = GeoDb::open_bundle(&dir).unwrap();
        assert_eq!(db.info().release, "2026-11");
        assert_eq!(
            db.lookup(ip("198.51.100.1")).unwrap().unwrap().country,
            "DE"
        );
        drop(db);
        // Wrong digest, path in the file name, missing file.
        let zero = "0".repeat(64);
        std::fs::write(dir.join(MANIFEST), manifest("dbip-city-lite.mmdb", &zero)).unwrap();
        assert!(matches!(
            GeoDb::open_bundle(&dir),
            Err(GeoError::Integrity(_))
        ));
        std::fs::write(dir.join(MANIFEST), manifest("../x.mmdb", &sha)).unwrap();
        assert!(matches!(
            GeoDb::open_bundle(&dir),
            Err(GeoError::Manifest(_))
        ));
        std::fs::write(dir.join(MANIFEST), manifest("other.mmdb", &sha)).unwrap();
        assert!(matches!(
            GeoDb::open_bundle(&dir),
            Err(GeoError::Integrity(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Against a real bundle: `VANTA_GEOIP_DIR=<dir with geoip.json> cargo test -p vanta-geo
    /// -- --ignored`.
    #[test]
    #[ignore]
    fn real_bundle() {
        let dir = std::env::var_os("VANTA_GEOIP_DIR").expect("VANTA_GEOIP_DIR");
        let t = std::time::Instant::now();
        let db = GeoDb::open_bundle(Path::new(&dir)).unwrap();
        eprintln!("open + sha256: {:?} {:?}", t.elapsed(), db.info());
        for a in [
            "8.8.8.8",
            "1.1.1.1",
            "2a00:1450:4001:80b::200e",
            "81.2.69.160",
            "185.60.216.35",
        ] {
            eprintln!("{a}: {:?}", db.lookup(ip(a)).unwrap());
        }
        assert_eq!(db.lookup(ip("8.8.8.8")).unwrap().unwrap().country, "US");
        assert_eq!(db.lookup(ip("10.1.2.3")).unwrap(), None);
    }

    #[test]
    fn dates() {
        assert_eq!(build_date(0), "1970-01-01");
        assert_eq!(build_date(1_793_491_200), "2026-11-01");
        assert_eq!(build_date(951_782_400), "2000-02-29");
    }
}
