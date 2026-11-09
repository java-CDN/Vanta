//! A minimal MaxMind DB (MMDB 2.0) writer for tests: an IPv6 tree (IPv4 under `::/96`),
//! 24-bit records and the DB-IP "IP to City Lite" record shape. Made from the format
//! specification (<https://maxmind.github.io/MaxMind-DB/>), so tests need no third-party
//! database file.

use std::net::IpAddr;

/// One MMDB data value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    F64(f64),
    U16(u16),
    U32(u32),
    U64(u64),
    Bool(bool),
    Map(Vec<(String, Value)>),
    Array(Vec<Value>),
}

fn s(v: &str) -> Value {
    Value::Str(v.into())
}

fn names(en: &str) -> Value {
    Value::Map(vec![("en".into(), s(en))])
}

/// A record shaped like DB-IP "IP to City Lite" (no time zone, no accuracy radius).
pub fn dbip_city(
    country: &str,
    country_name: &str,
    region: Option<&str>,
    city: &str,
    latitude: f64,
    longitude: f64,
) -> Value {
    let mut m = vec![
        (
            "city".into(),
            Value::Map(vec![("names".into(), names(city))]),
        ),
        (
            "continent".into(),
            Value::Map(vec![
                ("code".into(), s("EU")),
                ("geoname_id".into(), Value::U32(6_255_148)),
                ("names".into(), names("Europe")),
            ]),
        ),
        (
            "country".into(),
            Value::Map(vec![
                ("geoname_id".into(), Value::U32(1)),
                ("is_in_european_union".into(), Value::Bool(true)),
                ("iso_code".into(), s(country)),
                ("names".into(), names(country_name)),
            ]),
        ),
        (
            "location".into(),
            Value::Map(vec![
                ("latitude".into(), Value::F64(latitude)),
                ("longitude".into(), Value::F64(longitude)),
            ]),
        ),
    ];
    if let Some(r) = region {
        m.push((
            "subdivisions".into(),
            Value::Array(vec![Value::Map(vec![("names".into(), names(r))])]),
        ));
    }
    Value::Map(m)
}

fn ctrl(out: &mut Vec<u8>, ty: u8, size: usize) {
    let (first_type, ext) = if ty <= 7 {
        (ty << 5, None)
    } else {
        (0, Some(ty - 7))
    };
    let (bits, extra): (u8, Vec<u8>) = if size < 29 {
        (size as u8, vec![])
    } else if size < 29 + 256 {
        (29, vec![(size - 29) as u8])
    } else if size < 285 + 65_536 {
        (30, ((size - 285) as u16).to_be_bytes().to_vec())
    } else {
        (31, ((size - 65_821) as u32).to_be_bytes()[1..].to_vec())
    };
    out.push(first_type | bits);
    if let Some(e) = ext {
        out.push(e);
    }
    out.extend(extra);
}

fn uint(out: &mut Vec<u8>, ty: u8, v: u64) {
    let b = v.to_be_bytes();
    let skip = b.iter().take_while(|x| **x == 0).count();
    ctrl(out, ty, 8 - skip);
    out.extend_from_slice(&b[skip..]);
}

/// Encode one value in the MMDB data format.
pub fn encode(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Str(x) => {
            ctrl(out, 2, x.len());
            out.extend_from_slice(x.as_bytes());
        }
        Value::F64(x) => {
            ctrl(out, 3, 8);
            out.extend_from_slice(&x.to_be_bytes());
        }
        Value::U16(x) => uint(out, 5, *x as u64),
        Value::U32(x) => uint(out, 6, *x as u64),
        Value::U64(x) => uint(out, 9, *x),
        Value::Bool(x) => ctrl(out, 14, *x as usize),
        Value::Map(m) => {
            ctrl(out, 7, m.len());
            for (k, v) in m {
                encode(out, &Value::Str(k.clone()));
                encode(out, v);
            }
        }
        Value::Array(a) => {
            ctrl(out, 11, a.len());
            for v in a {
                encode(out, v);
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Rec {
    Empty,
    Node(usize),
    Data(usize),
}

/// Builds a database from (network, record) pairs.
pub struct MmdbWriter {
    database_type: String,
    nodes: Vec<[Rec; 2]>,
    data: Vec<u8>,
}

impl MmdbWriter {
    pub fn new(database_type: &str) -> Self {
        Self {
            database_type: database_type.into(),
            nodes: vec![[Rec::Empty, Rec::Empty]],
            data: Vec::new(),
        }
    }

    /// Add `ip/prefix` (IPv4 prefixes count IPv4 bits). Networks must not overlap.
    pub fn insert(&mut self, ip: IpAddr, prefix: u8, record: &Value) -> &mut Self {
        let (bits, len) = match ip {
            IpAddr::V4(v4) => (u32::from(v4) as u128, 96 + prefix as usize),
            IpAddr::V6(v6) => (u128::from(v6), prefix as usize),
        };
        assert!((1..=128).contains(&len), "prefix out of range");
        let off = self.data.len();
        encode(&mut self.data, record);
        let mut node = 0usize;
        for depth in 0..len {
            let bit = ((bits >> (127 - depth)) & 1) as usize;
            if depth == len - 1 {
                self.nodes[node][bit] = Rec::Data(off);
                break;
            }
            node = match self.nodes[node][bit] {
                Rec::Node(n) => n,
                Rec::Empty => {
                    self.nodes.push([Rec::Empty, Rec::Empty]);
                    let n = self.nodes.len() - 1;
                    self.nodes[node][bit] = Rec::Node(n);
                    n
                }
                Rec::Data(_) => panic!("overlapping networks"),
            };
        }
        self
    }

    /// The finished database file.
    pub fn build(&self) -> Vec<u8> {
        let count = self.nodes.len();
        let val = |r: Rec| -> u32 {
            let v = match r {
                Rec::Empty => count,
                Rec::Node(n) => n,
                Rec::Data(o) => count + 16 + o,
            };
            assert!(v < 1 << 24, "too large for 24-bit records");
            v as u32
        };
        let mut out = Vec::new();
        for [l, r] in &self.nodes {
            out.extend_from_slice(&val(*l).to_be_bytes()[1..]);
            out.extend_from_slice(&val(*r).to_be_bytes()[1..]);
        }
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&self.data);
        out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
        let meta = Value::Map(vec![
            ("binary_format_major_version".into(), Value::U16(2)),
            ("binary_format_minor_version".into(), Value::U16(0)),
            ("build_epoch".into(), Value::U64(1_793_491_200)), // 2026-11-01
            (
                "database_type".into(),
                Value::Str(self.database_type.clone()),
            ),
            (
                "description".into(),
                Value::Map(vec![("en".into(), s("Vanta test database"))]),
            ),
            ("ip_version".into(), Value::U16(6)),
            ("languages".into(), Value::Array(vec![s("en")])),
            ("node_count".into(), Value::U32(count as u32)),
            ("record_size".into(), Value::U16(24)),
        ]);
        encode(&mut out, &meta);
        out
    }
}

/// The networks the tests of this and other crates use (documentation ranges,
/// RFC 5737 / RFC 3849).
pub fn sample_db() -> Vec<u8> {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let mut w = MmdbWriter::new("DBIP-City-Lite");
    w.insert(
        ip("198.51.100.0"),
        24,
        &dbip_city(
            "DE",
            "Germany",
            Some("Hesse"),
            "Frankfurt am Main",
            50.1109,
            8.6821,
        ),
    )
    .insert(
        ip("203.0.113.0"),
        25,
        &dbip_city(
            "US",
            "United States",
            Some("California"),
            "Los Angeles",
            34.0522,
            -118.2437,
        ),
    )
    .insert(
        ip("203.0.113.128"),
        25,
        &dbip_city(
            "CA",
            "Canada",
            Some("Quebec"),
            "Montreal",
            45.5017,
            -73.5673,
        ),
    )
    .insert(
        ip("192.0.2.0"),
        24,
        &dbip_city("ZZ", "Nowhere", None, "Test", 0.0, 0.0),
    )
    .insert(
        ip("2001:db8::"),
        32,
        &dbip_city(
            "NL",
            "Netherlands",
            Some("North Holland"),
            "Amsterdam",
            52.37,
            4.89,
        ),
    );
    w.build()
}
