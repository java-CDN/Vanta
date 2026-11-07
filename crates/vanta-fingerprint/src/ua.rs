//! User-Agent and UA Client Hints, built from the installed engine version (R5).
//!
//! GREASE brand and brand order are an exact port of Chromium 156
//! components/embedder_support/user_agent_utils.cc (GetGreasedUserAgentBrandVersion,
//! GetRandomOrder, ShuffleBrandList), seeded by the major version.

use vanta_types::{EngineVersion, OsKind};

const GREASEY_CHARS: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
const GREASED_VERSIONS: [&str; 3] = ["8", "99", "24"];
const ORDERS3: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

/// (brand, version) — version is major or full depending on the list.
pub type BrandVersion = (String, String);

pub fn grease_brand(major: u32) -> (String, &'static str) {
    let s = major as usize;
    let brand = format!(
        "Not{}A{}Brand",
        GREASEY_CHARS[s % 11],
        GREASEY_CHARS[(s + 1) % 11]
    );
    (brand, GREASED_VERSIONS[s % 3])
}

fn shuffle(list: Vec<BrandVersion>, seed: usize) -> Vec<BrandVersion> {
    let order = ORDERS3[seed % 6];
    let mut out = vec![(String::new(), String::new()); 3];
    for (i, bv) in list.into_iter().enumerate() {
        out[order[i]] = bv;
    }
    out
}

/// `navigator.userAgentData.brands` / Sec-CH-UA (major versions).
pub fn brands(v: &EngineVersion, brand: &str) -> Vec<BrandVersion> {
    let (g, gv) = grease_brand(v.major);
    let m = v.major.to_string();
    shuffle(
        vec![
            (g, gv.to_string()),
            ("Chromium".into(), m.clone()),
            (brand.into(), m),
        ],
        v.major as usize,
    )
}

/// `fullVersionList` / Sec-CH-UA-Full-Version-List.
pub fn full_version_list(v: &EngineVersion, brand: &str) -> Vec<BrandVersion> {
    let (g, gv) = grease_brand(v.major);
    let f = v.to_string();
    shuffle(
        vec![
            (g, format!("{gv}.0.0.0")),
            ("Chromium".into(), f.clone()),
            (brand.into(), f),
        ],
        v.major as usize,
    )
}

/// Structured-header form: `"Not:A-Brand";v="8", "Chromium";v="156", ...`
pub fn header(list: &[BrandVersion]) -> String {
    list.iter()
        .map(|(b, v)| format!("\"{b}\";v=\"{v}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// OS token of the reduced User-Agent. Chrome freezes it for every Windows release and
/// CPU (Windows 10, Windows 11 and ARM64 all send the same token); the real release and
/// architecture are only exposed through UA-CH `platformVersion` / `architecture`.
pub const WINDOWS_UA_TOKEN: &str = "Windows NT 10.0; Win64; x64";

/// Reduced User-Agent string, as Chrome sends it.
pub fn user_agent(_os: OsKind, v: &EngineVersion) -> String {
    format!(
        "Mozilla/5.0 ({WINDOWS_UA_TOKEN}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{} Safari/537.36",
        v.reduced()
    )
}

/// UA-CH `platform` value.
pub fn ch_platform(os: OsKind) -> &'static str {
    os.family()
}

#[cfg(test)]
mod tests {
    use super::*;
    const V156: EngineVersion = EngineVersion::new(156, 0, 8078, 79);

    #[test]
    fn grease_156_matches_chromium() {
        assert_eq!(grease_brand(156), ("Not:A-Brand".to_string(), "8"));
    }

    #[test]
    fn matches_real_chrome_131_header() {
        // Real Chrome 131 sent exactly this Sec-CH-UA; same algorithm, different seed.
        assert_eq!(
            header(&brands(
                &EngineVersion::new(131, 0, 6778, 86),
                "Google Chrome"
            )),
            r#""Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24""#
        );
    }

    #[test]
    fn brand_order_156() {
        // 156 % 6 == 0 -> identity order: GREASE, Chromium, brand.
        assert_eq!(
            header(&brands(&V156, "Google Chrome")),
            r#""Not:A-Brand";v="8", "Chromium";v="156", "Google Chrome";v="156""#
        );
    }

    #[test]
    fn full_version_list_156() {
        assert_eq!(
            header(&full_version_list(&V156, "Google Chrome")),
            r#""Not:A-Brand";v="8.0.0.0", "Chromium";v="156.0.8078.79", "Google Chrome";v="156.0.8078.79""#
        );
    }

    #[test]
    fn shuffle_is_a_permutation_for_all_seeds() {
        for major in 100..200 {
            let b = brands(&EngineVersion::new(major, 0, 0, 0), "Google Chrome");
            let mut names: Vec<&str> = b.iter().map(|x| x.0.as_str()).collect();
            names.sort();
            assert!(names.contains(&"Chromium") && names.contains(&"Google Chrome"));
            assert!(names.iter().all(|n| !n.is_empty()));
        }
    }

    #[test]
    fn ua_strings() {
        let expected = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
        assert_eq!(user_agent(OsKind::Windows11, &V156), expected);
        assert_eq!(user_agent(OsKind::Windows10, &V156), expected);
        assert_eq!(ch_platform(OsKind::Windows10), "Windows");
    }
}
