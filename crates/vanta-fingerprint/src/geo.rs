//! Geo Auto-Match (F07): from an exit-IP location (country, region, coordinates) to the
//! persona's time zone, locale and geolocation.
//!
//! The offline database (DB-IP "IP to City Lite") has no time zone, so the zone is derived
//! here: single-zone countries map directly, multi-zone countries take the zone of the
//! nearest reference city. Rule C018 accepts exactly the zones of this table (plus a few
//! IANA aliases), so a matched persona always passes it.

use crate::geo_tables::{Zone, ALIASES, LOCALES, REGION_LOCALES, ZONES};
use crate::persona::Geo;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Largest distance (metres) between the database coordinates and the persona's
/// geolocation. Every profile on the same exit gets its own point near the city centre.
pub const JITTER_M: f64 = 1_000.0;
/// Accuracy (metres) reported with the geolocation: a city-level fix, drawn per profile.
pub const ACCURACY_RANGE_M: (u32, u32) = (1_200, 2_800);

fn zones_of(country: &str) -> Option<&'static [Zone]> {
    ZONES
        .iter()
        .find(|(c, _)| c.eq_ignore_ascii_case(country))
        .map(|(_, z)| *z)
}

/// IANA zones plausible for a country (C018): the table's zones and their aliases.
/// `None` = country not in the table, the zone cannot be verified.
pub fn timezones_for(country: &str) -> Option<Vec<&'static str>> {
    let mut v: Vec<&'static str> = zones_of(country)?.iter().map(|(z, _)| *z).collect();
    if let Some((_, a)) = ALIASES
        .iter()
        .find(|(c, _)| c.eq_ignore_ascii_case(country))
    {
        v.extend_from_slice(a);
    }
    Some(v)
}

/// The IANA zone for a point in `country`: the only zone, or the zone of the nearest
/// reference city. `None` when the country is not in the table.
pub fn timezone_at(country: &str, latitude: f64, longitude: f64) -> Option<&'static str> {
    let zones = zones_of(country)?;
    if zones.len() == 1 || !latitude.is_finite() || !longitude.is_finite() {
        return zones.first().map(|(z, _)| *z);
    }
    let mut best = (f64::INFINITY, zones[0].0);
    for (zone, cities) in zones {
        for &(lat, lon) in *cities {
            let d = distance_km(latitude, longitude, lat, lon);
            if d < best.0 {
                best = (d, zone);
            }
        }
    }
    Some(best.1)
}

/// Browser locale for a country, refined by region where the region speaks another
/// language (Quebec -> fr-CA, Ticino -> it-CH ...). `None` when the country is unknown.
pub fn locale_for(country: &str, region: Option<&str>) -> Option<&'static str> {
    if let Some(r) = region {
        let r = r.trim().to_lowercase();
        if let Some((_, _, l)) = REGION_LOCALES
            .iter()
            .find(|(c, name, _)| c.eq_ignore_ascii_case(country) && *name == r)
        {
            return Some(l);
        }
    }
    LOCALES
        .iter()
        .find(|(c, _)| c.eq_ignore_ascii_case(country))
        .map(|(_, l)| *l)
}

/// Great-circle distance in km.
pub fn distance_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = p2 - p1;
    let dl = (lon2 - lon1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    6371.0 * 2.0 * a.sqrt().min(1.0).asin()
}

/// What Geo Auto-Match sets on a persona for one exit location.
#[derive(Debug, Clone, PartialEq)]
pub struct GeoMatch {
    pub geo: Geo,
    /// Locale for navigator.language / Accept-Language (applied only when the user keeps
    /// "languages" selected).
    pub locale: &'static str,
}

/// The persona values for an exit location. `seed` (the persona's seed) places the
/// geolocation within [`JITTER_M`] of the database point and draws the accuracy, so the
/// same profile always gets the same values for the same exit and two profiles on one
/// exit do not share an exact point. `None` when the country is not in the table.
pub fn match_location(
    country: &str,
    region: Option<&str>,
    latitude: f64,
    longitude: f64,
    seed: u64,
) -> Option<GeoMatch> {
    let country = country.trim().to_ascii_uppercase();
    let timezone = timezone_at(&country, latitude, longitude)?;
    let locale = locale_for(&country, region)?;
    let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x6765_6f5f_6175_746f); // "geo_auto"
    let r = JITTER_M * rng.gen::<f64>().sqrt();
    let theta = rng.gen::<f64>() * std::f64::consts::TAU;
    let dlat = r * theta.cos() / 111_320.0;
    let dlon = r * theta.sin() / (111_320.0 * latitude.to_radians().cos().abs().max(0.01));
    let round = |x: f64| (x * 10_000.0).round() / 10_000.0;
    let accuracy_m = rng.gen_range(ACCURACY_RANGE_M.0..=ACCURACY_RANGE_M.1) / 10 * 10;
    Some(GeoMatch {
        geo: Geo {
            country,
            timezone: timezone.into(),
            latitude: round((latitude + dlat).clamp(-90.0, 90.0)),
            longitude: round(((longitude + dlon + 540.0) % 360.0) - 180.0),
            accuracy_m,
        },
        locale,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_zone_countries() {
        assert_eq!(timezone_at("DE", 52.5, 13.4), Some("Europe/Berlin"));
        assert_eq!(timezone_at("de", 0.0, 0.0), Some("Europe/Berlin"));
        assert_eq!(timezone_at("IN", 19.0, 72.8), Some("Asia/Kolkata"));
        assert_eq!(timezone_at("ZZ", 0.0, 0.0), None);
    }

    #[test]
    fn multi_zone_countries_take_the_nearest_city() {
        let cases = [
            ("US", 40.73, -73.99, "America/New_York"),
            ("US", 41.85, -87.65, "America/Chicago"),
            ("US", 37.39, -122.08, "America/Los_Angeles"), // Mountain View
            ("US", 39.74, -104.98, "America/Denver"),
            ("US", 31.76, -106.45, "America/Denver"), // El Paso
            ("US", 33.42, -111.83, "America/Phoenix"), // Mesa
            ("US", 47.67, -116.78, "America/Los_Angeles"), // Coeur d'Alene
            ("US", 21.3, -157.8, "Pacific/Honolulu"),
            ("CA", 45.5, -73.6, "America/Toronto"),
            ("CA", 49.25, -123.1, "America/Vancouver"),
            ("CA", 51.0, -114.1, "America/Edmonton"),
            ("AU", -31.9, 115.9, "Australia/Perth"),
            ("AU", -33.9, 151.2, "Australia/Sydney"),
            ("BR", -3.1, -60.0, "America/Manaus"),
            ("BR", -23.5, -46.6, "America/Sao_Paulo"),
            ("RU", 55.75, 37.6, "Europe/Moscow"),
            ("RU", 55.0, 82.9, "Asia/Novosibirsk"),
            ("MX", 32.5, -117.0, "America/Tijuana"),
            ("ES", 28.1, -15.4, "Atlantic/Canary"),
        ];
        for (cc, lat, lon, tz) in cases {
            assert_eq!(timezone_at(cc, lat, lon), Some(tz), "{cc} {lat},{lon}");
        }
    }

    #[test]
    fn every_derived_zone_is_accepted_for_its_country() {
        for (cc, zones) in ZONES {
            let ok = timezones_for(cc).unwrap();
            for (z, cities) in *zones {
                assert!(ok.contains(z), "{cc} {z}");
                for &(lat, lon) in *cities {
                    assert_eq!(timezone_at(cc, lat, lon), Some(*z), "{cc} city of {z}");
                }
            }
            assert!(locale_for(cc, None).is_some(), "locale for {cc}");
        }
        assert!(timezones_for("IN").unwrap().contains(&"Asia/Calcutta"));
    }

    #[test]
    fn locale_by_country_and_region() {
        assert_eq!(locale_for("DE", None), Some("de-DE"));
        assert_eq!(locale_for("CA", Some("Ontario")), Some("en-CA"));
        assert_eq!(locale_for("CA", Some("Québec")), Some("fr-CA"));
        assert_eq!(locale_for("CH", Some("Ticino")), Some("it-CH"));
        assert_eq!(locale_for("XX", None), None);
    }

    #[test]
    fn match_is_deterministic_near_the_point_and_differs_per_seed() {
        let a = match_location("de", Some("Hesse"), 50.11, 8.68, 7).unwrap();
        assert_eq!(
            a,
            match_location("DE", Some("Hesse"), 50.11, 8.68, 7).unwrap()
        );
        assert_eq!(a.geo.country, "DE");
        assert_eq!(a.geo.timezone, "Europe/Berlin");
        assert_eq!(a.locale, "de-DE");
        let d = distance_km(50.11, 8.68, a.geo.latitude, a.geo.longitude);
        assert!(d <= JITTER_M / 1000.0 + 0.02, "{d} km");
        assert!((ACCURACY_RANGE_M.0..=ACCURACY_RANGE_M.1).contains(&a.geo.accuracy_m));
        let b = match_location("DE", None, 50.11, 8.68, 8).unwrap();
        assert_ne!(
            (a.geo.latitude, a.geo.longitude),
            (b.geo.latitude, b.geo.longitude)
        );
        assert!(match_location("ZZ", None, 0.0, 0.0, 1).is_none());
        // Longitude stays in range across the antimeridian.
        let f = match_location("FJ", None, -17.8, 179.999, 3).unwrap();
        assert!((-180.0..180.0).contains(&f.geo.longitude));
    }
}
