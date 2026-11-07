//! The 56 checks and the scoring, against fixture probe JSON.

use std::collections::HashSet;
use std::time::Instant;
use vanta_health::checks::{Area, Outcome, Severity, CHECKS};
use vanta_health::dns::DnsLeakResult;
use vanta_health::input::TlsCapture;
use vanta_health::report::penalty;
use vanta_health::testkit::{self, consistent};
use vanta_health::{evaluate, HealthInput, HealthReport, CRITICAL_CAP, LAUNCH_THRESHOLD};

fn outcome(r: &HealthReport, id: &str) -> Outcome {
    r.result(id)
        .unwrap_or_else(|| panic!("no check {id}"))
        .outcome
}

fn broken(f: impl FnOnce(&mut HealthInput)) -> HealthReport {
    let mut i = consistent();
    f(&mut i);
    evaluate(&i)
}

fn probe(i: &mut HealthInput) -> &mut vanta_health::ProbeReport {
    i.probe.as_mut().unwrap()
}

#[test]
fn exactly_56_checks_in_8_areas_with_unique_ids() {
    assert_eq!(CHECKS.len(), 56);
    for (n, c) in CHECKS.iter().enumerate() {
        assert_eq!(c.id, format!("H{:02}", n + 1));
    }
    let keys: HashSet<_> = CHECKS.iter().map(|c| c.key).collect();
    assert_eq!(keys.len(), 56);
    let per_area: Vec<usize> = Area::ALL
        .iter()
        .map(|a| CHECKS.iter().filter(|c| c.area == *a).count())
        .collect();
    // Same split as the prototype screen (design/prototype/src/data.js).
    assert_eq!(per_area, [10, 6, 6, 9, 8, 4, 5, 8]);
    let crit: Vec<_> = CHECKS
        .iter()
        .filter(|c| c.severity == Severity::Critical)
        .map(|c| c.key)
        .collect();
    for k in [
        "net.reach",
        "net.direct",
        "dns.leak",
        "rtc.host",
        "nav.ua",
        "net.geo",
    ] {
        assert!(crit.contains(&k), "{k} must be critical");
    }
}

#[test]
fn consistent_persona_scores_at_least_90_and_launches() {
    let r = evaluate(&consistent());
    let problems: Vec<_> = r
        .problems()
        .iter()
        .map(|p| format!("{} {}: {}", p.id, p.key, p.message))
        .collect();
    assert!(r.score >= 90, "score {} problems {problems:#?}", r.score);
    assert!(!r.blocked);
    assert!(r.critical_failures().is_empty());
    assert_eq!(
        r.score, 100,
        "every check passes on the fixture: {problems:#?}"
    );
    assert_eq!(r.by_area().iter().map(|(_, ok, _)| ok).sum::<usize>(), 56);
}

#[test]
fn static_fixture_json_parses_and_scores() {
    // The JSON shape the probe page posts (field names as in probe.html).
    let mut i = consistent();
    let json = include_str!("fixtures/good_probe.json");
    i.probe = Some(vanta_health::ProbeReport::from_json(json).unwrap());
    let r = evaluate(&i);
    assert!(r.score >= 90, "{:#?}", r.problems());
}

#[test]
fn ua_mismatch_is_critical() {
    let r = broken(|i| {
        probe(i).ua = probe(i).ua.replace("Chrome/156.0.0.0", "Chrome/155.0.0.0");
    });
    assert_eq!(outcome(&r, "H23"), Outcome::Fail);
    assert!(r.score <= CRITICAL_CAP && r.blocked);
    // The HTTP header disagreeing with navigator is caught too.
    let r = broken(|i| {
        let h = i.http1.as_mut().unwrap();
        for (k, v) in h.headers.iter_mut() {
            if k == "User-Agent" {
                *v = "Mozilla/5.0 (X11; Linux x86_64)".into();
            }
        }
    });
    assert_eq!(outcome(&r, "H23"), Outcome::Fail);
}

#[test]
fn webrtc_leak_is_critical() {
    let r = broken(|i| {
        probe(i).rtc.candidates = vec![
            "candidate:1 1 udp 2122260223 192.168.1.20 54400 typ host generation 0".into(),
            "candidate:2 1 udp 1686052607 198.51.100.77 54400 typ srflx raddr 192.168.1.20 rport 54400".into(),
        ];
        i.stun.push(vanta_health::stun::StunRequest {
            from: "127.0.0.1:54400".parse().unwrap(),
            transaction_id: [0; 12],
            attributes: vec![],
            username: None,
        });
    });
    assert_eq!(outcome(&r, "H17"), Outcome::Fail);
    assert_eq!(outcome(&r, "H18"), Outcome::Fail);
    assert_eq!(outcome(&r, "H19"), Outcome::Fail);
    assert_eq!(outcome(&r, "H22"), Outcome::Fail);
    assert!(r.score <= CRITICAL_CAP && r.blocked);
    assert!(r.critical_failures().contains(&"H18"));
}

#[test]
fn mdns_host_candidate_is_fine() {
    let r = broken(|i| {
        probe(i).rtc.candidates =
            vec!["candidate:1 1 udp 2122260223 4b1f8c2e-7d0a-4e7b-9a55-2b1d3c7e9f10.local 54400 typ host".into()];
    });
    assert_eq!(outcome(&r, "H18"), Outcome::Pass);
    assert_eq!(outcome(&r, "H19"), Outcome::Pass);
}

#[test]
fn dns_leak_is_critical() {
    let r = broken(|i| {
        i.dns = Some(DnsLeakResult {
            expected: 3,
            via_doh: 1,
            missing: vec!["a.leak.vanta.invalid".into(), "b.leak.vanta.invalid".into()],
        })
    });
    assert_eq!(outcome(&r, "H21"), Outcome::Fail);
    assert!(r.score <= CRITICAL_CAP && r.blocked);
    let r = broken(|i| i.dns = None);
    assert_eq!(outcome(&r, "H21"), Outcome::Fail);
    let r = broken(|i| i.guard.doh_through_proxy = false);
    assert_eq!(outcome(&r, "H20"), Outcome::Fail);
}

#[test]
fn timezone_mismatch_is_critical() {
    let r = broken(|i| {
        probe(i).timezone = "America/New_York".into();
        probe(i).worker.as_mut().unwrap().timezone = "America/New_York".into();
        probe(i).iframe.as_mut().unwrap().timezone = "America/New_York".into();
    });
    assert_eq!(outcome(&r, "H05"), Outcome::Fail);
    assert!(r.score <= CRITICAL_CAP && r.blocked);
    // Exit country moved but the profile was not re-matched.
    let r = broken(|i| i.exit.country = Some("NL".into()));
    assert_eq!(outcome(&r, "H05"), Outcome::Fail);
    assert!(r.blocked);
}

/// F03 acceptance: ten deliberately broken profiles, each caught by its check.
#[test]
fn ten_known_broken_profiles_are_each_caught() {
    type Break = fn(&mut HealthInput);
    let cases: [(&str, &str, Break); 10] = [
        ("proxy down", "H06", |i| i.guard.proxy_reachable = false),
        ("exit is own IP", "H01", |i| {
            i.exit.ip = Some("198.51.100.77".parse().unwrap())
        }),
        ("webdriver on", "H49", |i| probe(i).webdriver = Some(true)),
        ("CDP attached", "H50", |i| probe(i).cdp_trace = true),
        ("canvas noise per read", "H36", |i| {
            probe(i).canvas[2] = "different".into()
        }),
        ("worker says other cores", "H30", |i| {
            probe(i).worker.as_mut().unwrap().hardware_concurrency = 4
        }),
        ("screen from other device", "H38", |i| {
            probe(i).screen.width = 1366
        }),
        ("Go HTTP/2 client", "H13", |i| {
            i.h2.as_mut().unwrap().settings = vec![(2, 0), (4, 4_194_304), (6, 10_485_760)]
        }),
        ("Python TLS stack", "H11", |i| {
            i.tls = Some(TlsCapture {
                ja4: "t13d4312h1_c7886603b240_b26ce05bbdd6".into(),
                alpn: vec!["http/1.1".into()],
                sni: None,
            })
        }),
        ("macOS fonts", "H45", |i| {
            probe(i).fonts.push("Helvetica Neue".into())
        }),
    ];
    let good = evaluate(&consistent()).score;
    for (name, id, f) in cases {
        let r = broken(f);
        assert_ne!(outcome(&r, id), Outcome::Pass, "{name}: {id} not caught");
        assert!(r.score < good, "{name}: score did not drop");
    }
}

#[test]
fn no_probe_report_blocks_launch() {
    let r = broken(|i| i.probe = None);
    assert!(r.blocked);
    assert_eq!(outcome(&r, "H23"), Outcome::Fail);
    assert!(r.result("H23").unwrap().message.contains("did not report"));
}

#[test]
fn chromium_variant_ja4_only_warns() {
    let r = broken(|i| i.tls.as_mut().unwrap().ja4 = "t13d1516h2_8daaf6152771_806a8c22fdea".into());
    assert_eq!(outcome(&r, "H11"), Outcome::Warn);
    assert!(!r.blocked && r.score >= 90);
    let r = broken(|i| i.tls.as_mut().unwrap().ja4 = "t13d1518h2_8daaf6152771_4980c97edce0".into());
    assert_eq!(
        outcome(&r, "H11"),
        Outcome::Warn,
        "same ciphers, other extensions"
    );
}

#[test]
fn ja4_from_a_parsed_hello_feeds_the_check() {
    let rec = vanta_health::tls::chrome::client_hello("vanta-health.localhost");
    let h = vanta_health::tls::parse_client_hello(&rec).unwrap();
    let cap = TlsCapture::from(&h);
    assert_eq!(cap.alpn, ["h2", "http/1.1"]);
    let r = broken(|i| i.tls = Some(cap));
    assert_eq!(outcome(&r, "H12"), Outcome::Pass);
    assert_ne!(outcome(&r, "H11"), Outcome::Fail, "Chrome cipher list");
}

#[test]
fn scoring_weights_and_cap() {
    assert_eq!(penalty(Severity::Critical, Outcome::Pass), 0);
    assert!(penalty(Severity::Critical, Outcome::Fail) > penalty(Severity::Warn, Outcome::Fail));
    assert!(penalty(Severity::Warn, Outcome::Fail) > penalty(Severity::Info, Outcome::Fail));
    assert!(penalty(Severity::Warn, Outcome::Warn) < penalty(Severity::Warn, Outcome::Fail));
    // A single warn-level failure keeps the profile launchable.
    let r = broken(|i| probe(i).plugins = 0);
    assert!(!r.blocked && r.score >= 90);
    // Many non-critical failures can still block on their own.
    let r = broken(|i| {
        let p = probe(i);
        p.plugins = 0;
        p.chrome_object = false;
        p.screen.width = 1;
        p.device_pixel_ratio = 3.0;
        p.hardware_concurrency = 1;
        p.platform = "Linux x86_64".into();
        p.canvas.clear();
        p.audio.clear();
        p.rects.clear();
    });
    assert!(r.critical_failures().is_empty());
    assert!(r.score < LAUNCH_THRESHOLD && r.blocked, "score {}", r.score);
}

#[test]
fn score_feeds_the_launcher_gate() {
    use vanta_launcher::{preflight, Block, HealthGate, Preflight, MIN_HEALTH_SCORE};
    use vanta_proxy::ProxyState;
    assert_eq!(LAUNCH_THRESHOLD, MIN_HEALTH_SCORE);
    let now = 1_800_000_000_000;
    for r in [
        evaluate(&consistent()),
        broken(|i| probe(i).webdriver = Some(true)),
    ] {
        let p = Preflight {
            proxy: ProxyState::Online {
                checked_ms: now - 1000,
                latency_ms: 40,
            },
            proxy_max_age_ms: 300_000,
            relay_armed: true,
            rules_passed: true,
            health: HealthGate::Fresh {
                score: r.preflight_score().unwrap(),
            },
        };
        let gate = preflight(&p, now);
        assert_eq!(gate.is_err(), r.blocked);
        if r.blocked {
            assert_eq!(
                gate.unwrap_err(),
                vec![Block::HealthTooLow { score: r.score }]
            );
        }
    }
}

#[test]
fn full_evaluation_is_fast() {
    let i = consistent();
    let t = Instant::now();
    for _ in 0..100 {
        let _ = evaluate(&i);
    }
    assert!(
        t.elapsed().as_secs_f64() < 3.0,
        "100 runs took {:?}",
        t.elapsed()
    );
}

#[test]
fn fixture_persona_is_valid() {
    let p = testkit::persona();
    assert!(vanta_fingerprint::config::preflight(&p, testkit::ENGINE).is_ok());
}
