//! Geo Auto-Match (F07): the exit IP of each profile's proxy, measured through the proxy,
//! is looked up in the bundled offline GeoIP database; the profile's timezone,
//! geolocation and (when the user keeps them selected) locale, languages and
//! Accept-Language follow it. The user agent and every other persona field stay as they
//! are. Preview first ([`VantaApp::geo_preview`]), then apply exactly what was shown
//! ([`VantaApp::geo_apply`]; no network, the same database lookup).

use super::*;
use crate::dto::{GeoApply, GeoApplyResult, GeoDbStatus, GeoFieldChange, GeoLocationView, GeoPlan};
use std::collections::BTreeMap;
use std::net::IpAddr;
use vanta_fingerprint::geo::{match_location, GeoMatch};
use vanta_geo::{GeoDb, Location};

/// Proxies measured at the same time during a preview.
const MEASURE_PARALLEL: usize = 8;

/// Where the offline database stands (set by the shell, which opens it in the background).
#[derive(Debug, Clone, Default)]
pub enum GeoState {
    /// This build has no database (no `geoip/geoip.json` in the resources).
    #[default]
    NotBundled,
    /// Integrity check / open in progress.
    Loading,
    Ready(Arc<GeoDb>),
    /// Present but failed its check: lookups refused.
    Failed(String),
}

fn view(l: &Location) -> GeoLocationView {
    GeoLocationView {
        country: l.country.clone(),
        country_name: l.country_name.clone(),
        region: l.region.clone(),
        city: l.city.clone(),
        latitude: l.latitude,
        longitude: l.longitude,
        timezone: l.timezone.clone(),
    }
}

fn geo_text(g: &vanta_fingerprint::Geo) -> String {
    format!(
        "{:.4}, {:.4} (±{} m)",
        g.latitude, g.longitude, g.accuracy_m
    )
}

/// What applying `m` (with or without languages) changes on `p`.
pub(super) fn diff(p: &Persona, m: &GeoMatch) -> Vec<GeoFieldChange> {
    let mut out = Vec::new();
    let mut push = |field: &str, from: Option<String>, to: String, language: bool| {
        if from.as_deref() != Some(to.as_str()) {
            out.push(GeoFieldChange {
                field: field.into(),
                from,
                to,
                language,
            });
        }
    };
    let old = p.geo.as_ref();
    push(
        "country",
        old.map(|g| g.country.clone()),
        m.geo.country.clone(),
        false,
    );
    push(
        "timezone",
        old.map(|g| g.timezone.clone()),
        m.geo.timezone.clone(),
        false,
    );
    push("geolocation", old.map(geo_text), geo_text(&m.geo), false);
    let mut q = p.clone();
    q.apply_geo(m.geo.clone(), Some(m.locale));
    push("locale", Some(p.locale.clone()), q.locale.clone(), true);
    push(
        "languages",
        Some(p.languages.join(", ")),
        q.languages.join(", "),
        true,
    );
    push(
        "accept_language",
        Some(p.accept_language()),
        q.accept_language(),
        true,
    );
    out
}

impl VantaApp {
    pub fn set_geo_db(&self, state: GeoState) {
        *lock(&self.inner.geo) = state;
    }

    pub fn geo_db_status(&self) -> GeoDbStatus {
        match &*lock(&self.inner.geo) {
            GeoState::NotBundled => GeoDbStatus::NotBundled,
            GeoState::Loading => GeoDbStatus::Loading,
            GeoState::Ready(db) => GeoDbStatus::Ready {
                info: db.info().clone(),
            },
            GeoState::Failed(m) => GeoDbStatus::Failed { message: m.clone() },
        }
    }

    /// The open database, or why there is none.
    fn geo_db(&self) -> CoreResult<Arc<GeoDb>> {
        match &*lock(&self.inner.geo) {
            GeoState::Ready(db) => Ok(db.clone()),
            GeoState::NotBundled => Err(CoreError::Unsupported {
                message: "this build has no offline GeoIP database".into(),
            }),
            GeoState::Loading => Err(CoreError::Unsupported {
                message: "the GeoIP database is still being checked; try again in a moment".into(),
            }),
            GeoState::Failed(m) => Err(CoreError::Unsupported {
                message: format!("the GeoIP database is not usable: {m}"),
            }),
        }
    }

    /// Location of an IP from the offline database, when one is open.
    pub(super) fn geo_lookup(&self, ip: IpAddr) -> Option<Location> {
        let db = match &*lock(&self.inner.geo) {
            GeoState::Ready(db) => db.clone(),
            _ => return None,
        };
        db.lookup(ip).ok().flatten()
    }

    /// The exit IP of a proxy, asked through the proxy (IP echo, as in health runs).
    async fn measure_exit(&self, proxy_id: String) -> Result<IpAddr, String> {
        let rec = lock(&self.inner.store)
            .get_proxy(&proxy_id)
            .map_err(|e| e.to_string())?;
        let ep = self.endpoint(&rec).map_err(|e| e.to_string())?;
        let policy = GuardPolicy::default();
        let bootstrap = self.inner.deps.net.bootstrap(&policy);
        let addr = resolve_upstream(&ep, &*bootstrap)
            .await
            .map_err(|_| "proxy host did not resolve".to_string())?;
        let url = lock(&self.inner.ip_echo_url).clone();
        self.inner
            .deps
            .ip_echo
            .exit_ip(&url, &ep, addr, self.inner.cfg.proxy_timeout)
            .await
            .map_err(|e| format!("exit IP not measured: {e}"))
    }

    /// Geo Auto-Match preview for `ids`: each proxy's exit IP is measured once (through
    /// the proxy), looked up offline, and the values each profile would get are listed
    /// next to its current ones. Nothing is stored.
    pub async fn geo_preview(&self, ids: &[ProfileId]) -> CoreResult<Vec<GeoPlan>> {
        self.require_unlocked()?;
        let db = self.geo_db()?;
        let mut metas = Vec::with_capacity(ids.len());
        for id in ids {
            metas.push(lock(&self.inner.store).get(*id)?);
        }
        // One measurement per proxy, a few at a time.
        let proxies: BTreeMap<String, ()> = metas
            .iter()
            .filter_map(|m| m.proxy_id.clone())
            .map(|p| (p, ()))
            .collect();
        let sem = Arc::new(tokio::sync::Semaphore::new(MEASURE_PARALLEL));
        let mut set = tokio::task::JoinSet::new();
        for proxy in proxies.into_keys() {
            let (app, sem) = (self.clone(), sem.clone());
            set.spawn(async move {
                let _permit = sem.acquire_owned().await;
                let r = app.measure_exit(proxy.clone()).await;
                (proxy, r)
            });
        }
        let mut exits: HashMap<String, Result<IpAddr, String>> = HashMap::new();
        while let Some(r) = set.join_next().await {
            if let Ok((proxy, ip)) = r {
                exits.insert(proxy, ip);
            }
        }

        let mut plans = Vec::with_capacity(metas.len());
        for meta in metas {
            let mut plan = GeoPlan {
                profile_id: meta.id,
                name: meta.name.clone(),
                proxy_id: meta.proxy_id.clone(),
                exit_ip: None,
                location: None,
                changes: Vec::new(),
                problem: None,
            };
            let Some(proxy) = &meta.proxy_id else {
                plan.problem = Some("no proxy assigned".into());
                plans.push(plan);
                continue;
            };
            let ip = match exits.get(proxy) {
                Some(Ok(ip)) => *ip,
                Some(Err(e)) => {
                    plan.problem = Some(e.clone());
                    plans.push(plan);
                    continue;
                }
                None => {
                    plan.problem = Some("exit IP not measured".into());
                    plans.push(plan);
                    continue;
                }
            };
            plan.exit_ip = Some(ip.to_string());
            match db.lookup(ip) {
                Ok(Some(loc)) => {
                    plan.location = Some(view(&loc));
                    let persona = self.load_config(meta.id)?.persona;
                    match match_location(
                        &loc.country,
                        loc.region.as_deref(),
                        loc.latitude,
                        loc.longitude,
                        persona.seed,
                    ) {
                        Some(m) => plan.changes = diff(&persona, &m),
                        None => {
                            plan.problem = Some(format!(
                                "no time zone table for country {}; set it by hand",
                                loc.country
                            ))
                        }
                    }
                }
                Ok(None) => {
                    plan.problem = Some(format!("{ip} is not in the GeoIP database"));
                }
                Err(e) => plan.problem = Some(e.to_string()),
            }
            plans.push(plan);
        }
        Ok(plans)
    }

    /// Apply previewed matches: for each item the exit IP the user saw is looked up again
    /// (offline, same result) and the profile's timezone and geolocation are set; locale,
    /// languages and Accept-Language only when `languages` is set. The user agent is left
    /// as it is. A profile whose persona changed loses its health report (the next launch
    /// needs a new health run). Running profiles are refused: the change would only apply
    /// at the next start and the open browser would contradict it.
    pub fn geo_apply(&self, items: &[GeoApply]) -> CoreResult<Vec<GeoApplyResult>> {
        self.require_unlocked()?;
        let db = self.geo_db()?;
        let mut out = Vec::with_capacity(items.len());
        for it in items {
            let res = self.geo_apply_one(&db, it);
            out.push(match res {
                Ok(changed) => GeoApplyResult {
                    profile_id: it.profile_id,
                    changed,
                    error: None,
                },
                Err(e) => GeoApplyResult {
                    profile_id: it.profile_id,
                    changed: false,
                    error: Some(e.to_string()),
                },
            });
        }
        Ok(out)
    }

    fn geo_apply_one(&self, db: &GeoDb, it: &GeoApply) -> CoreResult<bool> {
        if lock(&self.inner.running).contains_key(&it.profile_id) {
            return Err(CoreError::AlreadyRunning);
        }
        let ip: IpAddr = it.exit_ip.trim().parse().map_err(|_| {
            CoreError::from(VantaError::Invalid(format!(
                "not an IP address: {}",
                it.exit_ip
            )))
        })?;
        let loc = db
            .lookup(ip)
            .map_err(|e| VantaError::Invalid(e.to_string()))?
            .ok_or_else(|| VantaError::Invalid(format!("{ip} is not in the GeoIP database")))?;
        let mut cfg = self.load_config(it.profile_id)?;
        let m = match_location(
            &loc.country,
            loc.region.as_deref(),
            loc.latitude,
            loc.longitude,
            cfg.persona.seed,
        )
        .ok_or_else(|| {
            VantaError::Invalid(format!("no time zone table for country {}", loc.country))
        })?;
        let before = cfg.persona.clone();
        let ua = before.user_agent.clone();
        cfg.persona
            .apply_geo(m.geo.clone(), it.languages.then_some(m.locale));
        debug_assert_eq!(
            cfg.persona.user_agent, ua,
            "Geo Auto-Match never touches the UA"
        );
        let changed = cfg.persona != before;
        if changed {
            self.save_config(it.profile_id, &cfg)?;
        }
        let store = lock(&self.inner.store);
        let mut meta = store.get(it.profile_id)?;
        meta.exit_ip = ip.to_string();
        meta.country = m.geo.country.clone();
        store.update_meta(&meta)?;
        if changed {
            store.clear_health(it.profile_id)?;
        }
        Ok(changed)
    }

    /// C018 at launch: the profile's location must be the country of its proxy's last
    /// known exit IP (Proxy Hub check). `None` = nothing to object to (no database, no
    /// known exit, or no location on the profile yet, which C018 reports as a note).
    pub(super) fn geo_launch_problem(&self, p: &Prepared) -> Option<BlockReason> {
        let geo = p.persona.geo.as_ref()?;
        let rec = lock(&self.inner.store).get_proxy(&p.proxy_id).ok()?;
        let checks: ProxyChecks = serde_json::from_str(rec.checks.as_deref()?).ok()?;
        let ip = checks.exit.ok()?.ip?;
        let loc = self.geo_lookup(ip)?;
        if loc.country.eq_ignore_ascii_case(&geo.country) {
            return None;
        }
        Some(BlockReason::new(
            "geo_mismatch",
            format!(
                "launch blocked: the proxy's exit IP {ip} is in {} but the profile's location is {} (C018); run Geo Auto-Match",
                loc.country, geo.country
            ),
        ))
    }
}
