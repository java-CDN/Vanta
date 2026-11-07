import { useEffect, useState, type ReactNode } from 'react';
import { useApp } from '../state/store';
import { Main } from '../components/Shell';
import { CC, Empty, Icon, Seg, Spin } from '../components/ui';
import type * as T from '../api/types';

type Tab = 'nav' | 'screen' | 'gpu' | 'noise' | 'fonts' | 'media' | 'geo';
const TABS: [Tab, string][] = [['nav', 'Navigator & UA-CH'], ['screen', 'Screen'], ['gpu', 'WebGL / GPU'], ['noise', 'Canvas / Audio'], ['fonts', 'Fonts'], ['media', 'Media'], ['geo', 'Timezone / locale']];
/** Which tab shows the values a rule checks (crates/vanta-fingerprint/src/rules.rs). */
export const RULE_TAB: Record<string, Tab> = {
  C001: 'nav', C002: 'nav', C003: 'nav', C004: 'gpu', C005: 'gpu', C006: 'gpu', C007: 'gpu', C008: 'screen', C009: 'screen', C010: 'screen',
  C011: 'screen', C012: 'fonts', C013: 'fonts', C014: 'nav', C015: 'nav', C016: 'screen', C017: 'nav', C018: 'geo', C019: 'geo', C020: 'geo',
  C021: 'nav', C022: 'nav', C023: 'media', C024: 'geo', C025: 'gpu', C026: 'noise', C027: 'gpu', C028: 'gpu', C029: 'screen', C030: 'nav',
};
const W11_ONLY = ['Segoe UI Variable', 'Segoe Fluent Icons'];
const mode = (m: T.SurfaceMode, seed: string) => (m === 'real' ? 'Real GPU' : m === 'noise' ? `Noise (seed 0x${seed}…)` : 'Block');

function Row({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return <><dt>{label}</dt><dd>{children}{hint && <div className="dim" style={{ fontSize: 11, marginTop: 3 }}>{hint}</div>}</dd></>;
}
const Ro = ({ children }: { children: ReactNode }) => <span className="mono" style={{ color: 'var(--text2)' }}>{children}</span>;

export function FingerprintsScreen() {
  const a = useApp();
  const pid = a.profiles.some(p => p.id === a.routeArg) ? a.routeArg : a.profiles[0]?.id;
  const p = a.profiles.find(x => x.id === pid);
  const [tab, setTab] = useState<Tab>('nav');
  const [filter, setFilter] = useState<'all' | 'issues'>('all');
  const [fp, setFp] = useState<T.FingerprintView | null>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setFp(null); setErr('');
    if (!pid) return;
    let live = true;
    a.b.fingerprint(pid).then(v => live && setFp(v)).catch(e => live && setErr(String((e as { message?: string }).message ?? e)));
    return () => { live = false; };
  }, [pid, p?.health, a.b]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!p) return <Main title="Fingerprint Studio" sub="No profiles yet."><div className="card"><Empty icon="fp" title="No profiles" text="Create a profile first."><button className="btn p s" onClick={() => a.go('new')}><Icon n="plus" s={13} />New profile</button></Empty></div></Main>;

  const regen = async () => {
    const os = await new Promise<T.OsKind | null>(resolve => {
      let chosen: T.OsKind = p.os;
      const pick = (v: T.OsKind | null) => { resolve(v); a.closeModal(); };
      function Body() {
        const [o, setO] = useState<T.OsKind>(p!.os);
        chosen = o;
        return <div style={{ display: 'flex', flexDirection: 'column', gap: 12, color: 'var(--text2)', lineHeight: 1.5 }}>
          <div>A new real-device record and new noise seeds replace the current identity of <b>{p!.name}</b>. Its language and location stay. Sites that knew the old fingerprint will see a different device.</div>
          <div className="field"><label>Operating system</label><div><Seg value={o} onChange={setO} options={[['windows11', 'Windows 11'], ['windows10', 'Windows 10']]} name="Operating system" /></div></div>
          <div className="note"><Icon n="info" s={13} /><span>The last health check no longer applies; run one before the next launch.</span></div>
        </div>;
      }
      a.openModal({ title: `Regenerate ${p.name}?`, width: 480, onClose: () => resolve(null), body: <Body />,
        foot: <><button className="btn" onClick={() => pick(null)}>Cancel</button><button className="btn p" id="cfOk" onClick={() => pick(chosen)}><Icon n="refresh" s={14} />Regenerate</button></> });
    });
    if (!os) return;
    setBusy(true);
    try {
      const m = await a.b.regenerateFingerprint(p.id, os);
      a.patchProfile(m);
      const v = await a.b.fingerprint(p.id); setFp(v);
      a.toast(<>New seed 0x{v.seed_prefix}… · device {v.device_id}</>, '', 'refresh');
    } catch (e) { a.fail(e); } finally { setBusy(false); }
  };

  const rules = fp?.rules ?? [];
  const rs = { ok: rules.filter(r => r.level === 'pass').length, warn: rules.filter(r => r.level === 'note').length, bad: rules.filter(r => r.level === 'fail').length };
  const badBy = (t: Tab) => rules.filter(r => RULE_TAB[r.id] === t && r.level === 'fail').length;
  const px = a.proxyOf(p);
  let body: ReactNode = <div className="muted">{err || <><Spin s={10} /> Loading…</>}</div>;
  if (fp) {
    const kv = (c: ReactNode) => <div className="kv" style={{ gridTemplateColumns: '170px 1fr' }}>{c}</div>;
    if (tab === 'nav') body = kv(<>
      <Row label="Operating system" hint="Desktop Windows identities only. Change it with Regenerate.">{fp.os === 'windows11' ? 'Windows 11' : 'Windows 10'}</Row>
      <Row label="Chrome version" hint="Rule C030: never stored in the profile; taken from the installed engine at every launch. Not editable."><span style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}><b>{fp.engine}</b><span className="pill ok"><Icon n="lock" s={11} />bound to engine</span></span></Row>
      <Row label="User-Agent" hint="Fixed by design: derived from the engine version and the Windows token."><Ro>{fp.user_agent}</Ro></Row>
      <Row label="Sec-CH-UA"><Ro>{fp.sec_ch_ua}</Ro></Row>
      <Row label="UA-CH platform"><Ro>"{fp.ua_platform}"</Ro></Row>
      <Row label="Platform version" hint="Windows 10 reports 1–10; Windows 11 reports 13.0.0 or higher."><Ro>{fp.platform_version}</Ro></Row>
      <Row label="Architecture"><Ro>{fp.architecture} · {fp.bitness}-bit</Ro></Row>
      <Row label="navigator.platform"><Ro>{fp.navigator_platform}</Ro></Row>
      <Row label="hardwareConcurrency"><Ro>{fp.hardware_concurrency}</Ro></Row>
      <Row label="deviceMemory" hint="Chrome rounds and caps this value at 8."><Ro>{fp.device_memory}</Ro></Row>
    </>);
    if (tab === 'screen') body = kv(<>
      <Row label="Resolution"><Ro>{fp.screen_width} × {fp.screen_height}</Ro></Row>
      <Row label="Available size" hint="screen.availHeight = height − taskbar (rule C029)."><Ro>{fp.avail_width} × {fp.avail_height}</Ro></Row>
      <Row label="Taskbar height"><Ro>{fp.screen_height - fp.avail_height} px</Ro></Row>
      <Row label="devicePixelRatio"><Ro>{fp.device_pixel_ratio}</Ro></Row>
      <Row label="Color depth"><Ro>{fp.color_depth}-bit</Ro></Row>
      <Row label="maxTouchPoints"><Ro>{fp.max_touch_points}</Ro></Row>
    </>);
    if (tab === 'gpu') body = kv(<>
      <Row label="WebGL vendor" hint="Must name the same maker as the renderer (C006)."><Ro>{fp.gpu_vendor}</Ro></Row>
      <Row label="WebGL renderer"><Ro>{fp.gpu_renderer}</Ro></Row>
      <Row label="WebGPU adapter"><Ro>vendor {fp.webgpu_vendor} · arch {fp.webgpu_arch}</Ro></Row>
      <Row label="Device record"><span className="mono">{fp.device_id}</span></Row>
    </>);
    if (tab === 'noise') body = kv(<>
      <Row label="Canvas 2D" hint="Noise is seeded per profile, so every read returns the same image."><Ro>{mode(fp.canvas, fp.seed_prefix)}</Ro></Row>
      <Row label="WebGL image"><Ro>{mode(fp.webgl_image, fp.seed_prefix)}</Ro></Row>
      <Row label="AudioContext"><Ro>{mode(fp.audio, fp.seed_prefix)}</Ro></Row>
      <Row label="Noise seed" hint="Changes only with Regenerate."><Ro>0x{fp.seed_prefix}…</Ro></Row>
    </>);
    if (tab === 'fonts') body = kv(<>
      <Row label="Font set"><Ro>{fp.fonts.length} fonts · {fp.os === 'windows11' ? 'Windows 11' : 'Windows 10'}</Ro></Row>
      <Row label="Emoji font"><Ro>Segoe UI Emoji</Ro></Row>
      <Row label="Fonts exposed"><div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 2 }}>{fp.fonts.map(f => <span key={f} className={`pill ${W11_ONLY.includes(f) && fp.os === 'windows10' ? 'bad' : ''}`}>{f}</span>)}</div></Row>
    </>);
    if (tab === 'media') body = kv(<>
      <Row label="Microphones"><Ro>{fp.microphones}</Ro></Row>
      <Row label="Cameras"><Ro>{fp.cameras}</Ro></Row>
      <Row label="Speakers"><Ro>{fp.speakers}</Ro></Row>
      <Row label="Labels"><Ro>hidden until permission is granted</Ro></Row>
      <Row label="Battery"><Ro>none (desktop)</Ro></Row>
    </>);
    if (tab === 'geo') body = kv(<>
      <Row label="Exit IP">{px ? (p.exit_ip ? <><CC c={p.country} /> <span className="mono">{p.exit_ip}</span></> : <span className="mono">{px.host} <span className="dim">(exit not measured yet)</span></span>) : <span className="dim">No proxy</span>}</Row>
      <Row label="Timezone" hint="Set from the exit IP by Geo Auto-Match (rule C018).">{fp.timezone ? <Ro>{fp.timezone}</Ro> : <span className="dim">not set yet · follows the exit IP</span>}</Row>
      <Row label="Locale"><Ro>{fp.locale}</Ro></Row>
      <Row label="navigator.languages"><Ro>{JSON.stringify(fp.languages)}</Ro></Row>
      <Row label="Accept-Language"><Ro>{fp.accept_language}</Ro></Row>
      <Row label="Geolocation"><Ro>{fp.latitude != null ? `${fp.latitude.toFixed(2)}, ${fp.longitude?.toFixed(2)} (${fp.country})` : 'not set'}</Ro></Row>
      <Row label="WebRTC"><Ro>{fp.webrtc_policy === 'disable_non_proxied_udp' ? 'Proxy only (public IP = exit IP)' : fp.webrtc_policy}</Ro></Row>
    </>);
  }
  const shown = filter === 'issues' ? rules.filter(r => r.level !== 'pass') : rules;
  return (
    <Main title={<>Fingerprint Studio · {p.name}</>} sub="One seeded identity drives every surface: pages, workers, iframes and HTTP headers."
      actions={<>
        <select className="inp" style={{ width: 190 }} id="fpPick" aria-label="Profile" value={p.id} onChange={e => a.go('fingerprints', e.target.value)}>{a.profiles.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select>
        <button className="btn p" data-a="fpRegen" disabled={busy || !fp} onClick={regen}>{busy ? <Spin /> : <Icon n="refresh" s={14} />}Regenerate</button>
      </>}>
      <div className="row" style={{ alignItems: 'flex-start' }}>
        <div className="col" style={{ flex: 1.25 }}>
          <div className="card" style={{ padding: 0 }}>
            <div className="tabs" role="tablist" style={{ padding: '0 10px' }}>
              {TABS.map(([k, l]) => <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? 'on' : ''} data-a="fpTab" data-id={k} onClick={() => setTab(k)}>{l}{badBy(k) > 0 && <span className="badge">{badBy(k)}</span>}</button>)}
            </div>
            <div style={{ padding: '16px 18px' }}>{body}</div>
          </div>
          <div className="note" style={{ padding: '0 4px' }}><Icon n="lock" s={13} /><span>Values are read-only: an identity is a consistent whole from one real device record, so it changes only by regenerating it. The config is signed (Ed25519) at every launch; the engine refuses an unsigned or altered one.</span></div>
        </div>
        <div className="col" style={{ flex: 1 }}>
          <div className="card"><h3><Icon n="check" s={15} />Consistency <span className={`r ${rs.bad ? 'bad' : 'ok'}`}>{rs.ok} pass · {rs.warn} note · {rs.bad} fail</span></h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <Seg value={filter} onChange={setFilter} options={[['all', `All ${rules.length || 30}`], ['issues', `Issues (${rs.warn + rs.bad})`]]} name="Rule filter" />
              {rs.bad ? <span className="pill bad"><Icon n="alert" s={11} />launch blocked</span> : <span className="pill ok">ready to launch</span>}
            </div>
            <div style={{ maxHeight: 430, overflow: 'auto', paddingRight: 4 }}>
              {shown.length ? shown.map(r => (
                <div key={r.id} className="chk" style={{ cursor: 'pointer' }} onClick={() => setTab(RULE_TAB[r.id] ?? 'nav')} title={`Open ${TABS.find(t => t[0] === (RULE_TAB[r.id] ?? 'nav'))![1]}`}>
                  <span className={`ic ${r.level === 'pass' ? 'ok' : r.level === 'fail' ? 'bad' : 'warn'}`}>{r.level === 'pass' ? '✓' : r.level === 'fail' ? '✕' : '!'}</span>
                  <span className="mono dim">{r.id}</span><span style={r.level === 'fail' ? { color: 'var(--badt)' } : undefined}>{r.message}</span>
                </div>
              )) : fp ? <div className="empty" style={{ padding: 24 }}><Icon n="check" s={20} />No issues</div> : <div className="muted"><Spin s={10} /></div>}
            </div>
            <div className="dim" style={{ marginTop: 8, fontSize: 11.5 }}>30 rules (C001–C030) checked against the installed engine. A red rule blocks launch. Click a rule to open its section.</div>
          </div>
          <div className="card"><h3>Source</h3><div className="note"><Icon n="db" s={13} /><span>Built from real-device record <b>{fp?.device_id ?? '…'}</b>. Chrome version is not stored: it is taken from the installed engine at every launch. Signed with Ed25519 before launch.</span></div></div>
        </div>
      </div>
    </Main>
  );
}
