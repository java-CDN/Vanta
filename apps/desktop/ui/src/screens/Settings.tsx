import { useEffect, useState, type ReactNode } from 'react';
import { useApp } from '../state/store';
import { Main } from '../components/Shell';
import { Icon, Spin, Tog } from '../components/ui';
import type { IconName } from '../lib/icons';
import { AUTOLOCK_OPTIONS } from '../lib/format';
import { errorText } from '../api/backend';
import { StrengthBar } from './Lock';
import { DEFAULT_IP_ECHO_URL, echoUrlProblem } from '../lib/echo';

type Sec = 'general' | 'security' | 'engine' | 'data' | 'appearance' | 'privacy' | 'about';
const SECS: [Sec, string, IconName][] = [['general', 'General', 'gear'], ['security', 'Security & vault', 'lock'], ['engine', 'Engine', 'cpu'], ['data', 'Data', 'hdd'], ['appearance', 'Appearance', 'sun'], ['privacy', 'Privacy', 'eye'], ['about', 'About', 'info']];

function ChangePassword() {
  const a = useApp();
  const [o, setO] = useState(''); const [n, setN] = useState(''); const [n2, setN2] = useState('');
  const [err, setErr] = useState(''); const [busy, setBusy] = useState(false);
  const save = async () => {
    setErr('');
    if (!o) return setErr('Enter your current password.');
    if (n.length < 12) return setErr('New password needs at least 12 characters.');
    if (n !== n2) return setErr('The new passwords do not match.');
    setBusy(true);
    try { await a.b.changePassword(o, n); a.closeModal(); a.toast('Master password changed', 'ok', 'key'); }
    catch (e) { setErr((e as { kind?: string }).kind === 'crypto' ? 'Current password is not correct.' : errorText(e)); setBusy(false); }
  };
  return <>
    <div className="mb"><div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="field"><label htmlFor="cpOld">Current password</label><input className="inp" type="password" id="cpOld" autoComplete="current-password" value={o} onChange={e => setO(e.target.value)} /></div>
      <div className="field"><label htmlFor="cpNew">New password</label><input className="inp" type="password" id="cpNew" autoComplete="new-password" value={n} onChange={e => setN(e.target.value)} /><StrengthBar v={n} /></div>
      <div className="field"><label htmlFor="cpNew2">Repeat new password</label><input className="inp" type="password" id="cpNew2" autoComplete="new-password" value={n2} onChange={e => setN2(e.target.value)} /></div>
      <div className="err" id="cpErr">{err}</div>
      <div className="note"><Icon n="info" s={13} /><span>Only the vault key is re-wrapped; profiles are not re-encrypted, so this takes about a second.</span></div>
    </div></div>
    <div className="mf"><button className="btn" onClick={a.closeModal}>Cancel</button><button className="btn p" data-a="cpSave" disabled={busy} onClick={save}>{busy ? <><Spin />Re-wrapping key…</> : 'Change password'}</button></div>
  </>;
}

export function SettingsScreen() {
  const a = useApp();
  const sec: Sec = (SECS.some(s => s[0] === a.routeArg) ? a.routeArg : 'general') as Sec;
  const st = a.settings;
  const [enginePath, setEnginePath] = useState(st.engine_path ?? '');
  const [echoUrl, setEchoUrl] = useState(st.ip_echo_url ?? '');
  const echoErr = echoUrlProblem(echoUrl);
  const [logTotal, setLogTotal] = useState<number | null>(null);
  useEffect(() => { a.b.activityLog({ limit: 1 }).then(r => setLogTotal(r.total)).catch(() => {}); }, [a.b]);
  const set = async (patch: Partial<typeof st>, msg?: ReactNode) => {
    try { await a.saveSettings({ ...st, ...patch }); if (msg) a.toast(msg, 'ok'); } catch (e) { a.fail(e); }
  };
  const tg = (on: boolean, label: string, onChange: () => void, desc?: string) => (
    <div className="chk"><div style={{ flex: 1 }}><div>{label}</div>{desc && <div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>{desc}</div>}</div><Tog on={on} label={label} onChange={onChange} /></div>
  );
  let body: ReactNode = null;
  if (sec === 'general') body = <div className="card"><h3><Icon n="gear" s={15} />General</h3>
    <div className="chk"><div style={{ flex: 1 }}>Ask before launching more than</div><select className="inp" style={{ width: 120 }} id="setMax" value={st.max_launch} onChange={e => set({ max_launch: Number(e.target.value) }, 'Saved')}>{[4, 8, 12, 20, 50].map(n => <option key={n} value={n}>{n} profiles</option>)}</select></div>
    {tg(st.confirm_delete, 'Confirm before deleting profiles', () => set({ confirm_delete: !st.confirm_delete }))}
    <div className="chk"><div style={{ flex: 1 }}>Interface language</div><select className="inp" style={{ width: 160 }} id="setLang" value="English" onChange={() => {}}><option>English</option></select></div>
  </div>;
  if (sec === 'security') body = <>
    <div className="card"><h3><Icon n="lock" s={15} />Vault</h3>
      <div className="kv" style={{ gridTemplateColumns: '170px 1fr' }}>
        <dt>Master password</dt><dd>set · <span className="lnk" data-a="changePw" tabIndex={0} onClick={() => a.openModal({ title: 'Change master password', width: 460, raw: true, body: <ChangePassword /> })}>change</span></dd>
        <dt>Key derivation</dt><dd>Argon2id · 64 MiB · 3 passes (~0.7 s)</dd>
        <dt>Encryption</dt><dd>XChaCha20-Poly1305 · one random key per profile</dd>
        <dt>Recovery key</dt><dd className="muted">Shown once when the vault was created. It unlocks the vault from the lock screen if the password is lost.</dd>
      </div></div>
    <div className="card"><h3><Icon n="clock" s={15} />Auto-lock</h3>
      <div className="chk"><div style={{ flex: 1 }}><div>Lock after idle</div><div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>Shown in the sidebar footer. Keys are wiped from memory when locked; running profiles keep running.</div></div>
        <select className="inp" style={{ width: 130 }} id="setAutolock" value={st.autolock_minutes} onChange={e => { const m = Number(e.target.value); set({ autolock_minutes: m }, m ? `Auto-lock set to ${AUTOLOCK_OPTIONS.find(o => o[0] === m)?.[1]}` : 'Auto-lock turned off'); }}>
          {AUTOLOCK_OPTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></div>
      <div className="chk"><div style={{ flex: 1 }}><div>Lock when the PC sleeps, the lid closes or Windows locks (Win+L)</div><div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>Not in this build yet: lock with Ctrl+L before you step away.</div></div><Tog on={false} locked label="Lock on sleep or Windows lock" /></div>
      <div className="chk"><div style={{ flex: 1 }}><div>Windows Hello unlock</div><div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>Not in this build yet; the master password is always required.</div></div><Tog on={false} locked label="Windows Hello" /></div>
      <div className="chk"><div style={{ flex: 1 }}>Lock now</div><button className="btn s" onClick={() => a.lockNow()}><Icon n="lock" s={13} />Lock <kbd style={{ marginLeft: 4 }}>Ctrl L</kbd></button></div></div>
  </>;
  if (sec === 'engine') body = <div className="card"><h3><Icon n="cpu" s={15} />Engine <span className="r lock-ic"><Icon n="lock" s={11} />version read-only</span></h3>
    <div className="kv" style={{ gridTemplateColumns: '170px 1fr' }}>
      <dt>Name</dt><dd>Vanta Chromium</dd>
      <dt>Version</dt><dd className="mono">{a.info.engine_version}</dd>
      <dt>Path in use</dt><dd className="mono">{a.info.engine_path}</dd>
      <dt>Status</dt><dd className={a.info.engine_found ? 'ok' : 'warn'}>{a.info.engine_found ? 'found' : 'not found at this path — profiles cannot launch until the engine is installed'}</dd>
      <dt>Fingerprint version</dt><dd>Always taken from this engine (rule C030). Profiles never store a Chrome version.</dd>
      <dt>Updates</dt><dd>Arrive with a new Vanta installer. No background update checks.</dd>
    </div>
    <div className="field" style={{ marginTop: 12 }}><label htmlFor="setEngine">Engine executable (leave empty for the default install path)</label>
      <div className="row" style={{ gap: 8 }}><input className="inp mono" id="setEngine" style={{ flex: 1 }} value={enginePath} placeholder="%LOCALAPPDATA%\Programs\Vanta\engine\vanta-chromium.exe" onChange={e => setEnginePath(e.target.value)} spellCheck={false} />
        <button className="btn" disabled={(st.engine_path ?? '') === enginePath.trim()} onClick={() => set({ engine_path: enginePath.trim() || null }, 'Engine path saved · restart Vanta to use it')}>Save</button></div>
      <span className="dim" style={{ fontSize: 11 }}>The version is read from the VERSION file next to the executable. Takes effect after a restart.</span></div>
  </div>;
  if (sec === 'data') body = <div className="card"><h3><Icon n="hdd" s={15} />Data</h3>
    <div className="kv" style={{ gridTemplateColumns: '170px 1fr' }}>
      <dt>Data folder</dt><dd className="mono">{a.info.data_dir}</dd>
      <dt>Profiles</dt><dd>{a.profiles.length.toLocaleString()} · encrypted, one key each</dd>
      <dt>Proxies</dt><dd>{a.proxies.length} · passwords in vault</dd>
      <dt>Activity log</dt><dd>{logTotal ?? '…'} entries · kept 90 days</dd>
      <dt>Backup</dt><dd className="muted">Copy the data folder with any file backup. It cannot be opened without the password or recovery key.</dd>
    </div></div>;
  if (sec === 'appearance') body = <div className="card"><h3><Icon n="sun" s={15} />Appearance</h3>
    <div className="chk"><div style={{ flex: 1 }}>Theme</div><span className="seg">{([['dark', 'moon', 'Dark'], ['light', 'sun', 'Light']] as const).map(([k, i, l]) => <button key={k} className={st.theme === k ? 'on' : ''} data-a="setTheme" data-id={k} onClick={() => set({ theme: k })}><Icon n={i} s={13} style={{ verticalAlign: -2, marginRight: 5 }} />{l}</button>)}</span></div>
    <div className="grid2" style={{ marginTop: 12 }}>{(['dark', 'light'] as const).map(k => (
      <div key={k} role="button" tabIndex={0} onClick={() => set({ theme: k })} style={{ cursor: 'pointer', borderRadius: 10, border: `2px solid ${st.theme === k ? 'var(--accent)' : 'var(--line)'}`, overflow: 'hidden' }}>
        <div style={{ height: 90, display: 'flex', background: k === 'dark' ? '#12141b' : '#f4f5f8' }}><div style={{ width: '30%', background: k === 'dark' ? '#171922' : '#eceef3' }} />
          <div style={{ flex: 1, padding: 10, display: 'flex', flexDirection: 'column', gap: 6 }}><div style={{ height: 8, width: '60%', borderRadius: 4, background: k === 'dark' ? '#3a3d4b' : '#cfd2dc' }} /><div style={{ height: 30, borderRadius: 6, background: k === 'dark' ? '#20222c' : '#fff', border: `1px solid ${k === 'dark' ? '#2d303c' : '#e1e3ea'}` }} /><div style={{ height: 8, width: '30%', borderRadius: 4, background: '#6366f1' }} /></div></div>
        <div style={{ padding: '6px 10px', fontSize: 12 }}>{k === 'dark' ? 'Dark (default)' : 'Light'}</div></div>))}</div></div>;
  if (sec === 'privacy') body = <><div className="card"><h3><Icon n="eye" s={15} />Privacy</h3>
    <div className="chk">Telemetry<span className="r pill ok">none, ever</span></div>
    <div className="chk">Usage analytics<span className="r pill ok">none</span></div>
    <div className="chk">Cloud sync / accounts<span className="r pill ok">not built</span></div>
    <div className="chk">Update checks<span className="r pill ok">none · installer only</span></div>
    <div className="chk">Crash reports<span className="r pill">none</span></div>
    <div className="chk">Activity log<span className="r pill">encrypted · this PC only · 90 days</span></div>
    <div className="note" style={{ marginTop: 10 }}><Icon n="shield" s={13} /><span>Vanta sends no data about you anywhere. Profiles you launch go online only through their proxy. Vanta itself only checks your proxies, resolves names over DNS-over-HTTPS, and asks the IP echo below during a health check.</span></div></div>
    <div className="card"><h3><Icon n="globe" s={15} />Health check IP echo</h3>
      <div className="dim" style={{ fontSize: 12, lineHeight: 1.5 }}>A health run asks a plain-text IP echo service which address a request comes from: once through the profile's proxy (the exit IP, checks H01, H07, H17) and once directly (your own public IP). Your own IP is only compared with what the proxy and the page show; it is never stored, logged or sent anywhere else. The service sees the two requests, as any website would.</div>
      <div className="field" style={{ marginTop: 12 }}><label htmlFor="setEcho">IP echo URL (https, answers with the IP only; empty = {DEFAULT_IP_ECHO_URL})</label>
        <div className="row" style={{ gap: 8 }}><input className="inp mono" id="setEcho" style={{ flex: 1 }} value={echoUrl} placeholder={DEFAULT_IP_ECHO_URL} onChange={e => setEchoUrl(e.target.value)} spellCheck={false} />
          <button className="btn" data-a="saveEcho" disabled={!!echoErr || (st.ip_echo_url ?? '') === echoUrl.trim()} onClick={() => set({ ip_echo_url: echoUrl.trim() || null }, 'IP echo URL saved')}>Save</button></div>
        <span className={echoErr ? 'err' : 'dim'} id="echoErr" style={{ fontSize: 11 }}>{echoErr ?? 'Takes effect with the next health run.'}</span></div></div>
  </>;
  if (sec === 'about') body = <div className="card"><h3><Icon n="info" s={15} />About Vanta</h3>
    <div style={{ display: 'flex', gap: 14, alignItems: 'center', marginBottom: 12 }}><div className="brand" style={{ padding: 0 }}><div className="lg" style={{ width: 44, height: 44, borderRadius: 12 }}><Icon n="shield" s={22} /></div></div><div><b style={{ fontSize: 16 }}>Vanta</b><div className="muted">Private multi-profile browser for Windows 10 and 11</div></div></div>
    <div className="kv" style={{ gridTemplateColumns: '170px 1fr' }}>
      <dt>App</dt><dd>Vanta {a.info.app_version}{a.info.mock ? ' · browser preview (demo data)' : ''}</dd><dt>Shell</dt><dd>Tauri desktop app (Rust core)</dd><dt>Engine</dt><dd>Vanta Chromium {a.info.engine_version}</dd>
      <dt>Features</dt><dd>Profile Manager · Fingerprint Studio · Health Check (56 checks) · Proxy Hub · Network Guard · Vault Lock · Geo Auto-Match · Activity Log</dd><dt>Supported OS</dt><dd>Windows 10 and Windows 11 (64-bit)</dd></div></div>;
  return (
    <Main title="Settings" sub="Vanta stays light: a small native manager; only open profiles use resources.">
      <div className="row" style={{ alignItems: 'flex-start' }}>
        <div className="card sub-nav" style={{ width: 210, padding: 8, flex: 'none' }}>{SECS.map(([k, l, i]) => <a key={k} className={sec === k ? 'on' : ''} data-a="setSec" data-id={k} tabIndex={0} onClick={() => a.go('settings', k)}><Icon n={i} s={14} />{l}</a>)}</div>
        <div className="col" style={{ flex: 1, maxWidth: 820 }}>{body}</div>
      </div>
    </Main>
  );
}
