import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useApp, type AppCtx } from '../state/store';
import { Main } from '../components/Shell';
import { CC, Empty, Icon, OsBadge, Seg, Spin } from '../components/ui';
import type * as T from '../api/types';
import { offlineReason, proxyName, proxyStatus, relDay, schemeLabel } from '../lib/format';
import { parseList } from '../lib/proxyparse';
import { emptyPreset, fitTo, PRESETS_NOTE, PROVIDERS, spec } from '../lib/presets';
import { errorText } from '../api/backend';
import { assignWithWarning, ProxyStatus } from './Profiles';

type StepKind = 'ok' | 'bad' | 'warn' | 'pend' | 'run';
type Step = [string, StepKind, ReactNode];

/** Steps 4-7 of the proxy check from the stored extended check. */
function checkSteps(x: T.ProxyView, running: boolean, speeding: boolean): Step[] {
  const c = x.checks;
  const pend = (label: string, why = ''): Step => [label, running ? 'run' : 'pend', why];
  const notOk = (label: string, k: T.Check<unknown>): Step => [label, k.status === 'failed' ? 'bad' : 'pend', k.status === 'ok' ? '' : k.reason];
  if (!c) return [pend('Exit IP · ASN · country', 'not checked yet'), pend('UDP (SOCKS5)'), pend('Blacklists'), [ 'Speed', speeding ? 'run' : 'pend', 'not measured' ]];
  const out: Step[] = [];
  if (running) out.push(pend('Exit IP · ASN · country'));
  else if (c.exit.status === 'ok') {
    const i = c.exit.result; const want = x.preset?.params.country?.toUpperCase();
    const mismatch = !!want && !!i.country && i.country !== want;
    out.push(['Exit IP · ASN · country', mismatch ? 'warn' : 'ok', <span id="pxExit"><CC c={i.country} /> {i.asn != null ? `AS${i.asn}` : 'ASN ?'}{i.org ? ` ${i.org}` : ''}{i.ip ? <span className="mono"> · {i.ip}</span> : ''}{mismatch ? <span className="warn"> · preset asks {want}</span> : ''}</span>]);
  } else out.push(notOk('Exit IP · ASN · country', c.exit));
  if (running) out.push(pend('UDP (SOCKS5)'));
  else if (c.udp.status === 'ok') {
    const r = c.udp.result;
    out.push(['UDP (SOCKS5)', r.support === 'supported' ? 'ok' : 'pend', <span id="pxUdp">{r.support === 'supported' ? 'UDP ASSOCIATE supported · QUIC stays off' : r.support === 'unsupported' ? `not supported (reply ${r.reply}) · QUIC stays off` : 'n/a for HTTP proxies'}</span>]);
  } else out.push(notOk('UDP (SOCKS5)', c.udp));
  if (running) out.push(pend('Blacklists'));
  else if (c.blacklist.status === 'ok') {
    const l = c.blacklist.result; const listed = l.filter(z => z.state === 'listed'); const unknown = l.filter(z => z.state === 'unknown');
    out.push(['Blacklists', listed.length ? 'bad' : unknown.length === l.length ? 'pend' : unknown.length ? 'warn' : 'ok', <span id="pxBl" title={l.map(z => `${z.name}: ${z.state === 'listed' ? `listed (${z.codes.join(', ')})` : z.state === 'unknown' ? `unknown: ${z.reason}` : 'not listed'}`).join('\n')}>{listed.length ? `listed on ${listed.map(z => z.name).join(', ')}` : `not listed on ${l.length - unknown.length} of ${l.length}`}{unknown.length ? ` · ${unknown.length} unknown` : ''}</span>]);
  } else out.push(notOk('Blacklists', c.blacklist));
  const sp = c.speed;
  if (speeding) out.push(['Speed', 'run', '']);
  else if (!sp) out.push(['Speed', 'pend', 'not measured']);
  else if (sp.result.status === 'ok') { const r = sp.result.result; out.push(['Speed', r.mbps < 2 ? 'warn' : 'ok', <span id="pxSpeed">{r.mbps.toFixed(1)} Mbps · {(r.bytes / 1e6).toFixed(1)} MB in {(r.millis / 1000).toFixed(1)} s{r.complete ? '' : ' (cut at the time limit)'}</span>]); }
  else out.push(notOk('Speed', sp.result));
  return out;
}

function ProxyTabs({ active }: { active: 'proxies' | 'geo' }) {
  const a = useApp();
  return <div className="tabs" role="tablist" style={{ flex: 'none' }}>
    <button role="tab" aria-selected={active === 'proxies'} className={active === 'proxies' ? 'on' : ''} data-id="proxies" onClick={() => a.go('proxies')}>Proxy list <span className="dim">{a.proxies.length}</span></button>
    <button role="tab" aria-selected={active === 'geo'} className={active === 'geo' ? 'on' : ''} data-id="geo" onClick={() => a.go('geo')}>Geo Auto-Match</button>
  </div>;
}

const latency = (x: T.ProxyView) => x.state.state !== 'online' ? <span className="dim">—</span> : <span className={x.state.latency_ms > 300 ? 'warn' : x.state.latency_ms > 120 ? '' : 'ok'}>{x.state.latency_ms} ms</span>;

async function testOne(a: AppCtx, id: string, quiet = false) {
  const v = await a.b.testProxy(id);
  await a.refreshProxies();
  if (!quiet) a.toast(v.state.state === 'offline' ? <><b>{proxyName(v)}</b> is offline: {offlineReason(v.state.reason)}</> : <><b>{proxyName(v)}</b> online · {v.state.state === 'online' ? v.state.latency_ms : 0} ms</>, v.state.state === 'offline' ? 'bad' : proxyStatus(v.state) === 'slow' ? 'warn' : 'ok', 'zap');
  return v;
}


/** Add / edit form for one proxy: plain login or a provider username preset. The password
 *  is handed to the backend once and goes into the vault; it is never shown again. */
function ProxyFormBody({ a, initial, onSaved }: { a: AppCtx; initial?: T.ProxyView; onSaved: (v: T.ProxyView) => void }) {
  const [mode, setMode] = useState<'preset' | 'plain'>(initial ? (initial.preset ? 'preset' : 'plain') : 'preset');
  const [scheme, setScheme] = useState<T.ProxyScheme>(initial?.scheme ?? 'socks5');
  const [host, setHost] = useState(initial?.host ?? '');
  const [port, setPort] = useState(initial ? String(initial.port) : '');
  const [label, setLabel] = useState(initial?.label ?? '');
  const [username, setUsername] = useState(initial && !initial.preset ? initial.username ?? '' : '');
  const [password, setPassword] = useState('');
  const [removePw, setRemovePw] = useState(false);
  const [preset, setPreset] = useState<T.ProviderPreset>(initial?.preset ?? emptyPreset());
  const [preview, setPreview] = useState<{ username?: string; err?: string }>({});
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const sp = spec(preset.provider);
  const prm = preset.params;
  const setP = (patch: Partial<T.SessionParams>) => setPreset(p => ({ ...p, params: { ...p.params, ...patch } }));
  const num = (v: string) => (v.trim() === '' ? null : Number(v));
  useEffect(() => {
    if (mode !== 'preset') return;
    if (!preset.base_user.trim()) { setPreview({ err: `Enter the base username (${sp.baseHint})` }); return; }
    let live = true;
    const t = setTimeout(() => {
      a.b.previewPreset(preset).then(r => {
        if (!live) return;
        setPreview({ username: r.username });
        // Keep the session key the backend chose for a new preset.
        if (!preset.session_key) setPreset(p => (p.session_key ? p : { ...p, session_key: r.preset.session_key }));
      }).catch(e => { if (live) setPreview({ err: errorText(e) }); });
    }, 150);
    return () => { live = false; clearTimeout(t); };
  }, [mode, preset, a.b, sp.baseHint]);
  const save = async () => {
    setErr('');
    const p = Number(port);
    if (!host.trim()) return setErr('Enter the proxy host (the gateway address from your provider).');
    if (!Number.isInteger(p) || p < 1 || p > 65535) return setErr('Port must be a number from 1 to 65535.');
    if (mode === 'preset' && preview.err) return setErr(preview.err);
    const form: T.ProxyForm = { scheme, host: host.trim(), port: p, label: label.trim(), username: mode === 'plain' ? (username.trim() || null) : null, preset: mode === 'preset' ? preset : null };
    setBusy(true);
    try {
      const v = initial ? await a.b.editProxy(initial.id, form, removePw ? '' : (password || null)) : await a.b.addProxy(form, password || null);
      setPassword('');
      a.closeModal();
      onSaved(v);
    } catch (e) { setErr(errorText(e)); setBusy(false); }
  };
  const lbl = { fontSize: 11 } as const;
  return <>
    <div className="mb"><div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <Seg value={mode} onChange={setMode} name="Username" options={[['preset', 'Provider preset'], ['plain', 'Plain login']]} />
      <div className="row" style={{ gap: 10 }}>
        <div className="field" style={{ width: 110 }}><label htmlFor="pfScheme">Type</label><select className="inp" id="pfScheme" value={scheme} onChange={e => setScheme(e.target.value as T.ProxyScheme)}><option value="socks5">SOCKS5</option><option value="http">HTTP</option><option value="https">HTTPS</option></select></div>
        <div className="field" style={{ flex: 1 }}><label htmlFor="pfHost">Host (gateway)</label><input className="inp mono" id="pfHost" value={host} spellCheck={false} placeholder="gate.provider.example" onChange={e => setHost(e.target.value)} /></div>
        <div className="field" style={{ width: 90 }}><label htmlFor="pfPort">Port</label><input className="inp mono" id="pfPort" inputMode="numeric" value={port} placeholder="1080" onChange={e => setPort(e.target.value.replace(/\D/g, '').slice(0, 5))} /></div>
      </div>
      {mode === 'preset' ? <>
        <div className="row" style={{ gap: 10 }}>
          <div className="field" style={{ width: 150 }}><label htmlFor="pfProv">Provider</label><select className="inp" id="pfProv" value={preset.provider} onChange={e => setPreset(p => fitTo(p, e.target.value as T.Provider))}>{PROVIDERS.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></div>
          <div className="field" style={{ flex: 1 }}><label htmlFor="pfBase">Base username (as in the provider dashboard)</label><input className="inp mono" id="pfBase" value={preset.base_user} spellCheck={false} placeholder={sp.baseHint} onChange={e => setPreset(p => ({ ...p, base_user: e.target.value }))} /></div>
        </div>
        <div className="row" style={{ gap: 10 }}>
          <div className="field" style={{ width: 80 }}><label htmlFor="pfCc">Country</label><input className="inp mono" id="pfCc" maxLength={2} value={prm.country ?? ''} placeholder="US" onChange={e => setP({ country: e.target.value.replace(/[^a-z]/gi, '').toUpperCase() || null })} /></div>
          <div className="field" style={{ flex: 1 }}><label htmlFor="pfCity">City {sp.city ? '' : `(not in the ${sp.name} grammar)`}</label><input className="inp" id="pfCity" disabled={!sp.city} value={prm.city ?? ''} placeholder={sp.city ? 'optional' : '—'} onChange={e => setP({ city: e.target.value || null })} /></div>
          {sp.pool
            ? <div className="field" style={{ width: 120 }}><label htmlFor="pfPool">Endpoints in plan</label><input className="inp mono" id="pfPool" inputMode="numeric" value={prm.pool_size ?? ''} onChange={e => setP({ pool_size: num(e.target.value.replace(/\D/g, '').slice(0, 6)) })} /></div>
            : <div className="field" style={{ width: 140 }}><label htmlFor="pfTtl">Session (minutes){sp.ttl ? '' : ' n/a'}</label><input className="inp mono" id="pfTtl" inputMode="numeric" disabled={!sp.ttl} value={prm.session_ttl_min ?? ''} placeholder={sp.ttl ? 'provider default' : '—'} onChange={e => setP({ session_ttl_min: num(e.target.value.replace(/\D/g, '').slice(0, 4)) })} /></div>}
        </div>
        <div className="field"><label>Final username (sticky session for this entry)</label>
          <div className="row" style={{ gap: 8, alignItems: 'center' }}>
            <div id="pfPreview" className={`inp mono ${preview.err ? 'bad' : ''}`} style={{ flex: 1, fontSize: 11.5, overflowWrap: 'anywhere', minHeight: 32, height: 'auto', padding: '6px 10px' }}>{preview.username ?? <span className="bad">{preview.err ?? '…'}</span>}</div>
            <button className="btn s" data-a="pfRotate" title="Move this entry to a new sticky session (new exit IP)" onClick={() => setP({ rotation: prm.rotation + 1 })}><Icon n="refresh" s={13} />New session</button>
          </div>
          <span className="dim" style={lbl}>Session {prm.rotation + 1} · the session id is derived from a random key kept with this entry, so it stays the same across launches until you ask for a new one.</span></div>
        <div className="note"><Icon n="info" s={13} /><span><span className="pill warn" style={{ marginRight: 6 }}>from public docs, not verified live</span>{PRESETS_NOTE}</span></div>
      </> : <div className="field"><label htmlFor="pfUser">Username (kept as written)</label><input className="inp mono" id="pfUser" value={username} spellCheck={false} autoComplete="off" placeholder="optional" onChange={e => setUsername(e.target.value)} /></div>}
      <div className="row" style={{ gap: 10 }}>
        <div className="field" style={{ flex: 1 }}><label htmlFor="pfPw">Password{initial?.has_password ? ' (leave empty to keep the one in the vault)' : ''}</label><input className="inp" type="password" id="pfPw" autoComplete="new-password" disabled={removePw} value={password} placeholder={initial?.has_password ? '••••••• in vault' : 'optional'} onChange={e => setPassword(e.target.value)} /></div>
        <div className="field" style={{ width: 160 }}><label htmlFor="pfLabel">Label</label><input className="inp" id="pfLabel" maxLength={64} value={label} placeholder="optional" onChange={e => setLabel(e.target.value)} /></div>
      </div>
      {initial?.has_password && <label className="row" style={{ gap: 8, fontSize: 12, alignItems: 'center' }}><input type="checkbox" id="pfRmPw" checked={removePw} onChange={e => setRemovePw(e.target.checked)} />Remove the saved password</label>}
      <div className="err" id="pfErr">{err}</div>
      <div className="note"><Icon n="lock" s={13} /><span>The password goes straight into the vault and is never shown again or written to the log. Changing the host, login or password resets the proxy check and the health runs made through it.</span></div>
    </div></div>
    <div className="mf"><button className="btn" onClick={a.closeModal}>Cancel</button><button className="btn p" id="pfOk" disabled={busy} onClick={save}>{busy ? <Spin /> : null}{initial ? 'Save proxy' : 'Add proxy'}</button></div>
  </>;
}

function openEdit(a: AppCtx, x: T.ProxyView) {
  a.openModal({ title: `Edit ${proxyName(x)}`, width: 680, raw: true, body: <ProxyFormBody a={a} initial={x} onSaved={async v => { await Promise.all([a.refreshProxies(), a.refreshProfiles()]); a.toast(<><b>{proxyName(v)}</b> saved{v.state.state === 'unknown' ? ' · test it before the next launch' : ''}</>, 'ok', 'check'); }} /> });
}

function openAdd(a: AppCtx, onAdded: (ids: string[]) => void) {
  function Body() {
    const [tab, setTab] = useState<'list' | 'one'>('list');
    const tabs = <div className="tabs" role="tablist" style={{ padding: '0 18px' }}>
      <button role="tab" aria-selected={tab === 'list'} className={tab === 'list' ? 'on' : ''} data-id="apList" onClick={() => setTab('list')}>Paste list</button>
      <button role="tab" aria-selected={tab === 'one'} className={tab === 'one' ? 'on' : ''} data-id="apOne" onClick={() => setTab('one')}>One proxy · provider preset</button>
    </div>;
    if (tab === 'one') return <>{tabs}<ProxyFormBody a={a} onSaved={async v => { await a.refreshProxies(); a.toast(<>Added <b>{proxyName(v)}</b> · testing now</>, 'ok', 'plus'); onAdded([v.id]); }} /></>;
    return <>{tabs}<ListBody /></>;
  }
  function ListBody() {
    const [text, setText] = useState('');
    const [scheme, setScheme] = useState<T.ProxyScheme>('socks5');
    const [busy, setBusy] = useState(false);
    const rows = useMemo(() => parseList(text, scheme), [text, scheme]);
    const ok = rows.filter(r => !r.err); const bad = rows.filter(r => r.err);
    const dup = ok.filter(r => a.proxies.some(x => x.host === r.host && x.port === r.port));
    const submit = async () => {
      setBusy(true);
      try {
        const r = await a.b.importProxies(text, scheme);
        a.closeModal();
        await a.refreshProxies();
        a.toast(<>Added {r.added.length} prox{r.added.length === 1 ? 'y' : 'ies'}{r.errors.length ? ` · ${r.errors.length} line${r.errors.length > 1 ? 's' : ''} skipped (${r.errors.slice(0, 3).map(e => `line ${e.line}: ${e.message}`).join('; ')})` : ''} · testing now</>, r.errors.length ? 'warn' : 'ok', 'import');
        onAdded(r.added.map(x => x.id));
      } catch (e) { a.fail(e); setBusy(false); }
    };
    return <>
      <div className="mb"><div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="row" style={{ gap: 12 }}><div className="field" style={{ flex: 1 }}><label htmlFor="apType">Type for lines without a scheme</label>
          <select className="inp" id="apType" value={scheme} onChange={e => setScheme(e.target.value as T.ProxyScheme)}><option value="socks5">SOCKS5</option><option value="http">HTTP</option><option value="https">HTTPS</option></select></div></div>
        <div className="field"><label htmlFor="apText">Paste proxies (one per line)</label>
          <textarea className="inp mono" id="apText" rows={6} spellCheck={false} value={text} onChange={e => setText(e.target.value)} placeholder={'203.0.113.77:12000:user:pass\nsocks5://user:pass@198.51.100.50:1080\nhttp://192.0.2.90:8080'} /></div>
        <div id="apPrev" className="muted" style={{ fontSize: 12 }}>
          {rows.length ? <>
            <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}><span className="pill ok">{ok.length} valid</span>{bad.length > 0 && <span className="pill bad">{bad.length} invalid</span>}{dup.length > 0 && <span className="pill warn">{dup.length} already in hub</span>}</div>
            <div style={{ maxHeight: 150, overflow: 'auto', border: '1px solid var(--line)', borderRadius: 8 }}><table><thead><tr><th>Line</th><th>Type</th><th>Host</th><th>Port</th><th>Auth</th><th>Result</th></tr></thead><tbody>
              {rows.map(r => <tr key={r.line}><td className="dim">{r.line}</td>{r.err ? <><td colSpan={4} className="mono bad">—</td><td><span className="pill bad">{r.err}</span></td></> : <><td>{schemeLabel(r.scheme!)}</td><td className="mono">{r.host}</td><td className="mono">{r.port}</td><td>{r.user ? <>{r.user.slice(0, 14)}{r.user.length > 14 ? '…' : ''} · ••••</> : <span className="dim">none</span>}</td><td><span className="pill ok">ok</span></td></>}</tr>)}
            </tbody></table></div>
          </> : 'Supported: host:port · host:port:user:pass · user:pass@host:port · socks5://, http:// or https:// URLs.'}
        </div>
        <div className="note"><Icon n="lock" s={13} /><span>Passwords go straight into the vault and are never shown again or written to the log.</span></div>
      </div></div>
      <div className="mf">
        <button className="btn ghost" data-a="apSample" style={{ marginRight: 'auto' }} onClick={() => setText('203.0.113.77:12000:user-geo-es:Xk29aa\nsocks5://brd-user:pw1@198.51.100.50:1080\nhttp://192.0.2.90:8080\n192.0.2.300:8080\nproxy.example.net:99999')}><Icon n="wand" s={14} />Fill sample</button>
        <button className="btn" onClick={a.closeModal}>Cancel</button>
        <button className="btn p" id="apOk" disabled={!ok.length || busy} onClick={submit}>{busy ? <Spin /> : null}{ok.length ? `Add ${ok.length} prox${ok.length === 1 ? 'y' : 'ies'}` : 'Add proxies'}</button>
      </div>
    </>;
  }
  a.openModal({ title: 'Add proxies', width: 700, raw: true, body: <Body /> });
}

export function ProxiesScreen() {
  const a = useApp();
  const [q, setQ] = useState('');
  const [fType, setFType] = useState('');
  const [fStatus, setFStatus] = useState('');
  const [selId, setSelId] = useState<string | null>(null);
  const [testing, setTesting] = useState<Record<string, boolean>>({});
  const [inspecting, setInspecting] = useState<Record<string, 'full' | 'speed'>>({});
  const [all, setAll] = useState(false);
  const [assignTo, setAssignTo] = useState('');
  const [flash, setFlash] = useState<string | null>(null);

  const list = a.proxies.filter(x => {
    const st = proxyStatus(x.state);
    return (!q || [proxyName(x), x.host, x.username ?? '', x.scheme].join(' ').toLowerCase().includes(q.toLowerCase()))
      && (!fType || x.scheme === fType) && (!fStatus || (fStatus === 'free' ? !a.usedBy(x.id).length : st === fStatus));
  });
  const sel = a.proxies.find(x => x.id === selId) ?? list[0] ?? a.proxies[0];
  useEffect(() => { if (a.profiles.length && !a.profiles.some(p => p.id === assignTo)) setAssignTo(a.profiles[0].id); }, [a.profiles, assignTo]);
  const online = a.proxies.filter(x => x.state.state === 'online').length;

  const test = async (id: string, quiet = false) => {
    setTesting(t => ({ ...t, [id]: true }));
    try { await testOne(a, id, quiet); } catch (e) { if (!quiet) a.fail(e); } finally { setTesting(t => { const n = { ...t }; delete n[id]; return n; }); }
  };
  const inspect = async (id: string, speed: boolean) => {
    setInspecting(m => ({ ...m, [id]: speed ? 'speed' : 'full' }));
    try {
      const v = await a.b.inspectProxy(id, speed);
      await a.refreshProxies();
      const c = v.checks;
      if (v.state.state === 'offline') a.toast(<><b>{proxyName(v)}</b> is offline: {offlineReason(v.state.reason)}</>, 'bad', 'zap');
      else if (speed && c?.speed?.result.status === 'ok') a.toast(<><b>{proxyName(v)}</b> · {c.speed.result.result.mbps.toFixed(1)} Mbps</>, 'ok', 'zap');
      else if (speed) a.toast(<><b>{proxyName(v)}</b> speed test: {c?.speed && c.speed.result.status !== 'ok' ? c.speed.result.reason : 'no result'}</>, 'warn', 'zap');
      else {
        const listed = c?.blacklist.status === 'ok' ? c.blacklist.result.filter(z => z.state === 'listed').length : 0;
        a.toast(<><b>{proxyName(v)}</b> checked{c?.exit.status === 'ok' && c.exit.result.asn != null ? ` · AS${c.exit.result.asn}` : ''}{listed ? ` · on ${listed} blacklist${listed > 1 ? 's' : ''}` : ''}</>, listed ? 'warn' : 'ok', 'zap');
      }
    } catch (e) { a.fail(e); } finally { setInspecting(m => { const n = { ...m }; delete n[id]; return n; }); }
  };
  const testAll = async () => {
    setAll(true);
    const ids = a.proxies.map(x => x.id); let i = 0;
    await Promise.all(Array.from({ length: 6 }, async () => { while (i < ids.length) await test(ids[i++], true); }));
    const ls = await a.refreshProxies();
    const on = ls.filter(x => x.state.state === 'online').length; const off = ls.filter(x => x.state.state === 'offline').length;
    setAll(false);
    a.toast(`Tested ${ls.length} proxies · ${on} online · ${off} offline`, off ? 'warn' : 'ok', 'refresh');
  };
  const del = async (x: T.ProxyView) => {
    const u = a.usedBy(x.id);
    const ok = await a.confirm({ title: `Delete ${proxyName(x)}?`, danger: true, ok: 'Delete proxy', text: <>The proxy and its vault password are removed.{u.length > 0 && <div className="pill warn" style={{ marginTop: 10 }}>{u.length} profile{u.length > 1 ? 's' : ''} will have no proxy: {u.map(p => p.name).join(', ')}</div>}</> });
    if (!ok) return;
    try {
      for (const p of u) await a.b.assignProxy(p.id, null);
      await a.b.deleteProxy(x.id);
      await Promise.all([a.refreshProxies(), a.refreshProfiles()]);
      if (selId === x.id) setSelId(null);
      a.toast(<><b>{proxyName(x)}</b> deleted</>, 'ok', 'trash');
    } catch (e) { a.fail(e); }
  };
  const menu = (el: HTMLElement, x: T.ProxyView) => a.openMenu(el, [
    { label: 'Test', icon: 'zap', id: 'pxTest', onClick: () => test(x.id) },
    { label: 'Edit…', icon: 'edit', id: 'pxEdit', onClick: () => openEdit(a, x) },
    { label: 'Assign to profile…', icon: 'link', id: 'pxAssignMenu', onClick: () => { setSelId(x.id); setTimeout(() => document.getElementById('pxAssign')?.focus(), 30); } },
    { label: 'Copy endpoint', icon: 'copy', id: 'pxCopy', onClick: () => { navigator.clipboard?.writeText(`${x.host}:${x.port}`).catch(() => {}); a.toast(<>Copied {x.host}:{x.port} (password stays in the vault)</>, 'ok', 'copy'); } }, '-',
    { label: 'Delete', icon: 'trash', id: 'pxDel', danger: true, onClick: () => del(x) },
  ]);

  const t = sel ? testing[sel.id] : false;
  const st = sel ? proxyStatus(sel.state) : 'untested';
  const steps: Step[] = sel ? [
    ['TCP connect', t ? 'run' : st === 'untested' ? 'pend' : sel.state.state === 'offline' && (sel.state.reason === 'unreachable' || sel.state.reason === 'timeout') ? 'bad' : 'ok', sel.state.state === 'offline' && !t ? offlineReason(sel.state.reason) : ''],
    [sel.scheme === 'socks5' ? 'SOCKS5 handshake + login' : 'HTTP CONNECT handshake', t ? 'pend' : st === 'untested' ? 'pend' : sel.state.state === 'offline' ? (sel.state.reason === 'auth_failed' || sel.state.reason === 'protocol_error' ? 'bad' : 'pend') : 'ok', sel.state.state === 'offline' && (sel.state.reason === 'auth_failed' || sel.state.reason === 'protocol_error') ? offlineReason(sel.state.reason) : ''],
    ['Round trip', t ? 'pend' : sel.state.state === 'online' ? (st === 'slow' ? 'warn' : 'ok') : 'pend', sel.state.state === 'online' ? `${sel.state.latency_ms} ms` : ''],
  ] : [];
  const ins = sel ? inspecting[sel.id] : undefined;
  if (sel) steps.push(...checkSteps(sel, ins === 'full' || ins === 'speed', ins === 'speed'));
  const u = sel ? a.usedBy(sel.id) : [];
  return (
    <Main title="Proxy Hub" sub="HTTP and SOCKS5 proxies from any provider. Passwords stay in the vault; the engine only sees Vanta's local relay."
      actions={<><button className="btn" data-a="pxTestAll" disabled={all || !a.proxies.length} onClick={testAll}>{all ? <><Spin />Testing…</> : <><Icon n="refresh" s={14} />Test all</>}</button>
        <button className="btn p" data-a="pxAdd" onClick={() => openAdd(a, ids => { if (ids[0]) { setSelId(ids[0]); setFlash(ids[0]); setTimeout(() => setFlash(null), 1700); } ids.forEach(id => test(id, true)); })}><Icon n="plus" s={14} />Add proxy</button></>}
      contentStyle={{ overflow: 'hidden' }}>
      <ProxyTabs active="proxies" />
      <div className="row" style={{ flex: 1, minHeight: 0 }}>
        <div className="card" style={{ flex: 1, padding: 0, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', gap: 8, padding: '10px 12px', borderBottom: '1px solid var(--line)', alignItems: 'center', flexWrap: 'wrap' }}>
            <div className="inp" style={{ width: 240 }}><Icon n="search" s={14} /><input id="pxQ" value={q} onChange={e => setQ(e.target.value)} placeholder="Search proxies" aria-label="Search proxies" /></div>
            <select className={`pillsel ${fType ? 'act' : ''}`} aria-label="Type" value={fType} onChange={e => setFType(e.target.value)}><option value="">Type: any</option><option value="http">HTTP</option><option value="https">HTTPS</option><option value="socks5">SOCKS5</option></select>
            <select className={`pillsel ${fStatus ? 'act' : ''}`} aria-label="Status" value={fStatus} onChange={e => setFStatus(e.target.value)}><option value="">Status: any</option><option value="ok">Online</option><option value="slow">Slow</option><option value="offline">Offline</option><option value="untested">Not tested</option><option value="free">Free (unassigned)</option></select>
            <span className="muted" style={{ marginLeft: 'auto' }}>{a.proxies.length} proxies · {online} online</span>
          </div>
          <div className="tw">{list.length ? <table><thead><tr><th>Name</th><th>Endpoint</th><th>Latency</th><th>Status</th><th>Profile</th><th /></tr></thead><tbody>
            {list.map(x => {
              const used = a.usedBy(x.id);
              return <tr key={x.id} className={`click ${sel && x.id === sel.id ? 'sel' : ''} ${flash === x.id ? 'flash' : ''}`} onClick={() => setSelId(x.id)}>
                <td><b style={{ fontWeight: 600 }}>{proxyName(x)}</b><div className="dim" style={{ fontSize: 11 }}>{schemeLabel(x.scheme)}{x.username ? ' · login' : ''}</div></td>
                <td><span className="mono">{x.host}:{x.port}</span>{used[0]?.exit_ip && <div className="dim" style={{ fontSize: 11 }}>exit <CC c={used[0].country} /> {used[0].exit_ip}</div>}</td>
                <td>{testing[x.id] ? <span className="dim">…</span> : latency(x)}</td>
                <td><ProxyStatus x={x} testing={testing[x.id]} /></td>
                <td>{used.length ? <span title={used.map(p => p.name).join(', ')}>{used[0].name}{used.length > 1 && <> <span className="pill warn">+{used.length - 1}</span></>}</span> : <span className="dim">free</span>}</td>
                <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}><button className="ib" data-a="pxTest" title="Test" aria-label={`Test ${proxyName(x)}`} disabled={testing[x.id]} onClick={e => { e.stopPropagation(); test(x.id); }}><Icon n="zap" s={14} /></button>
                  <button className="ib" data-a="pxMenu" aria-label={`More for ${proxyName(x)}`} onClick={e => { e.stopPropagation(); menu(e.currentTarget, x); }}><Icon n="more" s={14} /></button></td>
              </tr>;
            })}</tbody></table>
            : <Empty icon="globe" title={a.proxies.length ? 'No proxies match' : 'No proxies yet'} text={a.proxies.length ? 'Change the filters.' : 'Paste a list from any provider to get started.'}><button className="btn p s" onClick={() => openAdd(a, ids => ids.forEach(id => test(id, true)))}><Icon n="plus" s={13} />Add proxy</button></Empty>}</div>
        </div>
        <div className="col pxside" style={{ width: 370, flex: 'none', overflow: 'auto' }}>
          {sel && <>
            <div className="card"><h3>{proxyName(sel)} <span className={`r ${sel.state.state === 'offline' ? 'bad' : 'ok'}`}>{t ? 'testing…' : sel.state.state === 'unknown' ? 'not tested' : 'checked ' + relDay(sel.state.checked_ms).toLowerCase()}</span></h3>
              <div className="kv" style={{ gridTemplateColumns: '96px 1fr' }}>
                <dt>Endpoint</dt><dd className="mono">{sel.host}:{sel.port}</dd>
                <dt>Type</dt><dd>{schemeLabel(sel.scheme)}</dd>
                <dt>Username</dt><dd className="mono" style={{ fontSize: 11, overflowWrap: 'anywhere' }}>{sel.username ?? <span className="dim">none</span>}</dd>
                {sel.preset && <><dt>Preset</dt><dd id="pxPreset">{spec(sel.preset.provider).name}{sel.preset.params.country ? ` · ${sel.preset.params.country}` : ''}{sel.preset.params.city ? ` · ${sel.preset.params.city}` : ''}{sel.preset.params.session_ttl_min ? ` · ${sel.preset.params.session_ttl_min} min` : ''} · session {sel.preset.params.rotation + 1} <span className="pill warn" title={PRESETS_NOTE}>not verified live</span></dd></>}
                <dt>Password</dt><dd>{sel.has_password ? <>••••••• <span className="dim">(vault)</span></> : <span className="dim">none</span>}</dd>
                <dt>Assigned</dt><dd>{u.length ? <>{u.map(p => <span key={p.id} className="pill acc" style={{ margin: '0 4px 2px 0' }}>{p.name}</span>)}{u.length > 1 && <div className="warn" style={{ fontSize: 11, marginTop: 3 }}>Shared by several profiles — they can be linked.</div>}</> : <span className="dim">free</span>}</dd>
              </div>
              <div className="row" style={{ gap: 8, marginTop: 12 }}>
                <select className="inp" id="pxAssign" style={{ flex: 1 }} aria-label="Assign to profile" value={assignTo} onChange={e => setAssignTo(e.target.value)}>{a.profiles.map(p => <option key={p.id} value={p.id}>{p.name}{p.proxy_id ? ` (now ${proxyName(a.proxies.find(x => x.id === p.proxy_id) ?? sel)})` : ' (no proxy)'}</option>)}</select>
                <button className="btn" data-a="pxAssign" disabled={!assignTo} onClick={async () => {
                  const p = a.profiles.find(x => x.id === assignTo); if (!p) return;
                  try { if (await assignWithWarning(a, p, sel.id)) { await a.refreshProfiles(); a.toast(<><b>{proxyName(sel)}</b> assigned to <b>{p.name}</b> · run a health check before the next launch</>, 'ok', 'link'); } } catch (e) { a.fail(e); }
                }}><Icon n="link" s={14} />Assign</button>
              </div>
              <div className="row" style={{ gap: 8, marginTop: 8 }}><button className="btn s" data-a="pxCheck" disabled={t || !!ins} onClick={() => inspect(sel.id, false)}><Icon n="zap" s={13} />Test</button><button className="btn s" data-a="pxEdit" onClick={() => openEdit(a, sel)}><Icon n="edit" s={13} />Edit</button><button className="btn s d" onClick={() => del(sel)}><Icon n="trash" s={13} />Delete</button></div>
            </div>
            <div className="card"><h3>Proxy check {(t || ins) && <span className="r acc"><Spin s={10} /></span>}{!t && !ins && sel.checks && <span className="r dim">full check {relDay(sel.checks.checked_ms).toLowerCase()}</span>}</h3>
              {steps.map(([s, k, v], i) => <div key={s} className="step" style={{ alignItems: 'flex-start' }}><span className={`ic ${k === 'run' ? 'pend' : k}`} style={{ width: 18, height: 18, flex: 'none' }}>{k === 'ok' ? '✓' : k === 'bad' ? '✕' : k === 'warn' ? '!' : k === 'run' ? <Spin s={9} style={{ borderWidth: 1.5, color: 'var(--accent2)' }} /> : ''}</span><span style={{ flex: 'none' }}>{i + 1}. {s}</span><span className="r dim" style={{ textAlign: 'right', minWidth: 0, overflowWrap: 'anywhere', fontSize: 11.5 }}>{v}</span></div>)}
              <div className="row" style={{ gap: 8, marginTop: 10 }}>
                <button className="btn s" data-a="pxFull" disabled={t || !!ins} onClick={() => inspect(sel.id, false)}>{ins === 'full' ? <Spin s={11} /> : <Icon n="shield" s={13} />}Full check</button>
                <button className="btn s" data-a="pxSpeed" disabled={t || !!ins} title="Downloads at most 2 MB through this proxy" onClick={() => inspect(sel.id, true)}>{ins === 'speed' ? <Spin s={11} /> : <Icon n="pulse" s={13} />}Speed test</button>
              </div>
              <div className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>Every step goes through this proxy, never directly. Blacklists are asked over DNS-over-HTTPS through the proxy; a list that refuses public resolvers (Spamhaus) shows as unknown rather than a guess. The speed test downloads at most 2 MB. Results stay with this proxy on this PC.</div>
            </div>
          </>}
          <div className="card"><h3><Icon n="import" s={15} />Import</h3><div className="note"><Icon n="zap" s={13} /><span>Paste <span className="mono">host:port:user:pass</span> or <span className="mono">socks5://user:pass@host:port</span>, one per line. Usernames in a pasted list are kept as written; use <b>One proxy · provider preset</b> to build a sticky-session username for Bright Data, SOAX, Geonode, DataImpulse, Webshare or Thordata.</span></div>
            <button className="btn s" style={{ marginTop: 10 }} onClick={() => openAdd(a, ids => ids.forEach(id => test(id, true)))}><Icon n="plus" s={13} />Paste list</button></div>
        </div>
      </div>
    </Main>
  );
}

type GeoRow = { p: T.ProfileMeta; fp?: T.FingerprintView; st: 'ok' | 'mismatch' | 'unknown' | 'noproxy' };

export function GeoScreen() {
  const a = useApp();
  const [fps, setFps] = useState<Record<string, T.FingerprintView>>({});
  const [f, setF] = useState<'all' | 'mismatch' | 'ok' | 'unknown'>('all');
  const LIMIT = 500;
  useEffect(() => {
    let live = true;
    const ids = a.profiles.slice(0, LIMIT).map(p => p.id).filter(id => !fps[id]);
    let i = 0;
    Promise.all(Array.from({ length: 6 }, async () => {
      while (i < ids.length && live) {
        const id = ids[i++];
        try { const v = await a.b.fingerprint(id); if (live) setFps(m => ({ ...m, [id]: v })); } catch { /* locked or gone */ }
      }
    }));
    return () => { live = false; };
  }, [a.profiles.length, a.b]); // eslint-disable-line react-hooks/exhaustive-deps
  const rows: GeoRow[] = a.profiles.slice(0, LIMIT).map(p => {
    const fp = fps[p.id];
    const c18 = fp?.rules.find(r => r.id === 'C018');
    const st: GeoRow['st'] = !p.proxy_id ? 'noproxy' : c18?.level === 'fail' ? 'mismatch' : fp?.timezone && c18?.level === 'pass' ? 'ok' : 'unknown';
    return { p, fp, st };
  });
  const n = (s: GeoRow['st']) => rows.filter(r => r.st === s).length;
  const list = rows.filter(r => f === 'all' || r.st === f);
  const pill = { ok: <span className="pill ok">matched</span>, mismatch: <span className="pill bad">mismatch</span>, unknown: <span className="pill info">not located yet</span>, noproxy: <span className="pill">no proxy</span> };
  return (
    <Main title="Geo Auto-Match" sub="Timezone, locale, languages and geolocation follow each profile's proxy exit IP. Lookups use the offline GeoIP database."
      actions={<><span className="muted" style={{ fontSize: 12 }}>On launch: ask if the country changes</span><button className="btn p" disabled title="Needs the bundled offline GeoIP database (not in this build)"><Icon n="wand" s={14} />Match all</button></>}
      contentStyle={{ overflow: 'hidden' }}>
      <ProxyTabs active="geo" />
      <div className="row" style={{ gap: 12, flex: 'none' }}>
        <div className="card stat"><div className="k">Matched</div><div className="v ok">{n('ok')}</div></div>
        <div className="card stat"><div className="k">Mismatch</div><div className={`v ${n('mismatch') ? 'bad' : ''}`}>{n('mismatch')} <small>· timezone ≠ exit IP country (C018)</small></div></div>
        <div className="card stat"><div className="k">Not located yet</div><div className="v">{n('unknown')}</div></div>
        <div className="card stat"><div className="k">No proxy</div><div className="v">{n('noproxy')}</div></div>
      </div>
      <div className="card" style={{ flex: 1, padding: 0, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', gap: 8, padding: '10px 12px', borderBottom: '1px solid var(--line)', alignItems: 'center' }}>
          <Seg value={f} onChange={setF} options={[['all', 'All'], ['mismatch', 'Mismatch'], ['ok', 'Matched'], ['unknown', 'Not located']]} name="Filter" />
          <span className="muted" style={{ marginLeft: 'auto', fontSize: 12 }}>{a.profiles.length > LIMIT ? `First ${LIMIT} profiles · ` : ''}Matching runs at launch once the GeoIP database ships</span>
        </div>
        <div className="tw">{list.length ? <table><thead><tr><th>Profile</th><th>Proxy exit</th><th>Timezone</th><th>Locale</th><th>Languages</th><th>Geolocation</th><th>Status</th><th /></tr></thead><tbody>
          {list.map(({ p, fp, st }) => {
            const px = a.proxyOf(p);
            return <tr key={p.id} className={a.routeArg === p.id ? 'flash' : ''}>
              <td><b style={{ fontWeight: 600 }}>{p.name}</b><div className="dim" style={{ fontSize: 11 }}><OsBadge os={p.os} /></div></td>
              <td>{px ? (p.exit_ip ? <><CC c={p.country} /> <span className="mono">{p.exit_ip}</span></> : <span className="dim">{px.host} · not measured</span>) : <span className="dim">—</span>}</td>
              {fp ? <>
                <td className={st === 'mismatch' ? 'hl-bad' : ''}>{fp.timezone ?? <span className="dim">unset</span>}</td>
                <td>{fp.locale}</td>
                <td className="mono" style={{ fontSize: 11 }}>{fp.languages.slice(0, 3).join(', ')}</td>
                <td>{fp.latitude != null ? <>{fp.latitude.toFixed(2)}, {fp.longitude?.toFixed(2)}<div className="dim" style={{ fontSize: 10.5 }}>{fp.country}</div></> : <span className="dim">unset</span>}</td>
              </> : <td colSpan={4}><Spin s={10} style={{ color: 'var(--accent2)' }} /> <span className="acc">Reading persona…</span></td>}
              <td>{pill[st]}</td>
              <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}><button className={`btn s ${st === 'mismatch' ? 'p' : ''}`} disabled title="Needs the bundled offline GeoIP database (not in this build)"><Icon n="pin" s={12} />Match now</button></td>
            </tr>;
          })}</tbody></table>
          : <Empty icon="check" title="Nothing here" text={f === 'mismatch' ? 'Every profile matches its exit IP.' : 'No profiles in this view.'} />}</div>
      </div>
    </Main>
  );
}
