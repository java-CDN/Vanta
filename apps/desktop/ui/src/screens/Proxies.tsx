import { useEffect, useMemo, useState } from 'react';
import { useApp, type AppCtx } from '../state/store';
import { Main } from '../components/Shell';
import { CC, Empty, Icon, OsBadge, Seg, Spin } from '../components/ui';
import type * as T from '../api/types';
import { offlineReason, proxyName, proxyStatus, relDay, schemeLabel } from '../lib/format';
import { parseList } from '../lib/proxyparse';
import { assignWithWarning, ProxyStatus } from './Profiles';

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

function openAdd(a: AppCtx, onAdded: (ids: string[]) => void) {
  function Body() {
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
  a.openModal({ title: 'Add proxies', width: 680, raw: true, body: <Body /> });
}

export function ProxiesScreen() {
  const a = useApp();
  const [q, setQ] = useState('');
  const [fType, setFType] = useState('');
  const [fStatus, setFStatus] = useState('');
  const [selId, setSelId] = useState<string | null>(null);
  const [testing, setTesting] = useState<Record<string, boolean>>({});
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
    { label: 'Assign to profile…', icon: 'link', id: 'pxAssignMenu', onClick: () => { setSelId(x.id); setTimeout(() => document.getElementById('pxAssign')?.focus(), 30); } },
    { label: 'Copy endpoint', icon: 'copy', id: 'pxCopy', onClick: () => { navigator.clipboard?.writeText(`${x.host}:${x.port}`).catch(() => {}); a.toast(<>Copied {x.host}:{x.port} (password stays in the vault)</>, 'ok', 'copy'); } }, '-',
    { label: 'Delete', icon: 'trash', id: 'pxDel', danger: true, onClick: () => del(x) },
  ]);

  const t = sel ? testing[sel.id] : false;
  const st = sel ? proxyStatus(sel.state) : 'untested';
  const steps: [string, 'ok' | 'bad' | 'warn' | 'pend' | 'run', string][] = sel ? [
    ['TCP connect', t ? 'run' : st === 'untested' ? 'pend' : sel.state.state === 'offline' && (sel.state.reason === 'unreachable' || sel.state.reason === 'timeout') ? 'bad' : 'ok', sel.state.state === 'offline' && !t ? offlineReason(sel.state.reason) : ''],
    [sel.scheme === 'socks5' ? 'SOCKS5 handshake + login' : 'HTTP CONNECT handshake', t ? 'pend' : st === 'untested' ? 'pend' : sel.state.state === 'offline' ? (sel.state.reason === 'auth_failed' || sel.state.reason === 'protocol_error' ? 'bad' : 'pend') : 'ok', sel.state.state === 'offline' && (sel.state.reason === 'auth_failed' || sel.state.reason === 'protocol_error') ? offlineReason(sel.state.reason) : ''],
    ['Round trip', t ? 'pend' : sel.state.state === 'online' ? (st === 'slow' ? 'warn' : 'ok') : 'pend', sel.state.state === 'online' ? `${sel.state.latency_ms} ms` : ''],
  ] : [];
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
                <dt>Username</dt><dd className="mono" style={{ fontSize: 11 }}>{sel.username ?? <span className="dim">none</span>}</dd>
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
              <div className="row" style={{ gap: 8, marginTop: 8 }}><button className="btn s" disabled={t} onClick={() => test(sel.id)}><Icon n="zap" s={13} />Test</button><button className="btn s d" onClick={() => del(sel)}><Icon n="trash" s={13} />Delete</button></div>
            </div>
            <div className="card"><h3>Proxy check {t && <span className="r acc"><Spin s={10} /></span>}</h3>
              {steps.map(([s, k, v], i) => <div key={s} className="step"><span className={`ic ${k === 'run' ? 'pend' : k}`} style={{ width: 18, height: 18 }}>{k === 'ok' ? '✓' : k === 'bad' ? '✕' : k === 'warn' ? '!' : k === 'run' ? <Spin s={9} style={{ borderWidth: 1.5, color: 'var(--accent2)' }} /> : ''}</span>{i + 1}. {s}<span className="r dim">{v}</span></div>)}
              <div className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>Exit IP and country are measured by the health check through the relay. ASN, speed, UDP and blacklist steps are not part of this build yet.</div>
            </div>
          </>}
          <div className="card"><h3><Icon n="import" s={15} />Import</h3><div className="note"><Icon n="zap" s={13} /><span>Paste <span className="mono">host:port:user:pass</span> or <span className="mono">socks5://user:pass@host:port</span>, one per line. Provider session usernames (Bright Data, SOAX, Geonode, DataImpulse, Webshare, Thordata) are kept as written.</span></div>
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
