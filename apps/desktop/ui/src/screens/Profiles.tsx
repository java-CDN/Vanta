import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useApp, type AppCtx } from '../state/store';
import { Main } from '../components/Shell';
import { CC, Cb, Empty, Icon, OsBadge, Ring, Score, Spin } from '../components/ui';
import type * as T from '../api/types';
import { buildQuery, validate } from '../lib/search';
import { cleanTag, nameError, offlineReason, proxyName, proxyStatus, relDay, schemeLabel, scoreCls } from '../lib/format';
import { asCoreError } from '../api/backend';

const SAVED = ['health:<80', 'status:running', 'tag:shop os:win11', 'status:blocked'];
type SortK = 'name' | 'tags' | 'os' | 'proxy' | 'health' | 'status' | 'last';

export function StatusCell({ p }: { p: T.ProfileMeta }) {
  const a = useApp();
  const busy = a.busy[p.id];
  if (busy || p.status === 'starting') return <><Spin s={10} style={{ color: 'var(--accent2)' }} /> <span className="acc">{busy === 'stop' ? 'Stopping…' : 'Launching…'}</span></>;
  if (p.status === 'running') return <><span className="dot pulse" /> Running</>;
  if (p.status === 'crashed') return <><span className="dot b" /> <span className="bad">Crashed</span></>;
  if (p.status === 'blocked') {
    const px = a.proxyOf(p);
    const why = !px ? 'no proxy' : px.state.state === 'offline' ? 'proxy offline' : p.health > 0 && p.health < 60 ? 'health < 60' : 'check failed';
    return <><span className="dot b" /> <span className="bad">Blocked: {why}</span></>;
  }
  return <><span className="dot g" /> Stopped</>;
}

export function ProxyCell({ p }: { p: T.ProfileMeta }) {
  const a = useApp();
  const px = a.proxyOf(p);
  if (!px) return <span className="dim">No proxy</span>;
  return <>
    {p.country || p.exit_ip ? <><CC c={p.country} /> <span className="mono">{p.exit_ip || px.host}</span></> : <><span className="mono">{px.host}:{px.port}</span> <span className="dim">· {schemeLabel(px.scheme)}</span></>}
    {px.state.state === 'offline' && <span className="pill bad" style={{ marginLeft: 4 }}>offline</span>}
  </>;
}

function uniqueName(base: string, taken: (n: string) => boolean) {
  const root = base.replace(/-copy(-\d+)?$/, '');
  let n = root + '-copy'; let i = 2;
  while (taken(n)) n = `${root}-copy-${i++}`;
  return n;
}

const sameExit = (x: T.ProxyView, y: T.ProxyView) => x.scheme === y.scheme && x.host === y.host && x.port === y.port && x.username === y.username;
/** Other profiles exiting through the same proxy (same rule as vanta-proxy check_assignment). */
export function sharers(a: AppCtx, profileId: string, proxyId: string): T.ProfileMeta[] {
  const t = a.proxies.find(x => x.id === proxyId);
  if (!t) return [];
  return a.profiles.filter(p => p.id !== profileId && p.proxy_id && (() => { const o = a.proxies.find(x => x.id === p.proxy_id); return !!o && sameExit(o, t); })());
}

/** Assign with the one-proxy-one-profile warning. Returns false when the user cancels. */
export async function assignWithWarning(a: AppCtx, p: T.ProfileMeta, proxyId: string | null): Promise<boolean> {
  if (proxyId) {
    const others = sharers(a, p.id, proxyId);
    if (others.length) {
      const px = a.proxies.find(x => x.id === proxyId)!;
      const ok = await a.confirm({ title: 'Share this proxy?', ok: 'Share anyway', text: <><b>{proxyName(px)}</b> is already used by <b>{others.map(o => o.name).join(', ')}</b>. Profiles on the same IP can be linked by sites. Default is one proxy per profile.</> });
      if (!ok) return false;
    }
  }
  await a.b.assignProxy(p.id, proxyId);
  return true;
}

export function proxyOptions(a: AppCtx, selfId: string | null): ReactNode[] {
  return a.proxies.slice()
    .sort((x, y) => (a.usedBy(x.id).filter(p => p.id !== selfId).length - a.usedBy(y.id).filter(p => p.id !== selfId).length) || (Number(x.state.state === 'offline') - Number(y.state.state === 'offline')))
    .map(x => {
      const u = a.usedBy(x.id).filter(p => p.id !== selfId);
      return <option key={x.id} value={x.id}>{proxyName(x)} · {schemeLabel(x.scheme)} · {x.host}{x.state.state === 'offline' ? ' · OFFLINE' : ''}{u.length ? ` · used by ${u[0].name}` : ' · free'}</option>;
    });
}

export function openEdit(a: AppCtx, p: T.ProfileMeta) {
  const folders = [...new Set(a.profiles.map(x => x.folder).filter(Boolean))].sort();
  function Body() {
    const [name, setName] = useState(p.name);
    const [folder, setFolder] = useState(p.folder);
    const [tags, setTags] = useState(p.tags.join(', '));
    const [proxy, setProxy] = useState(p.proxy_id ?? '');
    const [notes, setNotes] = useState(p.notes);
    const [err, setErr] = useState('');
    const [busy, setBusy] = useState(false);
    const save = async () => {
      const n = name.trim();
      const e = nameError(n, x => a.profiles.some(q => q.name.toLowerCase() === x.toLowerCase() && q.id !== p.id));
      if (e) { setErr(e); return; }
      setBusy(true);
      try {
        let m = await a.b.editProfile(p.id, { name: n, folder: folder.trim(), tags: tags.split(',').map(cleanTag).filter(Boolean), notes });
        if ((p.proxy_id ?? '') !== proxy) {
          if (!(await assignWithWarning(a, p, proxy || null))) { setBusy(false); return; }
          m = { ...m, proxy_id: proxy || null };
        }
        a.closeModal();
        await a.refreshProfiles();
        a.patchProfile(m);
        a.toast(<><b>{m.name}</b> saved</>, 'ok', 'check');
      } catch (er) { setErr(asCoreError(er).kind === 'invalid' ? String((asCoreError(er) as { message: string }).message) : ''); a.fail(er); }
      finally { setBusy(false); }
    };
    return <><div className="mb"><div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="row" style={{ gap: 12 }}>
        <div className="field" style={{ flex: 1 }}><label htmlFor="edName">Name</label><input className={`inp ${err ? 'invalid' : ''}`} id="edName" value={name} onChange={e => setName(e.target.value)} maxLength={40} /><div className="err" id="edErr">{err}</div></div>
        <div className="field" style={{ flex: 1 }}><label htmlFor="edFolder">Folder</label><input className="inp" id="edFolder" list="edFolders" value={folder} onChange={e => setFolder(e.target.value)} /><datalist id="edFolders">{folders.map(f => <option key={f} value={f} />)}</datalist></div>
      </div>
      <div className="field"><label htmlFor="edTags">Tags (comma separated)</label><input className="inp" id="edTags" value={tags} onChange={e => setTags(e.target.value)} /></div>
      <div className="field"><label htmlFor="edProxy">Proxy</label><select className="inp" id="edProxy" value={proxy} onChange={e => setProxy(e.target.value)}><option value="">No proxy (launch blocked by kill switch)</option>{proxyOptions(a, p.id)}</select></div>
      <div className="field"><label htmlFor="edNotes">Notes</label><textarea className="inp" id="edNotes" rows={3} value={notes} onChange={e => setNotes(e.target.value)} /></div>
      <div className="note"><Icon n="info" s={13} /><span>OS and device are part of the fingerprint. Change them in Fingerprint Studio (Regenerate).</span></div>
    </div></div>
      <div className="mf">
        <button className="btn" onClick={a.closeModal}>Cancel</button>
        <button className="btn p" data-a="saveEdit" disabled={busy} onClick={save}><Icon n="check" s={14} />Save</button>
      </div></>;
  }
  a.openModal({ title: `Edit ${p.name}`, width: 560, raw: true, body: <Body /> });
}

export async function deleteProfiles(a: AppCtx, ids: string[]) {
  const ps = a.profiles.filter(p => ids.includes(p.id));
  if (!ps.length) return false;
  const running = ps.filter(p => p.status === 'running').length;
  if (a.settings.confirm_delete) {
    const ok = await a.confirm({
      title: ps.length === 1 ? `Delete ${ps[0].name}?` : `Delete ${ps.length} profiles?`, danger: true, ok: 'Delete permanently',
      text: <>{ps.length === 1 ? "The profile's own encryption key is destroyed" : "Each profile's own encryption key is destroyed"}, so its cookies, history and files become unreadable. This cannot be undone.
        {ps.length > 1 && <div className="mono dim" style={{ marginTop: 10, maxHeight: 90, overflow: 'auto' }}>{ps.map(p => p.name).join(', ')}</div>}
        {running > 0 && <div className="pill warn" style={{ marginTop: 10 }}>Running — {running === 1 ? 'it' : 'they'} will be stopped first</div>}</>,
    });
    if (!ok) return false;
  }
  try {
    const n = await a.b.deleteProfiles(ids);
    if (a.drawer && ids.includes(a.drawer)) a.setDrawer(null);
    await a.refreshProfiles();
    a.toast(ps.length === 1 ? <><b>{ps[0].name}</b> deleted</> : `${n} profiles deleted`, 'ok', 'trash');
    return true;
  } catch (e) { a.fail(e); return false; }
}

export async function duplicate(a: AppCtx, p: T.ProfileMeta) {
  const free = a.proxies.find(x => x.state.state !== 'offline' && !a.usedBy(x.id).length && !sharers(a, '', x.id).length);
  const name = uniqueName(p.name, n => a.profiles.some(x => x.name === n));
  try {
    const m = await a.b.createProfile({ name, folder: p.folder, tags: p.tags, os: p.os, notes: p.notes, color: p.color, proxy_id: free ? free.id : p.proxy_id });
    await a.refreshProfiles();
    a.setFlash(m.id);
    a.toast(<>Duplicated as <b>{m.name}</b> with a new fingerprint seed{free ? <> and free proxy {proxyName(free)}</> : '. It shares a proxy — assign a new one.'}</>, free ? 'ok' : 'warn', 'copy');
  } catch (e) { a.fail(e); }
}

export function rowMenu(a: AppCtx, el: HTMLElement, p: T.ProfileMeta) {
  a.openMenu(el, [
    { label: 'Open details', icon: 'eye', id: 'openDrawer', onClick: () => a.setDrawer(p.id) },
    p.status === 'running' ? { label: 'Stop', icon: 'stop', id: 'stopP', onClick: () => a.stop(p.id) } : { label: 'Launch', icon: 'play', id: 'launchP', onClick: () => a.launch(p.id) },
    { label: 'Edit profile', icon: 'edit', id: 'editP', onClick: () => openEdit(a, p) },
    { label: 'Fingerprint', icon: 'fp', id: 'fpOf', onClick: () => a.go('fingerprints', p.id) },
    { label: 'Run health check', icon: 'pulse', id: 'hcOf', onClick: () => a.go('health', p.id + ':run') },
    { label: 'Geo Auto-Match', icon: 'pin', id: 'geoOf', onClick: () => a.go('geo', p.id) },
    { label: 'Duplicate', icon: 'copy', id: 'dupP', onClick: () => duplicate(a, p) }, '-',
    { label: 'Delete', icon: 'trash', id: 'delP', danger: true, onClick: () => deleteProfiles(a, [p.id]) },
  ]);
}

const ROW_H = 47;
const VIRTUAL_FROM = 200;

export function ProfilesScreen() {
  const a = useApp();
  const all = a.profiles;
  const [q, setQ] = useState('');
  const [f, setF] = useState({ status: '', tag: '', country: '', folder: '' });
  const [sort, setSort] = useState<{ k: SortK; d: 1 | -1 }>({ k: 'last', d: -1 });
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [hits, setHits] = useState<string[] | null>(null);
  const [qErr, setQErr] = useState('');
  const [scroll, setScroll] = useState({ top: 0, h: 600 });
  const tw = useRef<HTMLDivElement>(null);
  const query = buildQuery(q, f);

  // Server-side search (SQLite FTS5 in the app); the empty query shows everything.
  useEffect(() => {
    const err = validate(query);
    setQErr(err);
    if (err) return;
    if (!query) { setHits(null); return; }
    let live = true;
    const t = setTimeout(async () => {
      try { const r = await a.b.listProfiles(query, 1_000_000, 0); if (live) setHits(r.items.map(x => x.id)); }
      catch (e) { if (live) setQErr(asCoreError(e).kind === 'invalid' ? (asCoreError(e) as { message: string }).message : 'search failed'); }
    }, 80);
    return () => { live = false; clearTimeout(t); };
  }, [query, a.b, all.length]);

  const byId = useMemo(() => new Map(all.map(p => [p.id, p])), [all]);
  const list = useMemo(() => {
    const base = hits ? hits.map(id => byId.get(id)).filter((x): x is T.ProfileMeta => !!x) : all.slice();
    const val = (p: T.ProfileMeta): string | number => {
      switch (sort.k) {
        case 'name': return p.name; case 'os': return p.os; case 'tags': return p.tags.join(',');
        case 'proxy': return (p.country || '') + (p.exit_ip || a.proxyOf(p)?.host || ''); case 'health': return p.health;
        case 'status': return p.status; default: return p.last_opened_ms ?? p.created_ms;
      }
    };
    return base.sort((x, y) => { const u = val(x), v = val(y); return (u > v ? 1 : u < v ? -1 : 0) * sort.d; });
  }, [hits, all, byId, sort, a]);

  useEffect(() => { setSel(s => { const n = new Set([...s].filter(id => byId.has(id))); return n.size === s.size ? s : n; }); }, [byId]);
  useEffect(() => {
    const el = tw.current; if (!el) return;
    const ro = new ResizeObserver(() => setScroll(s => ({ ...s, h: el.clientHeight })));
    ro.observe(el); return () => ro.disconnect();
  }, []);

  const running = all.filter(p => p.status === 'running').length;
  const scored = all.filter(p => p.health > 0);
  const avg = scored.length ? Math.round(scored.reduce((s, p) => s + p.health, 0) / scored.length) : 0;
  const attention = all.filter(p => p.status === 'blocked' || p.status === 'crashed' || (p.health > 0 && p.health < 80)).length;
  const offline = a.proxies.filter(x => x.state.state === 'offline' && a.usedBy(x.id).length).length;
  const tags = [...new Set(all.flatMap(p => p.tags))].sort();
  const ctrs = [...new Set(all.map(p => p.country).filter(Boolean))].sort();
  const folderCounts = useMemo(() => { const m = new Map<string, number>(); all.forEach(p => { if (p.folder) m.set(p.folder, (m.get(p.folder) ?? 0) + 1); }); return [...m.entries()].sort((x, y) => x[0].localeCompare(y[0])); }, [all]);
  const visSel = list.filter(p => sel.has(p.id)).length;
  const anyFilter = q || f.status || f.tag || f.country || f.folder;
  const clear = () => { setQ(''); setF({ status: '', tag: '', country: '', folder: '' }); };

  // virtual window
  // Short lists render whole; long ones (10k) render only the rows in view.
  const virtual = list.length > VIRTUAL_FROM;
  const start = virtual ? Math.max(0, Math.floor(scroll.top / ROW_H) - 10) : 0;
  const end = virtual ? Math.min(list.length, Math.ceil((scroll.top + scroll.h) / ROW_H) + 10) : list.length;
  const rows = list.slice(start, end);

  const th = (k: SortK, l: string) => <th className={`sort ${k === 'tags' ? 'hide-md' : ''}`} data-id={k} onClick={() => setSort(s => (s.k === k ? { k, d: (s.d * -1) as 1 | -1 } : { k, d: k === 'last' || k === 'health' ? -1 : 1 }))}>{l}{sort.k === k && <span className="arr">{sort.d > 0 ? '↑' : '↓'}</span>}</th>;
  const toggle = (id: string) => setSel(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const selIds = [...sel];

  return (
    <Main title="Profiles" sub="Every profile is a separate, encrypted browser identity. Closed profiles use no RAM or CPU."
      actions={<button className="btn p" data-a="newProfile" onClick={() => a.go('new')}><Icon n="plus" s={14} />New profile</button>}
      contentStyle={{ overflow: 'hidden' }}>
      <div className="row" style={{ gap: 12, flex: 'none' }}>
        <div className="card stat"><div className="k">Profiles</div><div className="v">{all.length.toLocaleString()}</div></div>
        <div className="card stat"><div className="k">Running now</div><div className="v">{running} <small>· stopped profiles use 0 RAM</small></div></div>
        <div className="card stat"><div className="k">Average health</div><div className={`v ${scoreCls(avg) === 'g' ? 'ok' : 'warn'}`}>{avg || '—'}</div></div>
        <div className="card stat"><div className="k">Need attention</div><div className={`v ${attention ? 'warn' : 'ok'}`}>{attention} <small>· {offline} proxy offline</small></div></div>
      </div>
      <div className="row" style={{ flex: 1, minHeight: 0 }}>
        <div className="card folders" style={{ width: 200, padding: '10px 8px', flex: 'none', overflow: 'auto' }}>
          <div className="grp" style={{ paddingTop: 0 }}>Folders</div>
          <div className="sub-nav">
            {[['', 'All profiles', all.length] as [string, string, number], ...folderCounts.map(([k, n]) => [k, k, n] as [string, string, number])].map(([k, l, n]) => (
              <a key={k || '_all'} className={f.folder === k ? 'on' : ''} data-a="folder" data-id={k} tabIndex={0} onClick={() => setF({ ...f, folder: k })}><Icon n="folder" s={14} />{l}<span className="dim" style={{ marginLeft: 'auto', fontSize: 11 }}>{n}</span></a>
            ))}
          </div>
          <div className="grp" style={{ marginTop: 8 }}>Saved searches</div>
          {SAVED.map(s => <a key={s} className="mono lnk" style={{ display: 'block', padding: '5px 10px', color: q === s ? 'var(--accent2)' : 'var(--muted)' }} data-a="savedSearch" tabIndex={0} onClick={() => setQ(q === s ? '' : s)}>{s}</a>)}
        </div>
        <div className="card" style={{ flex: 1, padding: 0, display: 'flex', flexDirection: 'column', minWidth: 0, position: 'relative' }}>
          <div style={{ display: 'flex', gap: 8, padding: '10px 12px', borderBottom: '1px solid var(--line)', alignItems: 'center', flexWrap: 'wrap' }}>
            <div className={`inp ${qErr ? 'invalid' : ''}`} style={{ width: 310 }} title={qErr}><Icon n="search" s={14} />
              <input id="psearch" value={q} onChange={e => setQ(e.target.value)} placeholder="Search name, tag, IP… or tag: os: health:" aria-label="Search profiles" aria-invalid={!!qErr} spellCheck={false} />
              {q && <button className="ib" style={{ width: 18, height: 18 }} onClick={() => setQ('')} aria-label="Clear search"><Icon n="x" s={12} /></button>}
            </div>
            <select className={`pillsel ${f.status ? 'act' : ''}`} id="fStatus" aria-label="Filter by status" value={f.status} onChange={e => setF({ ...f, status: e.target.value })}><option value="">Status: any</option>{['Running', 'Stopped', 'Blocked', 'Crashed'].map(s => <option key={s} value={s}>{s}</option>)}</select>
            <select className={`pillsel ${f.tag ? 'act' : ''}`} id="fTag" aria-label="Filter by tag" value={f.tag} onChange={e => setF({ ...f, tag: e.target.value })}><option value="">Tag: any</option>{tags.map(s => <option key={s}>{s}</option>)}</select>
            <select className={`pillsel ${f.country ? 'act' : ''}`} id="fCountry" aria-label="Filter by proxy country" value={f.country} onChange={e => setF({ ...f, country: e.target.value })}><option value="">Proxy country: any</option>{ctrs.map(s => <option key={s} value={s}>{s}</option>)}</select>
            <select className={`pillsel show-md ${f.folder ? 'act' : ''}`} aria-label="Folder" value={f.folder} onChange={e => setF({ ...f, folder: e.target.value })}><option value="">Folder: all</option>{folderCounts.map(([k]) => <option key={k}>{k}</option>)}</select>
            {anyFilter && <button className="btn ghost s" data-a="clearFilters" onClick={clear}><Icon n="x" s={12} />Clear</button>}
            <span className="muted" style={{ marginLeft: 'auto' }}>{qErr ? <span className="bad" id="qerr">{qErr}</span> : list.length === all.length ? `${all.length.toLocaleString()} profiles` : `${list.length.toLocaleString()} of ${all.length.toLocaleString()}`}</span>
          </div>
          <div className="tw" ref={tw} onScroll={e => setScroll({ top: e.currentTarget.scrollTop, h: e.currentTarget.clientHeight })}>
            {list.length ? (
              <table>
                <thead><tr>
                  <th style={{ width: 30 }}><Cb on={!!list.length && visSel === list.length} mid={visSel > 0} label="Select all" onToggle={() => setSel(s => { const n = new Set(s); const allOn = list.every(p => n.has(p.id)); list.forEach(p => (allOn ? n.delete(p.id) : n.add(p.id))); return n; })} /></th>
                  {th('name', 'Name')}{th('tags', 'Tags')}{th('os', 'OS')}{th('proxy', 'Proxy (exit)')}{th('health', 'Health')}{th('status', 'Status')}{th('last', 'Last opened')}<th />
                </tr></thead>
                <tbody>
                  {start > 0 && <tr aria-hidden="true" className="vpad" style={{ height: start * ROW_H }}><td colSpan={9} style={{ padding: 0, border: 0 }} /></tr>}
                  {rows.map(p => {
                    const s = sel.has(p.id); const busy = !!a.busy[p.id];
                    return (
                      <tr key={p.id} className={`click ${s ? 'sel' : ''} ${a.flash === p.id ? 'flash' : ''}`} style={{ height: ROW_H }} data-id={p.id} onClick={() => a.setDrawer(p.id)}>
                        <td><Cb on={s} label={`Select ${p.name}`} onToggle={() => toggle(p.id)} /></td>
                        <td><b style={{ fontWeight: 600 }}>{p.name}</b><div className="dim" style={{ fontSize: 11 }}>{p.folder}</div></td>
                        <td className="hide-md">{p.tags.map(t => <span key={t} className="pill" style={{ marginRight: 4 }}>{t}</span>)}</td>
                        <td><OsBadge os={p.os} /></td>
                        <td><ProxyCell p={p} /></td>
                        <td><Score n={p.health} /></td>
                        <td><StatusCell p={p} /></td>
                        <td className="muted">{relDay(p.last_opened_ms)}</td>
                        <td style={{ textAlign: 'right', color: 'var(--muted)', whiteSpace: 'nowrap' }}>
                          <button className="ib" data-a={p.status === 'running' ? 'stopP' : 'launchP'} disabled={busy} aria-label={`${p.status === 'running' ? 'Stop' : 'Launch'} ${p.name}`} title={p.status === 'running' ? 'Stop' : 'Launch'}
                            onClick={e => { e.stopPropagation(); p.status === 'running' ? a.stop(p.id) : a.launch(p.id); }}><Icon n={p.status === 'running' ? 'stop' : 'play'} s={14} /></button>
                          <button className="ib" data-a="rowMenu" aria-label={`More actions for ${p.name}`} title="More" onClick={e => { e.stopPropagation(); rowMenu(a, e.currentTarget, p); }}><Icon n="more" s={14} /></button>
                        </td>
                      </tr>
                    );
                  })}
                  {end < list.length && <tr aria-hidden="true" className="vpad" style={{ height: (list.length - end) * ROW_H }}><td colSpan={9} style={{ padding: 0, border: 0 }} /></tr>}
                </tbody>
              </table>
            ) : all.length ? (
              <Empty icon="search" title="No profiles match" text="Try a different search or clear the filters."><button className="btn s" onClick={clear}>Clear filters</button></Empty>
            ) : (
              <Empty icon="users" title="No profiles yet" text="Create your first private browser identity."><button className="btn p s" onClick={() => a.go('new')}><Icon n="plus" s={13} />New profile</button></Empty>
            )}
            {list.length > 0 && <div style={{ height: 60 }} />}
          </div>
          {sel.size > 0 && (
            <div className="bulk"><span style={{ padding: '0 6px', whiteSpace: 'nowrap' }} className="muted">{sel.size} selected</span>
              <button className="btn p s" data-a="bulkLaunch" onClick={async () => { const ids = selIds.filter(id => byId.get(id)?.status !== 'running'); a.toast(`Launching ${ids.length} profile${ids.length === 1 ? '' : 's'}…`, '', 'play'); for (const id of ids) await a.launch(id, { quiet: true }); }}><Icon n="play" s={13} />Launch</button>
              <button className="btn s" data-a="bulkStop" onClick={() => { const ids = selIds.filter(id => byId.get(id)?.status === 'running'); ids.forEach(id => a.stop(id, { quiet: true })); a.toast(ids.length ? `Stopping ${ids.length} profile${ids.length === 1 ? '' : 's'}` : 'None of the selected profiles are running'); }}><Icon n="stop" s={13} />Stop</button>
              <button className="btn s" data-a="bulkMove" onClick={() => openMove(a, selIds)}><Icon n="folder" s={13} />Move</button>
              <button className="btn s" data-a="bulkHealth" onClick={() => a.go('health', selIds[0] + ':run')}><Icon n="pulse" s={13} />Health check</button>
              <button className="btn s d" data-a="bulkDelete" onClick={async () => { if (await deleteProfiles(a, selIds)) setSel(new Set()); }}><Icon n="trash" s={13} />Delete</button>
              <button className="ib" data-a="clearSel" onClick={() => setSel(new Set())} aria-label="Clear selection"><Icon n="x" s={13} /></button>
            </div>
          )}
        </div>
      </div>
    </Main>
  );
}

function openMove(a: AppCtx, ids: string[]) {
  const folders = [...new Set(a.profiles.map(x => x.folder).filter(Boolean))].sort();
  function Body() {
    const [f, setF] = useState(folders[0] ?? '');
    return <>
      <div className="mb"><div className="field"><label htmlFor="mvF">Folder</label><input className="inp" id="mvF" list="mvFolders" value={f} onChange={e => setF(e.target.value)} /><datalist id="mvFolders">{folders.map(x => <option key={x} value={x} />)}</datalist></div></div>
      <div className="mf">
        <button className="btn" onClick={a.closeModal}>Cancel</button>
        <button className="btn p" data-a="doMove" onClick={async () => {
          const folder = f.trim();
          try { for (const id of ids) await a.b.editProfile(id, { folder }); a.closeModal(); await a.refreshProfiles(); a.toast(`Moved ${ids.length} to ${folder || 'no folder'}`, 'ok', 'folder'); }
          catch (e) { a.fail(e); }
        }}>Move</button>
      </div>
    </>;
  }
  a.openModal({ title: `Move ${ids.length} profile${ids.length === 1 ? '' : 's'}`, width: 400, raw: true, body: <Body /> });
}

/** Profile details drawer (prototype `#drawer`). */
export function Drawer() {
  const a = useApp();
  const p = a.drawer && !a.locked ? a.profiles.find(x => x.id === a.drawer) : undefined;
  const [detail, setDetail] = useState<T.ProfileDetail | null>(null);
  const [rules, setRules] = useState<T.RuleView[] | null>(null);
  const [notes, setNotes] = useState('');
  const [open, setOpen] = useState(false);
  const noteT = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => {
    setDetail(null); setRules(null);
    if (!p) { setOpen(false); return; }
    setNotes(p.notes);
    requestAnimationFrame(() => setOpen(true));
    let live = true;
    a.b.getProfile(p.id).then(d => live && setDetail(d)).catch(() => {});
    a.b.fingerprint(p.id).then(f => live && setRules(f.rules)).catch(() => {});
    return () => { live = false; };
  }, [p?.id, p?.health]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!p) return <aside className="drawer" id="drawer" aria-label="Profile details" />;
  const px = a.proxyOf(p);
  const rs = rules ? { ok: rules.filter(r => r.level === 'pass').length, warn: rules.filter(r => r.level === 'note').length, bad: rules.filter(r => r.level === 'fail').length } : null;
  const per = detail?.persona;
  const busy = a.busy[p.id];
  return (
    <aside className={`drawer ${open ? 'open' : ''}`} id="drawer" aria-label="Profile details">
      <div className="dh"><div><div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><b style={{ fontSize: 16 }}>{p.name}</b><OsBadge os={p.os} /></div><div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>{p.folder || 'No folder'} · created {relDay(p.created_ms)}</div></div>
        <button className="ib" style={{ marginLeft: 'auto' }} data-a="closeDrawer" onClick={() => a.setDrawer(null)} aria-label="Close details"><Icon n="x" s={16} /></button></div>
      <div className="db">
        <div className="row" style={{ gap: 10, alignItems: 'center' }}>
          <div className="ring"><Ring v={p.health} size={64} w={6} /><div className="rv"><b style={{ fontSize: 17 }}>{p.health || '—'}</b></div></div>
          <div style={{ flex: 1 }}><div style={{ fontWeight: 600 }}>Health {p.health === 0 ? <span className="warn">not checked</span> : p.health >= 90 ? <span className="ok">good</span> : p.health >= 60 ? <span className="warn">needs a look</span> : <span className="bad">launch blocked</span>}</div>
            <div className="dim" style={{ fontSize: 11.5 }}><StatusCell p={p} /> · last opened {relDay(p.last_opened_ms)}</div></div>
          <button className="btn s" onClick={() => a.go('health', p.id + ':run')}><Icon n="pulse" s={13} />Run check</button>
        </div>
        <div className="card" style={{ padding: '12px 14px' }}><h3 style={{ marginBottom: 8 }}><Icon n="fp" s={14} />Fingerprint {rs && <span className={`r ${rs.bad ? 'bad' : 'ok'}`}>{rs.ok} pass · {rs.warn} note · {rs.bad} fail</span>}</h3>
          {per ? <div className="kv" style={{ gridTemplateColumns: '110px 1fr', fontSize: 12 }}>
            <dt>Chrome</dt><dd>{a.info.engine_version.split('.')[0]} <span className="lock-ic"><Icon n="lock" s={11} />engine {a.info.engine_version}</span></dd>
            <dt>Platform</dt><dd>Windows · {per.os === 'windows11' ? 'Windows 11' : 'Windows 10'}</dd>
            <dt>GPU</dt><dd className="mono" style={{ fontSize: 11 }}>{per.gpu}</dd>
            <dt>Screen</dt><dd>{per.screen.replace('x', ' × ')}</dd>
            <dt>CPU / memory</dt><dd>{per.hardware_concurrency} cores · {per.device_memory} GB</dd>
            <dt>Locale</dt><dd>{per.locale}</dd>
            <dt>Record</dt><dd className="mono">{per.device_id}</dd>
          </div> : <div className="muted"><Spin s={10} /> Loading…</div>}
        </div>
        <div className="card" style={{ padding: '12px 14px' }}><h3 style={{ marginBottom: 8 }}><Icon n="globe" s={14} />Proxy & location</h3>
          {px ? <div className="kv" style={{ gridTemplateColumns: '110px 1fr', fontSize: 12 }}>
            <dt>Proxy</dt><dd>{proxyName(px)} · {schemeLabel(px.scheme)}</dd>
            <dt>Endpoint</dt><dd className="mono">{px.display}</dd>
            <dt>Exit</dt><dd>{p.exit_ip ? <><CC c={p.country} /> <span className="mono">{p.exit_ip}</span></> : <span className="dim">not measured yet</span>}</dd>
            <dt>Status</dt><dd><ProxyStatus x={px} /></dd>
          </div> : <div className="muted">No proxy assigned. The kill switch blocks every launch until you pick one.</div>}
          <div style={{ display: 'flex', gap: 6, marginTop: 10 }}><button className="btn s" onClick={() => openEdit(a, p)}><Icon n="globe" s={13} />Change proxy</button></div>
        </div>
        <div className="field"><label htmlFor="drNotes">Notes</label><textarea className="inp" id="drNotes" rows={3} placeholder="Add a note (saved automatically)" value={notes}
          onChange={e => { const v = e.target.value; setNotes(v); clearTimeout(noteT.current); noteT.current = setTimeout(() => a.b.editProfile(p.id, { notes: v }).then(a.patchProfile).catch(er => a.fail(er)), 500); }} /></div>
        <div className="field"><label>Tags</label><div>{p.tags.length ? p.tags.map(t => <span key={t} className="pill acc" style={{ marginRight: 4 }}>{t}</span>) : <span className="dim">none</span>}</div></div>
      </div>
      <div className="df">
        {p.status === 'running'
          ? <button className="btn s" onClick={() => a.stop(p.id)}><Icon n="stop" s={13} />Stop</button>
          : <button className="btn p s" disabled={!!busy} onClick={() => a.launch(p.id)}>{busy ? <><Spin />Launching…</> : <><Icon n="play" s={13} />Launch</>}</button>}
        <button className="btn s" onClick={() => openEdit(a, p)}><Icon n="edit" s={13} />Edit</button>
        <button className="btn s" onClick={() => a.go('fingerprints', p.id)}><Icon n="fp" s={13} />Fingerprint</button>
        <button className="btn s" onClick={() => duplicate(a, p)}><Icon n="copy" s={13} />Duplicate</button>
        <button className="btn d s" style={{ marginLeft: 'auto' }} aria-label="Delete" onClick={() => deleteProfiles(a, [p.id])}><Icon n="trash" s={13} /></button>
      </div>
    </aside>
  );
}

export function ProxyStatus({ x, testing }: { x: T.ProxyView; testing?: boolean }) {
  if (testing) return <><Spin s={10} style={{ color: 'var(--accent2)' }} /> <span className="acc">Testing…</span></>;
  const s = proxyStatus(x.state);
  if (s === 'ok') return <><span className="dot" /> Online</>;
  if (s === 'slow') return <><span className="dot w" /> Online · slow</>;
  if (s === 'offline') return <><span className="dot b" /> <span className="bad">Offline{x.state.state === 'offline' ? ` · ${offlineReason(x.state.reason)}` : ''}</span></>;
  return <><span className="dot g" /> Not tested</>;
}
