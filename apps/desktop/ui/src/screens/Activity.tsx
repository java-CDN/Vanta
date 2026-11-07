import { useEffect, useState } from 'react';
import { useApp } from '../state/store';
import { Main } from '../components/Shell';
import { Empty, Icon, Seg, Spin } from '../components/ui';
import type * as T from '../api/types';
import { dateLabel, dayStart, hms, LOG_INFO, LOG_TYPES } from '../lib/format';

const PAGE = 100;
type DateR = 'today' | 'yesterday' | '7d' | 'all';

export function rangeOf(d: DateR, now = Date.now()): { from_ms: number | null; to_ms: number | null } {
  const today = dayStart(now);
  if (d === 'today') return { from_ms: today, to_ms: null };
  if (d === 'yesterday') return { from_ms: today - 864e5, to_ms: today };
  if (d === '7d') return { from_ms: today - 6 * 864e5, to_ms: null };
  return { from_ms: null, to_ms: null };
}

export function ActivityScreen() {
  const a = useApp();
  const [type, setType] = useState('all');
  const [prof, setProf] = useState('');
  const [date, setDate] = useState<DateR>('all');
  const [q, setQ] = useState('');
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<T.LogPage | null>(null);
  const [all, setAll] = useState(0);
  const [chain, setChain] = useState(false);
  const [tick, setTick] = useState(0);

  useEffect(() => { setOffset(0); }, [type, prof, date]);
  useEffect(() => {
    let live = true;
    const kinds = LOG_TYPES.find(t => t[0] === type)![2];
    a.b.activityLog({ kinds, profile: prof || null, ...rangeOf(date), offset, limit: PAGE }).then(r => live && setPage(r)).catch(e => a.fail(e));
    a.b.activityLog({ limit: 1 }).then(r => live && setAll(r.total)).catch(() => {});
    return () => { live = false; };
  }, [type, prof, date, offset, tick, a.b]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { let u: (() => void) | undefined; a.b.onLog(() => setTick(t => t + 1)).then(f => { u = f; }); return () => u?.(); }, [a.b]);

  const entries = (page?.entries ?? []).filter(e => !q || [LOG_INFO[e.kind].title, a.profName(e.profile), e.detail, e.kind].join(' ').toLowerCase().includes(q.toLowerCase()));
  const integ = a.info.log_integrity;
  let lastDay: number | null = null;
  const today = dayStart(Date.now());
  const exportCsv = async () => {
    const ok = await a.confirm({ title: 'Export activity log?', ok: 'Export CSV', text: <>The {page?.entries.length ?? 0} events on this page are saved as a plain CSV file. <b>The file is not encrypted</b>: keep it somewhere safe. Entries never contain passwords or keys.</> });
    if (!ok || !page) return;
    const cell = (s: string) => `"${s.replace(/"/g, '""')}"`;
    const csv = ['seq,time,event,profile,detail', ...page.entries.map(e => [e.seq, new Date(e.ts_ms).toISOString(), LOG_INFO[e.kind].title, a.profName(e.profile), e.detail].map(v => cell(String(v))).join(','))].join('\n');
    const u = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); const l = document.createElement('a'); l.href = u; l.download = `vanta-activity-${new Date().toISOString().slice(0, 10)}.csv`; l.click(); setTimeout(() => URL.revokeObjectURL(u), 1000);
    a.toast(`Exported vanta-activity-${new Date().toISOString().slice(0, 10)}.csv · ${page.entries.length} events`, 'ok', 'export');
  };
  return (
    <Main title="Activity Log" sub="Encrypted and stored only on this PC. Never uploaded. Kept 90 days, hash-chained so edits are detectable."
      actions={<><button className="btn" data-a="verifyChain" onClick={() => setChain(true)}><Icon n="link" s={14} />Verify chain</button><button className="btn" data-a="logExport" disabled={!page?.entries.length} onClick={exportCsv}><Icon n="export" s={14} />Export</button></>}
      contentStyle={{ overflow: 'hidden' }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', flex: 'none' }}>
        <div className="inp" style={{ width: 260 }}><Icon n="search" s={14} /><input id="logQ" value={q} onChange={e => setQ(e.target.value)} placeholder="Search this page" aria-label="Search events" /></div>
        <Seg value={type} onChange={setType} options={LOG_TYPES.map(([k, l]) => [k, l] as [string, string])} name="Event type" />
        <select className={`pillsel ${prof ? 'act' : ''}`} aria-label="Profile" value={prof} onChange={e => setProf(e.target.value)}><option value="">Profile: any</option>{a.profiles.slice(0, 2000).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select>
        <select className={`pillsel ${date !== 'all' ? 'act' : ''}`} aria-label="Date range" value={date} onChange={e => setDate(e.target.value as DateR)}><option value="today">Today</option><option value="yesterday">Yesterday</option><option value="7d">Last 7 days</option><option value="all">All (90 days)</option></select>
        <span className="muted" id="logCount" style={{ marginLeft: 'auto' }}>{page ? `${page.total ? offset + 1 : 0}–${Math.min(offset + PAGE, page.total)} of ${page.total} events` : ''}{all && page && page.total !== all ? ` · ${all} total` : ''}</span>
        <button className="ib" aria-label="Newer" title="Newer" disabled={!offset} onClick={() => setOffset(Math.max(0, offset - PAGE))}><Icon n="right" s={14} style={{ transform: 'rotate(180deg)' }} /></button>
        <button className="ib" aria-label="Older" title="Older" disabled={!page || offset + PAGE >= page.total} onClick={() => setOffset(offset + PAGE)}><Icon n="right" s={14} /></button>
      </div>
      {chain && <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', flex: 'none', borderColor: integ?.state === 'ok' ? 'rgba(63,191,107,.4)' : 'rgba(229,83,75,.5)' }}>
        <span className={`ic ${integ?.state === 'ok' ? 'ok' : 'bad'}`} style={{ width: 26, height: 26, fontSize: 13 }}>{integ?.state === 'ok' ? '✓' : '✕'}</span>
        <div style={{ flex: 1 }}><b className={integ?.state === 'ok' ? 'ok' : 'bad'}>{integ?.state === 'ok' ? 'Hash chain verified' : integ ? 'Chain problem found' : 'Not verified in this session'}</b>
          <div className="dim" style={{ fontSize: 11.5 }}>{integ?.state === 'ok' ? `${all} entries · SHA-256 chain checked at unlock against the head sealed in the vault · no entry was edited or removed` : integ ? integ.detail : 'The chain is verified at every unlock.'}</div></div>
        <button className="ib" onClick={() => setChain(false)} aria-label="Dismiss"><Icon n="x" s={14} /></button></div>}
      <div className="card" style={{ padding: 0, flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}><div className="tw">
        {!page ? <div className="empty"><Spin /></div> : entries.length ? <table><thead><tr><th style={{ width: 90 }}>Time</th><th style={{ width: 30 }} /><th>Event</th><th>Profile</th><th>Details</th><th className="hide-md">#</th></tr></thead><tbody>
          {entries.map(e => {
            const d = dayStart(e.ts_ms); const sep = d !== lastDay; lastDay = d;
            const inf = LOG_INFO[e.kind];
            const pn = e.profile ? a.profiles.find(p => p.id === e.profile) : undefined;
            return [sep && <tr key={'d' + e.seq}><td colSpan={6} style={{ background: 'var(--sub)', fontSize: 11, fontWeight: 600, color: 'var(--muted)', letterSpacing: 0.4, padding: '6px 10px' }}>{d === today ? 'TODAY' : d === today - 864e5 ? 'YESTERDAY' : dateLabel(e.ts_ms).toUpperCase()} · {dateLabel(e.ts_ms)}</td></tr>,
              <tr key={e.seq}><td className="mono muted">{hms(new Date(e.ts_ms))}</td><td><span className={inf.cls}><Icon n={inf.icon as never} s={14} /></span></td><td><b style={{ fontWeight: 550 }}>{inf.title}</b></td>
                <td>{pn ? <span className="lnk" onClick={() => setProf(pn.id)}>{pn.name}</span> : e.profile ? <span className="dim">deleted profile</span> : '—'}</td>
                <td className="muted" style={{ whiteSpace: 'normal' }}>{e.detail}</td><td className="mono dim hide-md">{e.seq}</td></tr>];
          })}
        </tbody></table> : <Empty icon="list" title="No events match" text="Try another type, profile or date range."><button className="btn s" onClick={() => { setQ(''); setType('all'); setProf(''); setDate('all'); }}>Clear filters</button></Empty>}
      </div></div>
    </Main>
  );
}
