import { useEffect, useRef, useState } from 'react';
import { useApp } from '../state/store';
import { Main } from '../components/Shell';
import { Empty, Icon, Ring, Seg, Spin } from '../components/ui';
import type * as T from '../api/types';
import { AREAS, CHECKS } from '../lib/catalog';
import { osLong, relDay } from '../lib/format';

type Res = { s: 'ok' | 'warn' | 'bad'; note?: string };
interface Run { pid: string; running: boolean; started: number; result?: T.HealthResult; error?: string; dur?: string }

/** Per-check outcome from a run: listed problems (warn/fail), everything else passed. */
export function outcomes(r: T.HealthResult): Record<string, Res> {
  const out: Record<string, Res> = {};
  for (const c of CHECKS) out[c.id] = { s: 'ok' };
  for (const id of r.summary.failing) out[id] = { s: 'bad' };
  for (const p of r.problems) out[p.id] = { s: p.outcome === 'fail' ? 'bad' : 'warn', note: p.message };
  return out;
}

function report(p: T.ProfileMeta, r: T.HealthResult, engine: string): string {
  const res = outcomes(r);
  const esc = (s: string) => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));
  const rows = CHECKS.map(c => `<tr><td>${c.id}</td><td>${esc(AREAS.find(x => x[0] === c.area)![1])}</td><td>${esc(c.title)}</td><td>${res[c.id].s}</td><td>${esc(res[c.id].note ?? '')}</td></tr>`).join('');
  return `<!doctype html><meta charset="utf-8"><title>Vanta health report ${esc(p.name)}</title><style>body{font:13px system-ui;margin:24px}td,th{border-bottom:1px solid #ddd;padding:4px 8px;text-align:left}</style><h1>Health check · ${esc(p.name)}</h1><p>Score <b>${r.summary.score}</b>/100${r.summary.blocked ? ' (blocks launch)' : ''} · engine ${esc(engine)} · ${new Date(r.summary.ts_ms).toISOString()}</p><table><tr><th>Check</th><th>Area</th><th>Title</th><th>Result</th><th>Detail</th></tr>${rows}</table>`;
}

export function HealthScreen() {
  const a = useApp();
  const [argId, argRun] = a.routeArg.split(':');
  const pid = a.profiles.some(p => p.id === argId) ? argId : (a.profiles.find(p => p.status !== 'running') ?? a.profiles[0])?.id;
  const p = a.profiles.find(x => x.id === pid);
  const [run, setRun] = useState<Run | null>(null);
  const [hist, setHist] = useState<number[]>([]);
  const [filt, setFilt] = useState<'all' | 'issues' | 'pass'>('all');
  const [open, setOpen] = useState<Set<string> | null>(null);
  const [item, setItem] = useState<string | null>(null);
  const [, tick] = useState(0);
  const autorun = useRef('');

  const loadHist = async (id: string) => {
    try {
      const page = await a.b.activityLog({ kinds: ['health_run'], profile: id, limit: 12 });
      setHist(page.entries.map(e => Number(/score (\d+)/.exec(e.detail)?.[1] ?? NaN)).filter(n => !isNaN(n)).reverse());
    } catch { setHist([]); }
  };
  useEffect(() => { if (pid) loadHist(pid); }, [pid]); // eslint-disable-line react-hooks/exhaustive-deps

  const start = async () => {
    if (!p || run?.running) return;
    if (p.status === 'running') { a.toast(<>Stop <b>{p.name}</b> first: the health check starts its own engine in the local test lab.</>, 'warn', 'stop'); return; }
    const t0 = performance.now();
    setRun({ pid: p.id, running: true, started: Date.now() }); setItem(null); setFilt('all');
    const iv = setInterval(() => tick(x => x + 1), 120);
    try {
      const r = await a.b.runHealth(p.id);
      const res = outcomes(r);
      setOpen(new Set(AREAS.filter(([k]) => CHECKS.some(c => c.area === k && res[c.id].s !== 'ok')).map(([k]) => k)));
      setRun({ pid: p.id, running: false, started: 0, result: r, dur: ((performance.now() - t0) / 1000).toFixed(1) });
      await a.refreshProfiles(); loadHist(p.id);
      const sc = r.summary.score;
      a.toast(<>Health check for <b>{p.name}</b>: {sc}/100</>, sc >= 90 ? 'ok' : sc >= 60 ? 'warn' : 'bad', 'pulse');
    } catch (e) {
      setRun({ pid: p.id, running: false, started: 0, error: String((e as { message?: string }).message ?? '') });
      await a.refreshProfiles();
      a.fail(e, <>Health check for <b>{p.name}</b>:</>);
    } finally { clearInterval(iv); }
  };
  useEffect(() => {
    if (argRun === 'run' && p && autorun.current !== a.routeArg) { autorun.current = a.routeArg; start(); }
  }, [a.routeArg, p?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!p) return <Main title="Health Check" sub="No profiles."><div className="card"><Empty icon="pulse" title="No profiles to check" /></div></Main>;
  const hc = run && run.pid === p.id ? run : null;
  const res = hc?.result ? outcomes(hc.result) : null;
  const total = CHECKS.length;
  const cnt = (s: Res['s']) => (res ? CHECKS.filter(c => res[c.id].s === s).length : 0);
  // The backend reports when the whole run is done; the bar estimates progress (~3 s budget).
  const est = hc?.running ? Math.min(0.95, (Date.now() - hc.started) / 3200) : 0;
  const done = Math.round(est * total);
  const sc = hc?.result?.summary.score;
  let ring;
  if (hc?.running) ring = <><div className="ring"><Ring v={Math.round(est * 100)} color="var(--accent)" /><div className="rv"><div style={{ fontSize: 30, fontWeight: 700 }}>{Math.round(est * 100)}%</div><div className="muted" style={{ fontSize: 11 }}>{done} / {total}</div></div></div>
    <div className="acc" style={{ fontWeight: 600, marginTop: 6 }}><Spin s={11} /> Running checks…</div><div className="dim">Engine started in the local test lab</div></>;
  else if (sc != null) ring = <><div className="ring"><Ring v={sc} /><div className="rv"><div style={{ fontSize: 38, fontWeight: 700 }}>{sc}</div><div className="muted" style={{ fontSize: 11 }}>out of 100</div></div></div>
    <div className={sc >= 90 ? 'ok' : sc >= 60 ? 'warn' : 'bad'} style={{ fontWeight: 600, marginTop: 6, textAlign: 'center' }}>{sc >= 90 ? `Looks like one real ${osLong(p.os)} PC` : sc >= 60 ? 'Usable, but fix the notes' : 'Launch blocked until fixed'}</div>
    <div className="dim">{cnt('ok')} of {total} pass · {cnt('warn')} note · {cnt('bad')} fail</div></>;
  else ring = <><div className="ring"><Ring v={p.health} /><div className="rv"><div style={{ fontSize: 38, fontWeight: 700 }}>{p.health || '—'}</div><div className="muted" style={{ fontSize: 11 }}>last score</div></div></div>
    <div className="muted" style={{ marginTop: 6 }}>{hc?.error ? <span className="bad">Last run did not finish</span> : p.status === 'running' ? 'Running now: stop it to run a check' : 'Not run in this session'}</div>
    <button className="btn p s" data-a="runHealth" onClick={start}><Icon n="play" s={13} />Run {total} checks</button></>;

  const isOpen = (k: string) => (open ? open.has(k) : true);
  return (
    <Main title="Health Check" sub="A local test lab: every check runs on this PC against Vanta's own reflector, no third-party site needed."
      actions={<>
        <select className="inp" style={{ width: 190 }} id="hcPick" aria-label="Profile" disabled={hc?.running} value={p.id} onChange={e => { setRun(null); a.go('health', e.target.value); }}>{a.profiles.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select>
        <button className="btn" data-a="hcExport" disabled={!hc?.result} onClick={() => {
          const blob = new Blob([report(p, hc!.result!, a.info.engine_version)], { type: 'text/html' });
          const u = URL.createObjectURL(blob); const l = document.createElement('a'); l.href = u; l.download = `health-${p.name}-${new Date().toISOString().slice(0, 10)}.html`; l.click(); setTimeout(() => URL.revokeObjectURL(u), 1000);
          a.toast(<>Report saved: health-{p.name}-{new Date().toISOString().slice(0, 10)}.html (local file)</>, 'ok', 'export');
        }}><Icon n="export" s={14} />Export report</button>
        <button className="btn p" data-a="runHealth" disabled={hc?.running} onClick={start}>{hc?.running ? <><Spin />Running…</> : <><Icon n="refresh" s={14} />{hc?.result ? 'Run again' : 'Run checks'}</>}</button>
      </>}>
      <div className="row" style={{ flex: 'none' }}>
        <div className="card" style={{ width: 300, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 6, minHeight: 250 }}>{ring}</div>
        <div className="card" style={{ flex: 1 }}><h3>Checks by area <span className="r">{total} checks · runs locally{hc?.dur ? ` · ${hc.dur} s` : ''}</span></h3>
          <div className="grid2" style={{ gap: '0 24px' }}>
            {AREAS.map(([k, label]) => {
              const ids = CHECKS.filter(c => c.area === k).map(c => c.id);
              const st = res ? (ids.some(i => res[i].s === 'bad') ? 'bad' : ids.some(i => res[i].s === 'warn') ? 'warn' : 'ok') : hc?.running ? 'pend' : 'pend';
              return <div key={k} className="chk"><span className={`ic ${st}`}>{st === 'ok' ? '✓' : st === 'bad' ? '✕' : st === 'warn' ? '!' : hc?.running ? <Spin s={10} style={{ borderWidth: 1.5, color: 'var(--accent2)' }} /> : '·'}</span><span>{label}</span><span className="r muted">{res ? `${ids.filter(i => res[i].s === 'ok').length}/${ids.length}` : ids.length}</span></div>;
            })}
          </div>
          {hc?.running && <div className="bar" style={{ marginTop: 10 }}><i style={{ width: `${est * 100}%` }} /></div>}
        </div>
        <div className="card hide-md" style={{ width: 300 }}><h3>Score history <span className="r">last {hist.length} runs</span></h3>
          <div style={{ display: 'flex', gap: 4, height: 120, alignItems: 'flex-end' }}>
            {hist.length ? hist.map((v, i) => <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', alignItems: 'center', gap: 4, height: '100%' }}>
              <div style={{ width: '70%', maxWidth: 26, height: Math.max(4, (v - 30) * 1.4), background: v >= 90 ? 'var(--accent)' : v >= 60 ? 'var(--warn)' : 'var(--bad)', borderRadius: '4px 4px 0 0', opacity: i === hist.length - 1 ? 1 : 0.75 }} /><span className="dim" style={{ fontSize: 10 }}>{v}</span></div>)
              : <div className="dim" style={{ fontSize: 12, alignSelf: 'center' }}>No runs logged yet.</div>}
          </div>
          <div className="dim" style={{ fontSize: 11, marginTop: 8 }}>Any critical failure caps the score at 40. Profiles under 60 cannot launch until fixed.</div></div>
      </div>
      <div className="card" style={{ flex: 'none' }}>
        <h3>{hc?.result ? 'Latest run' : hc?.running ? 'Running' : 'Results'} · {p.name} <span className="r" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {hc?.result && <>{relDay(hc.result.summary.ts_ms)} · engine {hc.result.summary.engine}</>}
          {hc?.result && <Seg value={filt} onChange={setFilt} options={[['all', 'All'], ['issues', 'Issues'], ['pass', 'Passed']]} name="Filter" />}
        </span></h3>
        {!res ? (
          <Empty icon="pulse" title="Run a check to see every result" text={<>{total} checks in 8 areas run locally against Vanta's own reflector. Takes about 3 seconds.</>}>
            {!hc?.running && <button className="btn p s" onClick={start}><Icon n="play" s={13} />Run checks</button>}
          </Empty>
        ) : null}
        {res && <AreaList res={res} filt={filt} isOpen={isOpen} setOpen={setOpen} item={item} setItem={setItem} />}
      </div>
    </Main>
  );
}

function AreaList({ res, filt, isOpen, setOpen, item, setItem }: { res: Record<string, Res>; filt: string; isOpen: (k: string) => boolean; setOpen: (f: (o: Set<string> | null) => Set<string>) => void; item: string | null; setItem: (s: string | null) => void }) {
  const blocks = AREAS.map(([k, label]) => {
    const items = CHECKS.filter(c => c.area === k).filter(c => filt === 'all' || (filt === 'issues' ? res[c.id].s !== 'ok' : res[c.id].s === 'ok'));
    if (!items.length) return null;
    const issues = items.filter(c => res[c.id].s !== 'ok').length;
    return (
      <div key={k} className={`cat ${isOpen(k) ? 'open' : ''}`}>
        <div className="ch" role="button" tabIndex={0} aria-expanded={isOpen(k)} onClick={() => setOpen(o => { const n = new Set(o ?? AREAS.map(x => x[0])); n.has(k) ? n.delete(k) : n.add(k); return n; })}>
          <span className="chev"><Icon n="right" s={14} /></span><b style={{ fontWeight: 600 }}>{label}</b>{issues ? <span className="pill warn">{issues} issue{issues > 1 ? 's' : ''}</span> : <span className="pill ok">all pass</span>}<span className="r dim">{items.length} shown</span>
        </div>
        <div className="cl">{items.map(c => {
          const r = res[c.id]; const o = item === c.id;
          return <div key={c.id} className={`ci ${o ? 'open' : ''}`}>
            <div className="cih" role="button" tabIndex={0} aria-expanded={o} onClick={() => setItem(o ? null : c.id)}>
              <span className={`ic ${r.s}`}>{r.s === 'ok' ? '✓' : r.s === 'bad' ? '✕' : '!'}</span><span style={r.s === 'bad' ? { color: 'var(--badt)' } : undefined}>{c.title}</span>
              {c.severity === 'critical' && <span className="pill" style={{ fontSize: 10 }}>critical</span>}<span className="r dim"><span className="mono" style={{ marginRight: 6 }}>{c.id}</span><Icon n="chev" s={12} /></span>
            </div>
            <div className="cid">{c.why}{r.note && <div style={{ marginTop: 4, color: r.s === 'bad' ? 'var(--badt)' : 'var(--warnt)' }}>{r.note}</div>}</div>
          </div>;
        })}</div>
      </div>
    );
  }).filter(Boolean);
  return blocks.length ? <>{blocks}</> : <div className="empty" style={{ padding: 30 }}><Icon n="check" s={20} /><div>Nothing matches this filter.</div></div>;
}
