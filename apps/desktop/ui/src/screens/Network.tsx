import { useEffect, useState, type ReactNode } from 'react';
import { useApp } from '../state/store';
import { Main } from '../components/Shell';
import { CC, Icon, Spin, Tog } from '../components/ui';
import type * as T from '../api/types';
import { CHECKS } from '../lib/catalog';
import { dayStart, hms, LOG_INFO, proxyName, schemeLabel } from '../lib/format';
import { outcomes } from './Health';
import { DOH } from './NewProfile';

const dohKey = (d: T.DohProvider) => (typeof d === 'string' ? d : 'custom');
const LIMIT = 200;

function Locked({ label, desc, extra }: { label: string; desc: string; extra?: ReactNode }) {
  return <div className="chk" style={{ alignItems: 'flex-start' }}><div><div style={{ fontWeight: 550 }}>{label}</div><div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>{desc}</div></div>
    <span className="r" style={{ display: 'flex', gap: 8, alignItems: 'center', paddingLeft: 12 }}>{extra}<span className="lock-ic"><Icon n="lock" s={11} />always on</span><Tog on locked label={label} /></span></div>;
}

export function NetworkScreen() {
  const a = useApp();
  const [tp, setTp] = useState(a.profiles.find(p => p.proxy_id)?.id ?? a.profiles[0]?.id ?? '');
  const [pol, setPol] = useState<Record<string, T.GuardPolicy>>({});
  const [blocked, setBlocked] = useState<T.LogEntry[]>([]);
  const [dns, setDns] = useState<{ running: boolean; prof: string; at?: string; result?: T.HealthResult; error?: string } | null>(null);
  useEffect(() => {
    let live = true;
    const ids = a.profiles.slice(0, LIMIT).map(p => p.id);
    let i = 0;
    Promise.all(Array.from({ length: 6 }, async () => { while (i < ids.length && live) { const id = ids[i++]; try { const g = await a.b.guardPolicy(id); if (live) setPol(m => ({ ...m, [id]: g })); } catch { /* ignore */ } } }));
    a.b.activityLog({ kinds: ['blocked_event', 'kill_switch', 'launch_blocked'], from_ms: dayStart(Date.now()), limit: 50 }).then(r => live && setBlocked(r.entries)).catch(() => {});
    return () => { live = false; };
  }, [a.profiles.length, a.b]); // eslint-disable-line react-hooks/exhaustive-deps

  const p = a.profiles.find(x => x.id === tp);
  const px = a.proxyOf(p);
  const down = !px || px.state.state === 'offline';
  const exceptions = Object.values(pol).filter(g => dohKey(g.doh) !== 'cloudflare').length;

  const runDns = async () => {
    if (!p || dns?.running) return;
    setDns({ running: true, prof: p.name });
    try {
      const r = await a.b.runHealth(p.id);
      await a.refreshProfiles();
      setDns({ running: false, prof: p.name, at: hms(new Date()), result: r });
      const res = outcomes(r); const leak = ['H17', 'H18', 'H19', 'H20', 'H21', 'H22'].some(id => res[id]?.s === 'bad');
      a.toast(leak ? 'DNS / WebRTC leak check failed — see the details' : 'No DNS leak: every lookup went through DoH via the proxy', leak ? 'bad' : 'ok', 'pulse');
    } catch (e) { setDns({ running: false, prof: p.name, error: String((e as { message?: string }).message ?? '') }); a.fail(e, 'Leak test:'); }
  };
  const res = dns?.result ? outcomes(dns.result) : null;
  const leakChecks = CHECKS.filter(c => c.area === 'web_rtc_dns');
  const anyBad = res ? leakChecks.some(c => res[c.id].s === 'bad') : false;

  return (
    <Main title="Network Guard" sub="Default for every profile. A profile only launches when all its guards are armed."
      actions={<button className="btn" data-a="dnsTest" disabled={dns?.running || !p} onClick={runDns}><Icon n="pulse" s={14} />Run DNS leak test</button>}>
      <div className="row" style={{ alignItems: 'flex-start' }}>
        <div className="col" style={{ flex: 1 }}>
          <div className="card"><h3><Icon n="shield" s={15} />Leak protection <span className="r ok">all on · enforced</span></h3>
            <Locked label="Kill switch" desc="If the proxy drops, the profile loses network at once (5 s heartbeat, live traffic cut at once). No traffic ever goes out directly." />
            <Locked label="WebRTC: proxy only" desc="Chrome policy disable_non_proxied_udp, enforced in the engine. Sites see the exit IP, never your real or local IP." />
            <Locked label="DNS over HTTPS through the relay" desc="All lookups go through the proxy. Your ISP's DNS is never asked. Provider per profile below." />
            <Locked label="Block QUIC / HTTP3 and other UDP" desc="The relay carries TCP only, so QUIC is off and Chrome uses TCP like it does on many networks." />
            <Locked label="Block IPv6" desc="Prevents an IPv6 path that bypasses an IPv4-only proxy." />
            <Locked label="Block local network (LAN) access" desc="Pages cannot reach 192.168.x.x, your router or localhost." />
            <Locked label="Disable background networking" desc="No component updates, safe-browsing pings or metrics. Patched out of the engine." />
            <div className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>These guards have no "off" value in Vanta: no profile and no setting can disable them.</div>
          </div>
          <div className="card"><h3><Icon n="pulse" s={15} />DNS leak test {dns && !dns.running && <span className="r"><button className="btn s" onClick={runDns}><Icon n="refresh" s={12} />Run again</button></span>}</h3>
            {!dns ? <>
              <div className="muted" style={{ fontSize: 12 }}>Starts {p ? <b>{p.name}</b> : 'a profile'} in the local test lab, sends unique look-ups and checks which resolvers answer, plus the WebRTC candidates. Uses the profile's proxy; takes a few seconds.</div>
              <button className="btn p s" style={{ marginTop: 10 }} disabled={!p} onClick={runDns}><Icon n="play" s={13} />Run test</button>
            </> : dns.running ? <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}><Spin style={{ color: 'var(--accent2)' }} /><span>Testing {dns.prof} through its relay…</span></div>
              : !res ? <div className="bad">{dns.error || 'The test did not finish.'}</div>
                : <>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}><span className={`ic ${anyBad ? 'bad' : 'ok'}`} style={{ width: 26, height: 26, fontSize: 13 }}>{anyBad ? '✕' : '✓'}</span>
                    <div><b className={anyBad ? 'bad' : 'ok'}>{anyBad ? 'Leak detected' : 'No DNS leak'}</b><div className="dim" style={{ fontSize: 11.5 }}>{dns.at} · profile {dns.prof} · {leakChecks.length} checks</div></div></div>
                  <table><thead><tr><th>Check</th><th>Verdict</th></tr></thead><tbody>
                    {leakChecks.map(c => <tr key={c.id}><td>{c.title}{res![c.id].note && <div className="dim" style={{ fontSize: 11 }}>{res![c.id].note}</div>}</td><td><span className={`pill ${res![c.id].s === 'ok' ? 'ok' : res![c.id].s === 'bad' ? 'bad' : 'warn'}`}>{res![c.id].s === 'ok' ? 'via proxy' : res![c.id].s === 'bad' ? 'leak' : 'note'}</span></td></tr>)}
                  </tbody></table>
                </>}
          </div>
        </div>
        <div className="col" style={{ flex: 1.15 }}>
          <div className="card"><h3><Icon n="zap" s={15} />Traffic path <select className="inp" style={{ width: 170, marginLeft: 6, padding: '4px 26px 4px 8px', fontSize: 12 }} id="ngProf" aria-label="Profile" value={tp} onChange={e => setTp(e.target.value)}>{a.profiles.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select></h3>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '8px 0 6px' }}>
              {([['Engine', 'no direct route'], ['Local relay', `${p && a.relays[p.id] && p.status === 'running' ? `127.0.0.1:${a.relays[p.id]}` : '127.0.0.1:<per launch>'} · DoH`], ['Proxy', px ? `${schemeLabel(px.scheme)} · ${proxyName(px)}` : 'none'], ['Internet', px ? (p?.exit_ip ? `exit ${p.exit_ip} ${p.country}` : 'exit measured at launch') : 'blocked']] as [string, string][]).map(([x, y], i) => (
                <div key={x} style={{ display: 'contents' }}>
                  <div style={{ flex: 1, textAlign: 'center', padding: '12px 6px', border: `1px solid ${down && i >= 2 ? 'rgba(229,83,75,.5)' : 'var(--line2)'}`, borderRadius: 10, background: 'var(--sub)', minWidth: 0 }}>
                    <div style={{ fontWeight: 600 }}>{x}</div><div className="dim" style={{ fontSize: 11, marginTop: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{y}</div></div>
                  {i < 3 && <div style={{ color: down && i >= 1 ? 'var(--bad)' : 'var(--accent2)' }}>{down && i === 1 ? '✕' : '→'}</div>}
                </div>
              ))}
            </div>
            <div className="note"><Icon n="lock" s={13} /><span>{px && px.state.state === 'offline' ? 'Proxy is offline: the kill switch keeps this profile from launching. Nothing goes out directly.' : !px ? 'No proxy: the profile cannot launch. Nothing goes out directly.' : 'The engine only knows the local relay address. Only processes in the profile\'s own Job Object may use it; the proxy password never reaches the browser process.'}</span></div>
          </div>
          <div className="card"><h3><Icon n="gear" s={15} />Per-profile settings <span className="r">{exceptions} non-default DoH provider{exceptions === 1 ? '' : 's'}</span></h3>
            <div style={{ maxHeight: 300, overflow: 'auto' }}><table><thead><tr><th>Profile</th><th>Proxy</th><th>DoH provider</th><th>QUIC · IPv6 · LAN</th><th>Kill switch · WebRTC</th></tr></thead><tbody>
              {a.profiles.slice(0, LIMIT).map(q => {
                const x = a.proxyOf(q); const g = pol[q.id];
                return <tr key={q.id}><td><b style={{ fontWeight: 600 }}>{q.name}</b></td><td>{x ? <span className="pill">{schemeLabel(x.scheme)}</span> : <span className="dim">—</span>}</td>
                  <td>{g ? <select className="inp" style={{ width: 170, padding: '3px 24px 3px 8px', fontSize: 12 }} aria-label={`DoH provider for ${q.name}`} value={dohKey(g.doh)} disabled={dohKey(g.doh) === 'custom'}
                    onChange={async e => {
                      const v = e.target.value as T.DohProvider;
                      try { const n = await a.b.setDohProvider(q.id, v); setPol(m => ({ ...m, [q.id]: n })); await a.refreshProfiles(); a.toast(<>{q.name}: DoH via {DOH.find(d => d[0] === v)?.[1]}. Run a health check before the next launch.</>, 'ok', 'shield'); }
                      catch (er) { a.fail(er); }
                    }}>{DOH.map(([v, l]) => <option key={v} value={v}>{l}</option>)}{dohKey(g.doh) === 'custom' && <option value="custom">Custom</option>}</select> : <Spin s={10} />}</td>
                  <td><span className="lock-ic"><Icon n="lock" s={12} />blocked</span></td>
                  <td><span className="lock-ic" title="Cannot be turned off per profile"><Icon n="lock" s={12} />on</span></td></tr>;
              })}</tbody></table></div>
            <div className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>{a.profiles.length > LIMIT ? `First ${LIMIT} profiles. ` : ''}The kill switch, WebRTC rule, QUIC, IPv6 and LAN blocking cannot be turned off for any profile. Changing the DoH provider clears the profile's health check.</div>
          </div>
          <div className="card"><h3><Icon n="alert" s={15} />Blocked today <span className="r">{blocked.length} event{blocked.length === 1 ? '' : 's'} · nothing leaked</span></h3>
            {blocked.length ? <table><thead><tr><th>Time</th><th>Profile</th><th>What</th><th>Result</th></tr></thead><tbody>
              {blocked.slice(0, 8).map(e => <tr key={e.seq}><td className="mono muted">{hms(new Date(e.ts_ms))}</td><td>{a.profName(e.profile)}</td><td style={{ whiteSpace: 'normal' }}>{LOG_INFO[e.kind].title} <span className="dim">· {e.detail}</span></td>
                <td><span className={`pill ${e.kind === 'blocked_event' ? 'warn' : 'bad'}`}>{e.kind === 'launch_blocked' ? 'launch blocked' : e.kind === 'kill_switch' ? 'cut' : 'blocked'}</span></td></tr>)}
            </tbody></table> : <div className="empty" style={{ padding: 24 }}><Icon n="shield" s={20} /><div>Nothing blocked today.</div></div>}
            {p && <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>Exit for {p.name}: {p.exit_ip ? <><CC c={p.country} /> {p.exit_ip}</> : 'not measured yet'}</div>}
          </div>
        </div>
      </div>
    </Main>
  );
}
