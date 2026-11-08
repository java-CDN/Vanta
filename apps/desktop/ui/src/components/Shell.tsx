import { useEffect, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { useApp, type Route } from '../state/store';
import { Icon } from './ui';
import type { IconName } from '../lib/icons';
import { autolockLabel, pad } from '../lib/format';

const NAV: [string, [Route, IconName, string][]][] = [
  ['WORKSPACE', [['profiles', 'users', 'Profiles'], ['fingerprints', 'fp', 'Fingerprints'], ['health', 'pulse', 'Health Check'], ['proxies', 'globe', 'Proxies'], ['network', 'shield', 'Network Guard']]],
  ['SYSTEM', [['activity', 'list', 'Activity Log'], ['settings', 'gear', 'Settings']]],
];
const NAV_OWNER: Partial<Record<Route, Route>> = { new: 'profiles', geo: 'proxies' };

/** Shared last-activity clock for the footer countdown (the lock itself runs in the backend). */
export const activity = { last: Date.now() };

export function Nav() {
  const a = useApp();
  const owner = NAV_OWNER[a.route] || a.route;
  const running = a.profiles.filter(p => p.status === 'running').length;
  const counts: Partial<Record<Route, number>> = { profiles: a.profiles.length, proxies: a.proxies.length };
  const [, tick] = useState(0);
  useEffect(() => { const t = setInterval(() => tick(x => x + 1), 1000); return () => clearInterval(t); }, []);
  const ms = a.settings.autolock_minutes * 60000;
  const left = ms ? Math.max(0, ms - (Date.now() - activity.last)) : 0;
  return (
    <nav className="nav" aria-label="Main">
      <div className="brand"><div className="lg"><Icon n="shield" s={17} /></div><div><b>Vanta</b><small>Private multi-profile browser</small></div></div>
      {NAV.map(([g, items]) => (
        <div key={g} style={{ display: 'contents' }}>
          <div className="grp">{g}</div>
          {items.map(([k, i, l]) => (
            <a key={k} href={`#/${k}`} className={k === owner ? 'on' : ''} aria-current={k === owner ? 'page' : undefined}>
              <Icon n={i} /><span>{l}</span>
              <span className="n">{k === 'profiles' && running > 0 && <span className="dot pulse" style={{ width: 6, height: 6, marginRight: 5, verticalAlign: 1 }} title={`${running} running`} />}{counts[k] != null ? counts[k]!.toLocaleString() : ''}</span>
            </a>
          ))}
        </div>
      ))}
      <div className="navfoot">
        <div className="r" id="enginelbl" title={`Vanta Chromium ${a.info.engine_version}`}><span className={`dot ${!a.info.engine_found || a.info.engine_check.state === 'failed' ? 'w' : ''}`} />Engine {a.info.engine_version}{a.info.engine_check.state === 'failed' ? ' · invalid' : !a.info.engine_found ? ' · not found' : a.info.engine_check.state === 'pending' ? ' · checking…' : ''}</div>
        <div className="r" id="vaultlbl"><span className="dot i" />Vault unlocked · {autolockLabel(a.settings.autolock_minutes)}</div>
        <div className="lockbar" title="Time until auto-lock"><i id="lockbar" style={{ width: ms ? `${((left / ms) * 100).toFixed(1)}%` : '100%' }} /></div>
        <div className="dim" id="lockleft" style={{ fontSize: 10.5, margin: '-3px 0 0 14px' }}>{ms ? `Locks in ${Math.floor(left / 60000)}:${pad(Math.floor((left % 60000) / 1000))} if idle` : 'auto-lock is off'}</div>
        <button className="r" data-a="lockNow" onClick={() => a.lockNow()}><Icon n="lock" s={13} /><span style={{ marginLeft: 6 }}>Lock now <kbd style={{ marginLeft: 4 }}>Ctrl L</kbd></span></button>
      </div>
    </nav>
  );
}

export function Main({ title, sub, actions, contentStyle, children }: { title: ReactNode; sub: ReactNode; actions?: ReactNode; contentStyle?: CSSProperties; children: ReactNode }) {
  return (
    <main className="main">
      <div className="hd"><div><h1>{title}</h1><div className="sub">{sub}</div></div><div className="act">{actions}</div></div>
      <div className="content" style={contentStyle}><div className="view" style={{ display: 'contents' }}>{children}</div></div>
    </main>
  );
}

export function Overlays() {
  const a = useApp();
  const menuRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  useLayoutEffect(() => {
    if (!a.menu || !menuRef.current) { setPos(null); return; }
    const m = menuRef.current; const mh = m.offsetHeight, mw = m.offsetWidth;
    let top = a.menu.y + 4; if (top + mh > innerHeight - 8) top = a.menu.y - mh - 30;
    setPos({ top, left: Math.max(8, Math.min(innerWidth - mw - 8, a.menu.x - mw)) });
    setTimeout(() => (m.querySelector('button') as HTMLButtonElement | null)?.focus(), 10);
  }, [a.menu]);
  useEffect(() => {
    if (!a.menu) return;
    const h = (e: MouseEvent) => { if (menuRef.current && !menuRef.current.contains(e.target as Node)) a.closeMenu(); };
    const t = setTimeout(() => document.addEventListener('mousedown', h), 0);
    return () => { clearTimeout(t); document.removeEventListener('mousedown', h); };
  }, [a.menu, a]);
  return (
    <>
      <div id="layer">
        {a.modal && (
          <div className="ovl" onMouseDown={e => { if (e.target === e.currentTarget) a.closeModal(); }}>
            <div className="modal" role="dialog" aria-modal="true" aria-label={a.modal.title} style={{ width: a.modal.width ?? 520 }}
              onKeyDown={e => {
                const t = e.target as HTMLElement;
                if (e.key === 'Enter' && t.tagName === 'INPUT') { const p = (e.currentTarget.querySelector('.mf .btn.p') as HTMLButtonElement | null); if (p && !p.disabled) { e.preventDefault(); p.click(); } }
              }}>
              <div className="mh"><b>{a.modal.title}</b>{a.modal.pill}<button className="ib" style={{ marginLeft: 'auto' }} data-a="closeModal" onClick={a.closeModal} aria-label="Close"><Icon n="x" s={16} /></button></div>
              {a.modal.raw ? a.modal.body : <>
                <div className="mb">{a.modal.body}</div>
                {a.modal.foot && <div className="mf">{a.modal.foot}</div>}
              </>}
            </div>
          </div>
        )}
      </div>
      {a.menu && (
        <div className="menu" id="menu" role="menu" ref={menuRef} style={pos ? { top: pos.top, left: pos.left } : { visibility: 'hidden', top: 0, left: 0 }}
          onKeyDown={e => {
            if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
            e.preventDefault(); const bs = [...e.currentTarget.querySelectorAll('button')]; const i = bs.indexOf(document.activeElement as HTMLButtonElement);
            bs[(i + (e.key === 'ArrowDown' ? 1 : -1) + bs.length) % bs.length].focus();
          }}>
          {a.menu.items.map((it, i) => it === '-' ? <hr key={i} /> : (
            <button key={i} role="menuitem" className={it.danger ? 'd' : ''} data-a={it.id} onClick={() => { a.closeMenu(); it.onClick(); }}><Icon n={it.icon} s={14} />{it.label}</button>
          ))}
        </div>
      )}
      <div className="toasts" id="toasts" aria-live="polite">
        {a.toasts.map(t => {
          const ico: IconName = t.icon || (t.kind === 'ok' ? 'check' : t.kind === 'bad' || t.kind === 'warn' ? 'alert' : 'info');
          const col = t.kind === 'ok' ? 'var(--ok)' : t.kind === 'bad' ? 'var(--badt)' : t.kind === 'warn' ? 'var(--warn)' : 'var(--accent2)';
          return (
            <div key={t.id} className={`toast ${t.kind} ${t.out ? 'out' : ''}`} role="status">
              <span style={{ color: col, display: 'flex' }}><Icon n={ico} s={16} /></span><span style={{ flex: 1 }}>{t.msg}</span>
            </div>
          );
        })}
      </div>
    </>
  );
}
