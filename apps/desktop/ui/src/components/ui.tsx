import { useEffect, useRef, type CSSProperties, type ReactNode } from 'react';
import { P, type IconName } from '../lib/icons';
import { osLabel, scoreCls } from '../lib/format';
import type { OsKind } from '../api/types';

export function Icon({ n, s = 16, style }: { n: IconName; s?: number; style?: CSSProperties }) {
  // P holds static, bundled SVG path markup (never user data).
  return <svg className="i" viewBox="0 0 24 24" style={{ width: s, height: s, ...style }} dangerouslySetInnerHTML={{ __html: P[n] }} />;
}

export function WinLogo({ s = 13, style }: { s?: number; style?: CSSProperties }) {
  return (
    <svg viewBox="0 0 16 16" style={{ width: s, height: s, flex: 'none', ...style }}>
      <rect x="0" y="0" width="7.4" height="7.4" fill="#4ea8ff" /><rect x="8.6" y="0" width="7.4" height="7.4" fill="#4ea8ff" />
      <rect x="0" y="8.6" width="7.4" height="7.4" fill="#4ea8ff" /><rect x="8.6" y="8.6" width="7.4" height="7.4" fill="#4ea8ff" />
    </svg>
  );
}

export const OsBadge = ({ os }: { os: OsKind }) => <span className="osic"><WinLogo /><span>{osLabel(os)}</span></span>;
export const CC = ({ c }: { c?: string | null }) => <span className="cc">{c || '—'}</span>;
export const Score = ({ n }: { n: number | null | undefined }) => (n == null || n === 0 ? <span className="dim">—</span> : <span className={`score ${scoreCls(n)}`}>{n}</span>);
export const Spin = ({ s, style }: { s?: number; style?: CSSProperties }) => <span className="spin" style={{ ...(s ? { width: s, height: s } : {}), ...style }} />;

export function Ring({ v, size = 150, w = 14, color }: { v: number; size?: number; w?: number; color?: string }) {
  const r = (size - w) / 2; const c = 2 * Math.PI * r;
  const col = color || (v >= 90 ? 'var(--ok)' : v >= 60 ? 'var(--warn)' : 'var(--bad)');
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--barbg)" strokeWidth={w} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={col} strokeWidth={w} strokeLinecap="round" strokeDasharray={c} strokeDashoffset={c * (1 - v / 100)} style={{ transition: 'stroke-dashoffset .5s ease' }} />
    </svg>
  );
}

export function Tog({ on, locked, label, onChange, className = '', id }: { on: boolean; locked?: boolean; label: string; onChange?: () => void; className?: string; id?: string }) {
  return (
    <span id={id} className={`tog ${on ? 'on' : ''} ${locked ? 'locked' : ''} ${className}`} role="switch" tabIndex={0} aria-checked={on} aria-label={label} aria-disabled={locked || undefined}
      onClick={() => !locked && onChange?.()} onKeyDown={e => { if ((e.key === 'Enter' || e.key === ' ') && !locked) { e.preventDefault(); onChange?.(); } }} />
  );
}

export function Seg<K extends string>({ value, options, onChange, name }: { value: K; options: [K, ReactNode][]; onChange: (k: K) => void; name?: string }) {
  return (
    <span className="seg" role="radiogroup" aria-label={name}>
      {options.map(([k, l]) => <button key={k} role="radio" aria-checked={value === k} className={value === k ? 'on' : ''} data-id={k} onClick={() => onChange(k)}>{l}</button>)}
    </span>
  );
}

export function Chk({ s, children, r }: { s: 'ok' | 'bad' | 'warn' | 'pend'; children: ReactNode; r?: ReactNode }) {
  return <div className="chk"><span className={`ic ${s}`}>{s === 'ok' ? '✓' : s === 'bad' ? '✕' : s === 'warn' ? '!' : '·'}</span><span>{children}</span>{r != null && <span className="r">{r}</span>}</div>;
}

export function Empty({ icon, title, text, children }: { icon: IconName; title: string; text?: ReactNode; children?: ReactNode }) {
  return <div className="empty"><div className="ei"><Icon n={icon} s={22} /></div><b style={{ color: 'var(--text)' }}>{title}</b>{text && <div>{text}</div>}{children}</div>;
}

export function Cb({ on, mid, label, onToggle }: { on: boolean; mid?: boolean; label: string; onToggle: (e: React.MouseEvent | React.KeyboardEvent) => void }) {
  return <span className={`cb ${on ? 'on' : mid ? 'mid' : ''}`} role="checkbox" aria-checked={on} tabIndex={0} aria-label={label}
    onClick={e => { e.stopPropagation(); onToggle(e); }} onKeyDown={e => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); onToggle(e); } }} />;
}

/** Calls `fn` once after mount (async effects). */
export function useMount(fn: () => void | (() => void)) {
  const done = useRef(false);
  useEffect(() => { if (done.current) return; done.current = true; return fn(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
}
