import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { Backend } from '../api/backend';
import { errorText, asCoreError } from '../api/backend';
import type * as T from '../api/types';
import type { IconName } from '../lib/icons';
import { proxyName } from '../lib/format';

export const ROUTES = ['profiles', 'new', 'fingerprints', 'health', 'proxies', 'geo', 'network', 'activity', 'settings'] as const;
export type Route = (typeof ROUTES)[number];

export function parseRoute(hash: string): { route: Route; arg: string } {
  const h = hash.replace(/^#\/?/, '');
  const [r, arg = ''] = h.split('/');
  return { route: (ROUTES as readonly string[]).includes(r) ? (r as Route) : 'profiles', arg: decodeURIComponent(arg) };
}

export interface Toast { id: number; msg: ReactNode; kind: '' | 'ok' | 'bad' | 'warn'; icon?: IconName; out?: boolean }
export interface MenuItem { label: string; icon: IconName; onClick: () => void; danger?: boolean; id?: string }
/** `raw`: the body renders its own `.mb` and `.mf` (for forms whose footer needs the body's state). */
export interface ModalSpec { title: string; width?: number; pill?: ReactNode; body: ReactNode; foot?: ReactNode; raw?: boolean; onClose?: () => void }

export interface AppCtx {
  b: Backend;
  info: T.AppInfo;
  settings: T.Settings;
  locked: boolean;
  route: Route;
  routeArg: string;
  profiles: T.ProfileMeta[];
  proxies: T.ProxyView[];
  busy: Record<string, 'launch' | 'stop'>;
  relays: Record<string, number>;
  flash: string | null;
  drawer: string | null;
  toasts: Toast[];
  modal: ModalSpec | null;
  menu: { x: number; y: number; items: (MenuItem | '-')[] } | null;
  // actions
  go(route: Route, arg?: string): void;
  toast(msg: ReactNode, kind?: Toast['kind'], icon?: IconName): void;
  openModal(m: ModalSpec): void;
  closeModal(): void;
  confirm(o: { title: string; text: ReactNode; ok?: string; danger?: boolean }): Promise<boolean>;
  openMenu(anchor: HTMLElement, items: (MenuItem | '-')[]): void;
  closeMenu(): void;
  setDrawer(id: string | null): void;
  setFlash(id: string | null): void;
  refreshProfiles(): Promise<T.ProfileMeta[]>;
  refreshProxies(): Promise<T.ProxyView[]>;
  patchProfile(m: T.ProfileMeta): void;
  launch(id: string, opts?: { quiet?: boolean; force?: boolean }): Promise<boolean>;
  stop(id: string, opts?: { quiet?: boolean }): Promise<void>;
  lockNow(): Promise<void>;
  unlocked(info?: T.UnlockReport): Promise<void>;
  saveSettings(s: T.Settings): Promise<void>;
  setInfo(i: T.AppInfo): void;
  profName(id: string | null | undefined): string;
  proxyOf(p: T.ProfileMeta | undefined | null): T.ProxyView | undefined;
  usedBy(proxyId: string): T.ProfileMeta[];
  fail(e: unknown, prefix?: ReactNode): void;
}

const Ctx = createContext<AppCtx | null>(null);
export const useApp = () => useContext(Ctx)!;

let toastId = 0;

export function AppProvider({ b, initialInfo, initialSettings, children }: { b: Backend; initialInfo: T.AppInfo; initialSettings: T.Settings; children: ReactNode }) {
  const [info, setInfo] = useState(initialInfo);
  const [settings, setSettings] = useState(initialSettings);
  const [locked, setLocked] = useState(!initialInfo.unlocked);
  const [loc, setLoc] = useState(() => parseRoute(location.hash));
  const [profiles, setProfiles] = useState<T.ProfileMeta[]>([]);
  const [proxies, setProxies] = useState<T.ProxyView[]>([]);
  const [busy, setBusy] = useState<Record<string, 'launch' | 'stop'>>({});
  const [relays, setRelays] = useState<Record<string, number>>({});
  const [flash, setFlash] = useState<string | null>(null);
  const [drawer, setDrawer] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [modal, setModal] = useState<ModalSpec | null>(null);
  const [menu, setMenu] = useState<AppCtx['menu']>(null);
  const profilesRef = useRef(profiles); profilesRef.current = profiles;
  const settingsRef = useRef(settings); settingsRef.current = settings;

  useEffect(() => { document.documentElement.dataset.theme = settings.theme; }, [settings.theme]);
  useEffect(() => {
    const on = () => { setLoc(parseRoute(location.hash)); setDrawer(null); setMenu(null); };
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);

  const toast = useCallback((msg: ReactNode, kind: Toast['kind'] = '', icon?: IconName) => {
    const id = ++toastId;
    setToasts(t => [...t.slice(-4), { id, msg, kind, icon }]);
    setTimeout(() => setToasts(t => t.map(x => (x.id === id ? { ...x, out: true } : x))), 3800);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 4100);
  }, []);
  const fail = useCallback((e: unknown, prefix?: ReactNode) => {
    toast(<>{prefix}{prefix ? ' ' : ''}{errorText(e)}</>, 'bad', asCoreError(e).kind === 'blocked' ? 'shield' : 'alert');
  }, [toast]);

  const refreshProfiles = useCallback(async () => {
    const page = await b.listProfiles('', 1_000_000, 0);
    setProfiles(page.items);
    return page.items;
  }, [b]);
  const refreshProxies = useCallback(async () => { const l = await b.listProxies(); setProxies(l); return l; }, [b]);

  // pushed events
  useEffect(() => {
    const subs: Promise<() => void>[] = [
      b.onStatus(ch => setProfiles(ps => ps.map(p => { const c = ch.find(x => x.profile_id === p.id); return c ? { ...p, status: c.status, last_opened_ms: c.status === 'running' ? Date.now() : p.last_opened_ms } : p; }))),
      b.onLocked(() => { setLocked(true); setModal(null); setMenu(null); setDrawer(null); }),
      b.onLog(entries => {
        for (const e of entries) {
          if (e.kind === 'kill_switch') toast(<><b>{nameOf(e.profile)}</b>: kill switch tripped, all connections cut. {e.detail}</>, 'bad', 'shield');
          if (e.kind === 'profile_crash') toast(<><b>{nameOf(e.profile)}</b> crashed: {e.detail}</>, 'bad', 'alert');
        }
      }),
    ];
    return () => { subs.forEach(s => s.then(u => u())); };
    function nameOf(id: string | null) { return profilesRef.current.find(p => p.id === id)?.name ?? 'Profile'; }
  }, [b, toast]);

  const closeModal = useCallback(() => setModal(m => { m?.onClose?.(); return null; }), []);
  const confirm = useCallback((o: { title: string; text: ReactNode; ok?: string; danger?: boolean }) => new Promise<boolean>(resolve => {
    let done = false;
    const finish = (v: boolean) => { if (!done) { done = true; resolve(v); } };
    setModal({
      title: o.title, width: 440, onClose: () => finish(false),
      body: <div style={{ color: 'var(--text2)', lineHeight: 1.5 }}>{o.text}</div>,
      foot: <>
        <button className="btn" onClick={() => { finish(false); setModal(null); }}>Cancel</button>
        <button className={`btn ${o.danger ? 'd' : 'p'}`} id="cfOk" autoFocus onClick={() => { finish(true); setModal(null); }}>{o.ok ?? 'Confirm'}</button>
      </>,
    });
  }), []);

  const launch = useCallback(async (id: string, opts: { quiet?: boolean; force?: boolean } = {}) => {
    const p = profilesRef.current.find(x => x.id === id);
    if (!p || p.status === 'running') return false;
    const running = profilesRef.current.filter(x => x.status === 'running').length;
    if (!opts.force && running >= settingsRef.current.max_launch) {
      const ok = await confirm({ title: 'Launch another profile?', text: `${running} profiles are already running. Your limit before asking is ${settingsRef.current.max_launch}.`, ok: 'Launch anyway' });
      if (!ok) return false;
    }
    setBusy(x => ({ ...x, [id]: 'launch' }));
    setProfiles(ps => ps.map(x => (x.id === id ? { ...x, status: 'starting' } : x)));
    try {
      const li = await b.launchProfile(id);
      setRelays(r => ({ ...r, [id]: li.relay_port }));
      setProfiles(ps => ps.map(x => (x.id === id ? { ...x, status: 'running', last_opened_ms: Date.now() } : x)));
      if (!opts.quiet) toast(<><b>{p.name}</b> is running · engine {li.engine_version} · relay 127.0.0.1:{li.relay_port}</>, 'ok', 'play');
      return true;
    } catch (e) {
      const c = asCoreError(e);
      setProfiles(ps => ps.map(x => (x.id === id ? { ...x, status: c.kind === 'blocked' || c.kind === 'bad_config_signature' || c.kind === 'version_mismatch' ? 'blocked' : 'stopped' } : x)));
      if (c.kind === 'blocked') toast(<><b>{p.name}</b> did not launch: {errorText(c)}. Nothing was sent.</>, 'bad', 'shield');
      else fail(e, <><b>{p.name}</b>:</>);
      return false;
    } finally {
      setBusy(x => { const n = { ...x }; delete n[id]; return n; });
    }
  }, [b, confirm, toast, fail]);

  const stop = useCallback(async (id: string, opts: { quiet?: boolean } = {}) => {
    const p = profilesRef.current.find(x => x.id === id);
    if (!p || p.status !== 'running') return;
    setBusy(x => ({ ...x, [id]: 'stop' }));
    try {
      await b.stopProfile(id);
      setProfiles(ps => ps.map(x => (x.id === id ? { ...x, status: 'stopped' } : x)));
      if (!opts.quiet) toast(<><b>{p.name}</b> stopped · RAM released</>, '', 'stop');
    } catch (e) { fail(e); } finally { setBusy(x => { const n = { ...x }; delete n[id]; return n; }); }
  }, [b, toast, fail]);

  const unlocked = useCallback(async () => {
    const [i] = await Promise.all([b.appInfo(), refreshProfiles(), refreshProxies()]);
    setInfo(i);
    setLocked(false);
  }, [b, refreshProfiles, refreshProxies]);

  const value = useMemo<AppCtx>(() => ({
    b, info, settings, locked, route: loc.route, routeArg: loc.arg, profiles, proxies, busy, relays, flash, drawer, toasts, modal, menu,
    go: (r, arg) => { const h = '#/' + r + (arg ? '/' + encodeURIComponent(arg) : ''); if (location.hash !== h) location.hash = h; else setLoc(parseRoute(h)); },
    toast, openModal: m => { setMenu(null); setModal(m); }, closeModal, confirm,
    openMenu: (a, items) => { const r = a.getBoundingClientRect(); setMenu({ x: r.right, y: r.bottom, items }); },
    closeMenu: () => setMenu(null),
    setDrawer, setFlash: id => { setFlash(id); if (id) setTimeout(() => setFlash(f => (f === id ? null : f)), 1700); },
    refreshProfiles, refreshProxies,
    patchProfile: m => setProfiles(ps => (ps.some(p => p.id === m.id) ? ps.map(p => (p.id === m.id ? m : p)) : [m, ...ps])),
    launch, stop,
    lockNow: async () => { await b.lock(); setLocked(true); setModal(null); setMenu(null); setDrawer(null); },
    unlocked,
    saveSettings: async s => { const n = await b.setSettings(s); setSettings(n); },
    setInfo,
    profName: id => profiles.find(p => p.id === id)?.name ?? (id ? id.slice(0, 8) : '—'),
    proxyOf: p => (p?.proxy_id ? proxies.find(x => x.id === p.proxy_id) : undefined),
    usedBy: pid => profiles.filter(p => p.proxy_id === pid),
    fail,
  }), [b, info, settings, locked, loc, profiles, proxies, busy, relays, flash, drawer, toasts, modal, menu, toast, closeModal, confirm, refreshProfiles, refreshProxies, launch, stop, unlocked, fail]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const proxyLabel = (x: T.ProxyView | undefined) => (x ? proxyName(x) : 'none');
