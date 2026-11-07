import { useEffect } from 'react';
import { useApp } from './state/store';
import { activity, Nav, Overlays } from './components/Shell';
import { LockScreen } from './screens/Lock';
import { Drawer, ProfilesScreen } from './screens/Profiles';
import { NewProfileScreen } from './screens/NewProfile';
import { FingerprintsScreen } from './screens/Fingerprints';
import { HealthScreen } from './screens/Health';
import { GeoScreen, ProxiesScreen } from './screens/Proxies';
import { NetworkScreen } from './screens/Network';
import { ActivityScreen } from './screens/Activity';
import { SettingsScreen } from './screens/Settings';
import { ErrorBoundary } from './components/ErrorBoundary';

const SCREENS = {
  profiles: ProfilesScreen, new: NewProfileScreen, fingerprints: FingerprintsScreen, health: HealthScreen,
  proxies: ProxiesScreen, geo: GeoScreen, network: NetworkScreen, activity: ActivityScreen, settings: SettingsScreen,
};

export function App() {
  const a = useApp();

  // Keyboard: Ctrl+L locks, Esc closes menu → modal → drawer (prototype behaviour).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'l' || e.key === 'L')) { e.preventDefault(); if (!a.locked) a.lockNow(); return; }
      if (e.key === 'Escape') {
        if (a.menu) { a.closeMenu(); return; }
        if (a.modal) { a.closeModal(); return; }
        if (a.drawer) { a.setDrawer(null); return; }
      }
      const t = e.target as HTMLElement;
      if ((e.key === 'Enter' || e.key === ' ') && t.matches('[tabindex]:not(button):not(input):not(textarea):not(select):not([role=switch]):not([role=checkbox])')) { e.preventDefault(); t.click(); }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [a]);

  // Activity resets the idle lock in the backend (throttled; the backend enforces the timeout).
  useEffect(() => {
    let sent = 0;
    const on = () => {
      activity.last = Date.now();
      if (!a.locked && Date.now() - sent > 15000) { sent = Date.now(); a.b.reportActivity().catch(() => {}); }
    };
    const evs = ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart'];
    evs.forEach(ev => document.addEventListener(ev, on, { passive: true }));
    return () => evs.forEach(ev => document.removeEventListener(ev, on));
  }, [a.locked, a.b]);
  useEffect(() => { if (!a.locked) activity.last = Date.now(); }, [a.locked]);

  // Window close with running profiles asks first (the shell sends close-requested).
  useEffect(() => {
    let u: (() => void) | undefined;
    a.b.onCloseRequested(async ({ running }) => {
      const ok = await a.confirm({ title: 'Close Vanta?', ok: 'Close', text: running ? `${running} running profile${running > 1 ? 's' : ''} will be stopped and the vault locked.` : 'The vault will be locked.' });
      if (ok) a.b.quit();
    }).then(f => { u = f; });
    return () => u?.();
  }, [a.b]); // eslint-disable-line react-hooks/exhaustive-deps

  // Initial data after an unlock that happened before this component mounted.
  useEffect(() => { if (!a.locked && !a.profiles.length) { a.refreshProfiles().catch(() => {}); a.refreshProxies().catch(() => {}); } }, [a.locked]); // eslint-disable-line react-hooks/exhaustive-deps

  const Screen = SCREENS[a.route] ?? ProfilesScreen;
  return (
    <div className="win" id="win">
      <div id="app" className="body">
        {a.locked ? <LockScreen /> : <><Nav /><ErrorBoundary resetKey={a.route}><Screen key={a.route} /></ErrorBoundary></>}
      </div>
      {!a.locked && <Drawer />}
      <Overlays />
    </div>
  );
}
