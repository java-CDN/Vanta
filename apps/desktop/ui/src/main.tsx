import { createRoot } from 'react-dom/client';
import './style.css';
import './app.css';
import { connect } from './api';
import { AppProvider } from './state/store';
import { App } from './App';

async function boot() {
  const root = createRoot(document.getElementById('root')!);
  try {
    const b = await connect();
    const [info, settings] = await Promise.all([b.appInfo(), b.getSettings()]);
    document.documentElement.dataset.theme = settings.theme;
    root.render(<AppProvider b={b} initialInfo={info} initialSettings={settings}><App /></AppProvider>);
  } catch (e) {
    root.render(<div className="lock-wrap"><div className="card" style={{ padding: 20, maxWidth: 520 }}><b>Vanta could not start</b><div className="muted" style={{ marginTop: 6 }}>{String((e as { message?: string })?.message ?? e)}</div></div></div>);
  }
}
boot();
