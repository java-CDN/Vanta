import { useEffect, useRef, useState } from 'react';
import { useApp } from '../state/store';
import { Icon, Spin } from '../components/ui';
import { asCoreError, errorText } from '../api/backend';
import { AUTOLOCK_OPTIONS } from '../lib/format';

function Logo() {
  return <div style={{ width: 64, height: 64, borderRadius: 18, margin: '0 auto 18px', background: 'linear-gradient(135deg,#6366f1,#8b5cf6)', display: 'grid', placeItems: 'center', boxShadow: '0 18px 50px rgba(99,102,241,.35)' }}><Icon n="shield" s={32} style={{ color: '#fff' }} /></div>;
}

function strength(v: string) {
  return Math.min(100, v.length * 6 + (/[A-Z]/.test(v) ? 10 : 0) + (/\d/.test(v) ? 10 : 0) + (/[^\w]/.test(v) ? 12 : 0) + (/\s/.test(v) ? 10 : 0));
}

export function StrengthBar({ v }: { v: string }) {
  const s = strength(v);
  return <>
    <div className="bar" style={{ marginTop: 4 }}><i style={{ width: `${s}%`, background: s < 50 ? 'var(--bad)' : s < 80 ? 'var(--warn)' : 'var(--ok)' }} /></div>
    <div className="dim" style={{ fontSize: 11 }}>{!v ? 'At least 12 characters. A passphrase of 4+ words is best.' : s < 50 ? 'Weak' : s < 80 ? 'Okay' : 'Strong'}</div>
  </>;
}

/** First run: create the vault, then show the recovery key exactly once. */
function CreateVault() {
  const a = useApp();
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [key, setKey] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const submit = async () => {
    setErr('');
    if (pw.length < 12) return setErr('Use at least 12 characters.');
    if (pw !== pw2) return setErr('The passwords do not match.');
    setBusy(true);
    try { const r = await a.b.createVault(pw); setPw(''); setPw2(''); setKey(r.recovery_key); }
    catch (e) { setErr(errorText(e)); }
    finally { setBusy(false); }
  };
  if (key) {
    return (
      <div style={{ width: 520, textAlign: 'center' }}>
        <Logo />
        <div style={{ fontSize: 24, fontWeight: 650 }}>Your recovery key</div>
        <div className="muted" style={{ margin: '6px 0 20px' }}>Shown once. Write it down or print it and keep it offline.</div>
        <div className="card" style={{ textAlign: 'left', padding: 20 }}>
          <div className="mono" id="recoveryKey" style={{ fontSize: 17, letterSpacing: 1, textAlign: 'center', padding: '14px 8px', border: '1px dashed var(--line2)', borderRadius: 10, userSelect: 'all', wordBreak: 'break-all' }}>{key}</div>
          <div className="note" style={{ marginTop: 12 }}><Icon n="key" s={13} /><span>It opens the vault if you forget the master password. Vanta does not keep a copy: once you leave this screen it cannot be shown again.</span></div>
          <label style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 14, cursor: 'pointer' }} className="muted">
            <span className={`cb ${saved ? 'on' : ''}`} id="rkSaved" role="checkbox" aria-checked={saved} tabIndex={0} onClick={() => setSaved(!saved)} onKeyDown={e => { if (e.key === ' ') { e.preventDefault(); setSaved(!saved); } }} />I have stored the recovery key safely
          </label>
          <button className="btn p" id="rkDone" style={{ width: '100%', justifyContent: 'center', padding: 10, marginTop: 14 }} disabled={!saved} onClick={async () => { setKey(null); await a.unlocked(); a.go('profiles'); a.toast('Vault created', 'ok', 'lock'); }}>Continue to Vanta</button>
        </div>
      </div>
    );
  }
  return (
    <div style={{ width: 440, textAlign: 'center' }}>
      <Logo />
      <div style={{ fontSize: 26, fontWeight: 650 }}>Create your vault</div>
      <div className="muted" style={{ margin: '6px 0 24px' }}>Every profile, proxy password and log entry is encrypted with this master password.</div>
      <form className="card" style={{ textAlign: 'left', padding: 20 }} onSubmit={e => { e.preventDefault(); submit(); }}>
        <div className="field"><label htmlFor="newPw">Master password</label><input className="inp" id="newPw" type="password" autoComplete="new-password" value={pw} onChange={e => setPw(e.target.value)} autoFocus /><StrengthBar v={pw} /></div>
        <div className="field" style={{ marginTop: 10 }}><label htmlFor="newPw2">Repeat password</label><input className="inp" id="newPw2" type="password" autoComplete="new-password" value={pw2} onChange={e => setPw2(e.target.value)} /></div>
        <div className="err" id="cvErr" role="alert">{err}</div>
        <button className="btn p" id="createBtn" type="submit" style={{ width: '100%', justifyContent: 'center', padding: 10, marginTop: 12 }} disabled={busy}>{busy ? <><Spin />Creating vault…</> : 'Create vault'}</button>
        <div className="note" style={{ marginTop: 14 }}><Icon n="lock" s={13} /><span>Argon2id (64 MiB, 3 passes) → XChaCha20-Poly1305. A recovery key is shown once after this step. Nothing is sent anywhere.</span></div>
      </form>
    </div>
  );
}

function Unlock() {
  const a = useApp();
  const [pw, setPw] = useState('');
  const [show, setShow] = useState(false);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [shake, setShake] = useState(0);
  const [recovery, setRecovery] = useState(false);
  const inp = useRef<HTMLInputElement>(null);
  useEffect(() => { setTimeout(() => inp.current?.focus(), 30); }, [recovery]);
  const go = async () => {
    if (busy) return;
    setErr('');
    if (!pw) { setErr(recovery ? 'Enter your recovery key.' : 'Enter your master password.'); setShake(s => s + 1); return; }
    setBusy(true);
    try {
      const r = recovery ? await a.b.unlockWithRecovery(pw) : await a.b.unlock(pw);
      setPw('');
      await a.unlocked(r);
      if (r.log_integrity.state !== 'ok') a.toast(<>Activity log integrity: {r.log_integrity.detail}</>, 'warn', 'alert');
      else a.toast(recovery ? 'Unlocked with the recovery key. Set a new master password in Settings.' : 'Vault unlocked', 'ok', 'lock');
    } catch (e) {
      const c = asCoreError(e);
      setErr(c.kind === 'crypto' ? (recovery ? 'That recovery key does not open this vault.' : 'Wrong master password. Check Caps Lock and type it again.') : errorText(e));
      setShake(s => s + 1);
      inp.current?.select();
    } finally { setBusy(false); }
  };
  const al = AUTOLOCK_OPTIONS.find(o => o[0] === a.settings.autolock_minutes)?.[1];
  return (
    <div style={{ width: 440, textAlign: 'center' }}>
      <Logo />
      <div style={{ fontSize: 26, fontWeight: 650 }}>Vanta is locked</div>
      <div className="muted" style={{ margin: '6px 0 24px' }}>Profiles and proxies are encrypted with your master password</div>
      <form className={`card ${shake ? 'shake' : ''}`} key={shake} id="lockcard" style={{ textAlign: 'left', padding: 20 }} onSubmit={e => { e.preventDefault(); go(); }}>
        <div className="field"><label htmlFor="pw">{recovery ? 'Recovery key' : 'Master password'}</label>
          <div className={`inp ${err ? 'invalid' : ''}`} style={{ padding: '9px 12px' }} id="pwbox"><Icon n="key" s={15} />
            <input id="pw" ref={inp} type={show || recovery ? 'text' : 'password'} autoComplete={recovery ? 'off' : 'current-password'} placeholder={recovery ? 'XXXX-XXXX-…' : 'Enter master password'} aria-describedby="pwerr" value={pw} onChange={e => setPw(e.target.value)} spellCheck={false} />
            {!recovery && <button type="button" className="ib" style={{ width: 22, height: 22 }} onClick={() => setShow(!show)} aria-label="Show password"><Icon n={show ? 'eyeoff' : 'eye'} s={15} /></button>}
          </div>
          <div className="err" id="pwerr" role="alert">{err}</div></div>
        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          <button className="btn p" id="unlockBtn" style={{ flex: 1, justifyContent: 'center', padding: 10 }} type="submit">{busy ? <><Spin />Unlocking…</> : 'Unlock'}</button>
          <button type="button" className="btn" style={{ padding: '10px 14px' }} disabled title="Windows Hello unlock is not available in this build"><Icon n="key" s={14} />Windows Hello</button>
        </div>
        <div className="note" style={{ marginTop: 14 }}><Icon n="lock" s={13} /><span>Argon2id (64 MiB, 3 passes) → XChaCha20-Poly1305. Unlock takes about 0.7 s on purpose so guessing is slow. Nothing is sent anywhere.</span></div>
      </form>
      <div className="dim" style={{ marginTop: 16, fontSize: 11.5 }}>
        {a.settings.autolock_minutes ? `Auto-locks after ${al} idle` : 'Auto-lock is off'} · <span className="lnk" id="useRecovery" role="button" tabIndex={0} onClick={() => { setRecovery(!recovery); setErr(''); setPw(''); }}>{recovery ? 'Use the master password' : 'Forgot password? Use the recovery key'}</span>
      </div>
    </div>
  );
}

export function LockScreen() {
  const a = useApp();
  return <div className="lock-wrap">{a.info.initialized ? <Unlock /> : <CreateVault />}</div>;
}
