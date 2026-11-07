import { useEffect, useMemo, useRef, useState } from 'react';
import { useApp } from '../state/store';
import { Main } from '../components/Shell';
import { Chk, Icon, Spin, Tog, WinLogo } from '../components/ui';
import type * as T from '../api/types';
import { cleanTag, nameError, newSeed, proxyName, proxyStatus, schemeLabel } from '../lib/format';
import { proxyOptions, sharers } from './Profiles';
import { asCoreError, errorText } from '../api/backend';

export const LOCALES = ['en-US', 'en-GB', 'en-CA', 'en-IN', 'de-DE', 'de-AT', 'fr-FR', 'fr-CA', 'nl-NL', 'es-ES', 'it-IT', 'pl-PL', 'pt-BR', 'ja-JP', 'hi-IN'];
export const DOH: [string, string][] = [['cloudflare', 'Cloudflare (1.1.1.1)'], ['quad9', 'Quad9 (9.9.9.9)'], ['google', 'Google (8.8.8.8)']];

export function NewProfileScreen() {
  const a = useApp();
  const folders = useMemo(() => [...new Set(a.profiles.map(x => x.folder).filter(Boolean))].sort(), [a.profiles]);
  const freeProxy = a.proxies.find(x => x.state.state === 'online' && !a.usedBy(x.id).length);
  const [name, setName] = useState('');
  const [folder, setFolder] = useState(folders[0] ?? '');
  const [tags, setTags] = useState<string[]>([]);
  const [tagIn, setTagIn] = useState('');
  const [os, setOs] = useState<T.OsKind>('windows11');
  const [seed, setSeed] = useState(newSeed);
  const [proxy, setProxy] = useState(freeProxy?.id ?? '');
  const [locale, setLocale] = useState('en-US');
  const [doh, setDoh] = useState('cloudflare');
  const [notes, setNotes] = useState('');
  const [errs, setErrs] = useState<{ name?: string; proxy?: string }>({});
  const [touched, setTouched] = useState(false);
  const [fp, setFp] = useState<T.FingerprintView | null>(null);
  const [busy, setBusy] = useState('');
  const nameRef = useRef<HTMLInputElement>(null);
  const taken = (n: string) => a.profiles.some(p => p.name.toLowerCase() === n.toLowerCase());

  useEffect(() => {
    let live = true;
    a.b.previewFingerprint(os, locale, seed).then(v => live && setFp(v)).catch(e => a.fail(e));
    return () => { live = false; };
  }, [os, locale, seed, a.b]); // eslint-disable-line react-hooks/exhaustive-deps

  const px = a.proxies.find(x => x.id === proxy);
  const shared = px ? sharers(a, '', px.id) : [];
  const rules = fp?.rules ?? [];
  const rs = { ok: rules.filter(r => r.level === 'pass').length, warn: rules.filter(r => r.level === 'note').length, bad: rules.filter(r => r.level === 'fail').length };
  const addTag = (t: string) => { const c = cleanTag(t); if (c && !tags.includes(c) && tags.length < 8) setTags([...tags, c]); };

  const create = async (launch: boolean) => {
    setTouched(true);
    let tg = tags;
    if (tagIn.trim()) { const c = cleanTag(tagIn); if (c && !tags.includes(c)) tg = [...tags, c]; setTags(tg); setTagIn(''); }
    const e: typeof errs = { name: nameError(name.trim(), taken) };
    if (px && px.state.state === 'offline') e.proxy = 'This proxy is offline. Pick another or test it in Proxy Hub.';
    setErrs(e);
    const bad = rules.find(r => r.level === 'fail');
    if (e.name || e.proxy || bad) {
      nameRef.current?.focus();
      a.toast(e.name ? 'Fix the highlighted fields' : e.proxy || `Rule ${bad!.id} fails: ${bad!.message}`, 'bad');
      return;
    }
    setBusy(launch ? 'launch' : 'create');
    try {
      const m = await a.b.createProfile({ name: name.trim(), folder: folder.trim(), tags: tg, os, locale, notes, proxy_id: proxy || null, seed });
      if (doh !== 'cloudflare') await a.b.setDohProvider(m.id, doh as T.DohProvider);
      await a.refreshProfiles();
      a.setFlash(m.id);
      a.go('profiles');
      if (!launch) { a.toast(<>Profile <b>{m.name}</b> created · run a health check before its first launch</>, 'ok', 'plus'); return; }
      a.toast(<>Profile <b>{m.name}</b> created · running the health check before launch…</>, 'ok', 'plus');
      try {
        const h = await a.b.runHealth(m.id);
        await a.refreshProfiles();
        if (h.summary.score < 60) { a.toast(<>Health check for <b>{m.name}</b>: {h.summary.score}/100. Launch blocked until fixed.</>, 'bad', 'pulse'); return; }
        await a.launch(m.id, { force: false });
      } catch (er) { await a.refreshProfiles(); a.fail(er, <><b>{m.name}</b>:</>); }
    } catch (er) {
      const c = asCoreError(er);
      if (c.kind === 'invalid') setErrs({ name: errorText(er) });
      a.fail(er);
    } finally { setBusy(''); }
  };

  const proxyState = px ? proxyStatus(px.state) : null;
  return (
    <Main title="New profile" sub="One profile = one private, encrypted browser identity built from a real Windows device record."
      actions={<>
        <button className="btn" data-a="npCancel" onClick={() => a.go('profiles')}>Cancel</button>
        <button className="btn" data-a="npCreate" disabled={!!busy} onClick={() => create(false)}>{busy === 'create' ? <Spin /> : <Icon n="check" s={14} />}Create</button>
        <button className="btn p" data-a="npCreateLaunch" disabled={!!busy} onClick={() => create(true)}>{busy === 'launch' ? <Spin /> : <Icon n="play" s={14} />}Create & launch</button>
      </>}>
      <div className="row" style={{ alignItems: 'flex-start' }}>
        <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 13, padding: '18px 20px' }}>
          <div className="row" style={{ gap: 12 }}>
            <div className="field" style={{ flex: 1 }}><label htmlFor="npName">Name *</label>
              <input ref={nameRef} className={`inp ${errs.name ? 'invalid' : ''}`} id="npName" value={name} maxLength={40} autoComplete="off" placeholder="e.g. shop-de-05"
                onChange={e => { setName(e.target.value); if (touched) setErrs({ ...errs, name: nameError(e.target.value.trim(), taken) }); }} />
              <div className="err">{errs.name}</div></div>
            <div className="field" style={{ flex: 1 }}><label htmlFor="npFolder">Folder</label>
              <input className="inp" id="npFolder" list="npFolders" value={folder} onChange={e => setFolder(e.target.value)} /><datalist id="npFolders">{folders.map(f => <option key={f} value={f} />)}</datalist></div>
          </div>
          <div className="field"><label htmlFor="npTag">Tags <span className="dim">(Enter or comma to add)</span></label>
            <div className="inp chip-in" onClick={e => { if (e.target === e.currentTarget) document.getElementById('npTag')?.focus(); }}>
              {tags.map((t, i) => <span key={t} className="pill acc">{t}<span className="x" role="button" aria-label={`Remove tag ${t}`} onClick={() => setTags(tags.filter((_, j) => j !== i))}><Icon n="x" s={10} /></span></span>)}
              <input id="npTag" value={tagIn} placeholder={tags.length ? '' : 'shop, de…'} autoComplete="off"
                onChange={e => { const v = e.target.value; if (/[,\s]$/.test(v) && v.trim().replace(/,$/, '')) { addTag(v.replace(/[,\s]+$/, '')); setTagIn(''); } else setTagIn(v); }}
                onKeyDown={e => {
                  if (e.key === 'Enter') { e.preventDefault(); if (tagIn.trim()) { addTag(tagIn); setTagIn(''); } }
                  if (e.key === 'Backspace' && !tagIn && tags.length) setTags(tags.slice(0, -1));
                }} />
            </div></div>
          <div className="field"><label>Operating system</label><div><span className="seg" role="radiogroup">
            {(['windows11', 'windows10'] as T.OsKind[]).map(o => <button key={o} role="radio" aria-checked={os === o} className={os === o ? 'on' : ''} data-a="npOs" data-id={o} onClick={() => setOs(o)}><WinLogo s={11} style={{ marginRight: 6, verticalAlign: -1 }} />{o === 'windows11' ? 'Windows 11' : 'Windows 10'}</button>)}
          </span></div></div>
          <div className="field"><label>Device (real-device record from the desktop device DB, picked by seed)</label>
            <div className="row" style={{ gap: 8 }}>
              <div className="inp ro" style={{ flex: 1 }} id="npDev">{fp ? <span className="mono" style={{ fontSize: 12 }}>{fp.gpu_renderer.replace(/^ANGLE \(/, '').replace(/ Direct3D.*$/, '')} · {fp.hardware_concurrency} threads · {fp.screen_width} × {fp.screen_height}</span> : <Spin s={10} />}</div>
              <button className="btn" data-a="npRegen" title="Pick a new device and seed" onClick={() => { setSeed(newSeed()); }}><Icon n="dice" s={14} />Regenerate seed</button>
            </div>
            <span className="dim" style={{ fontSize: 11 }}>Record <span className="mono">{fp?.device_id ?? '…'}</span> · seed <span className="mono">0x{seed}</span></span></div>
          <div className="field"><label htmlFor="npProxy">Proxy (from Proxy Hub)</label>
            <select className={`inp ${errs.proxy ? 'invalid' : ''}`} id="npProxy" value={proxy} onChange={e => { setProxy(e.target.value); setErrs({ ...errs, proxy: '' }); }}><option value="">No proxy</option>{proxyOptions(a, null)}</select>
            <div className="err">{errs.proxy}</div>
            {shared.length ? <span className="warn" style={{ fontSize: 11.5 }}><Icon n="alert" s={12} style={{ verticalAlign: -2 }} /> Used by {shared[0].name}. Sharing one IP links profiles together.</span>
              : <span className="dim" style={{ fontSize: 11 }}>Free proxies are listed first. Default: one proxy per profile.</span>}</div>
          <div className="card" style={{ background: 'var(--sub)', padding: '12px 14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}><div style={{ flex: 1 }}><div style={{ fontWeight: 550 }}><Icon n="pin" s={14} style={{ verticalAlign: -2, marginRight: 4 }} />Geo Auto-Match</div>
              <div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>Timezone and geolocation follow the proxy exit IP. The language stays yours unless you change it here.</div></div>
              <Tog on locked label="Geo Auto-Match" /></div>
            <div className="row" style={{ gap: 10, marginTop: 10 }}><div className="field" style={{ flex: 1 }}><label htmlFor="npLoc">Language (locale)</label>
              <select className="inp" id="npLoc" value={locale} onChange={e => setLocale(e.target.value)}>{LOCALES.map(l => <option key={l}>{l}</option>)}</select></div></div>
          </div>
          <div className="card" style={{ background: 'var(--sub)', padding: '12px 14px' }}><div style={{ fontWeight: 550, marginBottom: 4 }}><Icon n="shield" s={14} style={{ verticalAlign: -2, marginRight: 4 }} />Network Guard</div>
            <div className="chk">Kill switch<span className="r lock-ic"><Icon n="lock" s={11} />always on</span><Tog on locked label="Kill switch" /></div>
            <div className="chk">WebRTC: proxy only<span className="r lock-ic"><Icon n="lock" s={11} />always on</span><Tog on locked label="WebRTC proxy only" /></div>
            <div className="chk">QUIC / HTTP3 blocked (the relay carries TCP only)<span className="r lock-ic"><Icon n="lock" s={11} />always on</span><Tog on locked label="Block QUIC" /></div>
            <div className="chk">Block IPv6 and local network (LAN)<span className="r lock-ic"><Icon n="lock" s={11} />always on</span><Tog on locked label="Block IPv6 and LAN" /></div>
            <div className="chk">DNS over HTTPS through the proxy<span className="r"><select className="inp" id="npDoh" style={{ width: 190, padding: '4px 26px 4px 8px', fontSize: 12 }} value={doh} onChange={e => setDoh(e.target.value)}>{DOH.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></span></div>
          </div>
          <div className="field"><label htmlFor="npNotes">Notes</label><textarea className="inp" id="npNotes" rows={2} placeholder="Optional" value={notes} onChange={e => setNotes(e.target.value)} /></div>
        </div>
        <div className="col" style={{ width: 420, flex: 'none' }}>
          <div className="card" id="npPreview"><h3><Icon n="eye" s={15} />Live preview <span className="r">generated fingerprint</span></h3>
            {fp ? <div className="kv" style={{ gridTemplateColumns: '120px 1fr', fontSize: 12 }}>
              <dt>Chrome</dt><dd><b>{fp.engine.split('.')[0]}</b> <span className="pill ok">= engine {fp.engine}</span></dd>
              <dt>User-Agent</dt><dd className="mono" style={{ fontSize: 10.8 }}>{fp.user_agent}</dd>
              <dt>Sec-CH-UA</dt><dd className="mono" style={{ fontSize: 10.8 }}>{fp.sec_ch_ua}</dd>
              <dt>Platform</dt><dd>"{fp.ua_platform}" · <span className="mono">{fp.platform_version}</span> · {fp.architecture}</dd>
              <dt>GPU</dt><dd className="mono" style={{ fontSize: 10.8 }}>{fp.gpu_renderer}</dd>
              <dt>Screen</dt><dd>{fp.screen_width} × {fp.screen_height} · avail {fp.avail_width} × {fp.avail_height} · DPR {fp.device_pixel_ratio}</dd>
              <dt>CPU / memory</dt><dd>{fp.hardware_concurrency} threads · {fp.device_memory} GB reported</dd>
              <dt>Fonts</dt><dd>{fp.fonts.length} · {fp.os === 'windows11' ? 'Windows 11' : 'Windows 10'} set</dd>
              <dt>Media</dt><dd>{fp.microphones} mic · {fp.cameras} cam · {fp.speakers} speaker</dd>
              <dt>Timezone</dt><dd>{fp.timezone ?? 'set from the exit IP'} <span className="pill acc">from exit IP</span></dd>
              <dt>Accept-Language</dt><dd className="mono" style={{ fontSize: 10.8 }}>{fp.accept_language}</dd>
              <dt>Noise seed</dt><dd className="mono">0x{fp.seed_prefix}…</dd>
            </div> : <div className="muted"><Spin s={10} /> Generating…</div>}
          </div>
          <div className="card"><h3>Before it is saved</h3>
            <Chk s={rs.bad ? 'bad' : 'ok'} r={<span className={rs.bad ? 'bad' : 'ok'}>{rs.ok} pass · {rs.warn} note{rs.bad ? ` · ${rs.bad} fail` : ''}</span>}>Consistency rules C001–C030</Chk>
            {rules.filter(r => r.level === 'fail').map(r => <Chk key={r.id} s="bad"><span className="mono dim">{r.id}</span> {r.message}</Chk>)}
            <Chk s="ok">C030 Chrome {a.info.engine_version.split('.')[0]} = engine {a.info.engine_version}</Chk>
            {px ? <Chk s={proxyState === 'offline' ? 'bad' : proxyState === 'slow' || proxyState === 'untested' ? 'warn' : 'ok'}>Proxy {proxyState === 'offline' ? 'offline' : proxyState === 'untested' ? 'not tested yet' : 'online'} · {proxyName(px)} · {schemeLabel(px.scheme)}{px.state.state === 'online' ? ` · ${px.state.latency_ms} ms` : ''}</Chk>
              : <Chk s="warn">No proxy: launch will be blocked by the kill switch</Chk>}
            {px && <Chk s={shared.length ? 'warn' : 'ok'}>{shared.length ? 'Proxy already used by another profile' : 'Proxy not used by any other profile'}</Chk>}
            <Chk s="warn">A health check runs before the first launch (launch gate)</Chk>
            <div className="note" style={{ marginTop: 8 }}><Icon n="lock" s={13} /><span>The profile gets its own encryption key. Its config is signed (Ed25519) at every launch.</span></div>
          </div>
        </div>
      </div>
    </Main>
  );
}
