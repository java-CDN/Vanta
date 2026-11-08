// Provider username presets (mirrors crates/vanta-proxy/src/provider.rs). The Tauri build
// asks the backend (previewPreset), which is authoritative; this port feeds the mock
// backend and the form's field rules. tests/presets.test.ts checks it against the Rust
// test vectors. A preset never holds a password.

import type { PresetPreview, Provider, ProviderPreset, SessionParams } from '../api/types';

/** Shown next to every preset (vanta_proxy::PROVIDER_PRESETS_VERIFIED_LIVE is false). */
export const PRESETS_NOTE = 'Username grammars are from the providers’ public docs, not verified with live accounts. Check the preview against your provider dashboard.';

export interface ProviderSpec {
  id: Provider;
  name: string;
  /** What the base username looks like in the provider's dashboard. */
  baseHint: string;
  city: boolean;
  ttl: boolean;
  /** Webshare: the sticky slot is a numbered endpoint, so the plan's pool size is needed. */
  pool: boolean;
}

export const PROVIDERS: ProviderSpec[] = [
  { id: 'bright_data', name: 'Bright Data', baseHint: 'brd-customer-<id>-zone-<zone>', city: true, ttl: false, pool: false },
  { id: 'soax', name: 'SOAX', baseHint: 'package-<id>', city: true, ttl: true, pool: false },
  { id: 'geonode', name: 'Geonode', baseHint: 'geonode_<user>', city: true, ttl: true, pool: false },
  { id: 'data_impulse', name: 'DataImpulse', baseHint: '<login>', city: true, ttl: true, pool: false },
  { id: 'webshare', name: 'Webshare', baseHint: '<username>', city: false, ttl: false, pool: true },
  { id: 'thordata', name: 'Thordata', baseHint: 'td-customer-<user> or <user>', city: true, ttl: true, pool: false },
];

const TAG: Record<Provider, string> = { bright_data: 'brightdata', soax: 'soax', geonode: 'geonode', data_impulse: 'dataimpulse', webshare: 'webshare', thordata: 'thordata' };

export const spec = (p: Provider): ProviderSpec => PROVIDERS.find(x => x.id === p)!;

export function emptyPreset(provider: Provider = 'bright_data'): ProviderPreset {
  return { provider, base_user: '', params: { country: null, city: null, session_ttl_min: null, pool_size: spec(provider).pool ? 10 : null, rotation: 0 }, session_key: '' };
}

/** Drop the fields a provider has no syntax for (when the user switches provider). */
export function fitTo(p: ProviderPreset, provider: Provider): ProviderPreset {
  const s = spec(provider);
  return { ...p, provider, params: { ...p.params, city: s.city ? p.params.city : null, session_ttl_min: s.ttl ? p.params.session_ttl_min : null, pool_size: s.pool ? (p.params.pool_size ?? 10) : null } };
}

const invalid = (message: string) => ({ kind: 'invalid' as const, message });

function randomKey(): string {
  const b = new Uint8Array(16); crypto.getRandomValues(b);
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}

function parseKey(s: string): Uint8Array {
  const hex = s.replace(/-/g, '');
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw invalid('session key must be 32 hex digits');
  return Uint8Array.from({ length: 16 }, (_, i) => parseInt(hex.slice(2 * i, 2 * i + 2), 16));
}

const u32le = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };

async function digest(provider: Provider, key: Uint8Array, p: SessionParams): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const parts = [enc.encode('vanta/proxy-session/v1\0'), enc.encode(TAG[provider]), new Uint8Array([0]), key,
    enc.encode((p.country ?? '').toLowerCase()), new Uint8Array([0]), enc.encode((p.city ?? '').toLowerCase()), new Uint8Array([0]),
    u32le(p.session_ttl_min ?? 0), u32le(p.rotation)];
  const all = new Uint8Array(parts.reduce((n, x) => n + x.length, 0));
  let o = 0; for (const x of parts) { all.set(x, o); o += x.length; }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', all));
}

function city(c: string, space: string): string {
  const words = c.split(/\s+/).map(w => w.replace(/[^A-Za-z0-9]/g, '').toLowerCase()).filter(Boolean);
  if (!words.length) throw invalid('city name has no letters');
  return words.join(space);
}

/** Port of `ProviderPreset::normalized` + `username`. Throws a CoreError-shaped `invalid`. */
export async function buildPreset(input: ProviderPreset): Promise<PresetPreview> {
  const opt = (v?: string | null) => { const t = (v ?? '').trim(); return t ? t : null; };
  const params: SessionParams = { country: opt(input.params.country)?.toUpperCase() ?? null, city: opt(input.params.city), session_ttl_min: input.params.session_ttl_min ?? null, pool_size: input.params.pool_size ?? null, rotation: input.params.rotation };
  const key = input.session_key.trim() ? parseKey(input.session_key.trim()) : parseKey(randomKey());
  const preset: ProviderPreset = { provider: input.provider, base_user: input.base_user.trim(), params, session_key: [...key].map(x => x.toString(16).padStart(2, '0')).join('') };
  const s = spec(preset.provider); const base = preset.base_user;
  if (!base || base.length > 200) throw invalid('base username is empty or too long');
  if (/[\s:@]/.test(base)) throw invalid("base username contains whitespace, ':' or '@'");
  if (params.city && !params.country) throw invalid('a city needs a country');
  if (params.city && !s.city) throw invalid(`${s.name} has no city parameter`);
  if (params.session_ttl_min != null && !s.ttl) throw invalid(`${s.name} has no session lifetime parameter`);
  if (params.pool_size != null && !s.pool) throw invalid(`${s.name} has no pool size parameter`);
  if (params.session_ttl_min != null && !(params.session_ttl_min >= 1 && params.session_ttl_min <= 1440)) throw invalid('session lifetime must be 1 to 1440 minutes');
  if (params.country && !/^[A-Za-z]{2}$/.test(params.country)) throw invalid('country must be a two-letter ISO code');
  const d = await digest(preset.provider, key, params);
  const sid = [...d.slice(0, 6)].map(x => x.toString(16).padStart(2, '0')).join('');
  const cc = params.country?.toLowerCase() ?? null;
  const ttl = params.session_ttl_min;
  let u = base;
  const push = (k: string, v: string) => { u += `-${k}-${v}`; };
  switch (preset.provider) {
    case 'bright_data':
      if (!base.startsWith('brd-customer-') || !base.includes('-zone-')) throw invalid('Bright Data base username looks like brd-customer-<id>-zone-<zone>');
      if (cc) push('country', cc); if (params.city) push('city', city(params.city, '')); push('session', sid); break;
    case 'soax':
      if (!base.startsWith('package-')) throw invalid('SOAX base username looks like package-<id>');
      if (cc) push('country', cc); if (params.city) push('city', city(params.city, '+')); push('sessionid', sid); if (ttl != null) push('sessionlength', String(ttl * 60)); break;
    case 'geonode':
      if (!base.startsWith('geonode_')) throw invalid('Geonode base username looks like geonode_<user>');
      push('type', 'residential'); if (cc) push('country', cc); if (params.city) push('city', city(params.city, '')); push('session', sid); if (ttl != null) push('lifetime', String(ttl)); break;
    case 'thordata':
      if (!base.startsWith('td-customer-')) u = `td-customer-${base}`;
      if (cc) push('country', cc); if (params.city) push('city', city(params.city, '')); push('sessid', sid); if (ttl != null) push('sesstime', String(ttl)); break;
    case 'data_impulse': {
      if (base.includes('__')) throw invalid('DataImpulse base login must not already carry __ parameters');
      const kv: string[] = [];
      if (cc) kv.push(`cr.${cc}`); if (params.city) kv.push(`city.${city(params.city, '')}`); kv.push(`sessid.${sid}`); if (ttl != null) kv.push(`sessttl.${ttl}`);
      u = `${base}__${kv.join(';')}`; break;
    }
    case 'webshare': {
      const pool = params.pool_size;
      if (pool == null || pool < 1) throw invalid('Webshare sticky sessions need pool_size >= 1');
      const n = new DataView(d.buffer, d.byteOffset, 8).getBigUint64(0, true) % BigInt(pool) + 1n;
      if (cc) u += `-${cc.toUpperCase()}`; u += `-${n}`; break;
    }
  }
  return { preset, username: u };
}
