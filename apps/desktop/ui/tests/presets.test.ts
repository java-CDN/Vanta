import { describe, expect, it } from 'vitest';
import { buildPreset, emptyPreset, fitTo, PROVIDERS } from '../src/lib/presets';
import type { Provider } from '../src/api/types';

// Same vectors as crates/vanta-proxy/src/provider.rs `preset_vector_matches_the_ui_port`.
const KEY = '00112233-4455-6677-8899-AABBCCDDEEFF';

describe('provider presets (TS port of vanta-proxy)', () => {
  it('matches the Rust vectors', async () => {
    const r = await buildPreset({ provider: 'soax', base_user: ' package-123456 ', params: { country: 'us', city: 'New York', session_ttl_min: 30, pool_size: null, rotation: 2 }, session_key: KEY });
    expect(r.preset.session_key).toBe('00112233445566778899aabbccddeeff');
    expect(r.preset.params.country).toBe('US');
    expect(r.username).toBe('package-123456-country-us-city-new+york-sessionid-04d3accaaada-sessionlength-1800');
    const w = await buildPreset({ provider: 'webshare', base_user: 'abcd', params: { country: 'gb', pool_size: 10, rotation: 0 }, session_key: KEY });
    expect(w.username).toBe('abcd-GB-8');
  });

  it('builds every grammar and keeps the session per key', async () => {
    const p = (provider: Provider, base: string) => ({ ...fitTo({ ...emptyPreset(provider), base_user: base, params: { country: 'DE', city: 'Bad Homburg', session_ttl_min: 15, pool_size: 3, rotation: 0 } }, provider), session_key: KEY });
    const out = Object.fromEntries(await Promise.all(PROVIDERS.map(async s => [s.id, (await buildPreset(p(s.id, { bright_data: 'brd-customer-1-zone-res', soax: 'package-1', geonode: 'geonode_u', data_impulse: 'login', webshare: 'ws', thordata: 'user9' }[s.id]))).username])));
    expect(out.bright_data).toMatch(/^brd-customer-1-zone-res-country-de-city-badhomburg-session-[0-9a-f]{12}$/);
    expect(out.soax).toMatch(/^package-1-country-de-city-bad\+homburg-sessionid-[0-9a-f]{12}-sessionlength-900$/);
    expect(out.geonode).toMatch(/^geonode_u-type-residential-country-de-city-badhomburg-session-[0-9a-f]{12}-lifetime-15$/);
    expect(out.data_impulse).toMatch(/^login__cr\.de;city\.badhomburg;sessid\.[0-9a-f]{12};sessttl\.15$/);
    expect(out.webshare).toMatch(/^ws-DE-[1-3]$/);
    expect(out.thordata).toMatch(/^td-customer-user9-country-de-city-badhomburg-sessid-[0-9a-f]{12}-sesstime-15$/);
    // A fresh key is generated when none is given; a new rotation moves the session.
    const a = await buildPreset({ ...p('geonode', 'geonode_u'), session_key: '' });
    expect(a.preset.session_key).toMatch(/^[0-9a-f]{32}$/);
    const again = await buildPreset(a.preset);
    expect(again.username).toBe(a.username);
    const rot = await buildPreset({ ...a.preset, params: { ...a.preset.params, rotation: 1 } });
    expect(rot.username).not.toBe(a.username);
  });

  it('rejects what the Rust side rejects', async () => {
    const base = { ...emptyPreset('soax'), base_user: 'package-1', session_key: KEY };
    const bad = [
      { ...base, base_user: '' },
      { ...base, base_user: 'package 1' },
      { ...base, base_user: 'someone' },
      { ...base, params: { ...base.params, city: 'Paris' } },
      { ...base, params: { ...base.params, country: 'USA' } },
      { ...base, params: { ...base.params, session_ttl_min: 5000 } },
      { ...base, params: { ...base.params, pool_size: 3 } },
      { ...base, session_key: 'zz' },
      { ...emptyPreset('bright_data'), base_user: 'brd-customer-1-zone-z', params: { ...base.params, session_ttl_min: 10 }, session_key: KEY },
      { ...emptyPreset('webshare'), base_user: 'ws', params: { rotation: 0, pool_size: 0 }, session_key: KEY },
    ];
    for (const b of bad) await expect(buildPreset(b)).rejects.toMatchObject({ kind: 'invalid' });
  });

  it('drops fields the new provider cannot express', () => {
    const p = { ...emptyPreset('soax'), params: { country: 'US', city: 'Austin', session_ttl_min: 30, pool_size: null, rotation: 0 } };
    expect(fitTo(p, 'webshare').params).toMatchObject({ city: null, session_ttl_min: null, pool_size: 10 });
    expect(fitTo(p, 'bright_data').params).toMatchObject({ city: 'Austin', session_ttl_min: null, pool_size: null });
  });
});
