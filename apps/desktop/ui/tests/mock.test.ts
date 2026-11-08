import { describe, expect, it } from 'vitest';
import { mockBackend } from '../src/api/mock';
import { parseList } from '../src/lib/proxyparse';

describe('mock backend (demo data from the prototype)', () => {
  it('is locked until unlocked and refuses wrong passwords', async () => {
    const b = mockBackend({ speed: 0 });
    expect((await b.appInfo()).unlocked).toBe(false);
    await expect(b.fingerprint('x')).rejects.toMatchObject({ kind: 'locked' });
    await expect(b.unlock('wrong')).rejects.toMatchObject({ kind: 'crypto' });
    await b.unlock('anything');
    expect((await b.appInfo()).unlocked).toBe(true);
  });
  it('serves 25 Windows-only profiles and 28 proxies', async () => {
    const b = mockBackend({ speed: 0, unlocked: true });
    const page = await b.listProfiles('', 1000, 0);
    expect(page.total).toBe(25);
    expect(page.items.every(p => p.os === 'windows10' || p.os === 'windows11')).toBe(true);
    expect(await b.listProxies()).toHaveLength(28);
    expect((await b.listProfiles('tag:ads', 1000, 0)).total).toBe(7);
    await expect(b.listProfiles('os:mac', 10, 0)).rejects.toMatchObject({ kind: 'invalid' });
  });
  it('gates launches like vanta-core (offline proxy, failing rule)', async () => {
    const b = mockBackend({ speed: 0, unlocked: true });
    const all = (await b.listProfiles('', 1000, 0)).items;
    const jp = all.find(p => p.name === 'qa-jp-01')!;
    await expect(b.launchProfile(jp.id)).rejects.toMatchObject({ kind: 'blocked', reasons: expect.arrayContaining([expect.objectContaining({ code: 'proxy_offline' })]) });
    const de3 = all.find(p => p.name === 'shop-de-03')!;
    await expect(b.launchProfile(de3.id)).rejects.toMatchObject({ kind: 'blocked' });
    const nl = all.find(p => p.name === 'shop-nl-01')!;
    const li = await b.launchProfile(nl.id);
    expect(li.engine_version).toBe('156.0.8078.79');
    expect((await b.runningProfiles())).toContain(nl.id);
  });
  it('previews and creates the same device for a seed; 30 rules', async () => {
    const b = mockBackend({ speed: 0, unlocked: true });
    const v = await b.previewFingerprint('windows10', 'de-DE', '00000000DEADBEEF');
    expect(v.rules).toHaveLength(30);
    expect(v.os).toBe('windows10');
    await expect(b.previewFingerprint(null, null, 'zz')).rejects.toMatchObject({ kind: 'invalid' });
  });
  it('health run returns a score and problems with catalog ids', async () => {
    const b = mockBackend({ speed: 0, unlocked: true });
    const p = (await b.listProfiles('qa-de-01', 10, 0)).items[0];
    const r = await b.runHealth(p.id);
    expect(r.summary.score).toBeGreaterThan(60);
    expect(r.problems.every(x => /^H\d\d$/.test(x.id))).toBe(true);
  });
  it('activity log pages newest first', async () => {
    const b = mockBackend({ speed: 0, unlocked: true });
    const a = await b.activityLog({ limit: 5 });
    const c = await b.activityLog({ limit: 5, offset: 5 });
    expect(a.entries).toHaveLength(5);
    expect(a.entries[0].ts_ms).toBeGreaterThanOrEqual(a.entries[4].ts_ms);
    expect(a.entries[4].ts_ms).toBeGreaterThanOrEqual(c.entries[0].ts_ms);
    expect((await b.activityLog({ kinds: ['health_run'] })).entries.every(e => e.kind === 'health_run')).toBe(true);
  });
});

describe('proxy import preview (vanta-proxy grammar)', () => {
  it('parses the supported forms and rejects bad lines without echoing them', () => {
    const r = parseList('203.0.113.77:12000:user-geo-es:Xk29aa\nsocks5://brd-user:pw1@198.51.100.50:1080\nhttp://192.0.2.90:8080\n192.0.2.300:8080\nproxy.example.net:99999\n# comment\n\nu:p@h.example:80', 'http');
    expect(r.map(x => x.err ? 'err' : `${x.scheme}|${x.host}|${x.port}|${x.user ?? ''}|${x.hasPassword ?? false}`)).toEqual([
      'http|203.0.113.77|12000|user-geo-es|true', 'socks5|198.51.100.50|1080|brd-user|true', 'http|192.0.2.90|8080||false', 'err', 'err', 'http|h.example|80|u|true',
    ]);
    expect(r[3].line).toBe(4);
    expect(JSON.stringify(r)).not.toContain('Xk29aa');
  });
  it('changes the master password with the current one or the recovery key', async () => {
    const b = mockBackend({ speed: 0, fresh: true });
    const { recovery_key } = await b.createVault('first master password');
    await expect(b.changePassword('nope', 'second master password')).rejects.toMatchObject({ kind: 'crypto' });
    await b.changePassword('first master password', 'second master password');
    await b.changePassword(recovery_key.toLowerCase().replace(/-/g, ''), 'third master password');
    await b.lock();
    await expect(b.unlock('second master password')).rejects.toMatchObject({ kind: 'crypto' });
    await b.unlock('third master password');
  });
});
