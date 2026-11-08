// Headless interaction smoke test over the mock build (ui/dist-mock), adapted from the
// approved prototype's design/prototype/smoke.mjs. Uses playwright-core with a system or
// Playwright-installed Chromium:
//   npm run build:mock && npm run smoke
//   CHROME_PATH=/path/to/chrome npm run smoke
import { chromium } from 'playwright-core';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(here, '..', 'dist-mock');
const shots = path.join(here, '..', '..', 'smoke-shots');
if (!fs.existsSync(path.join(dist, 'index.html'))) { console.error('dist-mock missing: run `npm run build:mock` first'); process.exit(2); }

// --- static server (no dependencies) ---
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
const server = http.createServer((req, res) => {
  const u = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (u === '/favicon.ico') { res.writeHead(204); res.end(); return; }
  const f = path.join(dist, u === '/' ? 'index.html' : u);
  if (!f.startsWith(dist) || !fs.existsSync(f)) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'content-type': types[path.extname(f)] || 'application/octet-stream' });
  fs.createReadStream(f).pipe(res);
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}/`;

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  for (const c of ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe']) if (fs.existsSync(c)) return c;
  return undefined; // Playwright's own download (npx playwright-core install chromium)
}
const browser = await chromium.launch({ executablePath: findChrome(), args: ['--no-sandbox'] });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const errors = [];
page.on('pageerror', e => errors.push('EXC: ' + e.message));
page.on('console', m => { if (m.type() === 'error' || m.type() === 'warning') errors.push(`CONSOLE ${m.type()}: ${m.text()}`); });

const results = [];
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function check(name, fn) {
  let line;
  try { const ok = await fn(); line = `${ok ? 'PASS' : 'FAIL'}  ${name}`; }
  catch (e) { line = `FAIL  ${name}  — ${String(e.message || e).split('\n')[0]}`; }
  results.push(line);
  if (process.env.SMOKE_VERBOSE) console.log(line);
  // Reset transient UI between checks: close menus/modals.
  try { for (let i = 0; i < 2 && (await page.locator('.modal, #menu').count()); i++) { await page.keyboard.press('Escape'); await sleep(60); } } catch { /* page gone */ }
}
page.setDefaultTimeout(5000);
const rows = () => page.locator('tbody tr:not(.vpad)');
const rowOf = name => page.locator('tbody tr', { hasText: name }).first();
const toasts = () => page.locator('#toasts').innerText();
const until = async (f, ms = 10000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (await f()) return true; } catch { /* retry */ } await sleep(100); } return false; };
const go = async r => { await page.evaluate(h => { location.hash = h; }, '#/' + r); await sleep(150); };
const body = () => page.locator('body').innerText();

await page.goto(base + '?x=1#/profiles');
await page.waitForSelector('#pw');

// 1 lock screen
await check('lock screen shown', async () => !!(await page.$('#pw')) && (await body()).includes('Vanta is locked'));
await check('empty password errors', async () => { await page.click('#unlockBtn'); await sleep(300); return (await page.locator('#pwerr').innerText()).length > 0; });
await check('"wrong" password errors + shake', async () => { await page.fill('#pw', 'wrong'); await page.click('#unlockBtn'); await sleep(1000); return (await page.locator('#pwerr').innerText()).includes('Wrong') && (await page.locator('#lockcard').getAttribute('class')).includes('shake'); });
await check('unlock with spinner', async () => { await page.fill('#pw', 'hunter2'); await page.click('#unlockBtn'); await sleep(150); const sp = (await page.locator('#unlockBtn .spin').count()) > 0; await page.waitForSelector('.nav', { timeout: 5000 }); return sp; });
// 2 nav
await check('sidebar routes', async () => {
  const out = [];
  for (const r of ['fingerprints', 'health', 'proxies', 'network', 'activity', 'settings', 'profiles']) { await page.click(`.nav a[href="#/${r}"]`); await sleep(150); out.push((await page.locator('.nav a.on').getAttribute('href')) === '#/' + r && (await page.locator('.hd h1').count()) === 1); }
  return out.every(Boolean);
});
await check('profile count 25 & Win only', async () => (await rows().count()) === 25 && (await page.locator('tbody .osic span').allInnerTexts()).every(s => /^Win 1[01]$/.test(s)));
// 3 profiles
await check('live search (server query)', async () => { await page.fill('#psearch', 'shop-de'); await sleep(300); const n = await rows().count(); await page.fill('#psearch', ''); await sleep(250); return n === 4; });
await check('query syntax health:<80', async () => { await page.fill('#psearch', 'health:<80'); await sleep(300); const n = await rows().count(); await page.fill('#psearch', ''); await sleep(250); return n === 2; });
await check('query syntax error shown', async () => { await page.fill('#psearch', 'os:mac'); await sleep(250); const t = await page.locator('#qerr').innerText(); await page.fill('#psearch', ''); await sleep(250); return t.includes('unknown os'); });
await check('status filter', async () => { await page.selectOption('#fStatus', 'Running'); await sleep(300); const n = await rows().count(); await page.selectOption('#fStatus', ''); await sleep(250); return n === 5; });
await check('tag filter', async () => { await page.selectOption('#fTag', 'ads'); await sleep(300); const n = await rows().count(); await page.selectOption('#fTag', ''); await sleep(250); return n === 7; });
await check('country filter', async () => { await page.selectOption('#fCountry', 'IN'); await sleep(300); const n = await rows().count(); await page.selectOption('#fCountry', ''); await sleep(250); return n === 3; });
await check('sort by name', async () => { await page.click('th.sort[data-id=name]'); await sleep(100); const a = await page.locator('tbody tr td:nth-child(2) b').allInnerTexts(); return JSON.stringify(a) === JSON.stringify([...a].sort()); });
await check('select + bulk bar', async () => { const cbs = page.locator('tbody .cb'); await cbs.nth(0).click(); await cbs.nth(1).click(); await sleep(80); const ok = (await page.locator('.bulk').innerText()).includes('2 selected'); await page.click('[data-a=clearSel]'); return ok; });
await check('launch → launching → running', async () => {
  await rowOf('shop-nl-01').locator('[data-a=launchP]').click(); await sleep(150);
  const l = (await rowOf('shop-nl-01').innerText()).includes('Launching');
  return l && await until(async () => (await rowOf('shop-nl-01').innerText()).includes('Running'), 4000);
});
await check('stop', async () => { await rowOf('shop-nl-01').locator('[data-a=stopP]').click(); return until(async () => (await rowOf('shop-nl-01').innerText()).includes('Stopped'), 3000); });
await check('offline proxy blocks launch', async () => { await rowOf('qa-jp-01').locator('[data-a=launchP]').click(); return until(async () => (await toasts()).includes('offline')); });
await check('failing rule (C018 geo) blocks launch', async () => { await rowOf('shop-de-03').locator('[data-a=launchP]').click(); return until(async () => (await toasts()).includes('C018')); });
await check('drawer opens with details', async () => { await rows().first().locator('td').nth(1).click(); await sleep(400); const d = page.locator('#drawer'); return (await d.getAttribute('class')).includes('open') && (await d.innerText()).includes('Fingerprint') && (await d.innerText()).includes('Notes'); });
await check('Esc closes drawer', async () => { await page.keyboard.press('Escape'); await sleep(150); return !(await page.locator('#drawer').getAttribute('class')).includes('open'); });
await check('row menu → duplicate', async () => { const n = await rows().count(); await rows().first().locator('[data-a=rowMenu]').click(); await page.click('#menu [data-a=dupP]'); return until(async () => (await rows().count()) === n + 1, 3000); });
await check('edit modal saves', async () => {
  await rowOf('-copy').locator('[data-a=rowMenu]').click(); await page.click('#menu [data-a=editP]'); await page.fill('#edName', 'dup-renamed'); await page.click('[data-a=saveEdit]');
  return until(async () => (await rowOf('dup-renamed').count()) > 0, 3000);
});
await check('edit validation (duplicate name)', async () => {
  await rowOf('dup-renamed').locator('[data-a=rowMenu]').click(); await page.click('#menu [data-a=editP]'); await page.fill('#edName', 'shop-de-01'); await page.click('[data-a=saveEdit]'); await sleep(100);
  const ok = (await page.locator('#edErr').innerText()).includes('exists'); await page.keyboard.press('Escape'); await sleep(100); return ok && (await page.locator('.modal').count()) === 0;
});
await check('delete with confirm', async () => {
  await rowOf('dup-renamed').locator('[data-a=rowMenu]').click(); await page.click('#menu [data-a=delP]'); await sleep(100);
  const m = (await page.locator('.modal').innerText()).includes('Delete'); await page.click('#cfOk');
  return m && await until(async () => (await rowOf('dup-renamed').count()) === 0 && (await rows().count()) === 25, 3000);
});
await page.screenshot({ path: path.join(shots, '02-profiles.png') }).catch(() => {});
// 4 new profile
await check('new profile form', async () => { await page.click('[data-a=newProfile]'); await sleep(300); return (await page.evaluate(() => location.hash)) === '#/new' && (await page.locator('#npName').count()) === 1 && (await page.locator('[data-a=npOs]').count()) === 2; });
await check('validation blocks empty name', async () => { await page.click('[data-a=npCreate]'); await sleep(150); return (await page.locator('#npName').getAttribute('class')).includes('invalid'); });
await check('regenerate changes seed + preview', async () => { await until(async () => !(await page.locator('#npPreview').innerText()).includes('Generating')); const a = await page.locator('#npPreview').innerText(); await page.click('[data-a=npRegen]'); return until(async () => (await page.locator('#npPreview').innerText()) !== a, 3000); });
await check('OS switch to Windows 10', async () => { await page.click('[data-a=npOs][data-id=windows10]'); return until(async () => (await page.locator('#npPreview').innerText()).includes('10.0.0'), 3000); });
await check('create adds profile + toast', async () => {
  await page.fill('#npName', 'demo-win10-01'); await page.fill('#npTag', 'demo,'); await page.click('[data-a=npCreate]');
  return until(async () => (await page.evaluate(() => location.hash)) === '#/profiles' && (await rows().count()) === 26 && (await toasts()).includes('demo-win10-01'), 4000);
});
// 5 fingerprint studio
await check('FP studio: version bound to engine, UA read-only', async () => { await go('fingerprints'); await until(async () => (await body()).includes('bound to engine')); return (await page.locator('.main input, .main textarea').count()) === 0; });
await check('30 rules listed', async () => until(async () => (await page.locator('.card .chk .mono.dim').count()) === 30));
await check('tabs switch', async () => { await page.click('[data-a=fpTab][data-id=fonts]'); await sleep(100); return (await body()).includes('Fonts exposed'); });
await check('regenerate (confirm + OS) → new seed', async () => { await page.click('[data-a=fpRegen]'); await page.click('.modal #cfOk'); return until(async () => (await toasts()).includes('New seed'), 4000); });
// 6 health
await check('health run 56 + ring', async () => {
  await go('health'); await page.click('.hd [data-a=runHealth]'); await sleep(300);
  const mid = (await body()).includes('Running checks');
  const done = await until(async () => (await body()).includes('out of 100'), 8000); await sleep(150);
  return mid && done && (await page.locator('.ci').count()) === 56;
});
await check('expand explanation', async () => { await page.locator('.cat.open .ci .cih').first().click(); await sleep(80); return (await page.locator('.ci.open').count()) === 1; });
await check('issues filter', async () => { await page.click('.seg [data-id=issues]'); await sleep(80); const n = await page.locator('.ci').count(); await page.click('.seg [data-id=all]'); return n > 0 && n < 56; });
// 7 proxy hub
await check('proxy test single', async () => { await go('proxies'); await page.locator('tbody [data-a=pxTest]').first().click(); return until(async () => (await toasts()).includes('online'), 4000); });
await check('add proxy parse + import', async () => {
  const n = await rows().count();
  await page.click('.hd [data-a=pxAdd]'); await page.click('[data-a=apSample]'); await sleep(100);
  const t = await page.locator('#apPrev').innerText(); await page.click('#apOk');
  return t.includes('3 valid') && t.includes('2 invalid') && await until(async () => (await rows().count()) === n + 3, 3000);
});
await check('assign proxy (shared warning)', async () => {
  await rows().first().click(); await sleep(100);
  await page.locator('#pxAssign').selectOption({ index: 3 }); await page.click('[data-a=pxAssign]'); await sleep(200);
  if (await page.locator('#cfOk').count()) await page.click('#cfOk');
  return until(async () => (await toasts()).includes('assigned'), 3000);
});
await check('delete proxy', async () => { const n = await rows().count(); await rows().last().locator('[data-a=pxMenu]').click(); await page.click('#menu [data-a=pxDel]'); await page.click('#cfOk'); return until(async () => (await rows().count()) === n - 1, 3000); });
await check('test all', async () => { await page.click('[data-a=pxTestAll]'); return until(async () => (await toasts()).includes('Tested'), 15000); });
await check('geo tab', async () => { await page.click('.tabs [data-id=geo]'); await sleep(200); return (await page.evaluate(() => location.hash)) === '#/geo' && await until(async () => (await page.locator('tbody .pill.bad', { hasText: 'mismatch' }).count()) >= 1, 4000); });
// 8 network guard
await check('network guards locked on', async () => { await go('network'); await sleep(200); return (await page.locator('.card .tog.on.locked').count()) >= 7 && (await page.locator('.tog:not(.locked)').count()) === 0; });
await check('per-profile DoH provider', async () => { await until(async () => (await page.locator('select[aria-label^="DoH provider"]').count()) > 0); await page.locator('select[aria-label^="DoH provider"]').first().selectOption('quad9'); return until(async () => (await toasts()).includes('DoH via Quad9')); });
await check('DNS leak test', async () => { await page.selectOption('#ngProf', { label: 'qa-de-01' }); await page.click('.hd [data-a=dnsTest]'); return until(async () => (await body()).includes('No DNS leak'), 8000); });
// 9 activity
await check('activity filter + search', async () => {
  await go('activity'); await sleep(200);
  await page.click('.seg [data-id=blocked]'); await sleep(250);
  const t1 = await page.locator('tbody tr td b').allInnerTexts(); const ok = t1.length > 0 && t1.every(x => /Block|Kill switch|Launch blocked/i.test(x));
  await page.click('.seg [data-id=all]'); await sleep(250); await page.fill('#logQ', 'Launched'); await sleep(100);
  const t2 = await page.locator('tbody tr td b').allInnerTexts(); await page.fill('#logQ', '');
  return ok && t2.length > 0 && t2.every(x => x.includes('Launched'));
});
await check('paging', async () => { const t = await page.locator('#logCount').innerText(); const n = Number(/of (\d+)/.exec(t)?.[1]); if (!(n > 100 && t.startsWith('1–100'))) return false; await page.click('[aria-label=Older]'); return until(async () => (await page.locator('#logCount').innerText()).startsWith('101–')); });
await check('verify chain', async () => { await page.click('[data-a=verifyChain]'); return until(async () => (await body()).includes('Hash chain verified')); });
await check('export (with plain-file warning)', async () => { await page.click('[data-a=logExport]'); await sleep(100); const w = (await page.locator('.modal').innerText()).includes('not encrypted'); await page.click('#cfOk'); return w && until(async () => (await toasts()).includes('Exported')); });
// 10 settings
await check('autolock change → footer', async () => { await go('settings'); await page.click('[data-a=setSec][data-id=security]'); await sleep(100); await page.selectOption('#setAutolock', '5'); return until(async () => (await page.locator('#vaultlbl').innerText()).includes('5 min')); });
await check('change password validation', async () => { await page.click('[data-a=changePw]'); await page.fill('#cpOld', 'hunter2'); await page.fill('#cpNew', 'short'); await page.fill('#cpNew2', 'short'); await page.click('[data-a=cpSave]'); await sleep(80); const ok = (await page.locator('#cpErr').innerText()).includes('12'); await page.keyboard.press('Escape'); return ok; });
await check('engine version read-only, path setting', async () => { await page.click('[data-a=setSec][data-id=engine]'); await sleep(100); const t = await body(); return t.includes('156.0.8078.79') && t.includes('vanta-chromium.exe') && (await page.locator('#setEngine').count()) === 1; });
await check('IP echo URL setting (privacy)', async () => { await page.click('[data-a=setSec][data-id=privacy]'); await sleep(100); if (!(await body()).includes('api.ipify.org')) return false; await page.fill('#setEcho', 'http://icanhazip.com/'); await sleep(60); const refused = (await page.locator('[data-a=saveEcho]').isDisabled()) && (await page.locator('#echoErr').innerText()).includes('https://'); await page.fill('#setEcho', 'https://icanhazip.com/'); await sleep(60); await page.click('[data-a=saveEcho]'); const saved = await until(async () => (await toasts()).includes('IP echo URL saved')); await page.fill('#setEcho', ''); await page.click('[data-a=saveEcho]'); await sleep(80); return refused && saved; });
await check('theme switch', async () => { await page.click('[data-a=setSec][data-id=appearance]'); await sleep(80); await page.click('.seg [data-a=setTheme][data-id=light]'); await sleep(150); return (await page.evaluate(() => document.documentElement.dataset.theme)) === 'light'; });
await page.screenshot({ path: path.join(shots, '10-settings-light.png') }).catch(() => {});
await page.click('.seg [data-a=setTheme][data-id=dark]').catch(() => {});
// 11 lock
await check('Ctrl+L locks', async () => { await page.keyboard.press('Control+l'); await sleep(200); return (await page.locator('#pw').count()) === 1; });
await check('unlock again + Lock now button', async () => { await page.fill('#pw', 'x'); await page.click('#unlockBtn'); await page.waitForSelector('.nav'); await page.click('[data-a=lockNow]'); await sleep(200); return (await page.locator('#pw').count()) === 1; });
await check('close with running profiles asks first', async () => {
  await page.fill('#pw', 'x'); await page.click('#unlockBtn'); await page.waitForSelector('.nav');
  await page.evaluate(() => window.__vanta.requestClose()); await sleep(150);
  const ok = (await page.locator('.modal').innerText()).includes('Close Vanta?'); await page.keyboard.press('Escape'); return ok;
});
await check('no macOS/Linux text', async () => { let all = ''; for (const r of ['profiles', 'new', 'fingerprints', 'health', 'proxies', 'geo', 'network', 'activity', 'settings']) { await go(r); await sleep(150); all += await body(); } return !/mac ?os|linux|ubuntu|darwin|macintosh/i.test(all); });

// 12 virtual list with 10k profiles
await page.goto(base + '?unlocked=1&profiles=10000#/profiles'); await page.waitForSelector('tbody tr');
await check('10k profiles: virtualized rows', async () => { await sleep(300); const n = await rows().count(); const t = await page.locator('.card .muted').first().innerText(); return n < 120 && (await body()).includes('10,025 profiles') && t.length > 0; });
await check('10k profiles: scroll to end renders last rows', async () => { await page.locator('.tw').evaluate(el => { el.scrollTop = el.scrollHeight; }); await sleep(300); return (await rows().count()) < 120 && (await page.locator('tbody tr', { hasText: 'bulk-0' }).count()) > 0; });
await check('10k profiles: search', async () => { await page.fill('#psearch', 'bulk-09999'); return until(async () => (await rows().count()) === 1, 3000); });

// 13 first run: create vault, recovery key shown once
await page.goto(base + '?fresh=1#/profiles'); await page.waitForSelector('#newPw');
await check('first run: create vault', async () => {
  await page.fill('#newPw', 'short'); await page.fill('#newPw2', 'short'); await page.click('#createBtn'); await sleep(100);
  const v = (await page.locator('#cvErr').innerText()).includes('12');
  await page.fill('#newPw', 'correct horse battery staple'); await page.fill('#newPw2', 'correct horse battery staple'); await page.click('#createBtn');
  return v && await until(async () => (await page.locator('#recoveryKey').count()) === 1, 4000);
});
await check('recovery key shown once, continue needs confirmation', async () => {
  const key = await page.locator('#recoveryKey').innerText(); const dis = await page.locator('#rkDone').isDisabled();
  await page.click('#rkSaved'); await page.click('#rkDone'); await page.waitForSelector('.nav');
  return /^[A-Z0-9]{4}(-[A-Z0-9]{4}){7}$/.test(key) && dis && (await page.locator('#recoveryKey').count()) === 0;
});
await check('unlock with recovery key', async () => {
  const key = await page.evaluate(() => null); void key;
  await page.keyboard.press('Control+l'); await page.waitForSelector('#pw');
  await page.click('#useRecovery'); await page.fill('#pw', 'AAAA-BBBB'); await page.click('#unlockBtn'); await sleep(900);
  return (await page.locator('#pwerr').innerText()).includes('recovery key');
});

await sleep(200);
const fails = results.filter(r => r.startsWith('FAIL')).length;
console.log(results.join('\n'));
console.log(`\n${results.length - fails}/${results.length} passed`);
console.log(errors.length ? 'ERRORS:\n' + errors.join('\n') : 'No console errors / exceptions');
await browser.close(); server.close();
process.exit(fails || errors.length ? 1 : 0);
