// Frontend bundle budget: the Tauri build (ui/dist) must stay under 300 KB gzipped.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const BUDGET = 300 * 1024;
let raw = 0, gz = 0;
const walk = d => fs.readdirSync(d, { withFileTypes: true }).forEach(e => {
  const f = path.join(d, e.name);
  if (e.isDirectory()) return walk(f);
  const b = fs.readFileSync(f); raw += b.length; const g = zlib.gzipSync(b, { level: 9 }).length; gz += g;
  console.log(`${path.relative(dir, f).padEnd(36)} ${String(b.length).padStart(8)} B  gzip ${String(g).padStart(7)} B`);
});
walk(dir);
console.log(`total ${raw} B, gzip ${gz} B (${(gz / 1024).toFixed(1)} KB, budget ${BUDGET / 1024} KB)`);
process.exit(gz > BUDGET ? 1 : 0);
