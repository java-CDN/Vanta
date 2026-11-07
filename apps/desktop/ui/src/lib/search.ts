// Profile search language (F01), the same grammar as crates/vanta-store/src/query.rs:
//   tag:shop os:win11 health:<80 status:running folder:"QA Lab" proxy:DE frankfurt
// Terms are AND-ed; the word OR separates alternative groups. The real search runs in
// SQLite (FTS5); this module is used to build queries from the filter controls, to show
// syntax errors as the user types, and by the mock backend.

import type { ProfileMeta, ProfileStatus } from '../api/types';

export type Cmp = '<' | '<=' | '>' | '>=' | '=';
export type Term =
  | { k: 'tag'; v: string }
  | { k: 'os'; v: 'windows10' | 'windows11' }
  | { k: 'status'; v: ProfileStatus }
  | { k: 'health'; cmp: Cmp; n: number }
  | { k: 'folder'; v: string }
  | { k: 'proxy'; v: string }
  | { k: 'text'; v: string };
export type Query = Term[][];

export class SearchError extends Error {}

const STATUSES: ProfileStatus[] = ['stopped', 'starting', 'running', 'sleeping', 'blocked', 'crashed'];

export function tokenize(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQ = false;
  for (const c of s) {
    if (c === '"') inQ = !inQ;
    else if (/\s/.test(c) && !inQ) {
      if (cur) { out.push(cur); cur = ''; }
    } else cur += c;
  }
  if (inQ) throw new SearchError('unclosed quote in search');
  if (cur) out.push(cur);
  return out;
}

function osAlias(v: string): 'windows10' | 'windows11' {
  const l = v.toLowerCase();
  if (['win11', 'windows11', 'w11'].includes(l)) return 'windows11';
  if (['win10', 'windows10', 'w10'].includes(l)) return 'windows10';
  throw new SearchError(`unknown os '${l}' (use win10 or win11)`);
}

function health(v: string): Term {
  const m = /^(<=|>=|<|>|=)?(.*)$/.exec(v)!;
  const cmp = (m[1] || '=') as Cmp;
  if (!/^-?\d+$/.test(m[2])) throw new SearchError(`health value '${v}'`);
  const n = Number(m[2]);
  if (n < 0 || n > 100) throw new SearchError('health must be 0-100');
  return { k: 'health', cmp, n };
}

export function parse(s: string): Query {
  const q: Query = [];
  let group: Term[] = [];
  for (const tok of tokenize(s)) {
    if (tok === 'OR') {
      if (group.length) { q.push(group); group = []; }
      continue;
    }
    const i = tok.indexOf(':');
    const k = i > 0 ? tok.slice(0, i).toLowerCase() : '';
    const v = i > 0 ? tok.slice(i + 1) : '';
    let t: Term;
    if (!v) t = { k: 'text', v: tok };
    else if (k === 'tag') t = { k: 'tag', v: v.toLowerCase() };
    else if (k === 'os') t = { k: 'os', v: osAlias(v) };
    else if (k === 'status') {
      const sv = v.toLowerCase() as ProfileStatus;
      if (!STATUSES.includes(sv)) throw new SearchError(`unknown status '${sv}'`);
      t = { k: 'status', v: sv };
    } else if (k === 'health') t = health(v);
    else if (k === 'folder') t = { k: 'folder', v };
    else if (k === 'proxy') t = { k: 'proxy', v };
    else t = { k: 'text', v: tok };
    group.push(t);
  }
  if (group.length) q.push(group);
  return q;
}

/** Returns the syntax error message, or '' when the query parses. */
export function validate(s: string): string {
  try { parse(s); return ''; } catch (e) { return e instanceof SearchError ? e.message : String(e); }
}

const cmp = (a: number, c: Cmp, b: number) =>
  c === '<' ? a < b : c === '<=' ? a <= b : c === '>' ? a > b : c === '>=' ? a >= b : a === b;

/** In-memory evaluation with the SQL semantics (used by the mock backend). Text terms are
 *  word-prefix matches over name, tags, exit IP, notes and folder, like the FTS5 index. */
export function matches(q: Query, p: ProfileMeta): boolean {
  if (!q.length) return true;
  return q.some(g => g.every(t => {
    switch (t.k) {
      case 'tag': return p.tags.map(x => x.toLowerCase()).includes(t.v);
      case 'os': return p.os === t.v;
      case 'status': return p.status === t.v;
      case 'health': return cmp(p.health, t.cmp, t.n);
      case 'folder': return p.folder.toLowerCase() === t.v.toLowerCase();
      case 'proxy':
        return /^[a-z]{2}$/i.test(t.v) ? p.country === t.v.toUpperCase() : p.exit_ip.startsWith(t.v);
      case 'text': {
        const needle = t.v.toLowerCase();
        const words = [p.name, ...p.tags, p.exit_ip, p.notes, p.folder].join(' ').toLowerCase().split(/[^\p{L}\p{N}]+/u);
        const parts = needle.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
        if (!parts.length) return true;
        // FTS5 phrase-prefix: consecutive words, the last one as a prefix.
        for (let i = 0; i + parts.length <= words.length; i++) {
          if (parts.every((w, j) => (j === parts.length - 1 ? words[i + j].startsWith(w) : words[i + j] === w))) return true;
        }
        return false;
      }
    }
  }));
}

export interface Filters { status: string; tag: string; country: string; folder: string }

const quote = (v: string) => (/[\s"]/.test(v) ? `"${v.replace(/"/g, '')}"` : v);

/** Combine the free-text box with the filter dropdowns into one query (AND). */
export function buildQuery(text: string, f: Filters): string {
  const extra: string[] = [];
  if (f.status) extra.push(`status:${f.status.toLowerCase()}`);
  if (f.tag) extra.push(`tag:${quote(f.tag)}`);
  if (f.country) extra.push(`proxy:${f.country}`);
  if (f.folder) extra.push(`folder:${quote(f.folder)}`);
  const t = text.trim();
  if (!extra.length) return t;
  if (!t) return extra.join(' ');
  // Filters apply to every OR-group of the typed query.
  const groups = t.split(/\s+OR\s+/);
  return groups.map(g => `${g} ${extra.join(' ')}`).join(' OR ');
}
