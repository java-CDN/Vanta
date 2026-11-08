import type { Backend } from './backend';

declare const __MOCK__: boolean;

/** The backend for this build: Tauri in the desktop app, the in-memory mock in
 *  `--mode mock` builds (browser dev, smoke tests). `__MOCK__` is a build-time constant,
 *  so the other implementation is dropped from the bundle. */
export async function connect(): Promise<Backend> {
  if (__MOCK__) {
    const { mockBackend } = await import('./mock');
    const qs = new URLSearchParams(location.search);
    const b = mockBackend({ fresh: qs.get('fresh') === '1', unlocked: qs.get('unlocked') === '1', extraProfiles: Number(qs.get('profiles') || 0), engineCheck: qs.get('engine') === 'failed' ? 'failed' : undefined });
    (window as unknown as { __vanta: Backend }).__vanta = b;
    return b;
  }
  const { connectTauri } = await import('./tauri');
  return connectTauri();
}

export type { Backend } from './backend';
export { errorText, asCoreError } from './backend';
