// TypeScript mirrors of the serde DTOs in crates/vanta-core (dto.rs, error.rs) and the
// shell's own values (apps/desktop/src-tauri). Field names are the Rust names.

export type OsKind = 'windows10' | 'windows11';
export type ProfileStatus = 'stopped' | 'starting' | 'running' | 'sleeping' | 'blocked' | 'crashed';

export interface ProfileMeta {
  id: string;
  name: string;
  folder: string;
  tags: string[];
  os: OsKind;
  proxy_id: string | null;
  exit_ip: string;
  country: string;
  health: number;
  status: ProfileStatus;
  color: string;
  notes: string;
  created_ms: number;
  last_opened_ms: number | null;
}

export interface ProfilePage { items: ProfileMeta[]; total: number }

export interface HealthSummary {
  profile_id: string;
  score: number;
  blocked: boolean;
  failing: string[];
  engine: string;
  proxy_id: string | null;
  ts_ms: number;
}

export interface PersonaSummary {
  device_id: string;
  os: OsKind;
  user_agent: string;
  screen: string;
  gpu: string;
  locale: string;
  hardware_concurrency: number;
  device_memory: number;
}

export interface ProfileDetail { meta: ProfileMeta; persona: PersonaSummary; health: HealthSummary | null }

export interface NewProfile {
  name: string;
  folder?: string;
  tags?: string[];
  os?: OsKind | null;
  locale?: string | null;
  notes?: string;
  color?: string;
  proxy_id?: string | null;
  /** 64-bit seed (hex) from previewFingerprint. */
  seed?: string | null;
}

export interface ProfileEdit {
  name?: string;
  folder?: string;
  tags?: string[];
  notes?: string;
  color?: string;
}

export type OfflineReason = 'unreachable' | 'timeout' | 'auth_failed' | 'protocol_error';
export type ProxyState =
  | { state: 'unknown' }
  | { state: 'online'; checked_ms: number; latency_ms: number }
  | { state: 'offline'; checked_ms: number; reason: OfflineReason };

export type ProxyScheme = 'http' | 'https' | 'socks5';

export interface ProxyView {
  id: string;
  scheme: ProxyScheme;
  host: string;
  port: number;
  username: string | null;
  has_password: boolean;
  label: string;
  state: ProxyState;
  display: string;
}

export interface ImportResult { added: ProxyView[]; errors: { line: number; message: string }[] }
export interface AssignResult { shared_with: string[] }

export interface CheckProblem { id: string; title: string; outcome: 'warn' | 'fail'; message: string }
export interface HealthResult { summary: HealthSummary; problems: CheckProblem[] }

export interface LaunchInfo { profile_id: string; pid: number; relay_port: number; engine_version: string }
export interface StatusChange { profile_id: string; status: ProfileStatus; exit_code: number | null }

export type LogKind =
  | 'profile_launch'
  | 'profile_stop'
  | 'vault_unlock'
  | 'vault_lock'
  | 'proxy_failure'
  | 'blocked_event'
  | 'health_run'
  | 'kill_switch'
  | 'proxy_reconnect'
  | 'launch_blocked'
  | 'profile_crash';

export interface LogEntry { seq: number; ts_ms: number; kind: LogKind; profile: string | null; detail: string }
export interface LogQuery {
  kinds?: LogKind[];
  profile?: string | null;
  from_ms?: number | null;
  to_ms?: number | null;
  offset?: number;
  limit?: number;
}
export interface LogPage { entries: LogEntry[]; total: number }

export type LogIntegrity =
  | { state: 'ok' }
  | { state: 'head_mismatch'; detail: string }
  | { state: 'unreadable'; detail: string };

export interface UnlockReport { log_integrity: LogIntegrity; migrated_proxies: number }
export interface VaultCreated { recovery_key: string }

export interface RuleView { id: string; level: 'pass' | 'note' | 'fail'; message: string }
export type SurfaceMode = 'real' | 'noise' | 'block';

export interface FingerprintView {
  device_id: string;
  os: OsKind;
  engine: string;
  user_agent: string;
  sec_ch_ua: string;
  navigator_platform: string;
  ua_platform: string;
  platform_version: string;
  architecture: string;
  bitness: string;
  screen_width: number;
  screen_height: number;
  avail_width: number;
  avail_height: number;
  color_depth: number;
  device_pixel_ratio: number;
  hardware_concurrency: number;
  device_memory: number;
  max_touch_points: number;
  gpu_vendor: string;
  gpu_renderer: string;
  webgpu_vendor: string;
  webgpu_arch: string;
  fonts: string[];
  microphones: number;
  cameras: number;
  speakers: number;
  locale: string;
  languages: string[];
  accept_language: string;
  timezone: string | null;
  country: string | null;
  latitude: number | null;
  longitude: number | null;
  canvas: SurfaceMode;
  webgl_image: SurfaceMode;
  audio: SurfaceMode;
  webrtc_policy: string;
  seed_prefix: string;
  rules: RuleView[];
}

export type DohProvider = 'cloudflare' | 'google' | 'quad9' | { custom: { ip: string; host: string; path: string } };

export interface GuardPolicy {
  kill_switch: 'fail_closed';
  webrtc: 'disable_non_proxied_udp';
  doh: DohProvider;
}

/** Shell state for the UI (no secrets). */
export interface AppInfo {
  app_version: string;
  initialized: boolean;
  unlocked: boolean;
  engine_version: string;
  engine_path: string;
  engine_found: boolean;
  data_dir: string;
  /** Result of the activity-log verification at the last unlock. */
  log_integrity: LogIntegrity | null;
  /** True only for the browser mock backend. */
  mock: boolean;
}

/** Shell settings (settings.json in the data folder; non-secret). */
export interface Settings {
  /** 0 = never. */
  autolock_minutes: number;
  theme: 'dark' | 'light';
  /** Ask before launching more than this many profiles at once. */
  max_launch: number;
  confirm_delete: boolean;
  /** Override of the engine executable; null = default install path. Applies after restart. */
  engine_path: string | null;
  /** Plain-text IP echo endpoint for health runs; null = the default (api.ipify.org). */
  ip_echo_url: string | null;
}

export type CoreError =
  | { kind: 'not_initialized' }
  | { kind: 'already_initialized' }
  | { kind: 'locked' }
  | { kind: 'crypto' }
  | { kind: 'not_found'; message: string }
  | { kind: 'invalid'; message: string }
  | { kind: 'already_running' }
  | { kind: 'not_running' }
  | { kind: 'blocked'; reasons: { code: string; message: string }[] }
  | { kind: 'bad_config_signature' }
  | { kind: 'version_mismatch'; expected: string }
  | { kind: 'engine_exited'; code: number | null }
  | { kind: 'unsupported'; message: string }
  | { kind: 'storage'; message: string }
  | { kind: 'network'; message: string }
  /** The last `failures` launches failed in a row: ask the user, then launch with `confirmed`. */
  | { kind: 'confirm_required'; failures: number; last_error: string };

export interface LockedEvent { reason: 'idle' | 'user' | 'shortcut' }
export interface CloseRequest { running: number }
