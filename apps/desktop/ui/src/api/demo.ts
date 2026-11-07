// Demo data for the mock backend, taken from the approved prototype
// (design/prototype/src/data.js and core.js). Documentation IP ranges only.

export const ENGINE = '156.0.8078.79';

export const COUNTRIES: Record<string, { name: string; tz: string; locale: string; city: string; lat: number; lng: number }> = {
  DE: { name: 'Germany', tz: 'Europe/Berlin', locale: 'de-DE', city: 'Frankfurt', lat: 50.11, lng: 8.68 },
  NL: { name: 'Netherlands', tz: 'Europe/Amsterdam', locale: 'nl-NL', city: 'Amsterdam', lat: 52.37, lng: 4.9 },
  US: { name: 'United States', tz: 'America/New_York', locale: 'en-US', city: 'New York', lat: 40.71, lng: -74.01 },
  GB: { name: 'United Kingdom', tz: 'Europe/London', locale: 'en-GB', city: 'London', lat: 51.51, lng: -0.13 },
  IN: { name: 'India', tz: 'Asia/Kolkata', locale: 'en-IN', city: 'Mumbai', lat: 19.08, lng: 72.88 },
  FR: { name: 'France', tz: 'Europe/Paris', locale: 'fr-FR', city: 'Paris', lat: 48.86, lng: 2.35 },
  JP: { name: 'Japan', tz: 'Asia/Tokyo', locale: 'ja-JP', city: 'Tokyo', lat: 35.68, lng: 139.69 },
  CA: { name: 'Canada', tz: 'America/Toronto', locale: 'en-CA', city: 'Toronto', lat: 43.65, lng: -79.38 },
};

export const GPUS: Record<string, { v: string; name: string; arch: string; arm?: boolean }> = {
  rtx4070: { v: 'NVIDIA', name: 'NVIDIA GeForce RTX 4070 (0x00002786)', arch: 'lovelace' },
  rtx4060m: { v: 'NVIDIA', name: 'NVIDIA GeForce RTX 4060 Laptop GPU (0x000028A0)', arch: 'lovelace' },
  rtx3060: { v: 'NVIDIA', name: 'NVIDIA GeForce RTX 3060 (0x00002504)', arch: 'ampere' },
  gtx1650: { v: 'NVIDIA', name: 'NVIDIA GeForce GTX 1650 (0x00001F82)', arch: 'turing' },
  rx7800: { v: 'AMD', name: 'AMD Radeon RX 7800 XT (0x0000747E)', arch: 'rdna-3' },
  rx6600: { v: 'AMD', name: 'AMD Radeon RX 6600 (0x000073FF)', arch: 'rdna-2' },
  rx580: { v: 'AMD', name: 'Radeon RX 580 Series (0x000067DF)', arch: 'gcn-4' },
  uhd630: { v: 'Intel', name: 'Intel(R) UHD Graphics 630 (0x00003E92)', arch: 'gen-9' },
  uhd620: { v: 'Intel', name: 'Intel(R) UHD Graphics 620 (0x00005917)', arch: 'gen-9' },
  irisxe: { v: 'Intel', name: 'Intel(R) Iris(R) Xe Graphics (0x00009A49)', arch: 'gen-12lp' },
  arca770: { v: 'Intel', name: 'Intel(R) Arc(TM) A770 Graphics (0x000056A0)', arch: 'alchemist' },
  adreno: { v: 'Qualcomm', name: 'Qualcomm(R) Adreno(TM) X1-85 GPU (0x36334330)', arch: 'adreno-x1', arm: true },
};

export interface Device { id: string; os: ('windows10' | 'windows11')[]; gpu: string; cores: number; mem: number; res: string; dpr: number; w: number }
export const DEVICES: Device[] = [
  { id: 'win11-rtx4070-1440p', os: ['windows11'], gpu: 'rtx4070', cores: 16, mem: 8, res: '2560x1440', dpr: 1, w: 6 },
  { id: 'win11-rtx3060-1080p', os: ['windows11', 'windows10'], gpu: 'rtx3060', cores: 12, mem: 8, res: '1920x1080', dpr: 1, w: 14 },
  { id: 'win10-gtx1650-1080p', os: ['windows10', 'windows11'], gpu: 'gtx1650', cores: 12, mem: 8, res: '1920x1080', dpr: 1, w: 11 },
  { id: 'win11-rx7800xt-1440p', os: ['windows11'], gpu: 'rx7800', cores: 16, mem: 8, res: '2560x1440', dpr: 1, w: 4 },
  { id: 'win10-rx6600-1080p', os: ['windows10', 'windows11'], gpu: 'rx6600', cores: 12, mem: 8, res: '1920x1080', dpr: 1, w: 5 },
  { id: 'win10-uhd630-1080p', os: ['windows10', 'windows11'], gpu: 'uhd630', cores: 6, mem: 8, res: '1920x1080', dpr: 1, w: 13 },
  { id: 'win11-irisxe-laptop-1536', os: ['windows11', 'windows10'], gpu: 'irisxe', cores: 8, mem: 8, res: '1536x864', dpr: 1.25, w: 15 },
  { id: 'win11-arc-a770-1440p', os: ['windows11'], gpu: 'arca770', cores: 20, mem: 8, res: '2560x1440', dpr: 1, w: 2 },
  { id: 'win11-adreno-x1-laptop', os: ['windows11'], gpu: 'adreno', cores: 12, mem: 8, res: '1920x1200', dpr: 1.5, w: 2 },
  { id: 'win10-uhd620-laptop-1366', os: ['windows10'], gpu: 'uhd620', cores: 8, mem: 8, res: '1366x768', dpr: 1, w: 9 },
  { id: 'win11-rtx4060-laptop-1080p', os: ['windows11'], gpu: 'rtx4060m', cores: 20, mem: 8, res: '1920x1080', dpr: 1.25, w: 8 },
  { id: 'win10-rx580-1080p', os: ['windows10'], gpu: 'rx580', cores: 12, mem: 8, res: '1920x1080', dpr: 1, w: 4 },
];

export const FONTS_WIN11 = ['Segoe UI', 'Segoe UI Variable', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Segoe Fluent Icons', 'Segoe MDL2 Assets', 'Calibri', 'Cambria', 'Candara', 'Consolas', 'Constantia', 'Corbel', 'Cascadia Code', 'Cascadia Mono', 'Arial', 'Bahnschrift', 'Courier New', 'Georgia', 'Ink Free', 'Times New Roman', 'Trebuchet MS', 'Verdana', 'Tahoma'];
export const FONTS_WIN10 = ['Segoe UI', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Segoe MDL2 Assets', 'Calibri', 'Cambria', 'Candara', 'Consolas', 'Constantia', 'Corbel', 'Arial', 'Bahnschrift', 'Courier New', 'Georgia', 'Ink Free', 'Impact', 'Times New Roman', 'Trebuchet MS', 'Verdana', 'Tahoma', 'Comic Sans MS'];

/** name, scheme, provider, country, exit ip, latency, status */
export const PROXY_SEED: [string, 'socks5' | 'http', string, string, string, number | null, 'ok' | 'slow' | 'offline'][] = [
  ['geo-de-1', 'socks5', 'Geonode', 'DE', '203.0.113.24', 42, 'ok'],
  ['geo-de-2', 'socks5', 'Geonode', 'DE', '203.0.113.57', 51, 'ok'],
  ['di-nl-1', 'http', 'DataImpulse', 'NL', '198.51.100.12', 47, 'ok'],
  ['soax-us-1', 'socks5', 'SOAX', 'US', '198.51.100.73', 88, 'ok'],
  ['soax-us-2', 'socks5', 'SOAX', 'US', '198.51.100.88', 92, 'ok'],
  ['ws-gb-1', 'http', 'Webshare', 'GB', '192.0.2.41', 412, 'slow'],
  ['soax-in-1', 'socks5', 'SOAX', 'IN', '192.0.2.150', 118, 'ok'],
  ['soax-in-2', 'socks5', 'SOAX', 'IN', '192.0.2.151', 124, 'ok'],
  ['dc-fr-1', 'socks5', 'Own server', 'FR', '203.0.113.90', 29, 'ok'],
  ['dc-jp-1', 'socks5', 'Own server', 'JP', '203.0.113.120', null, 'offline'],
  ['ws-ca-1', 'http', 'Webshare', 'CA', '198.51.100.201', 77, 'ok'],
  ['ws-ca-2', 'http', 'Webshare', 'CA', '198.51.100.202', 81, 'ok'],
  ['geo-nl-1', 'socks5', 'Geonode', 'NL', '198.51.100.31', 49, 'ok'],
  ['soax-us-3', 'socks5', 'SOAX', 'US', '198.51.100.94', 85, 'ok'],
  ['geo-de-3', 'socks5', 'Geonode', 'DE', '203.0.113.61', 46, 'ok'],
  ['di-nl-2', 'http', 'DataImpulse', 'NL', '198.51.100.33', 52, 'ok'],
  ['bd-fr-1', 'socks5', 'Bright Data', 'FR', '203.0.113.95', 38, 'ok'],
  ['bd-us-1', 'socks5', 'Bright Data', 'US', '198.51.100.110', 79, 'ok'],
  ['ws-gb-2', 'http', 'Webshare', 'GB', '192.0.2.44', 58, 'ok'],
  ['th-ca-1', 'socks5', 'Thordata', 'CA', '198.51.100.205', 84, 'ok'],
  ['soax-in-3', 'socks5', 'SOAX', 'IN', '192.0.2.153', 131, 'ok'],
  ['th-us-1', 'socks5', 'Thordata', 'US', '198.51.100.120', 90, 'ok'],
  ['bd-gb-1', 'socks5', 'Bright Data', 'GB', '192.0.2.60', 61, 'ok'],
  ['dc-de-1', 'socks5', 'Own server', 'DE', '203.0.113.130', 24, 'ok'],
  ['geo-ca-1', 'socks5', 'Geonode', 'CA', '198.51.100.210', 88, 'ok'],
  ['geo-de-4', 'socks5', 'Geonode', 'DE', '203.0.113.66', 44, 'ok'],
  ['bd-nl-1', 'socks5', 'Bright Data', 'NL', '198.51.100.40', 45, 'ok'],
  ['th-jp-1', 'socks5', 'Thordata', 'JP', '203.0.113.140', 152, 'ok'],
];

/** name, folder, tags, os, proxy, health, status, minutes ago, device, geo (ok | tz:<tz> | none), notes */
export const PROFILE_SEED: [string, string, string[], 'windows10' | 'windows11', string, number, 'running' | 'stopped' | 'blocked', number, string, string, string][] = [
  ['shop-de-01', 'E-commerce', ['shop', 'de'], 'windows11', 'geo-de-1', 96, 'running', 5, 'win11-rtx4070-1440p', 'ok', 'Main store account. Keep on Geonode sticky session.'],
  ['shop-de-02', 'E-commerce', ['shop', 'de'], 'windows11', 'geo-de-2', 94, 'running', 7, 'win11-rtx3060-1080p', 'ok', ''],
  ['shop-nl-01', 'E-commerce', ['shop', 'nl'], 'windows10', 'di-nl-1', 91, 'stopped', 60 * 18, 'win10-gtx1650-1080p', 'ok', ''],
  ['ads-us-01', 'Ads', ['ads', 'us'], 'windows11', 'soax-us-1', 98, 'running', 52, 'win11-irisxe-laptop-1536', 'ok', 'Campaign manager, weekly budget review on Mondays.'],
  ['ads-us-02', 'Ads', ['ads', 'us'], 'windows10', 'soax-us-2', 88, 'stopped', 60 * 72, 'win10-uhd630-1080p', 'ok', ''],
  ['ads-gb-01', 'Ads', ['ads', 'gb'], 'windows11', 'ws-gb-1', 79, 'stopped', 60 * 96, 'win11-rtx3060-1080p', 'ok', 'Proxy is slow (DNS 410 ms). Consider moving to bd-gb pool.'],
  ['social-in-01', 'Social', ['social', 'in'], 'windows11', 'soax-in-1', 95, 'running', 150, 'win11-rtx4060-laptop-1080p', 'ok', ''],
  ['social-in-02', 'Social', ['social', 'in'], 'windows10', 'soax-in-2', 93, 'stopped', 60 * 50, 'win10-uhd620-laptop-1366', 'ok', ''],
  ['qa-fr-01', 'QA Lab', ['qa'], 'windows11', 'dc-fr-1', 97, 'running', 200, 'win11-rx7800xt-1440p', 'ok', 'Own server in Paris.'],
  ['qa-jp-01', 'QA Lab', ['qa'], 'windows11', 'dc-jp-1', 58, 'blocked', 60 * 120, 'win11-arc-a770-1440p', 'ok', 'Own server in Tokyo is down since Tuesday.'],
  ['research-01', 'Research', ['research'], 'windows11', 'ws-ca-1', 90, 'stopped', 320, 'win11-irisxe-laptop-1536', 'ok', ''],
  ['research-02', 'Research', ['research'], 'windows11', 'ws-ca-2', 92, 'stopped', 60 * 140, 'win11-rtx3060-1080p', 'tz:America/New_York', ''],
  ['shop-de-03', 'E-commerce', ['shop', 'de'], 'windows11', 'geo-nl-1', 95, 'stopped', 60 * 190, 'win10-rx6600-1080p', 'tz:Europe/Berlin', 'Proxy changed from DE pool to NL last week.'],
  ['ads-us-03', 'Ads', ['ads', 'us'], 'windows11', 'soax-us-3', 97, 'stopped', 60 * 210, 'win11-rtx4060-laptop-1080p', 'ok', ''],
  ['shop-de-04', 'E-commerce', ['shop', 'de'], 'windows11', 'geo-de-3', 95, 'stopped', 80, 'win11-rtx4070-1440p', 'ok', ''],
  ['shop-nl-02', 'E-commerce', ['shop', 'nl'], 'windows10', 'di-nl-2', 92, 'stopped', 60 * 30, 'win10-gtx1650-1080p', 'ok', ''],
  ['shop-fr-01', 'E-commerce', ['shop', 'fr'], 'windows11', 'bd-fr-1', 94, 'stopped', 60 * 26, 'win11-irisxe-laptop-1536', 'ok', ''],
  ['ads-us-04', 'Ads', ['ads', 'us'], 'windows10', 'bd-us-1', 89, 'stopped', 60 * 160, 'win10-rx580-1080p', 'ok', ''],
  ['ads-gb-02', 'Ads', ['ads', 'gb'], 'windows11', 'ws-gb-2', 93, 'stopped', 60 * 44, 'win11-rtx3060-1080p', 'ok', ''],
  ['ads-ca-01', 'Ads', ['ads', 'ca'], 'windows11', 'th-ca-1', 91, 'stopped', 60 * 230, 'win11-adreno-x1-laptop', 'ok', 'Snapdragon laptop record.'],
  ['social-in-03', 'Social', ['social', 'in'], 'windows10', 'soax-in-3', 87, 'stopped', 60 * 260, 'win10-uhd620-laptop-1366', 'ok', ''],
  ['social-us-01', 'Social', ['social', 'us'], 'windows11', 'th-us-1', 96, 'stopped', 60 * 22, 'win11-rtx4060-laptop-1080p', 'ok', ''],
  ['social-gb-01', 'Social', ['social', 'gb'], 'windows10', 'bd-gb-1', 90, 'stopped', 60 * 300, 'win10-uhd630-1080p', 'none', ''],
  ['qa-de-01', 'QA Lab', ['qa', 'de'], 'windows11', 'dc-de-1', 99, 'stopped', 60 * 6, 'win11-rx7800xt-1440p', 'ok', 'Reference profile for Health Check baselines.'],
  ['research-03', 'Research', ['research'], 'windows10', 'geo-ca-1', 85, 'stopped', 60 * 400, 'win10-gtx1650-1080p', 'none', ''],
];

export function hashStr(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
