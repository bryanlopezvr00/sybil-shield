export type HandleSignal = {
  normalized: string;
  stem: string;
  shape: string;
};

export function normalizeHandle(handle: string): string {
  return handle.trim().toLowerCase();
}

export function handleStem(handle: string): string {
  // Collapses common sybil naming patterns:
  // - removes non-alphanumerics
  // - strips trailing digits
  const normalized = normalizeHandle(handle);
  const alnum = normalized.replace(/[^a-z0-9]/g, '');
  return alnum.replace(/\d+$/g, '');
}

export function handleShape(handle: string): string {
  // e.g. "user_001" -> "aaaa_dddd"
  const normalized = normalizeHandle(handle);
  return normalized
    .replace(/[a-z]/g, 'a')
    .replace(/\d/g, 'd')
    .replace(/[^ad]/g, '_')
    .replace(/_+/g, '_');
}

export function computeHandleSignals(handles: string[]): Map<string, HandleSignal> {
  const map = new Map<string, HandleSignal>();
  for (const h of handles) {
    map.set(h, { normalized: normalizeHandle(h), stem: handleStem(h), shape: handleShape(h) });
  }
  return map;
}

export function computeHandlePatternScores(handles: string[]): {
  stemCounts: Map<string, number>;
  shapeCounts: Map<string, number>;
  scoreByHandle: Map<string, number>;
} {
  const signals = computeHandleSignals(handles);
  const stemCounts = new Map<string, number>();
  const shapeCounts = new Map<string, number>();

  for (const { stem, shape } of signals.values()) {
    if (stem) stemCounts.set(stem, (stemCounts.get(stem) || 0) + 1);
    if (shape) shapeCounts.set(shape, (shapeCounts.get(shape) || 0) + 1);
  }

  const scoreByHandle = new Map<string, number>();
  for (const [handle, s] of signals.entries()) {
    const stemSize = s.stem ? stemCounts.get(s.stem) || 1 : 1;
    const shapeSize = s.shape ? shapeCounts.get(s.shape) || 1 : 1;

    // Heuristic: repeated stems/shapes and numeric suffixes are common in sybil farms.
    const hasNumericSuffix = /\d{3,}$/.test(s.normalized.replace(/[^a-z0-9]/g, ''));
    const stemScore = Math.min((stemSize - 1) / 10, 1);
    const shapeScore = Math.min((shapeSize - 1) / 20, 1);
    const numericScore = hasNumericSuffix ? 0.4 : 0;

    scoreByHandle.set(handle, Math.min(0.5 * stemScore + 0.3 * shapeScore + numericScore, 1));
  }

  return { stemCounts, shapeCounts, scoreByHandle };
}

export function isLikelyPhishingUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    if (host.startsWith('xn--')) return true; // punycode often used for homograph attacks
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return true; // IP literal
    const labels = host.split('.').filter(Boolean);
    if (labels.length >= 5) return true; // excessive subdomains
    if (parsed.username || parsed.password) return true; // userinfo in URL
    if (isLikelyTyposquatHost(host)) return true;
    // Additional checks for mini-apps and scams
    if (host.includes('miniapp') && host.includes('scam')) return true;
    if (host.includes('wallet') && host.includes('drain')) return true;
    if (host.includes('airdrop') && host.includes('free')) return true;
    if (parsed.pathname.includes('login') && parsed.searchParams.has('redirect')) return true; // suspicious redirects
    return false;
  } catch {
    return false;
  }
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a) return b.length;
  if (!b) return a.length;
  const m = a.length;
  const n = b.length;
  const dp = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) dp[j] = j;
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + cost);
      prev = tmp;
    }
  }
  return dp[n];
}

const BRAND_HOSTS = [
  'metamask.io',
  'opensea.io',
  'github.com',
  'discord.com',
  'telegram.org',
  't.me',
  'x.com',
  'twitter.com',
  'coinbase.com',
  'binance.com',
  'etherscan.io',
];

function isLikelyTyposquatHost(host: string): boolean {
  const normalized = host.replace(/^www\./, '').toLowerCase();
  const labels = normalized.split('.').filter(Boolean);
  if (labels.length < 2) return false;

  const domain = labels.slice(-2).join('.');
  for (const brand of BRAND_HOSTS) {
    if (domain === brand) return false;
  }

  // Compare second-level label against known brands (edit distance 1-2)
  const sld = labels[labels.length - 2];
  for (const brand of BRAND_HOSTS) {
    const brandLabels = brand.split('.').filter(Boolean);
    const brandSld = brandLabels[brandLabels.length - 2];
    if (!brandSld) continue;
    const dist = levenshtein(sld, brandSld);
    if (dist === 1) return true;
    if (dist === 2 && sld.length >= 6) return true;
  }

  // Detect common homoglyph-ish substitutions without punycode (e.g., "d1scord")
  if (/[0-9]/.test(sld)) {
    const swaps = sld.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/7/g, 't');
    for (const brand of BRAND_HOSTS) {
      const brandSld = brand.split('.').slice(-2)[0];
      if (!brandSld) continue;
      const dist = levenshtein(swaps, brandSld);
      if (dist <= 1) return true;
    }
  }

  return false;
}
