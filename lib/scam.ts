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
    return false;
  } catch {
    return false;
  }
}

