type Bucket = { count: number; resetAt: number };

const buckets = new Map<string, Bucket>();

function getClientId(req: Request): string {
  const xff = req.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0]?.trim() || 'unknown';
  const realIp = req.headers.get('x-real-ip');
  if (realIp) return realIp.trim();
  return 'local';
}

export function rateLimit(req: Request, input: { key: string; max: number; windowMs: number }): { allowed: boolean; remaining: number; retryAfterSec: number } {
  const now = Date.now();
  const client = getClientId(req);
  const key = `${input.key}:${client}`;
  const windowMs = Math.max(1_000, input.windowMs);
  const max = Math.max(1, input.max);

  const current = buckets.get(key);
  if (!current || now >= current.resetAt) {
    const next: Bucket = { count: 1, resetAt: now + windowMs };
    buckets.set(key, next);
    return { allowed: true, remaining: max - 1, retryAfterSec: Math.ceil(windowMs / 1000) };
  }

  if (current.count >= max) {
    return { allowed: false, remaining: 0, retryAfterSec: Math.max(1, Math.ceil((current.resetAt - now) / 1000)) };
  }

  current.count += 1;
  buckets.set(key, current);
  return { allowed: true, remaining: Math.max(0, max - current.count), retryAfterSec: Math.max(1, Math.ceil((current.resetAt - now) / 1000)) };
}

