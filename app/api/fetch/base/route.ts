import { NextResponse } from 'next/server';
import { rateLimit } from '../../../../lib/rateLimit';

type LogEntry = {
  timestamp: string;
  platform: string;
  action: string;
  actor: string;
  target: string;
  amount?: number;
  txHash?: string;
  blockNumber?: number;
  meta?: string;
  targetType?: string;
};

type RpcLog = {
  address: string;
  topics: string[];
  data: string;
  blockNumber: string;
  transactionHash: string;
  logIndex: string;
};

const TRANSFER_TOPIC0 = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

function isBlockedHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local')) return true;
  if (h === '127.0.0.1' || h === '0.0.0.0' || h === '::1') return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
    const [a, b] = h.split('.').map((x) => Number.parseInt(x, 10));
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  return false;
}

function normalizePublicHttpsUrlInput(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== 'https:') return null;
    if (isBlockedHost(url.hostname)) return null;
    return url.toString();
  } catch {
    return null;
  }
}

function jsonRpc(url: string, method: string, params: unknown[], id: number) {
  return fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    cache: 'no-store',
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  });
}

function toHexBlock(n: number): string {
  return `0x${n.toString(16)}`;
}

function parseHexNumber(hex: string): number {
  return Number.parseInt(hex.startsWith('0x') ? hex.slice(2) : hex, 16);
}

function padTopicAddress(addr: string): string {
  const a = addr.toLowerCase();
  const stripped = a.startsWith('0x') ? a.slice(2) : a;
  if (stripped.length !== 40) throw new Error('Invalid address');
  return `0x${stripped.padStart(64, '0')}`;
}

function topicToAddress(topic: string): string {
  const t = topic.toLowerCase().startsWith('0x') ? topic.slice(2) : topic.toLowerCase();
  return `0x${t.slice(24)}`;
}

function parseUint256ToString(hexData: string): string {
  const h = hexData.startsWith('0x') ? hexData.slice(2) : hexData;
  if (!h) return '0';
  return BigInt(`0x${h}`).toString(10);
}

async function rpcResult<T>(res: Response): Promise<T> {
  const json = (await res.json()) as { error?: { message?: string }; result?: T };
  if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
  if (json.error) throw new Error(json.error.message || 'RPC error');
  if (json.result === undefined) throw new Error('RPC missing result');
  return json.result;
}

async function getBlockTimestampMs(rpcUrl: string, blockHex: string): Promise<number> {
  const res = await jsonRpc(rpcUrl, 'eth_getBlockByNumber', [blockHex, false], 1);
  const block = await rpcResult<{ timestamp: string }>(res);
  return parseHexNumber(block.timestamp) * 1000;
}

type GetLogsOptions = {
  rpcUrl: string;
  fromBlock: number;
  toBlock: number;
  addressTopic?: string;
  direction: 'in' | 'out';
  token?: string;
  chunkSize: number;
  maxLogs: number;
};

async function getTransferLogs(opts: GetLogsOptions): Promise<RpcLog[]> {
  const logs: RpcLog[] = [];
  const tokenAddress = opts.token ? opts.token.toLowerCase() : undefined;

  for (let start = opts.fromBlock; start <= opts.toBlock; start += opts.chunkSize + 1) {
    const end = Math.min(opts.toBlock, start + opts.chunkSize);
    const topics =
      opts.direction === 'out'
        ? [TRANSFER_TOPIC0, opts.addressTopic ?? null]
        : [TRANSFER_TOPIC0, null, opts.addressTopic ?? null];

    const filter: Record<string, unknown> = {
      fromBlock: toHexBlock(start),
      toBlock: toHexBlock(end),
      topics,
    };
    if (tokenAddress) filter.address = tokenAddress;

    const res = await jsonRpc(opts.rpcUrl, 'eth_getLogs', [filter], 2);
    const batch = await rpcResult<RpcLog[]>(res);
    logs.push(...batch);
    if (logs.length >= opts.maxLogs) return logs.slice(0, opts.maxLogs);
  }

  return logs;
}

function dedupeLogs(logs: RpcLog[]): RpcLog[] {
  const seen = new Set<string>();
  const out: RpcLog[] = [];
  for (const l of logs) {
    const key = `${l.transactionHash}:${l.logIndex}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(l);
  }
  return out;
}

export async function GET(req: Request) {
  const rl = rateLimit(req, { key: 'fetch_base', max: 30, windowMs: 60_000 });
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited. Try again later.' }, { status: 429 });

  const { searchParams } = new URL(req.url);
  const rpcUrlParam = searchParams.get('rpcUrl');
  const normalizedRpcUrlParam = rpcUrlParam ? normalizePublicHttpsUrlInput(rpcUrlParam) : null;
  if (rpcUrlParam && !normalizedRpcUrlParam) {
    return NextResponse.json(
      {
        error: 'Invalid `rpcUrl` (must be a public https URL; localhost/private IPs blocked).',
        hint: 'If you need a private/local RPC endpoint, set BASE_RPC_URL in .env.local instead.',
      },
      { status: 400 },
    );
  }

  const rpcUrl = normalizedRpcUrlParam || process.env.BASE_RPC_URL;
  if (!rpcUrl) {
    return NextResponse.json(
      {
        error: 'Base onchain fetch is not configured.',
        hint: 'Set BASE_RPC_URL in .env.local, or pass a public https `rpcUrl` query param.',
        requiredEnv: ['BASE_RPC_URL'],
      },
      { status: 501 },
    );
  }

  const address = (searchParams.get('address') || '').trim().toLowerCase();
  const token = (searchParams.get('token') || '').trim();
  const maxBlocks = Math.min(Math.max(Number.parseInt(searchParams.get('maxBlocks') || '5000', 10) || 5000, 100), 20000);
  const maxLogs = Math.min(Math.max(Number.parseInt(searchParams.get('maxLogs') || '2000', 10) || 2000, 100), 10000);
  const chunkSize = Math.min(Math.max(Number.parseInt(searchParams.get('chunkSize') || '1500', 10) || 1500, 250), 5000);
  const direction = (searchParams.get('direction') || 'both').toLowerCase();

  if (!address || !address.startsWith('0x') || address.length !== 42) {
    return NextResponse.json({ error: 'Missing/invalid `address` (expected 0x…20 bytes).' }, { status: 400 });
  }

  let latestBlock = 0;
  try {
    const res = await jsonRpc(rpcUrl, 'eth_blockNumber', [], 0);
    const hex = await rpcResult<string>(res);
    latestBlock = parseHexNumber(hex);
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : 'Failed to fetch latest block' }, { status: 502 });
  }

  const toBlock = latestBlock;
  const fromBlock = Math.max(0, latestBlock - maxBlocks);

  let addressTopic: string;
  try {
    addressTopic = padTopicAddress(address);
  } catch {
    return NextResponse.json({ error: 'Invalid `address`.' }, { status: 400 });
  }

  const requestedDirections: Array<'in' | 'out'> =
    direction === 'in' ? ['in'] : direction === 'out' ? ['out'] : ['in', 'out'];

  try {
    const all: RpcLog[] = [];
    for (const dir of requestedDirections) {
      const batch = await getTransferLogs({
        rpcUrl,
        fromBlock,
        toBlock,
        addressTopic,
        direction: dir,
        token: token || undefined,
        chunkSize,
        maxLogs,
      });
      all.push(...batch);
    }
    const logs = dedupeLogs(all);

    // Timestamp cache per block
    const tsByBlock = new Map<number, number>();
    const toIso = (ms: number) => new Date(ms).toISOString();

    const entries: LogEntry[] = [];
    for (const l of logs) {
      const blockNum = parseHexNumber(l.blockNumber);
      if (!tsByBlock.has(blockNum)) {
        const ms = await getBlockTimestampMs(rpcUrl, l.blockNumber);
        tsByBlock.set(blockNum, ms);
      }

      const from = l.topics[1] ? topicToAddress(l.topics[1]) : '';
      const to = l.topics[2] ? topicToAddress(l.topics[2]) : '';
      const amountStr = parseUint256ToString(l.data);

      entries.push({
        timestamp: toIso(tsByBlock.get(blockNum)!),
        platform: 'base',
        action: 'transfer',
        actor: from,
        target: to,
        txHash: l.transactionHash,
        blockNumber: blockNum,
        targetType: 'wallet',
        meta: JSON.stringify({
          chainId: 8453,
          token: l.address,
          amount: amountStr,
          kind: 'erc20-transfer',
        }),
      });
    }

    return NextResponse.json({
      address,
      token: token || null,
      direction,
      range: { fromBlock, toBlock, maxBlocks },
      fetchedAt: new Date().toISOString(),
      logs: entries,
      counts: { transfers: entries.length },
      notes: [
        'This fetcher returns ERC-20 Transfer logs (from/to wallet). Native ETH transfers are not included via eth_getLogs.',
        'For full history, increase maxBlocks or provide an indexer integration.',
      ],
    });
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : 'Base fetch failed' }, { status: 502 });
  }
}
