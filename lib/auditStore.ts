export type AuditEventType = 'analysis_run' | 'export_evidence' | 'import_urls' | 'scan_profile' | 'scan_profile_links' | 'fetch_source';

export type AuditEvent = {
  id: string;
  type: AuditEventType;
  at: string; // ISO
  summary: string;
  meta?: Record<string, unknown>;
};

const DB_NAME = 'sybil-shield-audit';
const DB_VERSION = 1;
const STORE = 'events';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) {
        const store = db.createObjectStore(STORE, { keyPath: 'id' });
        store.createIndex('by_at', 'at');
        store.createIndex('by_type', 'type');
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function withStore<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(STORE, mode);
        const store = tx.objectStore(STORE);
        const req = fn(store);
        req.onsuccess = () => resolve(req.result as T);
        req.onerror = () => reject(req.error);
      }),
  );
}

export async function addAuditEvent(ev: Omit<AuditEvent, 'id'> & { id?: string }): Promise<void> {
  const id = ev.id || `${ev.at}-${Math.random().toString(16).slice(2)}`;
  await withStore<IDBValidKey>('readwrite', (store) => store.put({ ...ev, id }));
}

export async function getRecentAuditEvents(limit = 500): Promise<AuditEvent[]> {
  const all = await withStore<AuditEvent[]>('readonly', (store) => store.getAll());
  all.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));
  return all.slice(0, Math.max(1, limit));
}

export async function clearAuditEvents(): Promise<void> {
  await withStore<undefined>('readwrite', (store) => store.clear());
}

