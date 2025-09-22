(function(){
  if (typeof window === 'undefined') return;
  const DB_NAME = 'nimbus';
  const DB_VERSION = 1;
  const STORE = 'files';

  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = (e) => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          const s = db.createObjectStore(STORE, { keyPath: 'key', autoIncrement: true });
          s.createIndex('by_name', 'name', { unique: false });
          s.createIndex('by_service', 'service', { unique: false });
          s.createIndex('by_uploadedAt', 'uploadedAt', { unique: false });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function putFile(rec) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => reject(tx.error);
      const obj = Object.assign({}, rec, { uploadedAt: rec.uploadedAt || new Date().toISOString() });
      tx.objectStore(STORE).add(obj);
    });
  }

  async function getAll(limit = 100) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const store = tx.objectStore(STORE);
      const idx = store.index('by_uploadedAt');
      const dir = 'prev';
      const req = idx.openCursor(null, dir);
      const out = [];
      req.onsuccess = () => {
        const cur = req.result;
        if (cur && out.length < limit) {
          out.push(cur.value);
          cur.continue();
        } else {
          resolve(out);
        }
      };
      req.onerror = () => reject(req.error);
    });
  }

  async function search(q, limit = 100) {
    const term = (q || '').toLowerCase();
    if (!term) return getAll(limit);
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const store = tx.objectStore(STORE);
      const req = store.openCursor();
      const out = [];
      req.onsuccess = () => {
        const cur = req.result;
        if (!cur) return resolve(out);
        const v = cur.value;
        const hay = `${v.name} ${v.type || ''} ${v.service || ''}`.toLowerCase();
        if (hay.includes(term)) {
          out.push(v);
          if (out.length >= limit) return resolve(out);
        }
        cur.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }

  window.NimbusDB = { putFile, getAll, search };
})();
