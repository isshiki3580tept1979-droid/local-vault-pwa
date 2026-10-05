import { CREATE_CONFLICT_MESSAGE, VaultConflictError, recordMatches } from "./conflict.js";

const DATABASE_NAME = "local-vault-prototype";
const DATABASE_VERSION = 1;
const STORE_NAME = "encrypted-vault";
const RECORD_KEY = "primary";

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(STORE_NAME)) database.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error("ブラウザの保存領域を開けませんでした。"));
    request.onblocked = () => reject(new Error("別のタブが保存領域を使用しています。"));
  });
}

export class IndexedDbStorage {
  async get() {
    const database = await openDatabase();
    try {
      return await new Promise((resolve, reject) => {
        const request = database.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(RECORD_KEY);
        request.onsuccess = () => resolve(request.result ?? null);
        request.onerror = () => reject(new Error("暗号化データを読み込めませんでした。"));
      });
    } finally { database.close(); }
  }

  /**
   * Compare-and-swap write. Inside ONE readwrite transaction (IndexedDB serializes these
   * across tabs) the stored vaultGenerationId AND revision are compared with what the caller
   * read before writing (see recordMatches):
   * - expectedRevision === null: only succeeds when no vault exists yet (initial create/restore).
   * - otherwise: the stored record must exist with exactly expectedGeneration and
   *   expectedRevision (legacy records count as generation null / revision 0).
   * On mismatch nothing is written and VaultConflictError is thrown.
   */
  async set(envelope, { expectedRevision = null, expectedGeneration = null } = {}) {
    const database = await openDatabase();
    try {
      await new Promise((resolve, reject) => {
        let transaction;
        let conflict = false;
        const fail = () => reject(new Error("暗号化データを保存できませんでした。"));
        try {
          transaction = database.transaction(STORE_NAME, "readwrite");
          const store = transaction.objectStore(STORE_NAME);
          const read = store.get(RECORD_KEY);
          read.onsuccess = () => {
            const current = read.result ?? null;
            if (!recordMatches(current, { expectedRevision, expectedGeneration })) {
              conflict = true;
              transaction.abort();
              return;
            }
            try { store.put(envelope, RECORD_KEY); } catch { try { transaction.abort(); } catch { /* inactive */ } }
          };
        } catch {
          try { transaction?.abort(); } catch { /* already inactive */ }
          fail();
          return;
        }
        transaction.oncomplete = () => resolve();
        transaction.onabort = () => {
          if (conflict) reject(new VaultConflictError(expectedRevision === null ? CREATE_CONFLICT_MESSAGE : undefined));
          else fail();
        };
      });
    } finally { database.close(); }
  }
}
