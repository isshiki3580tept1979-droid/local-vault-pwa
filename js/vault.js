import { CREATE_CONFLICT_MESSAGE, VaultConflictError, createGenerationId, generationOf, isGenerationId, revisionOf } from "./conflict.js";
import { createKeyMaterial, decryptVault, isAllowedAutoLockMinutes, deriveKeyFromEnvelope, encryptVault, parseBackup, validateEntry } from "./crypto.js";

function clone(value) { return structuredClone(value); }
function nowIso() { return new Date().toISOString(); }
function createId() { return crypto.randomUUID(); }

const LOCKED_MESSAGE = "保管庫はロックされています。";
/** Thrown when lock() or a newer create/unlock/restore superseded a running open operation. */
export const SUPERSEDED_MESSAGE = "処理中にロックされたか、別の操作が始まったため中断しました。";
/** Thrown when the write already reached storage but the vault was locked right after it. */
export const SAVED_THEN_LOCKED_MESSAGE = "保存は完了しましたが、直後にロックされました。ロックを解除して内容を確認してください。";
const MINIMUM_MASTER_PASSWORD_LENGTH = 12;

function assertMasterPassword(masterPassword) {
  if (typeof masterPassword !== "string" || masterPassword.length < MINIMUM_MASTER_PASSWORD_LENGTH) {
    throw new Error("マスターパスワードは12文字以上にしてください。");
  }
}

async function decryptBackup(text, backupPassword) {
  if (typeof backupPassword !== "string" || !backupPassword) throw new Error("バックアップのマスターパスワードを入力してください。");
  const envelope = parseBackup(text);
  const key = await deriveKeyFromEnvelope(backupPassword, envelope);
  // The backup key is used only here and is never retained.
  return decryptVault(envelope, key);
}

/**
 * Holds the decrypted vault and the derived key in memory only while unlocked.
 *
 * State changes follow "build candidate -> encrypt -> persist -> adopt": the in-memory
 * vault is replaced only after storage.set() succeeds, so a failed write leaves the
 * previous state intact. Auto-lock is decided by wall-clock time elapsed since the last
 * activity, so sleep, background tabs or frozen timers cannot extend a session.
 *
 * Multi-tab safety: every stored record carries two non-secret values, a vaultGenerationId
 * (which vault this is) and a revision (how many writes). A write is a compare-and-swap on
 * BOTH values as this tab last read or wrote them, so a tab holding stale data can never
 * overwrite a newer vault, including a vault re-created after storage was cleared whose
 * revision happens to match. Writes inside one tab are serialized. Cross-tab notifications
 * are only a hint; the stored-value check is authoritative.
 *
 * Session tokens: #session is a monotonically increasing token. lock() bumps it, and every
 * operation that opens a vault (create, unlock, restoreAsNew) also ends the current session
 * and takes a fresh token BEFORE its first await. Every async step re-checks the token after
 * each await (KDF, decrypt, encrypt, storage), so a result from an older, superseded
 * operation can never unlock the vault or overwrite newer in-memory state. Key derivation
 * itself cannot be cancelled; its result is simply discarded.
 */
export class VaultService {
  #storage;
  #vault = null;
  #keyMaterial = null;
  #timer = null;
  #lastActivityAt = 0;
  #session = 0;
  #pendingImport = null;
  #importToken = 0;
  #revision = null;
  #generation = null;
  #stale = false;
  #writeQueue = Promise.resolve();
  #onLock;
  #onCommit;
  #autoLockMsOverride;
  #now;

  constructor(storage, { onLock = () => {}, onCommit = () => {}, autoLockMsOverride = null, now = () => Date.now() } = {}) {
    this.#storage = storage;
    this.#onLock = onLock;
    this.#onCommit = onCommit;
    this.#autoLockMsOverride = autoLockMsOverride;
    this.#now = now;
  }

  get isUnlocked() { return this.#isActive(); }
  get snapshot() { return this.#isActive() ? clone(this.#vault) : null; }
  /** True when another tab is known to have written a newer revision. Saving is refused. */
  get isStale() { return this.#isActive() && this.#stale; }
  get revision() { return this.#isActive() ? this.#revision : null; }
  /** Non-secret id of the vault this tab has open (null for a not-yet-migrated legacy vault). */
  get generation() { return this.#isActive() ? this.#generation : null; }

  /**
   * Called with a revision announced by another tab (non-secret). Never replaces the
   * in-memory vault; it only marks this tab as stale so the user can reload.
   */
  noteRemoteRevision(revision, generation = null) {
    if (!Number.isSafeInteger(revision) || revision < 0 || !this.#isActive()) return false;
    if (generation !== null && !isGenerationId(generation)) return false;
    if (revision === this.#revision && generation === this.#generation) return false;
    this.#stale = true;
    return true;
  }

  async exists() { return Boolean(await this.#storage.get()); }

  async create(masterPassword) {
    assertMasterPassword(masterPassword);
    const session = this.#beginOpen();
    if (await this.exists()) throw new Error("保管庫はすでに存在します。");
    this.#assertCurrent(session);
    const createdAt = nowIso();
    const vault = { version: 1, createdAt, updatedAt: createdAt, settings: { autoLockMinutes: 5 }, entries: [] };
    const keyMaterial = await createKeyMaterial(masterPassword);
    this.#assertCurrent(session);
    return this.#persistAndOpen(session, vault, keyMaterial);
  }

  async unlock(masterPassword) {
    const session = this.#beginOpen();
    const envelope = await this.#storage.get();
    this.#assertCurrent(session);
    if (!envelope) throw new Error("保管庫が見つかりません。");
    const key = await deriveKeyFromEnvelope(masterPassword, envelope);
    this.#assertCurrent(session);
    const vault = await decryptVault(envelope, key);
    this.#assertCurrent(session);
    this.#open(vault, { key, salt: envelope.kdf.salt, iterations: envelope.kdf.iterations }, revisionOf(envelope), generationOf(envelope));
    return this.snapshot;
  }

  lock(reason = "manual") {
    const wasUnlocked = this.#vault !== null || this.#keyMaterial !== null;
    this.#session += 1;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = null;
    this.#vault = null;
    this.#keyMaterial = null;
    this.#pendingImport = null;
    this.#lastActivityAt = 0;
    this.#revision = null;
    this.#generation = null;
    this.#stale = false;
    if (wasUnlocked) this.#onLock(reason);
    return wasUnlocked;
  }

  /** Locks when the inactivity limit has passed. Returns true when it locked. */
  checkExpiry() {
    if (this.#vault === null || this.#keyMaterial === null) return false;
    const elapsed = this.#now() - this.#lastActivityAt;
    // A clock that moved backwards cannot prove recent activity, so fail closed.
    if (elapsed < 0 || elapsed >= this.#autoLockMs()) {
      this.lock("timeout");
      return true;
    }
    return false;
  }

  /** Records user activity. Never revives or extends an already expired session. */
  touch() {
    if (!this.#isActive()) return;
    this.#lastActivityAt = this.#now();
    this.#schedule();
  }

  list(query = "") {
    this.#requireUnlocked();
    const needle = query.trim().toLocaleLowerCase("ja");
    return clone(this.#vault.entries
      .filter(entry => !needle || [entry.service, entry.url, entry.username].some(value => value.toLocaleLowerCase("ja").includes(needle)))
      .sort((left, right) => left.service.localeCompare(right.service, "ja")));
  }

  get(id) {
    this.#requireUnlocked();
    const entry = this.#vault.entries.find(item => item.id === id);
    return entry ? clone(entry) : null;
  }

  async save(input) {
    this.#requireUnlocked();
    const normalized = {
      service: String(input.service ?? "").trim(),
      url: String(input.url ?? "").trim(),
      username: String(input.username ?? "").trim(),
      password: String(input.password ?? ""),
      notes: String(input.notes ?? "").trim(),
    };
    validateEntry(normalized);
    await this.#mutate(next => {
      const timestamp = nowIso();
      if (input.id) {
        const index = next.entries.findIndex(entry => entry.id === input.id);
        if (index < 0) throw new Error("編集対象が見つかりません。");
        next.entries[index] = { ...next.entries[index], ...normalized, updatedAt: timestamp };
      } else {
        next.entries.push({ id: createId(), ...normalized, createdAt: timestamp, updatedAt: timestamp });
      }
    });
    return this.snapshot;
  }

  async remove(id) {
    this.#requireUnlocked();
    await this.#mutate(next => {
      const index = next.entries.findIndex(entry => entry.id === id);
      if (index < 0) throw new Error("削除対象が見つかりません。");
      next.entries.splice(index, 1);
    });
  }

  async updateSettings({ autoLockMinutes }) {
    this.#requireUnlocked();
    const value = Number(autoLockMinutes);
    if (!isAllowedAutoLockMinutes(value)) throw new Error("自動ロック時間が不正です。");
    await this.#mutate(next => { next.settings.autoLockMinutes = value; });
    return clone(this.#vault.settings);
  }

  async exportText() {
    this.#requireUnlocked();
    const session = this.#session;
    const envelope = await this.#storage.get();
    if (session !== this.#session || !this.#isActive()) throw new Error(LOCKED_MESSAGE);
    if (!envelope) throw new Error("保管庫が見つかりません。");
    // revision and vaultGenerationId are local concurrency metadata, not part of the backup format.
    const { revision, vaultGenerationId, ...backup } = envelope;
    return JSON.stringify(backup, null, 2);
  }

  /**
   * Restore into the currently unlocked vault, step 1: decrypt and validate the backup with
   * the backup's own password. The decrypted candidate stays inside this service and is
   * discarded on lock. Returns only non-secret summary data.
   */
  async validateImport(text, backupPassword) {
    this.#requireUnlocked();
    const session = this.#session;
    // A newer validateImport()/cancelImport() supersedes this one, so a slower, older
    // decrypt can never replace the candidate the user is actually confirming.
    const token = ++this.#importToken;
    this.#pendingImport = null;
    const vault = await decryptBackup(text, backupPassword);
    if (session !== this.#session || !this.#isActive()) throw new Error(LOCKED_MESSAGE);
    if (token !== this.#importToken) throw new Error(SUPERSEDED_MESSAGE);
    this.#pendingImport = { session, vault: clone(vault) };
    return { entryCount: vault.entries.length };
  }

  /**
   * Restore step 2: re-encrypt the validated backup with the CURRENT vault key, salt and
   * KDF parameters. The current master password therefore stays unchanged.
   */
  async commitImport() {
    this.#requireUnlocked();
    const pending = this.#pendingImport;
    if (!pending || pending.session !== this.#session) throw new Error("検証済みバックアップがありません。");
    this.#pendingImport = null;
    await this.#mutate(() => clone(pending.vault));
    return this.snapshot;
  }

  cancelImport() {
    this.#importToken += 1;
    this.#pendingImport = null;
  }

  /**
   * Restore into a new environment (no vault yet): decrypt with the backup password, then
   * encrypt with a key derived from a NEW master password, fresh salt and current KDF settings.
   */
  async restoreAsNew(text, backupPassword, newMasterPassword) {
    assertMasterPassword(newMasterPassword);
    const session = this.#beginOpen();
    if (await this.exists()) throw new Error("保管庫がすでに存在するため、新規復元できません。");
    this.#assertCurrent(session);
    const vault = await decryptBackup(text, backupPassword);
    this.#assertCurrent(session);
    const keyMaterial = await createKeyMaterial(newMasterPassword);
    this.#assertCurrent(session);
    // Another tab created or restored a vault while we were deriving keys.
    if (await this.exists()) throw new VaultConflictError(CREATE_CONFLICT_MESSAGE);
    this.#assertCurrent(session);
    return this.#persistAndOpen(session, clone(vault), keyMaterial);
  }

  /**
   * Starts an operation that will open a vault: ends any current session (and with it any
   * in-flight write or pending import) and returns the new session token.
   */
  #beginOpen() {
    this.lock("replaced");
    return this.#session;
  }

  #assertCurrent(session) {
    if (session !== this.#session) throw new Error(SUPERSEDED_MESSAGE);
  }

  #autoLockMs() {
    return this.#autoLockMsOverride ?? this.#vault.settings.autoLockMinutes * 60_000;
  }

  #isActive() {
    if (this.#vault === null || this.#keyMaterial === null) return false;
    return !this.checkExpiry();
  }

  #requireUnlocked() {
    if (!this.#isActive()) throw new Error(LOCKED_MESSAGE);
  }

  #schedule() {
    if (this.#timer) clearTimeout(this.#timer);
    const remaining = Math.max(0, this.#lastActivityAt + this.#autoLockMs() - this.#now());
    // The timer is only a wake-up hint; checkExpiry() decides by elapsed wall-clock time.
    this.#timer = setTimeout(() => {
      this.#timer = null;
      if (!this.checkExpiry() && this.#vault) this.#schedule();
    }, Math.min(remaining + 5, 2_147_000_000));
    this.#timer?.unref?.();
  }

  #open(vault, keyMaterial, revision, generation) {
    this.#pendingImport = null;
    this.#revision = revision;
    this.#generation = generation;
    this.#stale = false;
    this.#vault = vault;
    this.#keyMaterial = keyMaterial;
    this.#lastActivityAt = this.#now();
    this.#schedule();
  }

  async #persistAndOpen(session, vault, keyMaterial) {
    // A new vault individual: fresh generation, revision starts at 1.
    const generation = createGenerationId();
    const envelope = { ...await encryptVault(vault, keyMaterial), revision: 1, vaultGenerationId: generation };
    this.#assertCurrent(session);
    // expectedRevision null: succeeds only if no vault exists (another tab may have created one).
    await this.#storage.set(envelope, { expectedRevision: null, expectedGeneration: null });
    // Locked or superseded while writing: the vault is persisted (other tabs are told), but
    // it stays locked here; the user unlocks it normally.
    if (session !== this.#session) {
      this.#notifyCommit(1, generation);
      throw new Error(SAVED_THEN_LOCKED_MESSAGE);
    }
    this.#open(vault, keyMaterial, 1, generation);
    this.#notifyCommit(1, generation);
    return this.snapshot;
  }

  /** Runs one read-modify-write at a time within this tab, on the latest adopted state. */
  #mutate(change) {
    const run = this.#writeQueue.then(() => {
      this.#requireUnlocked();
      const draft = clone(this.#vault);
      const next = change(draft) ?? draft;
      return this.#commit(next);
    });
    this.#writeQueue = run.catch(() => {});
    return run;
  }

  async #commit(next) {
    const session = this.#session;
    const keyMaterial = this.#keyMaterial;
    const expectedRevision = this.#revision;
    const expectedGeneration = this.#generation;
    if (this.#stale) throw new VaultConflictError();
    // Legacy vaults (no generation yet) are migrated lazily by their first successful save;
    // the CAS still requires "no generation + same revision", so other legacy tabs conflict.
    const nextGeneration = expectedGeneration ?? createGenerationId();
    next.updatedAt = nowIso();
    const envelope = { ...await encryptVault(next, keyMaterial), revision: expectedRevision + 1, vaultGenerationId: nextGeneration };
    if (session !== this.#session) throw new Error(LOCKED_MESSAGE);
    try {
      await this.#storage.set(envelope, { expectedRevision, expectedGeneration });
    } catch (error) {
      // Newer data exists: keep it, keep our old in-memory state, and refuse further saves.
      if (error instanceof VaultConflictError && session === this.#session) this.#stale = true;
      throw error;
    }
    // Locked while writing: the data is persisted (other tabs are told), but must not be
    // revived in memory. The caller is told it was saved, not that it failed.
    if (session !== this.#session) {
      this.#notifyCommit(expectedRevision + 1, nextGeneration);
      throw new Error(SAVED_THEN_LOCKED_MESSAGE);
    }
    this.#vault = next;
    this.#revision = expectedRevision + 1;
    this.#generation = nextGeneration;
    this.#notifyCommit(this.#revision, this.#generation);
    this.touch();
    // touch() locks when the write outlasted the auto-lock limit (e.g. the device slept).
    if (session !== this.#session) throw new Error(SAVED_THEN_LOCKED_MESSAGE);
  }

  #notifyCommit(revision, generation) {
    // Only the non-secret revision number and generation id leave this service.
    try { this.#onCommit(revision, generation); } catch { /* notification is best effort */ }
  }
}
