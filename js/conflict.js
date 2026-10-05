export const CONFLICT_MESSAGE = "別のタブでVaultが更新されました。この画面の内容は古いため保存できません。再読み込みしてください。";
export const CREATE_CONFLICT_MESSAGE = "別のタブで保管庫が作成または復元されました。再読み込みしてください。";

/** The stored vault changed since this tab read it. Carries no secret data. */
export class VaultConflictError extends Error {
  constructor(message = CONFLICT_MESSAGE) {
    super(message);
    this.name = "VaultConflictError";
  }
}

/** Records written before revisions existed count as revision 0. */
export function revisionOf(record) {
  return Number.isSafeInteger(record?.revision) && record.revision >= 0 ? record.revision : 0;
}

const GENERATION_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * vaultGenerationId identifies one vault "individual". It is a non-secret random UUID
 * (Web Crypto CSPRNG) assigned when a vault is created or restored into an empty
 * environment, and kept unchanged by ordinary saves. It is independent of the KDF salt.
 */
export function createGenerationId() {
  return crypto.randomUUID();
}

export function isGenerationId(value) {
  return typeof value === "string" && GENERATION_PATTERN.test(value);
}

/** Records written before generations existed (or with a malformed value) count as null. */
export function generationOf(record) {
  return isGenerationId(record?.vaultGenerationId) ? record.vaultGenerationId : null;
}

/**
 * The compare-and-set rule used inside the IndexedDB readwrite transaction.
 * - expectedRevision === null: initial create/restore, only when no record exists.
 * - otherwise the stored record must exist and BOTH its generation and revision must equal
 *   what this tab read. A re-created vault therefore never matches, even at the same revision.
 */
export function recordMatches(current, { expectedRevision = null, expectedGeneration = null } = {}) {
  if (expectedRevision === null) return current === null;
  return current !== null && generationOf(current) === expectedGeneration && revisionOf(current) === expectedRevision;
}
