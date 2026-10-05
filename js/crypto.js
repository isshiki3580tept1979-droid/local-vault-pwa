const ENVELOPE_SCHEMA = "local-vault-encrypted-backup";
const ENVELOPE_VERSION = 1;
const AAD = new TextEncoder().encode("local-vault-prototype:v1");
export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

function bytesToBase64(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value, expectedLength, label) {
  if (typeof value !== "string" || value.length > 20_000_000) throw new Error(`${label}が不正です。`);
  let binary;
  try { binary = atob(value); } catch { throw new Error(`${label}が不正です。`); }
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (expectedLength && bytes.length !== expectedLength) throw new Error(`${label}の長さが不正です。`);
  return bytes;
}

async function deriveKey(masterPassword, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(masterPassword),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export function assertEnvelope(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("バックアップ形式が不正です。");
  if (value.schema !== ENVELOPE_SCHEMA || value.version !== ENVELOPE_VERSION) throw new Error("対応していないバックアップ形式です。");
  if (value.kdf?.name !== "PBKDF2" || value.kdf?.hash !== "SHA-256") throw new Error("鍵導出方式が不正です。");
  if (!Number.isInteger(value.kdf.iterations) || value.kdf.iterations < 100_000 || value.kdf.iterations > 2_000_000) throw new Error("鍵導出の反復回数が不正です。");
  if (value.cipher?.name !== "AES-GCM" || value.cipher?.length !== 256) throw new Error("暗号化方式が不正です。");
  base64ToBytes(value.kdf.salt, 16, "salt");
  base64ToBytes(value.cipher.iv, 12, "IV");
  const ciphertext = base64ToBytes(value.ciphertext, undefined, "暗号文");
  if (ciphertext.length < 17 || ciphertext.length > 10_000_000) throw new Error("暗号文のサイズが不正です。");
  return value;
}

export async function createKeyMaterial(masterPassword, iterations = DEFAULT_PBKDF2_ITERATIONS) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(masterPassword, salt, iterations);
  return { key, salt: bytesToBase64(salt), iterations };
}

export async function deriveKeyFromEnvelope(masterPassword, envelope) {
  assertEnvelope(envelope);
  return deriveKey(masterPassword, base64ToBytes(envelope.kdf.salt, 16, "salt"), envelope.kdf.iterations);
}

export async function encryptVault(vault, keyMaterial) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(vault));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD }, keyMaterial.key, plaintext);
  return {
    schema: ENVELOPE_SCHEMA,
    version: ENVELOPE_VERSION,
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: keyMaterial.iterations, salt: keyMaterial.salt },
    cipher: { name: "AES-GCM", length: 256, iv: bytesToBase64(iv) },
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

export async function decryptVault(envelope, key) {
  assertEnvelope(envelope);
  const iv = base64ToBytes(envelope.cipher.iv, 12, "IV");
  const ciphertext = base64ToBytes(envelope.ciphertext, undefined, "暗号文");
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: AAD }, key, ciphertext);
  } catch {
    throw new Error("マスターパスワードが違うか、データが破損しています。");
  }
  let vault;
  try { vault = JSON.parse(new TextDecoder().decode(plaintext)); } catch { throw new Error("復号したデータの形式が不正です。"); }
  return validateVaultPayload(vault);
}

/** The only auto-lock values the settings UI offers; decrypted vaults must use one of them. */
export const ALLOWED_AUTO_LOCK_MINUTES = Object.freeze([1, 5, 10, 15, 30, 60, 120]);

const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

/** Accepts only the UTC ISO-8601 form produced by Date#toISOString() and a real calendar date. */
export function isValidTimestamp(value) {
  if (typeof value !== "string" || !ISO_TIMESTAMP.test(value)) return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString().slice(0, 19) === value.slice(0, 19);
}

export function isAllowedAutoLockMinutes(value) {
  return Number.isInteger(value) && ALLOWED_AUTO_LOCK_MINUTES.includes(value);
}

export function validateVaultPayload(vault) {
  if (!vault || typeof vault !== "object" || vault.version !== 1 || !Array.isArray(vault.entries)) throw new Error("Vaultデータの形式が不正です。");
  if (!vault.settings || typeof vault.settings !== "object" || Array.isArray(vault.settings)) throw new Error("Vault設定が不正です。");
  if (!isAllowedAutoLockMinutes(vault.settings.autoLockMinutes)) throw new Error("自動ロック設定が不正です。");
  if (!isValidTimestamp(vault.createdAt) || !isValidTimestamp(vault.updatedAt)) throw new Error("Vaultの日時が不正です。");
  if (vault.entries.length > 10_000) throw new Error("登録件数が上限を超えています。");
  const ids = new Set();
  for (const entry of vault.entries) {
    validateEntry(entry, { existing: true });
    if (ids.has(entry.id)) throw new Error("登録情報のIDが重複しています。");
    ids.add(entry.id);
  }
  return vault;
}

export function parseBackup(text) {
  if (typeof text !== "string" || text.length > 15_000_000) throw new Error("バックアップファイルが大きすぎるか不正です。");
  let value;
  try { value = JSON.parse(text); } catch { throw new Error("JSONファイルとして読み込めません。"); }
  return assertEnvelope(value);
}

export function validateEntry(entry, { existing = false } = {}) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error("登録情報の形式が不正です。");
  const text = (name, maximum, required = false) => {
    if (typeof entry[name] !== "string") throw new Error(`${name}が不正です。`);
    const value = entry[name].trim();
    if (required && !value) throw new Error(name === "service" ? "サービス名を入力してください。" : "パスワードを入力してください。");
    if (entry[name].length > maximum) throw new Error(`${name}が長すぎます。`);
  };
  text("service", 100, true);
  text("url", 2048);
  text("username", 320);
  text("password", 1024, true);
  text("notes", 5000);
  if (entry.url) {
    let url;
    try { url = new URL(entry.url); } catch { throw new Error("URLの形式を確認してください。"); }
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error("URLは http:// または https:// で入力してください。");
  }
  if (existing && [entry.id, entry.createdAt, entry.updatedAt].some(value => typeof value !== "string" || !value || value.length > 64)) throw new Error("登録情報の管理項目が不正です。");
  if (existing && ![entry.createdAt, entry.updatedAt].every(isValidTimestamp)) throw new Error("登録情報の日時が不正です。");
  return true;
}

const CHARACTER_SETS = {
  upper: "ABCDEFGHJKLMNPQRSTUVWXYZ",
  lower: "abcdefghijkmnopqrstuvwxyz",
  number: "23456789",
  symbol: "!@#$%^&*()-_=+[]{};:,.?",
};

function secureIndex(maximum) {
  if (!Number.isInteger(maximum) || maximum < 1 || maximum > 256) throw new Error("文字集合が不正です。");
  const limit = 256 - (256 % maximum);
  const bytes = new Uint8Array(1);
  do { crypto.getRandomValues(bytes); } while (bytes[0] >= limit);
  return bytes[0] % maximum;
}

export function generatePassword({ length = 20, upper = true, lower = true, number = true, symbol = true } = {}) {
  if (!Number.isInteger(length) || length < 12 || length > 128) throw new Error("文字数は12〜128文字で指定してください。");
  const selected = Object.entries({ upper, lower, number, symbol }).filter(([, enabled]) => enabled).map(([name]) => CHARACTER_SETS[name]);
  if (!selected.length) throw new Error("文字種を1つ以上選択してください。");
  if (length < selected.length) throw new Error("文字数が文字種の数より少なくなっています。");
  const all = selected.join("");
  const result = selected.map(set => set[secureIndex(set.length)]);
  while (result.length < length) result.push(all[secureIndex(all.length)]);
  for (let index = result.length - 1; index > 0; index -= 1) {
    const swap = secureIndex(index + 1);
    [result[index], result[swap]] = [result[swap], result[index]];
  }
  return result.join("");
}

