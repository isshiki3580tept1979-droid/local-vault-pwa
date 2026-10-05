import { isGenerationId } from "./conflict.js";

const CHANNEL_NAME = "local-vault-prototype:revision";
const NOTICE_TYPE = "vault-updated";

/**
 * The only message shape ever sent between tabs: a type tag, the non-secret random
 * vaultGenerationId (null for a not-yet-migrated legacy vault) and the revision.
 */
export function buildRevisionNotice(revision, generation = null) {
  if (!Number.isSafeInteger(revision) || revision < 0) throw new Error("revisionが不正です。");
  if (generation !== null && !isGenerationId(generation)) throw new Error("世代IDが不正です。");
  return { type: NOTICE_TYPE, vaultGenerationId: generation, revision };
}

/** Returns { revision, generation } from a well-formed notice, or null for anything else. */
export function parseRevisionNotice(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  if (Object.keys(data).length !== 3 || data.type !== NOTICE_TYPE || !Number.isSafeInteger(data.revision) || data.revision < 0) return null;
  if (!("vaultGenerationId" in data) || (data.vaultGenerationId !== null && !isGenerationId(data.vaultGenerationId))) return null;
  return { revision: data.revision, generation: data.vaultGenerationId };
}

/**
 * Same-origin, same-browser notification that another tab wrote a new revision.
 * This is a convenience only: missing or delayed notices are safe because every write is
 * still checked against the stored revision.
 */
export function createRevisionChannel({ onRemoteRevision, ChannelClass = globalThis.BroadcastChannel } = {}) {
  let channel = null;
  const open = () => {
    if (channel || typeof ChannelClass !== "function") return;
    try {
      channel = new ChannelClass(CHANNEL_NAME);
      channel.onmessage = event => {
        const notice = parseRevisionNotice(event?.data);
        if (notice !== null) onRemoteRevision(notice.revision, notice.generation);
      };
    } catch { channel = null; }
  };
  const close = () => {
    try { channel?.close(); } catch { /* already closed */ }
    channel = null;
  };
  open();
  return {
    open,
    close,
    notify(revision, generation = null) {
      open();
      try { channel?.postMessage(buildRevisionNotice(revision, generation)); } catch { /* best effort */ }
    },
  };
}
