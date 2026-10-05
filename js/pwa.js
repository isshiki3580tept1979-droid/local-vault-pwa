/**
 * Service worker registration and user-controlled updates.
 *
 * A new version is downloaded and verified in the background, then waits. `onUpdateReady` lets the
 * app show 「更新があります」; nothing is swapped until `applyUpdate()` (the app locks the vault
 * first). The page reloads only when THIS page asked for the switch, so an update applied from another
 * tab never reloads a page in the middle of an edit. If the switch does not happen, `onUpdateFailed`
 * is called and the current version keeps running.
 */
const UPDATE_CHECK_INTERVAL_MS = 60 * 60 * 1000;
const APPLY_TIMEOUT_MS = 15_000;

export function setupServiceWorker({ onUpdateReady = () => {}, onUpdateFailed = () => {} } = {}) {
  const container = globalThis.navigator?.serviceWorker;
  if (!container || !globalThis.isSecureContext) return { supported: false, async applyUpdate() { return false; }, async version() { return null; } };

  let requested = false;
  let reloading = false;
  container.addEventListener("controllerchange", () => {
    if (!requested || reloading) return;
    reloading = true;
    location.reload();
  });

  const registration = container.register("./sw.js", { scope: "./", updateViaCache: "none" }).then(reg => {
    // A waiting worker with an existing controller is an update (the very first install is not).
    const notify = () => { if (reg.waiting && container.controller) onUpdateReady(); };
    notify();
    reg.addEventListener("updatefound", () => {
      const worker = reg.installing;
      worker?.addEventListener("statechange", () => { if (worker.state === "installed") notify(); });
    });
    const check = () => reg.update().catch(() => {}); // offline or server error: keep the current version
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") check(); });
    setInterval(check, UPDATE_CHECK_INTERVAL_MS);
    return reg;
  }).catch(() => null);

  return {
    supported: true,
    /** Activate the waiting version. Resolves false when there is nothing to apply. */
    async applyUpdate() {
      const reg = await registration;
      const waiting = reg?.waiting;
      if (!waiting) return false;
      requested = true;
      waiting.postMessage({ type: "SKIP_WAITING" });
      setTimeout(() => { if (!reloading) { requested = false; onUpdateFailed(); } }, APPLY_TIMEOUT_MS);
      return true;
    },
    /** Version string of the controlling worker (null when not controlled). */
    async version() {
      const controller = container.controller;
      if (!controller) return null;
      return new Promise(resolve => {
        const channel = new MessageChannel();
        const timer = setTimeout(() => resolve(null), 2000);
        channel.port1.onmessage = event => { clearTimeout(timer); resolve(event.data?.version ?? null); };
        controller.postMessage({ type: "GET_VERSION" }, [channel.port2]);
      });
    },
  };
}
