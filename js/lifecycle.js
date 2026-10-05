/**
 * Page lifecycle guards for the vault.
 *
 * - pagehide: the page may enter the back/forward cache (bfcache). Lock first so that no
 *   decrypted data, derived key or secret DOM is stored in the cached page.
 * - pageshow with event.persisted: restored from bfcache. Lock again (fail closed).
 * - freeze: the browser may suspend the page for a long time. Lock.
 * - resume / visibilitychange(visible) / focus / pageshow(not persisted): re-check the
 *   inactivity limit by elapsed wall-clock time. These never extend the session.
 */
export function installLifecycleGuards({ windowTarget, documentTarget, service, onSecure = () => {} }) {
  const secure = reason => {
    service.lock(reason);
    onSecure(reason);
  };
  const recheck = () => { service.checkExpiry(); };

  windowTarget.addEventListener("pagehide", () => secure("pagehide"));
  windowTarget.addEventListener("pageshow", event => {
    if (event.persisted) secure("bfcache");
    else recheck();
  });
  windowTarget.addEventListener("focus", recheck);
  documentTarget.addEventListener("freeze", () => secure("freeze"));
  documentTarget.addEventListener("resume", recheck);
  documentTarget.addEventListener("visibilitychange", () => {
    if (!documentTarget.hidden) recheck();
  });
}
