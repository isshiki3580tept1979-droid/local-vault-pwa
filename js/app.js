import { VaultConflictError } from "./conflict.js";
import { generatePassword } from "./crypto.js";
import { installLifecycleGuards } from "./lifecycle.js";
import { IndexedDbStorage } from "./storage.js";
import { createRevisionChannel } from "./sync.js";
import { SAVED_THEN_LOCKED_MESSAGE, SUPERSEDED_MESSAGE, VaultService } from "./vault.js";
import { setupServiceWorker } from "./pwa.js";

// Refuse to run when another window can script this page: embedded in a frame, or opened by
// window.open() (the opener keeps a same-origin reference). On a shared origin such as
// <user>.github.io, any other site of the account is same-origin. Nothing is initialised here.
if (window.top !== window.self || window.opener) {
  const notice = document.createElement("p");
  notice.className = "embed-block";
  notice.textContent = "安全のため、ほかのページから開かれた状態では Local Vault を表示しません。このURLをブラウザのアドレスバーまたはホーム画面のアイコンから直接開いてください。";
  document.body.replaceChildren(notice);
  throw new Error("Local Vault: refused to run in an embedded or opened window.");
}

const byId = id => document.getElementById(id);
const views = ["list-view", "editor-view", "detail-view", "settings-view"];
let selectedEntryId = null;
let passwordVisible = false;
let toastTimer = null;

const service = new VaultService(new IndexedDbStorage(), {
  onCommit(revision, generation) { revisionChannel.notify(revision, generation); },
  onLock(reason) {
    clearSensitiveUi();
    showAuth("unlock");
    if (reason === "timeout") showToast("操作がなかったため自動ロックしました。", "error");
  },
});

// Other tabs only ever tell us a generation id and revision number; the vault itself is never exchanged.
const revisionChannel = createRevisionChannel({
  onRemoteRevision(revision, generation) { if (service.noteRemoteRevision(revision, generation)) showConflictBanner(); },
});

function showConflictBanner() {
  if (!service.isUnlocked) return;
  byId("conflict-banner").hidden = false;
}

/** Only messages written by this app reach the UI; unexpected exceptions stay generic. */
function userMessage(error) {
  if (error instanceof VaultConflictError) {
    showConflictBanner();
    return error.message;
  }
  // The write landed but the vault locked right after: say so on the unlock screen, where
  // the user now is, instead of reporting a failure on a hidden form.
  if (error instanceof Error && error.message === SAVED_THEN_LOCKED_MESSAGE && !service.isUnlocked) {
    byId("auth-error").textContent = error.message;
  }
  if (error instanceof Error && error.name === "Error" && error.message) return error.message;
  return "処理を完了できませんでした。再読み込みしてからお試しください。";
}

/**
 * Error display for the auth screen. When a create/unlock/restore was superseded (locked by
 * page lifecycle, or another open operation started), every secret input is cleared and the
 * auth screen is re-derived from storage: the vault may or may not exist now.
 */
async function showAuthError(error) {
  const message = userMessage(error);
  if (error instanceof Error && [SUPERSEDED_MESSAGE, SAVED_THEN_LOCKED_MESSAGE].includes(error.message) && !service.isUnlocked) {
    clearSensitiveUi();
    await refreshAuthView();
  }
  byId("auth-error").textContent = message;
}

function setBusy(button, busy) {
  if (!button) return;
  button.disabled = busy;
  button.setAttribute("aria-busy", String(busy));
}

function showToast(message, type = "info") {
  clearTimeout(toastTimer);
  const region = byId("toast-region");
  const toast = document.createElement("div");
  toast.className = `toast${type === "error" ? " toast-error" : ""}`;
  toast.textContent = message;
  region.replaceChildren(toast);
  toastTimer = setTimeout(() => region.replaceChildren(), 3400);
}

function showAuth(mode) {
  byId("app-view").hidden = true;
  byId("auth-view").hidden = false;
  byId("setup-form").hidden = mode !== "setup";
  byId("unlock-form").hidden = mode !== "unlock";
  byId("restore-new-panel").hidden = mode !== "setup";
  byId("auth-error").textContent = "";
  byId("auth-title").textContent = mode === "setup" ? "最初の保管庫を作成" : "保管庫のロックを解除";
  byId("auth-copy").textContent = mode === "setup"
    ? "マスターパスワードは保存されません。暗号化と復号にだけ使用します。"
    : "この端末内の暗号化データを復号します。";
  const focusTarget = mode === "setup" ? byId("setup-password") : byId("unlock-password");
  requestAnimationFrame(() => focusTarget.focus());
}

function showApp() {
  byId("auth-view").hidden = true;
  byId("app-view").hidden = false;
  showView("list-view");
  renderList();
}

function showView(id) {
  if (id !== "editor-view") resetEditor();
  if (id !== "detail-view") clearDetail();
  views.forEach(view => { byId(view).hidden = view !== id; });
  // A new screen starts at the top; otherwise on a phone its heading opens under the sticky header.
  window.scrollTo(0, 0);
  service.touch();
}

/** Form password visibility: the button label and aria-pressed always match the input type. */
function setFormPasswordVisible(visible) {
  byId("entry-password").type = visible ? "text" : "password";
  const toggle = byId("toggle-form-password");
  toggle.textContent = visible ? "非表示" : "表示";
  toggle.setAttribute("aria-pressed", String(visible));
}

function resetEditor() {
  byId("entry-form").reset();
  byId("entry-id").value = "";
  byId("entry-password").value = "";
  setFormPasswordVisible(false);
  byId("entry-error").textContent = "";
}

function clearDetail() {
  passwordVisible = false;
  byId("detail-fields").replaceChildren();
  byId("detail-title").textContent = "詳細";
}

function clearImportInputs() {
  byId("import-password").value = "";
  byId("import-file").value = "";
  document.querySelector(".file-picker").textContent = "暗号化バックアップを選択";
  byId("import-error").textContent = "";
  service.cancelImport();
}

function clearRestoreNewInputs() {
  byId("restore-new-form").reset();
}

function clearSensitiveUi() {
  selectedEntryId = null;
  byId("conflict-banner").hidden = true;
  const dialog = byId("confirm-dialog");
  if (dialog.open) dialog.close("cancel");
  byId("confirm-title").textContent = "確認";
  byId("confirm-message").textContent = "";
  resetEditor();
  clearDetail();
  byId("entry-list").replaceChildren();
  byId("empty-state").hidden = true;
  byId("search-input").value = "";
  byId("unlock-password").value = "";
  byId("setup-password").value = "";
  byId("setup-confirm").value = "";
  clearImportInputs();
  clearRestoreNewInputs();
}

function renderList() {
  const entries = service.list(byId("search-input").value);
  const list = byId("entry-list");
  list.replaceChildren();
  for (const entry of entries) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "entry-row";
    button.dataset.entryId = entry.id;
    const fields = [
      ["entry-main", entry.service],
      ["entry-secondary", entry.username || "ユーザーIDなし"],
      ["entry-url", entry.url || "URLなし"],
      ["entry-chevron", "›"],
    ];
    for (const [className, text] of fields) {
      const span = document.createElement("span");
      span.className = className;
      span.textContent = text;
      button.append(span);
    }
    list.append(button);
  }
  const empty = entries.length === 0;
  byId("empty-state").hidden = !empty;
  const searching = Boolean(byId("search-input").value.trim());
  byId("empty-title").textContent = searching ? "一致する登録情報がありません" : "登録情報はまだありません";
  byId("empty-copy").textContent = searching ? "検索語を変えてお試しください。" : "「新規登録」から最初の情報を追加できます。";
}

function openEditor(entry = null) {
  byId("entry-form").reset();
  byId("entry-error").textContent = "";
  byId("entry-id").value = entry?.id ?? "";
  byId("service-name").value = entry?.service ?? "";
  byId("service-url").value = entry?.url ?? "";
  byId("user-id").value = entry?.username ?? "";
  byId("entry-password").value = entry?.password ?? "";
  byId("entry-notes").value = entry?.notes ?? "";
  setFormPasswordVisible(false);
  byId("password-length").value = "20";
  byId("length-output").value = "20";
  ["include-upper", "include-lower", "include-number", "include-symbol"].forEach(id => { byId(id).checked = true; });
  byId("editor-title").textContent = entry ? "登録情報を編集" : "新規登録";
  showView("editor-view");
  byId("service-name").focus();
}

function addDetailRow(list, label, value, { secret = false, link = false } = {}) {
  const term = document.createElement("dt");
  term.textContent = label;
  const detail = document.createElement("dd");
  if (secret) {
    detail.className = "secret-value";
    const code = document.createElement("code");
    code.textContent = passwordVisible ? value : "••••••••••••";
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "button button-inline";
    toggle.textContent = passwordVisible ? "非表示" : "表示";
    toggle.setAttribute("aria-pressed", String(passwordVisible));
    toggle.setAttribute("aria-label", passwordVisible ? "パスワードを隠す" : "パスワードを表示");
    toggle.addEventListener("click", () => { passwordVisible = !passwordVisible; openDetail(selectedEntryId); });
    detail.append(code, toggle);
  } else if (link && value) {
    const anchor = document.createElement("a");
    anchor.href = value;
    anchor.target = "_blank";
    anchor.rel = "noopener noreferrer";
    anchor.textContent = value;
    detail.append(anchor);
  } else {
    detail.textContent = value || "—";
  }
  list.append(term, detail);
}

function formatDate(value) { return new Intl.DateTimeFormat("ja-JP", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }

function openDetail(id) {
  const entry = service.get(id);
  if (!entry) return showToast("登録情報が見つかりません。", "error");
  selectedEntryId = id;
  const list = byId("detail-fields");
  list.replaceChildren();
  byId("detail-title").textContent = entry.service;
  addDetailRow(list, "URL", entry.url, { link: true });
  addDetailRow(list, "ユーザーID", entry.username);
  addDetailRow(list, "パスワード", entry.password, { secret: true });
  addDetailRow(list, "メモ", entry.notes);
  addDetailRow(list, "作成日時", formatDate(entry.createdAt));
  addDetailRow(list, "更新日時", formatDate(entry.updatedAt));
  showView("detail-view");
}

function askConfirmation(title, message, acceptLabel = "実行する") {
  const dialog = byId("confirm-dialog");
  byId("confirm-title").textContent = title;
  byId("confirm-message").textContent = message;
  byId("confirm-accept").textContent = acceptLabel;
  dialog.returnValue = "";
  dialog.showModal();
  return new Promise(resolve => {
    dialog.addEventListener("close", () => {
      byId("confirm-message").textContent = "";
      resolve(dialog.returnValue === "confirm");
    }, { once: true });
  });
}

async function copyText(value, label) {
  if (!value) return showToast(`${label}が空です。`, "error");
  try { await navigator.clipboard.writeText(value); showToast(`${label}をコピーしました。`); }
  catch { showToast("クリップボードへコピーできませんでした。", "error"); }
  service.touch();
}

byId("setup-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.submitter;
  const password = byId("setup-password").value;
  const confirm = byId("setup-confirm").value;
  // Never kept in the DOM while the key is derived or after a failure; the user retypes.
  byId("setup-password").value = "";
  byId("setup-confirm").value = "";
  byId("auth-error").textContent = "";
  if (password !== confirm) {
    byId("setup-password").focus();
    return void (byId("auth-error").textContent = "確認用パスワードが一致しません。もう一度入力してください。");
  }
  setBusy(button, true);
  try { await service.create(password); clearSensitiveUi(); showApp(); showToast("暗号化保管庫を作成しました。"); }
  catch (error) { await showAuthError(error); }
  finally { setBusy(button, false); }
});

byId("unlock-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.submitter;
  byId("auth-error").textContent = "";
  setBusy(button, true);
  const password = byId("unlock-password").value;
  // Not kept in the field while the key is derived, nor after a wrong password.
  byId("unlock-password").value = "";
  try { await service.unlock(password); clearSensitiveUi(); showApp(); }
  catch (error) { await showAuthError(error); byId("unlock-password").focus(); }
  finally { setBusy(button, false); }
});

byId("new-entry-button").addEventListener("click", () => openEditor());
byId("entry-list").addEventListener("click", event => {
  const row = event.target.closest?.(".entry-row");
  if (row?.dataset.entryId) openDetail(row.dataset.entryId);
});
document.querySelectorAll(".js-back-list").forEach(button => button.addEventListener("click", () => { passwordVisible = false; showView("list-view"); renderList(); }));
byId("settings-button").addEventListener("click", () => { if (!service.isUnlocked) return; renderSettings(); clearImportInputs(); showView("settings-view"); });

function renderSettings() {
  const select = byId("auto-lock-minutes");
  select.value = String(service.snapshot.settings.autoLockMinutes);
  void pwa.version().then(version => { byId("app-version").textContent = version ?? "（オフライン保存なし）"; });
}
byId("lock-button").addEventListener("click", () => service.lock());
byId("conflict-reload-button").addEventListener("click", () => { service.lock("reload"); location.reload(); });
byId("search-input").addEventListener("input", () => { renderList(); service.touch(); });
byId("password-length").addEventListener("input", event => { byId("length-output").value = event.target.value; });
byId("toggle-form-password").addEventListener("click", () => {
  setFormPasswordVisible(byId("entry-password").type === "password");
});
byId("generate-button").addEventListener("click", () => {
  try {
    byId("entry-password").value = generatePassword({
      length: Number(byId("password-length").value),
      upper: byId("include-upper").checked,
      lower: byId("include-lower").checked,
      number: byId("include-number").checked,
      symbol: byId("include-symbol").checked,
    });
    setFormPasswordVisible(true);
    byId("entry-error").textContent = "";
  } catch (error) { byId("entry-error").textContent = userMessage(error); }
  service.touch();
});

byId("entry-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.submitter;
  byId("entry-error").textContent = "";
  setBusy(button, true);
  try {
    await service.save({ id: byId("entry-id").value || undefined, service: byId("service-name").value, url: byId("service-url").value, username: byId("user-id").value, password: byId("entry-password").value, notes: byId("entry-notes").value });
    const editing = Boolean(byId("entry-id").value);
    passwordVisible = false;
    showView("list-view");
    renderList();
    showToast(editing ? "登録情報を更新しました。" : "登録情報を追加しました。");
  } catch (error) { byId("entry-error").textContent = userMessage(error); }
  finally { setBusy(button, false); }
});

byId("edit-entry-button").addEventListener("click", () => openEditor(service.get(selectedEntryId)));
byId("delete-entry-button").addEventListener("click", async () => {
  const id = selectedEntryId;
  const entry = service.get(id);
  if (!entry || !await askConfirmation("登録情報を削除", `「${entry.service}」を完全に削除します。元に戻せません。`, "削除する")) return;
  try { await service.remove(id); selectedEntryId = null; showView("list-view"); renderList(); showToast("登録情報を削除しました。"); }
  catch (error) { showToast(userMessage(error), "error"); }
});
byId("copy-user-button").addEventListener("click", () => { const entry = service.get(selectedEntryId); copyText(entry?.username, "ユーザーID"); });
byId("copy-password-button").addEventListener("click", () => { const entry = service.get(selectedEntryId); copyText(entry?.password, "パスワード"); });

byId("save-settings-button").addEventListener("click", async event => {
  // event.currentTarget becomes null after the first await, so keep the element.
  const button = event.currentTarget;
  setBusy(button, true);
  try { await service.updateSettings({ autoLockMinutes: Number(byId("auto-lock-minutes").value) }); renderSettings(); showToast("自動ロック設定を保存しました。"); }
  catch (error) { if (service.isUnlocked) renderSettings(); showToast(userMessage(error), "error"); }
  finally { setBusy(button, false); }
});

byId("export-button").addEventListener("click", async () => {
  try {
    const text = await service.exportText();
    const blob = new Blob([text], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `local-vault-backup-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 0);
    showToast("暗号化バックアップを書き出しました。");
  } catch (error) { showToast(userMessage(error), "error"); }
});

byId("import-file").addEventListener("change", event => {
  const file = event.target.files[0];
  const picker = document.querySelector(".file-picker");
  picker.textContent = file ? file.name : "暗号化バックアップを選択";
  byId("import-error").textContent = "";
});

byId("import-button").addEventListener("click", async event => {
  const button = event.currentTarget;
  const file = byId("import-file").files[0];
  const password = byId("import-password").value;
  byId("import-password").value = "";
  byId("import-error").textContent = "";
  if (!file || !password) return void (byId("import-error").textContent = "ファイルとバックアップのマスターパスワードを入力してください。");
  setBusy(button, true);
  try {
    if (file.size > 15_000_000) throw new Error("バックアップファイルが大きすぎます。");
    const { entryCount } = await service.validateImport(await file.text(), password);
    const confirmed = await askConfirmation("保管庫を上書き", `現在の保管庫の内容を、検証済みバックアップ（${entryCount}件）で置き換えます。現在のマスターパスワードは変更されません。元に戻すには事前のバックアップが必要です。`, "上書きして復元");
    if (!confirmed) { service.cancelImport(); return; }
    await service.commitImport();
    clearImportInputs();
    showView("list-view");
    renderList();
    showToast("バックアップを復元しました。");
  } catch (error) {
    service.cancelImport();
    byId("import-password").value = "";
    byId("import-error").textContent = userMessage(error);
  } finally { setBusy(button, false); }
});

for (const eventName of ["pointerdown", "keydown", "touchstart"]) {
  document.addEventListener(eventName, () => service.touch(), { passive: true });
}
installLifecycleGuards({
  windowTarget: window,
  documentTarget: document,
  service,
  onSecure(reason) {
    clearSensitiveUi();
    if (reason === "pagehide") revisionChannel.close();
    if (reason === "bfcache") { revisionChannel.open(); void refreshAuthView(); }
  },
});

byId("restore-new-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = event.submitter;
  const file = byId("restore-new-file").files[0];
  const backupPassword = byId("restore-new-backup-password").value;
  const newPassword = byId("restore-new-password").value;
  const newConfirm = byId("restore-new-confirm").value;
  // Same as setup: secrets leave the DOM as soon as they are read, also on validation failure.
  for (const id of ["restore-new-backup-password", "restore-new-password", "restore-new-confirm"]) byId(id).value = "";
  byId("auth-error").textContent = "";
  if (!file || !backupPassword) return void (byId("auth-error").textContent = "バックアップファイルとバックアップのマスターパスワードを入力してください。");
  if (newPassword !== newConfirm) return void (byId("auth-error").textContent = "新しいマスターパスワード（確認）が一致しません。もう一度入力してください。");
  setBusy(button, true);
  try {
    if (file.size > 15_000_000) throw new Error("バックアップファイルが大きすぎます。");
    await service.restoreAsNew(await file.text(), backupPassword, newPassword);
    clearSensitiveUi();
    showApp();
    showToast("バックアップから新しい保管庫を復元しました。");
  } catch (error) {
    await showAuthError(error);
  } finally { setBusy(button, false); }
});

// --- PWA: offline app shell + user-controlled updates ---
const pwa = setupServiceWorker({
  onUpdateReady() { byId("update-banner").hidden = false; },
  onUpdateFailed() {
    byId("update-button").disabled = false;
    showToast("更新を適用できませんでした。現在のバージョンのまま利用できます。", "error");
  },
});
byId("update-button").addEventListener("click", async () => {
  byId("update-button").disabled = true;
  // Lock first: secrets leave memory and the DOM before the code underneath is replaced.
  if (service.isUnlocked) service.lock("update");
  if (!await pwa.applyUpdate()) {
    byId("update-button").disabled = false;
    byId("update-banner").hidden = true;
  }
});

async function refreshAuthView() {
  try { showAuth(await service.exists() ? "unlock" : "setup"); }
  catch (error) { showAuth("setup"); byId("auth-error").textContent = userMessage(error); }
}

refreshAuthView();

