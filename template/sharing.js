"use strict";
(() => {
  function initialize() {
    const input = document.getElementById("share-url");
    const button = document.getElementById("copy-share-link");
    const status = document.getElementById("copy-status");
    if (!input || !button || !status || button.dataset.ready) return;
    button.dataset.ready = "true";
    const permissions = document.getElementById("sharing-permissions");
    const mode = document.getElementById("share-mode");
    const recipients = document.getElementById("recipients");
    const recipientGroup = document.getElementById("sharing-recipients");
    const unsaved = document.getElementById("unsaved-sharing");
    const encrypted = document.getElementById("encrypted-sharing");
    const create = document.getElementById("create-encrypted-link");
    const result = document.getElementById("encrypted-link-result");
    const initialMode = mode.value, initialRecipients = recipients.value;
    let busy = false;
    const dirty = () => permissions.dataset.unsaved === "true" || mode.value !== initialMode || recipients.value !== initialRecipients;
    if (!encrypted) input.value = new URL(input.value, window.location.origin).href;
    button.hidden = false;
    const refresh = () => {
      const changed = dirty();
      unsaved.hidden = !changed;
      if (changed) status.textContent = "";
      recipientGroup.hidden = mode.value !== "selected";
      recipients.disabled = mode.value !== "selected";
      button.disabled = changed || busy || !input.value;
      if (create) create.disabled = changed || busy || !globalThis.ObjectShareCrypto;
      if (changed && encrypted) { input.value = ""; result.hidden = true; }
    };
    permissions.addEventListener("input", refresh);
    permissions.addEventListener("change", refresh);
    refresh();
    button.addEventListener("click", async () => {
      if (dirty() || busy || !input.value) return;
      try {
        await navigator.clipboard.writeText(input.value);
        status.textContent = "Link copied.";
      } catch {
        input.focus();
        input.select();
        status.textContent = "Copy the selected link using your browser or keyboard.";
      }
    });
    encrypted?.addEventListener("submit", async event => {
      event.preventDefault();
      if (busy || dirty() || !globalThis.ObjectShareCrypto) return;
      busy = true; input.value = ""; result.hidden = true; refresh();
      status.textContent = "Unlocking this file's sharing key…";
      const passphrase = document.getElementById("share-passphrase");
      const backup = document.getElementById("share-key-backup").files[0];
      const crypto = globalThis.ObjectShareCrypto;
      const phrase = passphrase.value;
      const generation = encrypted.dataset.generation || "0";
      passphrase.value = "";
      let raw, key;
      try {
        if (backup) {
          if (backup.size > 2048) throw new Error("Invalid encrypted key backup.");
          const vault = JSON.parse(await backup.text());
          raw = await crypto.unlockVault(vault, vault.user_id, phrase);
        } else {
          raw = await crypto.accountKey(phrase);
        }
        key = await crypto.fileKey(raw, encrypted.dataset.metadata);
        if (encrypted.dataset.disposed === "true" || !encrypted.isConnected || generation !== (encrypted.dataset.generation || "0")) return;
        if (dirty()) { status.textContent = "Save permissions, then create a new sharing link."; return; }
        const link = new URL(encrypted.dataset.shareUrl, window.location.origin);
        link.hash = `key=${crypto.b64(key)}`;
        input.value = link.href; result.hidden = false; input.focus(); input.select();
        status.textContent = "Link ready. Copy it for your intended recipients; saved access permissions still apply.";
      } catch (error) {
        status.textContent = error instanceof Error ? error.message : "Unable to create a sharing link.";
      } finally {
        raw?.fill(0); key?.fill(0); passphrase.value = "";
        busy = false; refresh();
      }
    });
  }
  function clearEncryption() {
    const encrypted = document.getElementById("encrypted-sharing");
    if (!encrypted) return;
    encrypted.dataset.disposed = "true";
    encrypted.dataset.generation = String(Number(encrypted.dataset.generation || "0") + 1);
    document.getElementById("share-passphrase").value = "";
    document.getElementById("share-url").value = "";
    document.getElementById("encrypted-link-result").hidden = true;
    document.getElementById("copy-status").textContent = "";
  }
  initialize();
  document.addEventListener("htmx:afterSwap", initialize);
  document.addEventListener("htmx:beforeSwap", event => {
    const encrypted = document.getElementById("encrypted-sharing");
    if (encrypted && event.detail.target.contains(encrypted)) clearEncryption();
  });
  window.addEventListener("pagehide", clearEncryption);
  window.addEventListener("pageshow", () => {
    const encrypted = document.getElementById("encrypted-sharing");
    if (encrypted) delete encrypted.dataset.disposed;
  });
})();
