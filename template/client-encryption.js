/* ObjectShare client encryption v1. Wire format documented in README.md. */
(() => {
  "use strict";
  const CHUNK = 1024 * 1024;
  const enc = new TextEncoder();
  const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  const unb64 = (value, length) => {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid encryption data.");
    const bytes = Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), c => c.charCodeAt(0));
    if (bytes.length !== length || b64(bytes) !== value) throw new Error("Invalid encryption data length.");
    return bytes;
  };
  const random = length => crypto.getRandomValues(new Uint8Array(length));
  const requireCrypto = () => {
    if (!globalThis.crypto?.subtle) throw new Error("Client encryption requires HTTPS (or localhost) and a browser with Web Crypto support.");
  };
  const keyID = async raw => b64(await crypto.subtle.digest("SHA-256", raw));
  const aesKey = raw => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  const wrappingKey = async (passphrase, salt) => {
    const material = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({name: "PBKDF2", hash: "SHA-256", iterations: 600000, salt}, material, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
  };
  const vaultAAD = (user, id) => enc.encode(`objectshare-vault-v1:${user}:${id}`);
  const createVault = async (user, passphrase) => {
    requireCrypto();
    if (passphrase.length < 16 || passphrase.length > 512) throw new Error("Use an encryption passphrase of 16–512 characters.");
    const raw = random(32), salt = random(16), iv = random(12), id = await keyID(raw);
    const key = await wrappingKey(passphrase, salt);
    const wrapped = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: vaultAAD(user, id)}, key, raw);
    return {raw, vault: {version: 1, user_id: user, key_id: id, salt: b64(salt), iv: b64(iv), wrapped_key: b64(wrapped)}};
  };
  const unlockVault = async (vault, user, passphrase) => {
    requireCrypto();
    if (vault.version !== 1 || vault.user_id !== user) throw new Error("The encrypted key belongs to a different account or format.");
    unb64(vault.key_id, 32);
    const key = await wrappingKey(passphrase, unb64(vault.salt, 16));
    let raw;
    try {
      raw = new Uint8Array(await crypto.subtle.decrypt({name: "AES-GCM", iv: unb64(vault.iv, 12), additionalData: vaultAAD(user, vault.key_id)}, key, unb64(vault.wrapped_key, 48)));
    } catch { throw new Error("Unable to unlock the key. Check your encryption passphrase."); }
    if (await keyID(raw) !== vault.key_id) { raw.fill(0); throw new Error("The encryption key fingerprint does not match."); }
    return raw;
  };
  const parseMetadata = raw => {
    if (raw.length > 512) throw new Error("Invalid file encryption metadata.");
    const meta = JSON.parse(raw);
    if (meta.version !== 1 || !Number.isSafeInteger(meta.size) || meta.size < 0 || meta.size > Number.MAX_SAFE_INTEGER - 1024) throw new Error("Unsupported encrypted file format.");
    unb64(meta.key_id, 32); unb64(meta.salt, 32);
    return meta;
  };
  const fileKey = async (raw, metadata) => {
    const meta = parseMetadata(metadata);
    if (await keyID(raw) !== meta.key_id) throw new Error("This file belongs to a different encryption key.");
    const material = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({name: "HKDF", hash: "SHA-256", salt: unb64(meta.salt, 32), info: enc.encode("objectshare-file-v1")}, material, 256));
  };
  const chunkParams = (metadata, index) => {
    const iv = new Uint8Array(12);
    new DataView(iv.buffer).setBigUint64(4, BigInt(index), false);
    return {name: "AES-GCM", iv, tagLength: 128, additionalData: enc.encode(`${metadata}:${index}`)};
  };
  const encryptFile = async (file, raw, report = () => {}) => {
    const metadata = JSON.stringify({version: 1, key_id: await keyID(raw), salt: b64(random(32)), size: file.size});
    const derived = await fileKey(raw, metadata), key = await aesKey(derived);
    derived.fill(0);
    const parts = [], count = Math.max(1, Math.ceil(file.size / CHUNK));
    for (let i = 0; i < count; i++) {
      const plain = new Uint8Array(await file.slice(i * CHUNK, (i + 1) * CHUNK).arrayBuffer());
      try { parts.push(await crypto.subtle.encrypt(chunkParams(metadata, i), key, plain)); } finally { plain.fill(0); }
      report(i + 1, count);
    }
    return {file: new File(parts, file.name, {type: "application/octet-stream"}), metadata};
  };
  const decryptFile = async (blob, metadata, rawKey, report = () => {}) => {
    const meta = parseMetadata(metadata), count = Math.max(1, Math.ceil(meta.size / CHUNK));
    if (blob.size !== meta.size + count * 16) throw new Error("The encrypted file is truncated or has an invalid size.");
    const key = await aesKey(rawKey), parts = [];
    for (let i = 0; i < count; i++) {
      const bytes = await blob.slice(i * (CHUNK + 16), Math.min(blob.size, (i + 1) * (CHUNK + 16))).arrayBuffer();
      try { parts.push(await crypto.subtle.decrypt(chunkParams(metadata, i), key, bytes)); }
      catch { throw new Error("File authentication failed. The key is wrong or the encrypted file was modified."); }
      report(i + 1, count);
    }
    return new Blob(parts, {type: "application/octet-stream"});
  };
  const saveBlob = (blob, name) => {
    const url = URL.createObjectURL(blob), link = document.createElement("a");
    link.href = url; link.download = name; document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  };
  const csrf = () => document.querySelector("input[name='csrf_token']")?.value || "";
  const loadVault = async () => {
    const response = await fetch("/account/encryption", {cache: "no-store", redirect: "error"});
    if (!response.ok) throw new Error("Log in to load your encryption key.");
    return response.json();
  };
  const accountKey = async passphrase => {
    const state = await loadVault();
    if (!state.vault) throw new Error("Set up client encryption in My account before uploading.");
    return unlockVault(state.vault, state.user_id, passphrase);
  };
  globalThis.ObjectShareCrypto = {createVault, unlockVault, encryptFile, decryptFile, fileKey, b64, unb64, accountKey};
  if (typeof document === "undefined") return; // Allows the same Web Crypto implementation to be tested in Node.

  const setup = document.querySelector("#encryption-setup");
  if (setup) {
    const status = setup.querySelector("[role='status']"), button = setup.querySelector("button[type='submit']");
    loadVault().then(state => {
      if (!state.vault) button.disabled = false;
      if (state.vault) { button.disabled = true; status.textContent = "Encryption is enabled. Your passphrase unlocks your uploads on any device. Keep a backup of the encrypted key below."; }
    }).catch(error => { status.textContent = error.message; });
    setup.addEventListener("submit", async event => {
      event.preventDefault(); button.disabled = true;
      let raw;
      try {
        const passphrase = setup.elements.encryption_passphrase.value;
        if (passphrase !== setup.elements.encryption_confirm.value) throw new Error("The encryption passphrases do not match.");
        const state = await loadVault();
        if (state.vault) throw new Error("An encryption key already exists for this account.");
        status.textContent = "Generating and protecting your account key…";
        const created = await createVault(state.user_id, passphrase); raw = created.raw;
        const response = await fetch("/account/encryption", {method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf()}, body: JSON.stringify(created.vault)});
        if (!response.ok) throw new Error((await response.text()).trim());
        saveBlob(new Blob([JSON.stringify(created.vault, null, 2)], {type: "application/json"}), "objectshare-encrypted-key.json");
        setup.reset(); status.textContent = "Encryption enabled. Save the encrypted key backup and your passphrase safely. You can now upload encrypted files.";
      } catch (error) { status.textContent = error.message; button.disabled = false; }
      finally { raw?.fill(0); }
    });
    setup.querySelector("#encryption-backup").addEventListener("click", async () => {
      try {
        const state = await loadVault();
        if (!state.vault) throw new Error("Set up encryption first.");
        saveBlob(new Blob([JSON.stringify(state.vault, null, 2)], {type: "application/json"}), "objectshare-encrypted-key.json");
      } catch (error) { status.textContent = error.message; }
    });
  }

  const download = document.querySelector("#encrypted-download");
  if (!download) return;
  const status = download.querySelector("[role='status']");
  let sharedKey = null;
  if (location.hash.startsWith("#key=")) {
    const fragment = location.hash.slice(5);
    history.replaceState(null, "", location.pathname + location.search);
    try { sharedKey = unb64(fragment, 32); status.textContent = "A file key was loaded from the sharing link."; }
    catch (error) { status.textContent = error.message; }
  }
  window.addEventListener("pagehide", () => { sharedKey?.fill(0); sharedKey = null; });
  const getDownloadKey = async () => {
    if (sharedKey) return sharedKey;
    const backup = download.querySelector("#encryption-key-backup").files[0];
    let raw;
    if (backup) {
      if (backup.size > 2048) throw new Error("Invalid encrypted key backup.");
      const vault = JSON.parse(await backup.text());
      raw = await unlockVault(vault, vault.user_id, download.elements.encryption_passphrase.value);
    } else { raw = await accountKey(download.elements.encryption_passphrase.value); }
    try { return await fileKey(raw, download.dataset.metadata); } finally { raw.fill(0); download.elements.encryption_passphrase.value = ""; }
  };
  download.addEventListener("submit", async event => {
    event.preventDefault(); const button = download.querySelector("button[type='submit']"); button.disabled = true;
    let key;
    try {
      key = await getDownloadKey();
      status.textContent = "Downloading encrypted file…";
      const body = new URLSearchParams();
      body.set("download_token", download.elements.download_token.value);
      const captcha = download.querySelector("input[name='cf-turnstile-response']");
      if (captcha) body.set("cf-turnstile-response", captcha.value);
      const response = await fetch(download.action, {method: "POST", body, cache: "no-store", redirect: "error"});
      if (!response.ok) throw new Error((await response.text()).trim() || "Download failed.");
      const plaintext = await decryptFile(await response.blob(), download.dataset.metadata, key, (n, total) => { status.textContent = `Decrypting ${n} of ${total} chunks…`; });
      saveBlob(plaintext, download.dataset.filename); status.textContent = "File authenticated and decrypted in your browser.";
    } catch (error) { status.textContent = error.message; if (window.turnstile) window.turnstile.reset(); }
    finally { if (key !== sharedKey) key?.fill(0); button.disabled = false; }
  });
  download.querySelector("#encrypted-share")?.addEventListener("click", async () => {
    let key;
    try {
      key = await getDownloadKey();
      const output = download.querySelector("#encrypted-share-link");
      output.value = `${location.origin}${location.pathname}#key=${b64(key)}`; output.hidden = false; output.select();
      status.textContent = "Copy this link for your recipients. It contains this file's key; sharing permissions still apply.";
    } catch (error) { status.textContent = error.message; }
    finally { if (key !== sharedKey) key?.fill(0); }
  });
})();
