(() => {
  "use strict";

  const form = document.querySelector("#upload-form");
  if (!form) return;
  const input = form.querySelector("#file");
  const modes = form.querySelectorAll("input[name='upload_mode']");
  const button = form.querySelector("#upload-button");
  const status = form.querySelector("#upload-status");
  const progressWrap = form.querySelector("#upload-progress-wrap");
  const progress = form.querySelector("#upload-progress");
  const selectedMode = () => form.querySelector("input[name='upload_mode']:checked")?.value || "single";
  const updateMode = () => { input.multiple = selectedMode() === "multiple"; input.value = ""; };
  modes.forEach((mode) => mode.addEventListener("change", updateMode));
  updateMode();

  const encrypted = form.dataset.clientEncryption === "true";
  if (!encrypted && form.dataset.directUpload !== "true") return;
  if (encrypted && (!globalThis.ObjectShareCrypto || !globalThis.crypto?.subtle)) {
    status.textContent = "Client encryption requires HTTPS (or localhost), JavaScript, and Web Crypto support.";
    status.classList.remove("d-none"); return;
  }
  button.disabled = false;
  const csrfInput = form.querySelector("input[name='csrf_token']");
  const csrfHeaders = csrfInput ? {"X-CSRF-Token": csrfInput.value} : {};
  const captchaToken = () => form.querySelector("input[name='cf-turnstile-response']")?.value || "";
  const showStatus = (message, isError = false) => {
    status.textContent = message;
    status.classList.remove("d-none", "alert-info", "alert-danger");
    status.classList.add(isError ? "alert-danger" : "alert-info");
  };
  const responseError = async (response) => new Error((await response.text()).trim() || `Upload failed with HTTP ${response.status}.`);
  const putFile = (url, file, contentType, index, total) => new Promise((resolve, reject) => {
    const upload = new XMLHttpRequest();
    upload.open("PUT", url); upload.setRequestHeader("Content-Type", contentType);
    upload.upload.addEventListener("progress", (event) => {
      if (!event.lengthComputable) return;
      const filePercent = event.loaded / event.total;
      const percent = Math.round(((index + filePercent) / total) * 100);
      progress.style.width = `${percent}%`; progress.setAttribute("aria-valuenow", String(percent));
      showStatus(`Uploading ${index + 1} of ${total}: ${file.name} (${Math.round(filePercent * 100)}%)`);
    });
    upload.addEventListener("load", () => upload.status >= 200 && upload.status < 300 ? resolve() : reject(new Error(`Object storage rejected ${file.name} with HTTP ${upload.status}.`)));
    upload.addEventListener("error", () => reject(new Error("The direct upload could not reach object storage. Check the bucket CORS policy.")));
    upload.addEventListener("abort", () => reject(new Error("Upload cancelled.")));
    upload.send(file);
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    let files = Array.from(input.files || []);
    if (!files.length) { showStatus("Choose at least one file first.", true); return; }
    if (selectedMode() === "single" && files.length !== 1) { showStatus("Single-file mode accepts exactly one file.", true); return; }
    if (encrypted) {
      if (files.length > Number(form.dataset.maxFiles)) { showStatus("Too many files for one upload batch.", true); return; }
      const limit = Number(form.dataset.maxFileMib) * 1024 * 1024;
      if (files.some(file => file.size + 16 * Math.max(1, Math.ceil(file.size / (1024 * 1024))) > limit)) {
        showStatus("An encrypted file exceeds the upload size limit (including authentication tags).", true); return;
      }
    }
    button.disabled = true; progressWrap.classList.remove("d-none"); progressWrap.setAttribute("aria-hidden", "false");
    progress.style.width = "0%"; progress.setAttribute("aria-valuenow", "0");
    let authorizations = []; const uploaded = new Set();
    let rawKey;
    try {
      const metadata = [];
      if (encrypted) {
        showStatus("Unlocking your account encryption key…");
        rawKey = await ObjectShareCrypto.accountKey(form.querySelector("#encryption-passphrase").value);
        form.querySelector("#encryption-passphrase").value = "";
        const ciphertexts = [];
        for (const file of files) {
          const result = await ObjectShareCrypto.encryptFile(file, rawKey, (n, total) => showStatus(`Encrypting ${file.name}: ${Math.round(n / total * 100)}%`));
          ciphertexts.push(result.file); metadata.push(result.metadata);
        }
        rawKey.fill(0); rawKey = null; files = ciphertexts;
      }
      if (form.dataset.directUpload !== "true") {
        showStatus(`Uploading ${files.length} encrypted file${files.length === 1 ? "" : "s"}…`);
        const body = new FormData(form); body.delete("file");
        files.forEach((file, index) => { body.append("file", file, file.name); body.append("client_encryption", metadata[index]); });
        const response = await fetch(form.action, {method: "POST", headers: {...csrfHeaders, "HX-Request": "true"}, body});
        if (!response.ok) throw await responseError(response);
        const location = response.headers.get("HX-Redirect");
        if (!location || !location.startsWith("/")) throw new Error("Upload finished but its result page is unavailable. Check My account before retrying.");
        window.location.assign(location); return;
      }
      showStatus(`Authorizing ${files.length} direct upload${files.length === 1 ? "" : "s"}…`);
      const begin = await fetch("/api/v1/uploads/direct/batch", {method: "POST", headers: {"Content-Type": "application/json", ...csrfHeaders}, body: JSON.stringify({
        files: files.map((file, index) => ({client_encryption: metadata[index] || "", share_mode: form.elements.share_mode.value, file_name: file.name, file_size: file.size, content_type: file.type || "application/octet-stream"})), captcha_token: captchaToken()
      })});
      if (!begin.ok) throw await responseError(begin);
      authorizations = (await begin.json()).uploads;
      const completedIDs = [];
      for (let index = 0; index < files.length; index += 1) {
        const authorization = authorizations[index]; const file = files[index]; const contentType = file.type || "application/octet-stream";
        await putFile(authorization.upload_url, file, contentType, index, files.length);
        uploaded.add(authorization.file_id);
        showStatus(`Verifying ${file.name}…`);
        const complete = await fetch(authorization.complete_url, {method: "POST", headers: {"Content-Type": "application/json", ...csrfHeaders}, body: JSON.stringify({token: authorization.token})});
        if (!complete.ok) throw await responseError(complete);
        const result = await complete.json(); completedIDs.push(authorization.file_id);
        if (files.length === 1) { window.location.assign(result.location); return; }
      }
      window.location.assign(`/uploads/complete?ids=${completedIDs.join(",")}`);
    } catch (error) {
      showStatus(error instanceof Error ? error.message : "Upload failed.", true); button.disabled = false;
      if (window.turnstile) window.turnstile.reset();
      authorizations.forEach((authorization) => {
        if (uploaded.has(authorization.file_id)) return;
        fetch(authorization.abort_url, {method: "POST", headers: {"Content-Type": "application/json", ...csrfHeaders}, body: JSON.stringify({token: authorization.token}), keepalive: true}).catch(() => {});
      });
    } finally { rawKey?.fill(0); }
  });
})();
