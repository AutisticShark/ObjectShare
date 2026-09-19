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
  const recovery = form.querySelector("#upload-recovery");
  const completedList = form.querySelector("#completed-uploads");
  const retryButton = form.querySelector("#retry-upload");
  let busy = false;
  let attempt = null;
  const selectedMode = () => form.querySelector("input[name='upload_mode']:checked")?.value || "single";
  const selection = form.querySelector("#file-selection");
  const dropzone = form.querySelector("#upload-dropzone");
  const encryptionChoice = form.querySelector("#encrypt-files");
  const passphrase = form.querySelector("#encryption-passphrase");
  const encryptionFields = form.querySelector("#encryption-fields");
  const encryptionSelected = () => encryptionChoice?.checked === true;
  const encryptionAvailable = !!(globalThis.ObjectShareCrypto && globalThis.crypto?.subtle);
  const describeSelection = () => {
    const encrypted = encryptionSelected();
    const files = Array.from(input.files || []);
    input.setCustomValidity("");
    if (selection) {
      selection.replaceChildren();
      for (const file of files) {
        const row = document.createElement("div");
        row.textContent = `${file.name} · ${(file.size / (1024 * 1024)).toFixed(2)} MiB`;
        selection.append(row);
      }
    }
    if (selectedMode() === "single" && files.length > 1) {
      input.setCustomValidity("Choose Multiple files to upload more than one file.");
    } else if (files.length > Number(form.dataset.maxFiles)) {
      input.setCustomValidity(`Choose up to ${form.dataset.maxFiles} files per batch.`);
    } else {
      const limit = Number(form.dataset.maxFileMib) * 1024 * 1024;
      if (files.some(file => file.size + (encrypted ? 16 * Math.max(1, Math.ceil(file.size / (1024 * 1024))) : 0) > limit)) {
        input.setCustomValidity(`Each file must fit within ${form.dataset.maxFileMib} MiB${encrypted ? ", including encryption overhead" : ""}.`);
      }
    }
  };
  const updateMode = () => { input.multiple = selectedMode() === "multiple"; input.value = ""; describeSelection(); };
  modes.forEach((mode) => mode.addEventListener("change", updateMode));
  input.addEventListener("change", describeSelection);
  if (dropzone) {
    dropzone.addEventListener("dragover", event => { event.preventDefault(); dropzone.classList.add("is-dragging"); });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("is-dragging"));
    dropzone.addEventListener("drop", event => {
      event.preventDefault(); dropzone.classList.remove("is-dragging");
      if (button.disabled || !event.dataTransfer?.files.length) return;
      try { input.files = event.dataTransfer.files; describeSelection(); input.reportValidity(); }
      catch { if (selection) selection.textContent = "Use Browse to choose files on this device."; }
    });
  }
  const access = form.querySelector("#share-mode");
  const explanation = form.querySelector("#sharing-explanation");
  access?.addEventListener("change", () => {
    if (explanation) explanation.textContent = {
      link: "Anyone who receives the link can open the file. Encrypted files also need a file key.",
      signed_in: "Recipients must log in before opening this file. Encrypted files also need a file key.",
      private: "Only you can open this file. After uploading, use Share to add selected accounts."
    }[access.value] || "";
  });
  updateMode();

  const updateEncryption = () => {
    const encrypted = encryptionSelected();
    if (encryptionFields) encryptionFields.hidden = !encrypted;
    if (passphrase) {
      passphrase.required = encrypted;
      passphrase.disabled = !encrypted;
      if (!encrypted) passphrase.value = "";
    }
    describeSelection();
  };
  if (encryptionChoice) {
    encryptionChoice.disabled = !encryptionAvailable;
    encryptionChoice.addEventListener("change", updateEncryption);
    updateEncryption();
    if (!encryptionAvailable) {
      status.textContent = "Client encryption requires HTTPS (or localhost) and Web Crypto support. You can upload without client-side encryption.";
      status.classList.remove("d-none");
    }
  }
  if (!encryptionChoice && form.dataset.directUpload !== "true") return;
  button.disabled = false;
  const csrfInput = form.querySelector("input[name='csrf_token']");
  const csrfHeaders = csrfInput ? {"X-CSRF-Token": csrfInput.value} : {};
  const captchaToken = () => form.querySelector("input[name='cf-turnstile-response']")?.value || "";
  const showStatus = (message, isError = false) => {
    status.textContent = message;
    status.classList.remove("d-none", "alert-info", "alert-danger");
    status.classList.add(isError ? "alert-danger" : "alert-info");
  };
  const responseError = async (response) => {
    const error = new Error((await response.text()).trim() || `Upload failed with HTTP ${response.status}.`);
    error.status = response.status;
    return error;
  };
  const controls = [input, ...modes, access].filter(Boolean);
  const setBusy = (value) => {
    busy = value;
    button.disabled = value || attempt !== null;
    controls.forEach(control => { control.disabled = value || attempt !== null; });
    if (encryptionChoice) encryptionChoice.disabled = value || attempt !== null || !encryptionAvailable;
    if (passphrase) passphrase.disabled = value || attempt !== null || !encryptionSelected();
    if (retryButton) retryButton.disabled = value;
    form.setAttribute?.("aria-busy", String(value));
  };
  const showCompleted = () => {
    if (!completedList || !attempt) return;
    completedList.replaceChildren();
    for (const index of attempt.completed) {
      const row = document.createElement("li");
      const link = document.createElement("a");
      link.href = `/file/${encodeURIComponent(attempt.authorizations[index].file_id)}`;
      link.textContent = `Uploaded: ${attempt.names[index]}`;
      link.target = "_blank"; link.rel = "noopener";
      row.append(link); completedList.append(row);
    }
  };
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

  const sendDirectAttempt = async () => {
    const current = attempt;
    for (let index = 0; index < current.files.length; index += 1) {
      if (current.completed.has(index)) continue;
      const authorization = current.authorizations[index];
      const file = current.files[index];
      if (!current.uploaded.has(index)) {
        await putFile(authorization.upload_url, file, file.type || "application/octet-stream", index, current.files.length);
        current.uploaded.add(index);
      }
      showStatus(`Verifying ${current.names[index]}…`);
      const complete = await fetch(authorization.complete_url, {method: "POST", headers: {"Content-Type": "application/json", ...csrfHeaders}, body: JSON.stringify({token: authorization.token})});
      if (!complete.ok) throw await responseError(complete);
      await complete.json();
      current.completed.add(index);
      current.files[index] = null; // Release the completed ciphertext Blob.
      showCompleted();
    }
    const ids = current.authorizations.map(authorization => encodeURIComponent(authorization.file_id));
    window.location.assign(ids.length === 1 ? `/file/${ids[0]}` : `/uploads/complete?ids=${ids.join(",")}`);
  };
  const failed = (error) => {
    const message = error instanceof Error ? error.message : "Upload failed.";
    showStatus(message, true);
    setBusy(false);
    if (attempt) {
      recovery?.classList.remove("d-none");
      showCompleted();
      if (error?.status === 410 || error?.status === 422) {
        if (retryButton) retryButton.disabled = true;
        showStatus(`${message} Completed files remain available below. Start another upload for the unfinished files.`, true);
      }
    } else if (window.turnstile) window.turnstile.reset();
  };
  retryButton?.addEventListener("click", async () => {
    if (busy || !attempt) return;
    setBusy(true);
    try { await sendDirectAttempt(); } catch (error) { failed(error); }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || attempt) return;
    const encrypted = encryptionSelected();
    if (encrypted && !encryptionAvailable) { showStatus("Client encryption is unavailable. Use HTTPS and a browser with Web Crypto support.", true); return; }
    if (encrypted && !passphrase.value) { showStatus("Enter your encryption passphrase first.", true); return; }
    let files = Array.from(input.files || []);
    if (!files.length) { showStatus("Choose at least one file first.", true); return; }
    if (selectedMode() === "single" && files.length !== 1) { showStatus("Single-file mode accepts exactly one file.", true); return; }
    if (files.length > Number(form.dataset.maxFiles)) { showStatus("Too many files for one upload batch.", true); return; }
    const limit = Number(form.dataset.maxFileMib) * 1024 * 1024;
    if (files.some(file => file.size + (encrypted ? 16 * Math.max(1, Math.ceil(file.size / (1024 * 1024))) : 0) > limit)) {
      showStatus("A file exceeds the upload size limit (including any encryption overhead).", true); return;
    }
    // Capture the selected policy and form fields before awaiting encryption or
    // disabling controls. A selection change must never change an active upload.
    const shareMode = form.elements.share_mode.value;
    const challenge = captchaToken();
    const body = form.dataset.directUpload === "true" ? null : new FormData(form);
    setBusy(true);
    progressWrap.classList.remove("d-none"); progressWrap.setAttribute("aria-hidden", "false");
    progress.style.width = "0%"; progress.setAttribute("aria-valuenow", "0");
    let rawKey;
    let proxiedRequestStarted = false;
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
      if (body) {
        showStatus(`Uploading ${files.length}${encrypted ? " encrypted" : ""} file${files.length === 1 ? "" : "s"}…`);
        body.delete("file");
        files.forEach((file, index) => { body.append("file", file, file.name); body.append("client_encryption", metadata[index] || ""); });
        proxiedRequestStarted = true;
        const response = await fetch(form.action, {method: "POST", headers: {...csrfHeaders, "HX-Request": "true"}, body});
        if (!response.ok) throw await responseError(response);
        const location = response.headers.get("HX-Redirect");
        if (!location || !location.startsWith("/") || location.startsWith("//")) throw new Error("Upload finished but its result page is unavailable. Check My files before retrying.");
        window.location.assign(location); return;
      }
      showStatus(`Authorizing ${files.length} direct upload${files.length === 1 ? "" : "s"}…`);
      const begin = await fetch("/api/v1/uploads/direct/batch", {method: "POST", headers: {"Content-Type": "application/json", ...csrfHeaders}, body: JSON.stringify({
        files: files.map((file, index) => ({client_encryption: metadata[index] || "", share_mode: shareMode, file_name: file.name, file_size: file.size, content_type: file.type || "application/octet-stream"})), captcha_token: challenge
      })});
      if (!begin.ok) throw await responseError(begin);
      const authorizations = (await begin.json()).uploads;
      if (!Array.isArray(authorizations) || authorizations.length !== files.length) throw new Error("The upload authorization was incomplete. No files were sent.");
      attempt = {files, names: files.map(file => file.name), authorizations, uploaded: new Set(), completed: new Set()};
      await sendDirectAttempt();
    } catch (error) {
      failed(error);
      if (proxiedRequestStarted) {
        showStatus(`${error instanceof Error ? error.message : "Upload could not be confirmed."} Check My files before uploading again; the server may have received some or all of this batch.`, true);
      }
    } finally { rawKey?.fill(0); }
  });
})();
