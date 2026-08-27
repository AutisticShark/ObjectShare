(() => {
  "use strict";

  const form = document.querySelector("#upload-form[data-direct-upload='true']");
  if (!form) return;

  const input = document.querySelector("#file");
  const button = document.querySelector("#upload-button");
  const status = document.querySelector("#upload-status");
  const progressWrap = document.querySelector("#upload-progress-wrap");
  const progress = document.querySelector("#upload-progress");

  const showStatus = (message, isError = false) => {
    status.textContent = message;
    status.classList.remove("d-none", "alert-info", "alert-danger");
    status.classList.add(isError ? "alert-danger" : "alert-info");
  };

  const responseError = async (response) => {
    const message = (await response.text()).trim();
    return new Error(message || `Upload failed with HTTP ${response.status}.`);
  };

  const putFile = (url, file, contentType) => new Promise((resolve, reject) => {
    const upload = new XMLHttpRequest();
    upload.open("PUT", url);
    upload.setRequestHeader("Content-Type", contentType);
    upload.upload.addEventListener("progress", (event) => {
      if (!event.lengthComputable) return;
      const percent = Math.round((event.loaded / event.total) * 100);
      progress.style.width = `${percent}%`;
      progress.setAttribute("aria-valuenow", String(percent));
      showStatus(`Uploading directly to object storage: ${percent}%`);
    });
    upload.addEventListener("load", () => {
      if (upload.status >= 200 && upload.status < 300) resolve();
      else reject(new Error(`Object storage rejected the upload with HTTP ${upload.status}.`));
    });
    upload.addEventListener("error", () => reject(new Error("The direct upload could not reach object storage. Check the R2 CORS policy.")));
    upload.addEventListener("abort", () => reject(new Error("Upload cancelled.")));
    upload.send(file);
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = input.files && input.files[0];
    if (!file) {
      showStatus("Choose a file first.", true);
      return;
    }

    button.disabled = true;
    progressWrap.classList.remove("d-none");
    progressWrap.setAttribute("aria-hidden", "false");
    progress.style.width = "0%";
    progress.setAttribute("aria-valuenow", "0");
    const contentType = file.type || "application/octet-stream";
    let authorization;
    let objectUploaded = false;

    try {
      showStatus("Authorizing a direct upload…");
      const begin = await fetch("/api/v1/uploads/direct", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({file_name: file.name, file_size: file.size, content_type: contentType})
      });
      if (!begin.ok) throw await responseError(begin);
      authorization = await begin.json();

      await putFile(authorization.upload_url, file, contentType);
      objectUploaded = true;
      showStatus("Verifying the uploaded object…");
      const complete = await fetch(authorization.complete_url, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({token: authorization.token})
      });
      if (!complete.ok) throw await responseError(complete);
      const result = await complete.json();
      window.location.assign(result.location);
    } catch (error) {
      showStatus(error instanceof Error ? error.message : "Upload failed.", true);
      button.disabled = false;
      if (authorization && !objectUploaded) {
        fetch(authorization.abort_url, {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({token: authorization.token}),
          keepalive: true
        }).catch(() => {});
      }
    }
  });
})();
