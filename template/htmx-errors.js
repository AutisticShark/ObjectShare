(() => {
  "use strict";

  // htmx does not swap 4xx/5xx responses, so a rejected submission (a wrong
  // setup token, a rate limit, an expired CSRF token) used to leave the page
  // unchanged. For forms that replace the page (hx-select), swap in the
  // server's error page when it sent one, and otherwise show its plain-text
  // message inside the form. The response stays an error, so other
  // htmx:responseError listeners still run.
  const root = document.documentElement;
  if (root.dataset.htmxErrors === "ready") return;
  root.dataset.htmxErrors = "ready";

  const pageSelector = element => element?.closest?.("[hx-select]")?.getAttribute("hx-select") || "";

  const showMessage = (element, text) => {
    const form = element?.closest?.("form");
    if (!form) return;
    let alert = form.querySelector("[data-htmx-error]");
    if (!alert) {
      alert = document.createElement("div");
      alert.className = "alert alert-danger";
      alert.setAttribute("role", "alert");
      alert.setAttribute("data-htmx-error", "");
      (form.querySelector(".card-body") || form).prepend(alert);
    }
    alert.textContent = text;
  };

  document.addEventListener("htmx:beforeRequest", event => {
    event.detail?.elt?.closest?.("form")?.querySelector("[data-htmx-error]")?.remove();
  });

  document.addEventListener("htmx:beforeSwap", event => {
    const detail = event.detail, xhr = detail?.xhr;
    if (!xhr || xhr.status < 400) return;
    const element = detail.requestConfig?.elt;
    const selector = pageSelector(element);
    if (!selector) return;
    const html = (xhr.getResponseHeader("Content-Type") || "").toLowerCase().startsWith("text/html");
    const body = String(detail.serverResponse ?? "");
    if (html && new DOMParser().parseFromString(body, "text/html").querySelector(selector)) {
      detail.shouldSwap = true;
      return;
    }
    const message = html ? "" : body.trim().slice(0, 300);
    showMessage(element, message || `The request failed (HTTP ${xhr.status}). Try again.`);
  });

  document.addEventListener("htmx:sendError", event => {
    const element = event.detail?.requestConfig?.elt || event.detail?.elt;
    if (pageSelector(element)) showMessage(element, "The server could not be reached. Check your connection and try again.");
  });
})();
