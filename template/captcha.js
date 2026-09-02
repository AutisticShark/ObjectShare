(() => {
  "use strict";

  const renderWidgets = (root = document) => {
    if (!window.turnstile) return;
    root.querySelectorAll(".objectshare-turnstile:not([data-widget-id])").forEach((element) => {
      const widgetId = window.turnstile.render(element, {
        sitekey: element.dataset.sitekey,
        action: element.dataset.action,
        theme: document.documentElement.dataset.themePreference === "system" ? "auto" : (document.documentElement.dataset.bsTheme || "auto")
      });
      element.dataset.widgetId = String(widgetId);
    });
  };

  window.objectShareTurnstileReady = () => renderWidgets();
  document.addEventListener("htmx:configRequest", (event) => {
    const element = event.detail.elt;
    const form = element && element.closest ? element.closest("form") : null;
    const response = form ? form.querySelector("input[name='cf-turnstile-response']") : null;
    if (response && response.value) event.detail.headers["X-Captcha-Token"] = response.value;
  });
  document.addEventListener("htmx:afterSwap", (event) => renderWidgets(event.detail.elt || document));
  document.addEventListener("htmx:responseError", () => {
    if (window.turnstile) window.turnstile.reset();
  });
})();
