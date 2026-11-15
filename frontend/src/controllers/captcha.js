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
  // The widget's token travels in its form; a rejected submission spends it.
  document.addEventListener("objectshare:submit-failed", () => {
    if (window.turnstile) window.turnstile.reset();
  });
})();
