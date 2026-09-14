(() => {
  "use strict";

  if (document.currentScript?.hasAttribute("data-account-theme")) {
    // HTMX may replace navigation fragments. Keep one document listener and
    // update the current controls, without replacing the surrounding page.
    if (document.documentElement.dataset.themePreference === "account") return;
    document.documentElement.dataset.themePreference = "account";
    const toggles = () => document.querySelectorAll("form[data-theme-toggle]");
    document.addEventListener("objectshare:theme", event => {
      const theme = event.detail?.theme;
      if (theme !== "light" && theme !== "dark") return;
      document.documentElement.dataset.bsTheme = theme;
      const next = theme === "dark" ? "light" : "dark";
      for (const form of toggles()) {
        form.querySelector("input[name='theme']").value = next;
        const button = form.querySelector("button");
        button.setAttribute("aria-label", `Switch to ${next} theme`);
        button.setAttribute("title", `Switch to ${next} theme`);
        for (const icon of form.querySelectorAll("[data-theme-icon]")) icon.hidden = icon.dataset.themeIcon !== next;
        form.querySelector("[data-theme-status]").textContent = "";
      }
      const selection = document.querySelector("select[name='theme']");
      if (selection) selection.value = theme;
    });
    const reportFailure = event => {
      const form = event.detail?.elt?.closest("form[data-theme-toggle]");
      if (form) form.querySelector("[data-theme-status]").textContent = "Theme could not be saved. Try again.";
    };
    document.addEventListener("htmx:responseError", reportFailure);
    document.addEventListener("htmx:sendError", reportFailure);
    return;
  }

  document.documentElement.dataset.themePreference = "system";
  const preference = window.matchMedia("(prefers-color-scheme: dark)");
  const applyTheme = () => {
    const theme = preference.matches ? "dark" : "light";
    document.documentElement.dataset.bsTheme = theme;
  };

  applyTheme();
  if (preference.addEventListener) {
    preference.addEventListener("change", applyTheme);
  } else {
    preference.addListener(applyTheme);
  }
})();
