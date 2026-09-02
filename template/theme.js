(() => {
  "use strict";

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
