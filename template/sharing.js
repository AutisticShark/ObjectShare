"use strict";
(() => {
  function initialize() {
    const input = document.getElementById("share-url");
    const button = document.getElementById("copy-share-link");
    const status = document.getElementById("copy-status");
    if (!input || !button || !status || button.dataset.ready) return;
    button.dataset.ready = "true";
    input.value = new URL(input.value, window.location.origin).href;
    button.hidden = false;
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(input.value);
        status.textContent = "Link copied.";
      } catch {
        input.focus();
        input.select();
        status.textContent = "Copy the selected link using your browser or keyboard.";
      }
    });
  }
  initialize();
  document.addEventListener("htmx:afterSwap", initialize);
})();
