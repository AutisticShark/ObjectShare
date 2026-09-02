(() => {
  "use strict";

  let pendingDialogID = "";

  const closeDialog = (dialog) => {
    if (!dialog) return;
    if (typeof dialog.close === "function" && dialog.open) {
      dialog.close();
      return;
    }
    dialog.removeAttribute("open");
  };

  const openDialog = (id) => {
    const dialog = document.getElementById(id);
    if (!dialog || dialog.tagName !== "DIALOG" || dialog.open) return;
    if (typeof dialog.showModal === "function") {
      dialog.showModal();
    } else {
      dialog.setAttribute("open", "");
    }
    const firstPassword = dialog.querySelector('input[name="password"]');
    if (firstPassword) firstPassword.focus();
  };

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;

    const opener = event.target.closest("[data-user-dialog-open]");
    if (opener) {
      openDialog(opener.getAttribute("data-user-dialog-open"));
      return;
    }

    const closer = event.target.closest("[data-user-dialog-close]");
    if (closer) {
      closeDialog(closer.closest("dialog"));
      return;
    }

    const dialog = event.target.closest("dialog");
    if (dialog && event.target === dialog) closeDialog(dialog);
  });

  document.addEventListener("htmx:beforeRequest", (event) => {
    if (!(event.target instanceof Element)) return;
    const form = event.target.closest("form[data-user-dialog-form]");
    pendingDialogID = form ? form.getAttribute("data-user-dialog-form") : "";
  });

  document.addEventListener("htmx:afterSwap", () => {
    if (!pendingDialogID) return;
    const dialogID = pendingDialogID;
    pendingDialogID = "";
    openDialog(dialogID);
  });

  document.addEventListener("htmx:responseError", () => {
    pendingDialogID = "";
  });
})();
