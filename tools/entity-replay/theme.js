(() => {
  "use strict";

  const storageKey = "overwatch-decoder-replay-theme";
  const preferences = ["system", "light", "dark"];
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  const root = document.documentElement;
  let preference = "system";

  function validPreference(value) {
    return preferences.includes(value) ? value : "system";
  }

  function applyTheme() {
    const theme = preference === "system" ? (systemTheme.matches ? "dark" : "light") : preference;
    root.dataset.theme = theme;
    document.dispatchEvent(new CustomEvent("overwatch-decoder-theme-change", { detail: { theme, preference } }));
  }

  try {
    preference = validPreference(localStorage.getItem(storageKey));
  } catch {
    // Theme selection still works for this page when storage is blocked.
  }
  applyTheme();

  systemTheme.addEventListener("change", () => {
    if (preference === "system") applyTheme();
  });

  document.addEventListener("DOMContentLoaded", () => {
    const control = document.getElementById("theme-preference");
    control.value = preference;
    control.addEventListener("change", () => {
      preference = validPreference(control.value);
      try {
        localStorage.setItem(storageKey, preference);
      } catch {
        // Keep the in-page preference if persistence is unavailable.
      }
      applyTheme();
    });
  });
})();
