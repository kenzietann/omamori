// A URL can select a theme for this visit; the switch persists the user preference.
try {
  const requested = new URLSearchParams(location.search).get("theme");
  const saved = localStorage.getItem("omamori-theme");
  document.documentElement.dataset.theme =
    requested === "dark" || requested === "light"
      ? requested
      : saved === "dark"
        ? "dark"
        : "light";
} catch {
  document.documentElement.dataset.theme = "light";
}
