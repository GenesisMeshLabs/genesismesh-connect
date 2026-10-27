import "./styles.css";
import "./home.css";

// Visible before native state or the application modules finish loading.
// A failed module must leave a usable retry screen, not just the header.
const startup = document.getElementById("startup")!;
const retry = document.getElementById("startup-retry")!;
retry.addEventListener("click", () => location.reload());
const waiting = setTimeout(() => {
  if (startup.hidden) return;
  document.getElementById("startup-detail")!.textContent =
    "Still opening your saved network. You can try again if this takes too long.";
  retry.hidden = false;
}, 8000);

void import("./main").catch((error: unknown) => {
  clearTimeout(waiting);
  if (startup.hidden) return;
  document.getElementById("startup-title")!.textContent = "Connect couldn’t open";
  document.getElementById("startup-detail")!.textContent =
    "Your saved network is still on this device. Try opening Connect again.";
  retry.hidden = false;
  console.error("Connect startup failed", error);
});
