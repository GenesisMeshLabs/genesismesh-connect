export function el<T extends HTMLElement = HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error("Missing interface element: " + id);
  return element as T;
}
export function input(id: string) {
  return el<HTMLInputElement | HTMLTextAreaElement>(id);
}
let toastTimer: ReturnType<typeof setTimeout>;
export function notify(message: string) {
  const toast = el("app-toast");
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.hidden = true;
  }, 5000);
}
export async function copyField(id: string) {
  const field = input(id);
  if (!field.value) return;
  try {
    await navigator.clipboard.writeText(field.value);
    notify("Copied. Share it directly with your other device.");
  } catch {
    field.closest("details")?.setAttribute("open", "");
    field.focus();
    field.select();
    notify("Text selected. Use Copy on your device to finish.");
  }
}
const pages = ["device", "files", "trust", "activity", "transport"];
export function showPage(name: string) {
  if (!pages.includes(name)) return;
  for (const current of pages) {
    el(`${current}-panel`).hidden = name !== current;
    el(`${current}-tab`).setAttribute("aria-pressed", String(name === current));
  }
  el(`${name}-panel`).scrollIntoView({ block: "start" });
}
export function initializeNavigation() {
  for (const button of document.querySelectorAll<HTMLElement>(
    "[data-page], [data-go]",
  )) {
    button.addEventListener("click", () =>
      showPage(button.dataset.page ?? button.dataset.go ?? "device"),
    );
  }
}
