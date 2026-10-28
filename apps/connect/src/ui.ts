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
const pages = ["guide", "connection-help", "access-help", "device", "files", "trust", "activity", "transport"];
export function showPage(name: string) {
  if (!pages.includes(name)) return;
  for (const current of pages) {
    el(`${current}-panel`).hidden = name !== current;
    el(`${current}-tab`).setAttribute("aria-pressed", String(name === current));
  }
  if (["device","files","trust","transport"].includes(name)) el<HTMLDetailsElement>("expert-tools").open=true;
  if (name==="guide")el<HTMLDetailsElement>("expert-tools").open=false;
  if (name==="trust")el<HTMLDetailsElement>("authority-route-editor").open=false;
  if (!el("advanced-shell").hidden) {
    const page=el(`${name}-panel`), mobile=window.matchMedia("(max-width:680px)").matches;
    const offset=el("close-advanced").getBoundingClientRect().height+(mobile?(document.querySelector<HTMLElement>("#advanced-shell .sidebar")?.getBoundingClientRect().height||0):0)+16;
    page.style.scrollMarginTop=`${offset}px`;page.scrollIntoView({block:"start"});
    const heading=page.querySelector<HTMLElement>("h1");if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});}
  }
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
