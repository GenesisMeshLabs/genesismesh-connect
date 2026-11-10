// Line icons from Lucide (ISC license), drawn at 24px with the current colour.
import {
  createElement, type IconNode,
  AppWindow, ArchiveRestore, ArrowLeft, Bot, ChevronRight, CircleAlert, CircleCheck, Clock, Copy, EllipsisVertical,
  File, FileText, Folder, FolderPlus, Folders, History, House, Image, Inbox, KeyRound, Link, LogOut,
  MonitorSmartphone, Plus, Power, RefreshCw, Send, Settings, Smartphone, Terminal, Trash2, WifiOff, Wrench, X,
} from "lucide";

const icons = {
  "app-window": AppWindow, "archive-restore": ArchiveRestore, "arrow-left": ArrowLeft, bot: Bot, "chevron-right": ChevronRight,
  "circle-alert": CircleAlert, "circle-check": CircleCheck, clock: Clock, copy: Copy, more: EllipsisVertical,
  file: File, "file-text": FileText, folder: Folder, "folder-plus": FolderPlus, folders: Folders, history: History,
  house: House, image: Image, inbox: Inbox, "key-round": KeyRound, link: Link, "log-out": LogOut,
  "monitor-smartphone": MonitorSmartphone, plus: Plus, power: Power, "refresh-cw": RefreshCw, send: Send,
  settings: Settings, smartphone: Smartphone, terminal: Terminal, trash: Trash2, "wifi-off": WifiOff, wrench: Wrench, x: X,
} satisfies Record<string, IconNode>;
export type IconName = keyof typeof icons;

export function icon(name: IconName, size = 24): SVGElement {
  const svg = createElement(icons[name], { width: size, height: size, "aria-hidden": "true", class: "icon" });
  svg.setAttribute("focusable", "false");
  return svg;
}
/** Draws every `data-icon` placeholder in the page's own markup. */
export function fillIcons(root: ParentNode = document) {
  for (const slot of root.querySelectorAll<HTMLElement>("[data-icon]"))
    if (!slot.firstElementChild) slot.append(icon(slot.dataset.icon as IconName, Number(slot.dataset.size) || 24));
}
