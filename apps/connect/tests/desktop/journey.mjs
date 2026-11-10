// Desktop hosting through the real app, driven over WebDriver (tauri-driver
// with WebKitWebDriver on Linux, Microsoft Edge WebDriver on Windows): create
// a network, invite a device, compare codes and approve, send it a file and
// close the app partway, restart and continue the send, remove the device,
// then restart and reopen. A headless test device (the second_device example)
// plays the other device. Run through run.sh (Linux) or run.ps1 (Windows),
// which set up the world. Prints one line per step with the time since the
// start.
import { spawn, execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { basename, dirname } from "node:path";
import { closeSync, mkdirSync, openSync, readFileSync, readdirSync, writeFileSync, writeSync } from "node:fs";

const APP = process.env.CONNECT_APP;
// Linux: device.sh, which gives the device its own home and keyring.
// Windows: the second_device binary itself, run directly.
const DEVICE = process.env.CONNECT_DEVICE_SCRIPT;
const WORLD = process.env.CONNECT_WORLD;
const OUT = process.env.CONNECT_OUT ?? `${WORLD}/out`;
const DRIVER = process.env.CONNECT_DRIVER ?? "http://127.0.0.1:4444";
const COMPUTER = process.platform === "win32" ? "Windows desktop" : "Linux desktop";
if (!APP || !DEVICE || !WORLD) throw new Error("Run through run.sh or run.ps1");
mkdirSync(OUT, { recursive: true });
const PROFILE = `${WORLD}/device/laptop`;
// The file the app sends: the debug test build's picker returns it.
const SOURCE = process.env.CONNECT_TEST_PICK;
const RECEIVED = `${WORLD}/device/received`;
// Large enough to close the app partway, small enough for a debug build.
const SEND_MB = Number(process.env.CONNECT_SEND_MB ?? 64);
if (!SOURCE) throw new Error("Run through run.sh or run.ps1");
// The command line for the test device: join reads the link written beside
// the profile.
function deviceCommand(...args) {
  if (DEVICE.endsWith(".sh")) return ["bash", [DEVICE, PROFILE, ...args]];
  if (args[0] === "join") {
    const link = readFileSync(`${PROFILE}.link`, "utf8").trim();
    return [DEVICE, [PROFILE, "join", link, ...args.slice(1)]];
  }
  return [DEVICE, [PROFILE, ...args]];
}

async function call(method, path, body) {
  const res = await fetch(DRIVER + path, {
    method,
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${JSON.stringify(json.value ?? json).slice(0, 300)}`);
  return json.value;
}
async function session() {
  const { sessionId } = await call("POST", "/session", {
    capabilities: { alwaysMatch: { browserName: "wry", "tauri:options": { application: APP } } },
  });
  const s = (method, path, body) => call(method, `/session/${sessionId}${path}`, body);
  const app = {
    js: (script, ...args) => s("POST", "/execute/sync", { script, args }),
    click: (css) => app.js(`const e=document.querySelector(arguments[0]); if(!e) throw new Error('Missing '+arguments[0]); e.click(); return true`, css),
    type: (css, text) => app.js(`const e=document.querySelector(arguments[0]); e.value=arguments[1]; e.dispatchEvent(new Event('input',{bubbles:true})); return true`, css, text),
    text: (css) => app.js(`const e=document.querySelector(arguments[0]); return e ? e.innerText : null`, css),
    visible: (css) => app.js(`const e=document.querySelector(arguments[0]); return !!e && !e.closest('[hidden]') && e.getClientRects().length > 0`, css),
    screenshot: async (name) => writeFileSync(`${OUT}/${name}.png`, Buffer.from(await s("GET", "/screenshot"), "base64")),
    until: async (condition, ms, label) => {
      const end = Date.now() + ms;
      while (Date.now() < end) {
        try { if (await condition()) return; } catch { /* the page may be reloading */ }
        await new Promise((r) => setTimeout(r, 500));
      }
      await app.screenshot(`timeout-${label.replace(/\W+/g, "-")}`).catch(() => {});
      throw new Error(`Timed out waiting for ${label}`);
    },
    close: () => s("DELETE", ""),
  };
  return app;
}
const device = (...args) => execFileSync(...deviceCommand(...args), { encoding: "utf8" });
const t0 = Date.now();
const step = (label) => console.log(`${((Date.now() - t0) / 1000).toFixed(1).padStart(6)} s  ${label}`);

let app = await session();
try {
  await app.until(() => app.visible("#choose-create"), 60_000, "Welcome");
  step("Welcome");
  await app.click("#choose-create");
  await app.type("#create-name", "Journey home");
  await app.type("#computer-name", COMPUTER);
  await app.js(`document.getElementById("create-form").requestSubmit()`);
  await app.until(async () => (await app.text("#home-network")) === "Journey home", 120_000, "network created");
  step("Network created");
  await app.screenshot("1-created");
  // Right after Create, Connect offers a recovery file; this run saves none.
  if (await app.visible("#recovery-offer-later")) await app.click("#recovery-offer-later");

  await app.js(`window.__copied = null; navigator.clipboard.writeText = async (text) => { window.__copied = text; }`);
  await app.click("#add-device-button");
  await app.until(() => app.visible("#pair-card"), 60_000, "invitation");
  // The app ignores a tap while it is still finishing the last action (here,
  // refreshing after the invitation appeared); wait for that, as a person does.
  await app.until(() => app.js(`return !document.querySelector('[aria-busy="true"]')`), 30_000, "invitation ready");
  await app.click("#copy-invitation");
  await app.until(() => app.js("return window.__copied"), 10_000, "invitation link");
  mkdirSync(`${WORLD}/device`, { recursive: true });
  writeFileSync(`${PROFILE}.link`, await app.js("return window.__copied"));
  step("Invitation created");

  const joiner = spawn(...deviceCommand("join", "Journey laptop"));
  let said = "";
  joiner.stdout.on("data", (d) => (said += d));
  joiner.stderr.on("data", (d) => (said += d));
  const joined = new Promise((resolve) => joiner.on("exit", resolve));
  await app.until(() => app.visible("#approval-card"), 90_000, "join request").catch((e) => { console.log(said); throw e; });
  const ownerCode = (await app.text("#approval-code")).replace(/\D/g, "");
  await app.until(async () => /\d{3}\s?\d{3}/.test(said), 30_000, "device code");
  const deviceCode = said.match(/\d{3}\s?\d{3}/)[0].replace(/\D/g, "");
  step(`Join request from "${await app.text("#approval-name")}": owner shows ${ownerCode}, device shows ${deviceCode}`);
  if (ownerCode !== deviceCode) throw new Error("The comparison codes differ");
  await app.screenshot("2-approval");
  await app.click("#approve-device");
  const exit = await Promise.race([joined, new Promise((r) => setTimeout(() => r("timeout"), 120_000))]);
  if (exit !== 0) throw new Error(`Joining ended with ${exit}: ${said}`);
  await app.until(async () => (await app.text("#saved-devices"))?.includes("Journey laptop"), 60_000, "device listed");
  const before = JSON.parse(device("status"));
  step(`Device joined, listed on the owner, ready ${before.ready}`);
  if (!before.ready) throw new Error("A joined device is not ready");
  await app.screenshot("3-joined");
} catch (error) {
  await app.close().catch(() => {});
  throw error;
}

// Journey 5: the laptop receives files, the app sends it one and is closed
// partway; after a restart the send continues where it stopped.
mkdirSync(dirname(SOURCE), { recursive: true });
const hash = createHash("sha256");
const out = openSync(SOURCE, "w");
for (let left = SEND_MB; left > 0; left -= 16) {
  const chunk = randomBytes(Math.min(left, 16) << 20);
  hash.update(chunk);
  writeSync(out, chunk);
}
closeSync(out);
const digest = hash.digest("hex");
const NAME = basename(SOURCE);
const [command, args] = deviceCommand("receive", RECEIVED);
// Its own process group on Linux, so stopping it stops the device too.
const receiver = spawn(command, args, { detached: process.platform !== "win32" });
let heard = "";
receiver.stdout.on("data", (d) => (heard += d));
receiver.stderr.on("data", (d) => (heard += d));
const stopReceiver = () => {
  try {
    if (process.platform === "win32") receiver.kill();
    else process.kill(-receiver.pid, "SIGTERM");
  } catch { /* already stopped */ }
};
const SEND = `[aria-label="Send a file to Journey laptop"]`;
try {
  const end = Date.now() + 90_000;
  while (!/Receiving in/.test(heard)) {
    if (Date.now() > end || receiver.exitCode !== null) throw new Error(`The laptop does not receive: ${heard}`);
    await new Promise((r) => setTimeout(r, 500));
  }
  await app.until(() => app.visible(SEND), 90_000, "laptop's inbox listed").catch(async (error) => {
    await app.js(`window.__dump = null; window.__TAURI_INTERNALS__.invoke("home_status").then(
      (s) => { window.__dump = JSON.stringify({ spaces: s.spaces, listed: document.querySelector("#library-count").innerText }); },
      (e) => { window.__dump = String(e); })`).catch(() => {});
    await new Promise((r) => setTimeout(r, 2000));
    const status = await app.js("return window.__dump").catch((e) => String(e));
    console.log(`         laptop: ${heard.trim()}\n         owner sees: ${status}`);
    throw error;
  });
  step(`The laptop receives files; sending ${NAME} (${SEND_MB} MB)`);
  await app.until(() => app.js(`return !document.querySelector('[aria-busy="true"]')`), 30_000, "send ready");
  await app.click(SEND);
  // Closed once part of it arrived, before all of it did.
  const partway = (text) => {
    const prefix = `${NAME} to Journey laptop: `;
    return text.startsWith(prefix) && /^[\d.]+ [KMG]B of /.test(text.slice(prefix.length));
  };
  await app.until(async () => partway((await app.text("#home-message")) ?? ""), 120_000, "send under way");
  step(`Closing the app while sending: ${await app.text("#home-message")}`);
  await app.screenshot("4-sending");
} catch (error) {
  stopReceiver();
  throw error;
} finally {
  await app.close();
}
// The app restarts; the laptop kept what arrived.
app = await session();
try {
  await app.until(async () => (await app.text("#home-network")) === "Journey home", 120_000, "network reopened");
  await app.until(() => app.visible("#unfinished-send"), 60_000, "unfinished send shown");
  const card = await app.text("#unfinished-send-detail");
  step(`Reopened: ${await app.text("#unfinished-send-title")}: ${card}`);
  if (!card.startsWith("Connect closed before it finished.") || !/(at least [\d.]+ [KMG]B of [\d.]+ MB arrived|may have arrived)/.test(card))
    throw new Error(`The unfinished send says: ${card}`);
  await app.screenshot("5-unfinished-send");
  await app.until(() => app.js(`return !document.querySelector('[aria-busy="true"]')`), 30_000, "continue ready");
  await app.click("#resume-send");
  const sent = `${NAME} to Journey laptop: Sent · saved as ${NAME}`;
  // What the screen says on the way: where the send started again, and any
  // problem, as evidence and to explain a failure.
  let said = "", progress = 0;
  await app.until(async () => {
    const [shown, error] = await app.js(`return [document.querySelector('#home-message').innerText,
      document.querySelector('#last-error-detail').textContent]`);
    const moving = / of [\d.]+ MB$/.test(shown);
    if (`${shown}|${error}` !== said && (!moving || progress++ === 0)) console.log(`         screen: ${shown}${error ? ` (problem: ${error})` : ""}`);
    said = `${shown}|${error}`;
    return shown === sent;
  }, 600_000, "send finished");
  step(`Continued: ${sent}`);
  const arrived = readdirSync(RECEIVED);
  const got = createHash("sha256").update(readFileSync(`${RECEIVED}/${NAME}`)).digest("hex");
  if (got !== digest || arrived.length !== 1)
    throw new Error(`The laptop received ${JSON.stringify(arrived)}, sha256 ${got}, expected one ${NAME}, sha256 ${digest}`);
  await app.until(async () => !(await app.visible("#unfinished-send")), 30_000, "unfinished send gone");
  step("Received whole and once: the same sha256, no second copy");
  await app.screenshot("6-sent");
  stopReceiver();

  await app.js(`window.confirm = () => true`);
  await app.js(`for (const menu of document.querySelectorAll('#saved-devices details.row-menu')) menu.open = true`);
  await app.js(`[...document.querySelectorAll('#saved-devices button')].find((b) => b.textContent.includes('Remove from network')).click()`);
  await app.until(async () => !(await app.text("#saved-devices"))?.includes("Journey laptop"), 60_000, "device removed");
  step(`Removed: ${await app.text("#home-message")}`);
  await app.screenshot("7-removed");
} finally {
  stopReceiver();
  await app.close();
}

// Restart: the same network reopens, without Welcome.
app = await session();
try {
  await app.until(async () => (await app.text("#home-network")) === "Journey home", 120_000, "network reopened");
  if (await app.visible("#welcome")) throw new Error("Welcome shown after a restart");
  step("Reopened after a restart");
  await app.screenshot("8-reopened");
} finally {
  await app.close();
}
console.log("Desktop journey passed.");
