// The Android app on an emulator, driven over its WebView's DevTools protocol
// (debug builds allow it): join a network that a headless Connect node runs,
// compare codes and approve, send a file to a laptop's inbox and stop the app
// partway the way Android stops it (force-stop ends the process), open it
// again and continue the send, then open it once more. The second_device
// example plays the laptop. Run through run.sh, which sets up the node and the
// world. Prints one line per step with the time since the start.
//
// Evidence from this journey is emulator evidence: the system file picker is
// replaced by the debug test build's placed file, and the device is virtual.
import { spawn, execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, readdirSync, writeFileSync, writeSync } from "node:fs";
import { connect } from "node:net";

const WORLD = process.env.CONNECT_WORLD;
const OUT = process.env.CONNECT_OUT ?? `${WORLD}/out`;
const DEVICE = process.env.CONNECT_DEVICE_SCRIPT;
const PACKAGE = process.env.CONNECT_PACKAGE ?? "org.genesismesh.connect.qualification";
if (!WORLD || !DEVICE) throw new Error("Run through run.sh");
mkdirSync(OUT, { recursive: true });
const CONTROL = `${WORLD}/node/control.sock`;
const PROFILE = `${WORLD}/device/laptop`;
const RECEIVED = `${WORLD}/device/received`;
const NAME = "journey.bin";
const SOURCE = `${WORLD}/send/${NAME}`;
// The same size as the desktop journey. Debug builds send slowly, an emulator
// more so; the size keeps the run within the job's time.
const SEND_MB = Number(process.env.CONNECT_SEND_MB ?? 8);
const DEVTOOLS_PORT = 9222;

const t0 = Date.now();
const step = (label) => console.log(`${((Date.now() - t0) / 1000).toFixed(1).padStart(6)} s  ${label}`);
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const adb = (...args) => execFileSync("adb", args, { encoding: "utf8", maxBuffer: 16 << 20 });
// Commands inside the app's own data directory, as the app's user.
const inApp = (command) => adb("shell", `run-as ${PACKAGE} sh -c '${command}'`);
// The files the app keeps for a send: its record and its copies of picked files.
const keeps = () => inApp("find cache/connect-sends cache/connect-picked -type f 2>/dev/null; true").split("\n").filter(Boolean);

async function until(condition, ms, label, onTimeout) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { const value = await condition(); if (value) return value; } catch { /* reopening or reloading */ }
    await pause(500);
  }
  await screenshot(`timeout-${label.replace(/\W+/g, "-")}`).catch(() => {});
  await onTimeout?.().catch(() => {});
  throw new Error(`Timed out waiting for ${label}`);
}
async function screenshot(name) {
  writeFileSync(`${OUT}/${name}.png`, execFileSync("adb", ["exec-out", "screencap", "-p"], { maxBuffer: 64 << 20 }));
}

// The node's control socket: one JSON request per connection, one reply line.
function control(request) {
  return new Promise((resolve, reject) => {
    const socket = connect(CONTROL);
    let line = "";
    socket.on("error", reject);
    socket.on("end", () => reject(new Error(`The node closed the connection: ${line}`)));
    socket.on("data", (d) => {
      line += d;
      if (!line.includes("\n")) return;
      socket.destroy();
      try {
        const reply = JSON.parse(line);
        if (reply.error) reject(new Error(String(reply.error)));
        else resolve(reply.ok);
      } catch (error) { reject(error); }
    });
    socket.write(`${JSON.stringify(request)}\n`);
  });
}

// Open Connect and attach to its WebView. Each process has its own DevTools
// socket, so a reopened app is attached again.
async function open() {
  const activity = adb("shell", "cmd", "package", "resolve-activity", "--brief", "-c", "android.intent.category.LAUNCHER", PACKAGE)
    .trim().split("\n").pop().trim();
  adb("shell", "am", "start", "-W", "-n", activity);
  const pid = await until(() => adb("shell", "pidof", PACKAGE).trim(), 60_000, "app process");
  const name = `webview_devtools_remote_${pid}`;
  await until(() => adb("shell", "cat", "/proc/net/unix").includes(`@${name}`), 60_000, "WebView debugging");
  adb("forward", `tcp:${DEVTOOLS_PORT}`, `localabstract:${name}`);
  const page = await until(async () => {
    const targets = await (await fetch(`http://127.0.0.1:${DEVTOOLS_PORT}/json`)).json();
    return targets.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
  }, 60_000, "WebView page");
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = () => reject(new Error("DevTools connection failed")); });
  let next = 0;
  const waiting = new Map();
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    const reply = waiting.get(message.id);
    if (!reply) return;
    waiting.delete(message.id);
    if (message.error) reply.reject(new Error(message.error.message));
    else reply.resolve(message.result);
  };
  socket.onclose = () => { for (const reply of waiting.values()) reply.reject(new Error("The app closed")); waiting.clear(); };
  const send = (method, params) => new Promise((resolve, reject) => {
    const id = ++next;
    waiting.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  const app = {
    pid,
    js: async (script, ...args) => {
      const result = await send("Runtime.evaluate", {
        expression: `(async function () { ${script} }).apply(null, ${JSON.stringify(args)})`,
        awaitPromise: true,
        returnByValue: true,
      });
      if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text);
      return result.result.value;
    },
    click: (css) => app.js(`const e=document.querySelector(arguments[0]); if(!e) throw new Error('Missing '+arguments[0]); e.click(); return true`, css),
    type: (css, text) => app.js(`const e=document.querySelector(arguments[0]); e.value=arguments[1]; e.dispatchEvent(new Event('input',{bubbles:true})); return true`, css, text),
    text: (css) => app.js(`const e=document.querySelector(arguments[0]); return e ? e.innerText : null`, css),
    visible: (css) => app.js(`const e=document.querySelector(arguments[0]); return !!e && !e.closest('[hidden]') && e.getClientRects().length > 0`, css),
    idle: () => app.js(`return !document.querySelector('[aria-busy="true"]')`),
    detach: () => { socket.close(); try { adb("forward", "--remove", `tcp:${DEVTOOLS_PORT}`); } catch { /* gone */ } },
  };
  return app;
}
// Android ends the process; nothing in the app runs on the way out.
function stop(app) {
  app.detach();
  adb("shell", "am", "force-stop", PACKAGE);
}

// The headless test device: device.sh gives it its own home and keyring.
const device = (...args) => execFileSync("bash", [DEVICE, PROFILE, ...args], { encoding: "utf8" });
const digits = (text) => String(text ?? "").replace(/\D/g, "");

// 1. The phone joins the node's network.
let app = await open();
await until(() => app.visible("#choose-join"), 120_000, "Welcome");
step("Welcome");
await screenshot("1-welcome");
let invitation = await control({ op: "pair_begin", name: "Journey server" });
await app.click("#choose-join");
await app.type("#join-name", "Journey phone");
await app.type("#join-link", invitation.link);
await app.js(`document.getElementById("join-form").requestSubmit()`);
let pending = await until(() => control({ op: "pair_pending" }), 120_000, "join request");
const phoneCode = await until(async () => (await app.visible("#joining-code")) && digits(await app.text("#joining-code")), 60_000, "phone code");
step(`Join request from "${pending.name}": node shows ${digits(pending.code)}, phone shows ${phoneCode}`);
if (digits(pending.code) !== phoneCode) throw new Error("The comparison codes differ");
await screenshot("2-joining");
const approved = control({ op: "pair_approve", id: pending.id });
await until(() => app.visible("#workspace"), 180_000, "phone joined");
await approved;
await until(async () => (await control({ op: "status" })).devices.includes("Journey phone"), 60_000, "phone listed on the node");
step("Phone joined and listed on the node");
await screenshot("3-joined");

// 2. A laptop joins too and receives files. The node takes the next
// invitation once the phone's pairing has closed.
invitation = await until(() => control({ op: "pair_begin", name: "Journey server" }), 60_000, "laptop's invitation");
mkdirSync(`${WORLD}/device`, { recursive: true });
writeFileSync(`${PROFILE}.link`, invitation.link);
const joiner = spawn("bash", [DEVICE, PROFILE, "join", "Journey laptop"]);
let said = "";
joiner.stdout.on("data", (d) => (said += d));
joiner.stderr.on("data", (d) => (said += d));
const joined = new Promise((resolve) => joiner.on("exit", resolve));
pending = await until(() => control({ op: "pair_pending" }), 120_000, "laptop's join request", async () => console.log(said));
const laptopCode = await until(() => said.match(/\d{3}\s?\d{3}/)?.[0], 30_000, "laptop code");
if (digits(pending.code) !== digits(laptopCode)) throw new Error("The laptop's comparison codes differ");
await control({ op: "pair_approve", id: pending.id });
const exit = await Promise.race([joined, pause(120_000).then(() => "timeout")]);
if (exit !== 0) throw new Error(`The laptop's joining ended with ${exit}: ${said}`);
const status = await control({ op: "status" });
step(`Laptop joined; the node lists ${JSON.stringify(status.devices)}`);

mkdirSync(`${WORLD}/send`, { recursive: true });
const hash = createHash("sha256");
const out = openSync(SOURCE, "w");
for (let left = SEND_MB; left > 0; left -= 4) {
  const chunk = randomBytes(Math.min(left, 4) << 20);
  hash.update(chunk);
  writeSync(out, chunk);
}
closeSync(out);
const digest = hash.digest("hex");
// Its own process group, so stopping it stops the device too.
const receiver = spawn("bash", [DEVICE, PROFILE, "receive", RECEIVED, "Journey phone"], { detached: true });
let heard = "";
receiver.stdout.on("data", (d) => (heard += d));
receiver.stderr.on("data", (d) => (heard += d));
const stopReceiver = () => { try { process.kill(-receiver.pid, "SIGTERM"); } catch { /* already stopped */ } };
const SEND = `[aria-label="Send a file to Journey laptop"]`;
try {
  await until(() => /Receiving in/.test(heard) || receiver.exitCode !== null, 90_000, "laptop receiving");
  if (receiver.exitCode !== null) throw new Error(`The laptop does not receive: ${heard}`);
  await until(() => app.visible(SEND), 120_000, "laptop's inbox listed on the phone", async () => {
    const seen = await app.js(`return window.__TAURI_INTERNALS__.invoke("home_status").then(
      (s) => JSON.stringify({ spaces: s.spaces, listed: document.querySelector("#library-count")?.innerText }), (e) => String(e))`).catch((e) => String(e));
    console.log(`         laptop: ${heard.trim()}\n         phone sees: ${seen}`);
  });
  step(`The laptop receives files; the phone sends ${NAME} (${SEND_MB} MB)`);

  // 3. The phone sends it and Android stops the app partway. The debug test
  // build takes the file placed in its cache instead of the system picker.
  adb("push", SOURCE, `/data/local/tmp/${NAME}`);
  adb("shell", `cat /data/local/tmp/${NAME} | run-as ${PACKAGE} sh -c 'mkdir -p cache/connect-test-pick && cat > cache/connect-test-pick/${NAME}'; rm /data/local/tmp/${NAME}`);
  const placed = Number(inApp(`stat -c %s cache/connect-test-pick/${NAME}`).trim());
  if (placed !== SEND_MB << 20) throw new Error(`The placed file has ${placed} bytes`);
  await until(() => app.idle(), 30_000, "send ready");
  await app.click(SEND);
  const partway = (text) => {
    const prefix = `${NAME} to Journey laptop: `;
    return text.startsWith(prefix) && /^[\d.]+ [KMG]B of /.test(text.slice(prefix.length));
  };
  await until(async () => partway((await app.text("#home-message")) ?? ""), 180_000, "send under way");
  step(`Stopping the app while sending: ${await app.text("#home-message")}`);
  await screenshot("4-sending");
  stop(app);
  const kept = keeps();
  step(`Stopped; the phone kept ${JSON.stringify(kept)}`);
  if (!kept.includes("cache/connect-sends/send.json") || !kept.some((f) => f.startsWith("cache/connect-picked/picked-")))
    throw new Error("The phone did not keep the send and its copy");

  // 4. Open again: the unfinished send is shown and continues.
  app = await open();
  await until(() => app.visible("#workspace"), 120_000, "network reopened");
  await until(() => app.visible("#unfinished-send"), 60_000, "unfinished send shown");
  const card = await app.text("#unfinished-send-detail");
  step(`Reopened: ${await app.text("#unfinished-send-title")}: ${card}`);
  if (!card.startsWith("Connect closed before it finished.") || !/(at least [\d.]+ [KMG]B of [\d.]+ MB arrived|may have arrived)/.test(card))
    throw new Error(`The unfinished send says: ${card}`);
  await screenshot("5-unfinished-send");
  await until(() => app.idle(), 30_000, "continue ready");
  await app.click("#resume-send");
  const sent = `${NAME} to Journey laptop: Sent · saved as ${NAME}`;
  let shownBefore = "", progress = 0;
  await until(async () => {
    const [shown, error] = await app.js(`return [document.querySelector('#home-message').innerText,
      document.querySelector('#last-error-detail').textContent]`);
    const moving = / of [\d.]+ MB$/.test(shown);
    if (`${shown}|${error}` !== shownBefore && (!moving || progress++ === 0)) console.log(`         screen: ${shown}${error ? ` (problem: ${error})` : ""}`);
    shownBefore = `${shown}|${error}`;
    return shown === sent;
  }, 900_000, "send finished");
  step(`Continued: ${sent}`);
  const arrived = readdirSync(RECEIVED);
  const got = createHash("sha256").update(readFileSync(`${RECEIVED}/${NAME}`)).digest("hex");
  if (got !== digest || arrived.length !== 1)
    throw new Error(`The laptop received ${JSON.stringify(arrived)}, sha256 ${got}, expected one ${NAME}, sha256 ${digest}`);
  await until(async () => !(await app.visible("#unfinished-send")), 30_000, "unfinished send gone");
  step("Received whole and once: the same sha256, no second copy");
  const left = keeps();
  if (left.length) throw new Error(`The phone still keeps ${JSON.stringify(left)}`);
  step("The phone's copy and send record are gone");
  await screenshot("6-sent");
} finally {
  stopReceiver();
}

// 5. Stopped and opened once more: the same network, without Welcome.
stop(app);
app = await open();
await until(() => app.visible("#workspace"), 120_000, "network reopened");
if (await app.visible("#welcome")) throw new Error("Welcome shown after a restart");
step("Reopened after another stop");
await screenshot("7-reopened");
app.detach();
console.log("Android emulator journey passed.");
