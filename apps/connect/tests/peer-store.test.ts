import { test } from "node:test";
import assert from "node:assert/strict";
import {
  loadPeers,
  savePeer,
  removePeer,
  validNode,
} from "../src/peer-store.ts";
const key = (byte: number) =>
  btoa(String.fromCharCode(...new Array(32).fill(byte)));
const scope = { network: "Home", root: key(1) };
const storage = () => {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (name: string) => map.get(name) ?? null,
    setItem: (name: string, value: string) => {
      map.set(name, value);
    },
  };
};
test("public references are isolated by both network and pinned root", () => {
  const store = storage();
  savePeer(store, scope, { name: "NAS", node: key(2) }, key(3));
  assert.equal(loadPeers(store, scope)[0]!.name, "NAS");
  assert.deepEqual(loadPeers(store, { ...scope, root: key(4) }), []);
  assert.deepEqual(loadPeers(store, { ...scope, network: "Other" }), []);
});
test("rename preserves the public key and persistence excludes extra fields", () => {
  const store = storage();
  savePeer(
    store,
    scope,
    { name: "Old name", node: key(2), ticket: "must-not-persist" } as {
      name: string;
      node: string;
    },
    key(3),
  );
  savePeer(store, scope, { name: " Home NAS ", node: key(2) }, key(3));
  assert.deepEqual(loadPeers(store, scope), [
    { name: "Home NAS", node: key(2) },
  ]);
  assert.ok(![...store.map.values()].join().includes("must-not-persist"));
});
test("malformed and own-device keys cannot become saved references", () => {
  const store = storage();
  for (const node of [
    "invalid",
    key(2).slice(0, -1),
    btoa("short"),
    "A".repeat(44),
  ]) {
    assert.equal(validNode(node), false);
    assert.throws(() =>
      savePeer(store, scope, { name: "Invalid", node }, key(3)),
    );
  }
  assert.throws(() =>
    savePeer(store, scope, { name: "Self", node: key(3) }, key(3)),
  );
  assert.equal(store.map.size, 0);
});
test("a corrupt address book is preserved rather than silently overwritten", () => {
  const store = storage();
  savePeer(store, scope, { name: "NAS", node: key(2) }, key(3));
  const name = [...store.map.keys()][0]!;
  store.map.set(name, '{"version":99,"peers":[]}');
  assert.throws(() =>
    savePeer(store, scope, { name: "New", node: key(4) }, key(3)),
  );
  assert.equal(store.map.get(name), '{"version":99,"peers":[]}');
});
test("forgetting a reference does not remove other network references", () => {
  const store = storage();
  savePeer(store, scope, { name: "NAS", node: key(2) }, key(3));
  const other = { ...scope, root: key(4) };
  savePeer(store, other, { name: "Other", node: key(5) }, key(3));
  assert.deepEqual(removePeer(store, scope, key(2)), []);
  assert.equal(loadPeers(store, other).length, 1);
});
