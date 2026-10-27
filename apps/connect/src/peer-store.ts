// A local address book of public keys and labels, never a source of trust.
export interface Peer {
  name: string;
  node: string;
}
export interface PeerScope {
  network: string;
  root: string;
}
export interface PeerStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}
export function validNode(node: string): boolean {
  try {
    return (
      /^[A-Za-z0-9+/]{43}=$/.test(node) &&
      atob(node).length === 32 &&
      btoa(atob(node)) === node
    );
  } catch {
    return false;
  }
}
function storageKey(scope: PeerScope) {
  if (!scope.network || !validNode(scope.root))
    throw new Error("A pinned network is required before saving devices.");
  return (
    "genesismesh.connect.peers.v1:" +
    JSON.stringify([scope.network, scope.root])
  );
}
function validate(peer: Peer) {
  if (
    !peer ||
    typeof peer.name !== "string" ||
    !peer.name.trim() ||
    peer.name.length > 64 ||
    !validNode(peer.node)
  )
    throw new Error("Enter a name and a valid 32-byte node public key.");
}
export function loadPeers(storage: PeerStorage, scope: PeerScope): Peer[] {
  const raw = storage.getItem(storageKey(scope));
  if (raw === null) return [];
  if (raw.length > 16 * 1024)
    throw new Error("Saved device references are too large.");
  const data = JSON.parse(raw) as { version: number; peers: Peer[] };
  if (
    data.version !== 1 ||
    !Array.isArray(data.peers) ||
    data.peers.length > 32
  )
    throw new Error("Saved device references need attention.");
  data.peers.forEach(validate);
  if (new Set(data.peers.map((p) => p.node)).size !== data.peers.length)
    throw new Error("Duplicate saved public keys need attention.");
  return data.peers.map((p) => ({ name: p.name, node: p.node }));
}
export function savePeer(
  storage: PeerStorage,
  scope: PeerScope,
  peer: Peer,
  ownNode: string,
): Peer[] {
  validate(peer);
  if (peer.node === ownNode)
    throw new Error(
      "Save your other device's public key, not this device's key.",
    );
  const peers = loadPeers(storage, scope);
  const index = peers.findIndex((p) => p.node === peer.node);
  const value = { name: peer.name.trim(), node: peer.node };
  if (index >= 0) peers[index] = value;
  else {
    if (peers.length >= 32)
      throw new Error("The address book holds up to 32 devices.");
    peers.push(value);
  }
  storage.setItem(storageKey(scope), JSON.stringify({ version: 1, peers }));
  return peers;
}
export function removePeer(
  storage: PeerStorage,
  scope: PeerScope,
  node: string,
): Peer[] {
  const peers = loadPeers(storage, scope).filter((p) => p.node !== node);
  storage.setItem(storageKey(scope), JSON.stringify({ version: 1, peers }));
  return peers;
}
