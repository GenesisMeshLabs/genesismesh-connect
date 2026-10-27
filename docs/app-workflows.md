# Connect app workflows

These are the technical controls retained under Settings → Advanced tools.
For ordinary setup and browsing, use the [everyday workflow](everyday-workflow.md).

The app is a device workspace. Rust owns device keys, certificate validation,
trust refresh and authority decisions. The interface displays these results.

## Devices

Create an identity with the network name and root public key supplied directly
by the operator. Select a local authority or configure a desktop bridge in
Trust & policies. Copy the new device's public key to obtain a bound invite,
then join as a client or as a sharing host with a local edge invite.

Give peer public keys recognizable names. References persist locally, are
separated by both network name and pinned root, and store only names/public
keys. They are an address book, not an authority device registry. Forgetting
a reference does not revoke it. Selecting a saved reference only fills the
expected public key; Rust still authenticates the peer on connection.

Start a secure session on both enrolled devices, open Exchange connection
tickets, and copy/paste the current tickets. Send a message or open Files.
Session-ready means the local endpoint and trust are ready for that selected
peer; only a confirmed operation proves an authenticated remote exchange.
Authenticated sessions currently use the local network. Public relay mode is
currently a separate transport diagnostic.

## Files

Start a secure session and add the host's session ticket in Devices first.
Enter a known collection and flat file name; optionally require a particular
SHA-256 version. Each read needs a live authority decision. The client checks
the payload digest and the host's signed confirmation before displaying a
verified result with its receipt ID. A late failure can follow released bytes;
an unconfirmed read is not presented as proof of zero-byte delivery.

An edge-enrolled host can configure one collection in Files while stopped.
The operator supplies the required policy and host attestation. Reads are
limited to flat files up to 64 KiB. Collection configuration resets on restart.
Folder browsing, binary export and resumable large transfers are not exposed.

## Trust & policies

Inspect the enrolled certificate, expiry, pinned network root, last accepted
trust update, revocation list sequence and authority key sequence. Checkpoint
metadata describes the last verified update; it never replaces current trust
validation. Refresh trust explicitly to check current authority state.

The policy card shows the host's actual configured collection, required policy
ID and attestation ID. It does not imply that every peer or file is allowed.
Remote hosts apply their own policy on each request. Policy authoring, network
policy lists and device revocation remain authority/operator functions.

## Activity

Actions in this app session report completion or an unconfirmed failure.
Successful reads reference the client-verified receipt. The view holds at most
50 events in memory, with filtering for completed actions or failures. Invites,
tickets, private keys, message text and file contents are excluded. This is not
a persisted authority audit log; signed read evidence remains on the host.

## Connection check and platform status

Connection check works independently of enrollment. Its result shows the
selected path, round-trip time and matched byte count; technical JSON remains
available in a disclosure. Public mode may upgrade to direct. A successful
echo proves connectivity, not Genesis Mesh authentication or permission.

Windows supports the enrolled workflows above. Apple Keychain storage and
physical iPhone protected-read acceptance remain pending. The shared interface
and official Genesis Mesh icons were built, signed, installed and launched on
the physical iPhone as version 0.1.0, build 2, on 2026-10-26. This updates the
phone UI and connection checks; enrolled iPhone workflows remain pending.
