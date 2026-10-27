# Join through a desktop

A new Windows device can enroll over Iroh without a local authority process.
Its node key stays in that device's account-protected vault. The host forwards a
node-signed join to its own loopback authority after proving its enrolled identity
and verifying the selected client's connection proof.

## Operator and device workflow

1. On the new device, select **Use another desktop**. Enter the network name and
   root public key obtained directly from the operator, then **Prepare device**.
   This saves a durable node key before any invitation is used. No local HTTP
   origin is configured.
2. Give the displayed **Node public key** to the desktop operator. On the enrolled
   desktop, select that exact key as the other device and **Start session**. The
   new device does not need a certificate for the host to select it.
3. The operator supplies the desktop's node public key, its **authority ticket**
   and a single-use invitation bound to the new device's public key. The invitation
   comes from the authority's existing signed admin workflow, outside Connect.
4. On the new device, expand **Authority connection**, enter the desktop key and
   authority ticket, and select **Set desktop connection**. These are explicit
   pins supplied by the operator; saving them does not assert successful host
   verification yet. Paste the invitation and select **Enroll device**.
5. Connect verifies the signed public trust records against the pinned root, then
   verifies the desktop's certificate and connection proof before sending the
   invitation. The desktop verifies possession of the selected node key. The NA
   verifies the unchanged signed join and invitation binding and assigns roles.
6. After the verified certificate is saved, choose the desktop's node public key,
   start the client session and exchange **session tickets** for a diagnostic
   message. Subsequent trust refresh and renewal use the saved desktop route.

The authority ticket and session ticket serve different protocols. A host restart
creates a new authority ticket; update it while the client session is stopped.
Remote-only profiles cannot switch to an unconfigured local authority. Existing
local profiles continue to open with the same identity and optional bridge route.

## Enrollment scope and proof

Enrollment uses the separate ALPN `genesismesh-connect/enroll/1`. The client's
bounded hello carries its node public key, actual Iroh endpoint ID, network/root
pins and a fresh challenge. It carries no invitation or certificate.

The desktop checks that hello against its selected node, actual transport peer
and pinned network. It sends its certificate, endpoint ID, challenge and a
node-signed proof. The client verifies the expected desktop node, certificate,
revocation/time/horizon, network/root and proof. It then proves possession of its
own node key. The transcript binds both endpoints/challenges, the client node key,
desktop certificate digest, signer role, network/root, protocol domain and the
connection's TLS exporter. Its domain is
`genesismesh-connect/enrollment-proof`; exporter label is
`EXPORTER-GenesisMesh-Connect-enrollment-v1`, with enrollment ALPN as context.

Only after these checks does the client send its SDK-signed `/join` body. The
bridge permits the exact enrollment fields, the selected node key, a nonempty
invite of at most 512 bytes, validity of 1–24 hours, a current timestamp, UUID v4
nonce and valid signature. It forwards only to `/join`, without modifying the
body or attaching operator credentials. Roles, URLs, methods, admin routes,
executor keys, extra fields and extra messages are refused. Edge enrollment is
outside this initial ordinary-node flow.

The host accepts at most three forwarded enrollment attempts per fixed minute,
within the shared bridge admission/concurrency budget and deadlines. The NA's
own invitation and per-address limits also apply. Signed, verified certificates
are persisted before the device can start diagnostic sessions. Enrollment itself
does not provide file or administrative access.

## Failure and validation limits

The pending marker is saved before enrollment is attempted. A lost response or
failed durable write may leave an invitation consumed; Connect keeps the same
node key and does not retry the join automatically. Ask the operator to inspect
the outcome before providing a new invitation. Automatic recovery of the lost
certificate, profile reset and expired-device recovery remain separate work.
Core also refuses joining with a node key marked compromised; the bridge does
not bypass that policy.

The Windows tests use the real authority and separate profiles on one host. They
cover no-local-authority preparation, wrong host and selected-node refusal,
wrong-recipient invites, single-use refusal, authority-assigned roles, enrollment,
persisted restart, authenticated diagnostics, subsequent renewal and host loss.
This establishes protocol/controller behavior, not a physical-device, cellular
or off-LAN result. Relays remain disabled for these authenticated endpoints.
Apple enrollment stays unavailable until Keychain storage and the iPhone build
are validated. The transport diagnostic remains independent.

Run the full Windows gate from the repository root:

```powershell
.\scripts\verify.ps1
```

It requires the core Python environment and stops on failed checks. The ignored
`temp/verification/latest.json` records the result; blocked or ignored tests do
not count as passing.
