> This page describes the retained legacy 64-KiB read protocol. The ordinary
> app now uses the metadata catalog and disk-backed downloads described in
> [everyday workflow](everyday-workflow.md). Mobile installation and physical
> large-file acceptance for the new update remain pending.

# One protected collection read

Connect can read a flat file of up to **64 KiB** from a dedicated folder on a
Windows sharing host. Every read requires a new authority decision and mutual
Genesis Mesh authentication over Iroh. The app previews UTF-8 text and reports
the verified digest and receipt ID. Binary data is verified in Rust but has no
export UI yet.

This is a Windows development milestone. Tests use separate identities on one
machine with the real native authority. Physical iPhone, off-LAN file access,
large files, resume, directory browsing and a background host remain pending.

## Operator setup

The sharing host needs an **edge enrollment**, because the authority's
`/node/boundary/evaluate` route accepts an enrolled edge identity. An ordinary
join certificate alone does not authorize this route. Clients can keep their
ordinary device enrollment.

Keep all operator keys and admin operations outside Connect. The test fixture
in `crates/connect-core/tests/support/na_fixture.py` demonstrates the actual
signed administration requests against a disposable authority:

1. Create a device-bound edge invite using `/admin/invite`. Set
   `recipient_public_key` to the host's displayed node key, assign its
   `node_sovereign_id` and an `executor_resource_prefix`, and choose its roles
   and certificate lifetime. Connect creates and protects the separate executor
   key and signs the edge enrollment proof itself.
2. Issue an attestation with `subject_id` equal to that edge sovereign,
   `subject_public_key` equal to the host node key, and
   `claims.capabilities` containing `connect.collection.read`.
3. Publish and activate a boundary policy selecting that capability. Allow only
   the chosen collection and authenticated peer, and set a maximum size. Give
   the host operator the attestation ID and required policy ID.

The fixture uses `boundary_policy_enforcement="required"`, `evidence_store="on"`
and `evidence_out_of_band="on"`. Configure the native authority's edge enrollment
and boundary routes accordingly; Connect does not change service settings.

For example, the gates inside a policy selecting `connect.collection.read` are:

```json
[
  {
    "gate_id": "collection", "gate_type": "allowlist.v1", "order": 0,
    "config": {"path": "request_parameters.collection_id", "values": ["notes"]}
  },
  {
    "gate_id": "peer", "gate_type": "allowlist.v1", "order": 1,
    "config": {"path": "request_parameters.peer_node", "values": ["CLIENT_NODE_PUBLIC_KEY"]}
  },
  {
    "gate_id": "size", "gate_type": "max_value.v1", "order": 2,
    "config": {"path": "request_parameters.size", "max": 65536}
  }
]
```

The host supplies `collection_id`, `file_name`, `peer_node`, `sha256` and `size`
in request parameters. `peer_node` comes from the authenticated session, and the
digest and size come from the host's captured bytes. A policy can restrict
filenames too. The host requests authority to release its data to that peer
under its own attestation; it does not impersonate the client at the authority.

## Use the Windows app

1. Follow [device setup](windows-device.md) with a native local authority. Before
   enrolling the host, select **Sharing host** in **Device role** and use the
   operator's edge invite. Existing ordinary profiles have no promotion/reset
   UI. Use a fresh development profile for a host; do not delete a real identity
   or consume more invitations as an attempted upgrade.
2. Enroll the client normally, locally or through the
   [desktop authority bridge](remote-enrollment.md). Confirm both node keys
   directly and select each other as the expected peer.
3. While the host session is stopped, expand **Share one collection**. Enter a
   collection ID such as `notes`, an absolute dedicated folder path, the host
   attestation ID and the required policy ID. Select **Configure sharing**.
4. Start both sessions and exchange their **session tickets**. Authority tickets
   are for lifecycle control, not file reads. The host currently needs its
   numeric-loopback authority and cannot use a bridge while sharing.
5. On the client, paste the host session ticket in **Other device's session
   ticket**. Expand **Read a protected file**, enter the collection ID and one
   filename, and select **Read file**. Supply an expected SHA-256 to refuse a
   changed version. The result appears only after digest and receipt checks.

Sharing configuration stays in memory. Stopping closes the serving endpoint;
restarting the app restores the host role and protected keys but leaves sessions
stopped and sharing disabled. Configure the collection explicitly again.

## Authorization and storage contract

Reads use their own `genesismesh-connect/read/1` ALPN, signed handshake domain
and TLS exporter label. The host advertises it only when sharing is configured.
The ordinary diagnostic protocol cannot request file access.

Before releasing any file bytes, the host refreshes verified key history and
CRL state, checks both certificates, captures a bounded file, obtains a live
decision, verifies its signatures and policy binding, then persists a prepared
receipt. The client independently verifies the decision and host receipt before
accepting payload chunks. An unavailable authority or receipt store refuses the
read; no cached allow decision or offline grant substitutes for it.

The authority-signed `context_id` is `connect-read:<canonical intent digest>`.
The intent includes the full request, both node keys, a host nonce, snapshot
SHA-256, size and required policy ID. Connect requires that exact commitment,
an authorized decision still within its validity and made less than five
seconds ago (give or take the five minutes a device's clock may differ from the
network computer's; the host nonce, not this window, stops replay), a currently
valid host-bound attestation, and the configured policy in a resolved policy
binding.
The authority computes its own ContextRecord digest; Connect does not reconstruct
that record or claim to recompute its `context_digest`.

File confinement uses a retained directory capability and opens relative to
that handle with final symlink following disabled. Names permit only ASCII
letters, digits, `.`, `_` and `-`, up to 128 characters. Traversal, subpaths,
Windows device names, alternate data streams and trailing dots are refused.
Only regular files with one hard link and at most 65,536 bytes are accepted.
An open shared file lock and before/after size and modification-time checks
guard capture; the resulting memory buffer is hashed and bound to the decision.
Locks are advisory on some platforms, so this is not a general atomic snapshot
guarantee against a hostile local writer. The dedicated folder and local OS
account remain trusted host configuration.

There is one active read per collection and at most 16 preparation attempts per
minute. Payload frames contain at most 8 KiB, with a five-second release window
after preparation, a 10-second connection timeout and a 20-second exchange
timeout after connection. Each chunk checks trust,
both certificates and decision expiry. Runtime credential refresh or suspension
cancels in-flight work. These limits do not promise instantaneous revocation:
revocation after a decision can race a short transfer, and bytes already queued
to the network cannot be recalled. No transfer resume is implemented.

The file capability and final no-follow behavior use
[cap-std](https://docs.rs/cap-std/4.0.3/cap_std/fs/struct.Dir.html) and
[cap-fs-ext](https://docs.rs/cap-fs-ext/4.0.3/cap_fs_ext/trait.OpenOptionsFollowExt.html).

## What the receipts prove

Connect stores signed evidence envelopes under the profile's
`sharing/receipts/`. Each contains the intent, authority decision, attestation,
both certificates and a host-signed receipt:

- `prepared`: the authorized snapshot was prepared for release and this receipt
  was saved before payload transmission. This does not prove delivery.
- `client_verified`: the certified client signed an acknowledgment binding the
  intent, prepared receipt, payload digest and byte count. The host verifies and
  saves it before returning confirmation. This records a client claim that its
  in-memory payload verification succeeded; it is not proof of a file saved to
  disk or a hardware attestation.

These are versioned **Connect receipts**, not core ResourceChangeRecords. Core's
resource-action enum has no read operation. Central receipt ingestion and retry
remain future work. The authority stores its evaluated decisions; requests
refused before evaluation, such as unknown collections, are not a complete
central denial audit.

Receipts contain filenames, identities and hashes, but no file contents. Treat
that metadata as private. Each shared folder keeps its receipts for 90 days,
the period devices keep their own history. Before each write it drops receipts
older than that and, if the store is still near its limits (2,048 entries,
32 MiB, 512 KiB per envelope), the oldest ones until 1,792 entries and 24 MiB
remain, so sharing never stops for lack of room. Preparation reserves space
for one maximum-size confirmation envelope. Copy receipts elsewhere if you
need them longer; keeping the full history on the network computer is part of
Activity. A failure after data
release can leave only a prepared receipt and return an unconfirmed read. It
does not mean that no bytes reached the client.

## Verification

Run `scripts/verify.ps1` from the repository root. It includes the real-authority
protected-read test, Windows host-role persistence test, default Rust tests,
Clippy, formatting and native/frontend build. The read integration test checks
text and a 64 KiB binary payload, verified receipts, changed-version refusal,
policy denial/reactivation, revoked attestation or selected-peer certificate,
authority outage and unavailable receipt storage. It also suspends a host while
the real authority decision is pending, checks zero file release, then requires
explicit refresh and a fresh authorized read for recovery. Denials before release
assert that the host's payload-byte counter did not increase. Unit checks cover
unsafe names, hard links, oversized files and receipt tampering. See the
[acceptance matrix](two-device-acceptance.md) for physical-device and active-transfer
checks still pending.
