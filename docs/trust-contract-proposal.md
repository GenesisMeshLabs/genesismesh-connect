# Connect and radio: trust contract proposal

Status: **proposal, not an agreed or implemented common protocol**. Reviewed
2026-10-25 against the local Connect implementation and radio main
`74f8b955c7d3d934fc17452896dc6399598d45b5`, including the existing Codex chat
“Explain Meshtastic in GenesisMesh”. These are separate applications. This
comparison does not establish that duplication is resolved or authorize a broad
refactor.

The radio track completed its parallel review and wrote
`genesismesh-radio/.local/connect-radio-contract-proposal.json` with status
`proposal_not_adopted`. This Connect review read that draft too: the ownership,
offline/retry differences and evidence qualifications align. The proposed
destination is one core/SDK-owned specification and shared conformance vectors,
with these application drafts retained as review inputs until adoption. No
mutual adoption or common implementation is claimed.

## Ownership

| Owner | Responsibility |
| --- | --- |
| Genesis Mesh core, existing edge agent and SDK maintainers | Canonical Genesis Mesh records, signatures, certificate/attestation/grant validation, authority key succession and vouching, revocation, policy evaluation and core execution evidence |
| Connect | Windows/mobile lifecycle, platform key stores, Iroh connection proof, desktop authority forwarding, client connectivity and future tunneling, confined file access and read acceptance |
| Radio | Constrained Rust device state machine, RAK4631 firmware, device MAC profile, radio adapters, replay counters, trusted-time and persistence integration, RF and hardware acceptance |
| Joint contract review | Typed identity/provenance, scope/deadline terminology, refusal and uncertainty rules, recovery obligations and cross-adapter conformance scenarios |

Neither application should copy the core's policy engine, cryptographic verifier
or grant accounting rules. Connect already calls SDK v1.8.1; radio's Python bridge
calls the existing `genesis-mesh-edge` Rust agent from `sdk-rust/edge` through its
local API. The allocation-free radio device library depends
on HMAC/SHA-256, not the full SDK. No shared cross-application Rust crate was found
or is assumed suitable for that device.

## What exists, what overlaps

| Concern | Connect today | Radio today | Reuse or difference |
| --- | --- | --- | --- |
| Identity | Root-pinned join certificate and node Ed25519 key; separate Iroh transport key; edge host has a separate executor key | Enrolled edge bridge; provisioned numeric device ID, route, audience and per-device shared MAC key | Common identity/provenance vocabulary; a MAC-authenticated device is not a certified Genesis Mesh node |
| Signed requests | SDK canonical node requests with timestamp/nonce; SDK executor proof for host enrollment; channel-bound node signatures for sessions | Local authenticated edge API, whose existing edge agent handles authority requests; compact direction-bound HMAC frames at the radio device | Reuse core signing/verification through existing APIs; retain different wire profiles |
| Scope | `connect.collection.read`; host attestation, required policy, peer, collection, filename, size and snapshot digest | `radio.command.dispatch`; edge resource/action and bounded interval; device independently checks its configured local bounds | Shared exact-intent rule; separate capabilities and resource semantics |
| Expiry | Certificate, trust, attestation and decision validity; five-second decision freshness/release policy | Edge decides permission; radio TTL bounds action-call start; `report_by` only bounds reporting | Distinct permission, execution-start, reporting and transport deadlines; never substitute one for another |
| Revocation/offline | Fresh live decision for each read; no offline fallback; signed CRL/history and recent certificates | Existing edge agent may consume a scoped offline grant; device does not independently verify Genesis Mesh grants/revocations | Common explicit offline-mode declaration, different current guarantees |
| Replay/idempotency | TLS-exporter-bound challenges stop proof replay; request UUID is correlation, not a durable result ledger; each read reauthorizes | Directional durable counters; service request-ID journal detects conflicting reuse; no automatic actuation redispatch | Shared scenarios, not one counter or nonce algorithm |
| Recovery | DPAPI identity persists; missing/corrupt state refuses; uncertain invite consumption and lost read confirmation remain limitations | Durable intent/result state; interrupted physical commands stay uncertain; outcome/report retry differs from action retry | Both must preserve uncertainty and avoid silent identity/security-state reset |
| Evidence | Node-signed `prepared` and `client_verified` read receipts with authority decision and client acknowledgment | Core execution evidence through edge; bridge statement about an authenticated shared-key MAC outcome | Preserve claim type and signer; MAC outcome is not an independent device signature; transport ACK is not execution |

Potential duplicated infrastructure includes strict bounded HTTP/JSON handling,
loopback-only endpoints, private storage ownership, atomic state replacement,
freshness/time checks and conservative recovery bookkeeping. Some of this is
deliberate adapter defense: Connect talks to an NA and handles invites; radio
talks to a bearer/Unix-socket edge API and physical commands. Similar code does
not prove equivalent semantics or justify sharing it unchanged.

There is a more substantial host-side overlap with `sdk-rust/edge`: Connect
orchestrates enrollment, renewal, verified trust refresh and durable checkpoints,
while the existing agent also adopts credentials, verifies key history and CRLs,
refreshes/renews and maintains grant/evidence state. That agent is currently a
binary with its own state/API implementation, not a ready-made portable
Connect/device library. Its Linux storage/service assumptions and Connect's
Windows DPAPI/Iroh/mobile lifecycle must be compared before extracting a host
identity/trust component or choosing to use the service. This overlap remains
open; using the same SDK verifier does not resolve duplicated lifecycle code.

App-specific checks around SDK results are also present in Connect (selected
peer, required policy, context commitment, local freshness bounds). Review them
against SDK conformance tests before extracting anything. Radio intentionally
does not rebuild those rules in its bridge or microcontroller.

## Proposed reusable contract: governed operation, version 1

Reuse one **semantic contract and conformance suite**, with separate encodings
and transport/device adapters. This is an application integration contract;
existing Genesis Mesh records remain authoritative. The following are proposed
obligations, not claims that both applications already implement them all.

1. **Name the trust boundary and identity class.** Bind a request to the pinned
   network/root or provisioned deployment, intended audience, authenticated actor,
   subject/resource, adapter profile and direction. Carry the authentication
   class: certified node, local enrolled bridge, or device authenticated by a
   shared MAC. A route, relay, channel membership or endpoint ticket is not
   service permission. Never relabel a bridge's observation as a device signature.
2. **Bind exact intent.** Correlate capability, resource/action, policy parameters,
   relevant immutable version/digest and operation ID. Rich hosts use core/SDK
   canonical records; compact devices use their documented domain-separated
   authenticated bytes. Cross-profile vectors demonstrate the intended mapping;
   a lossy encoding must not widen scope. Connect's context_id commits its intent,
   but it does not reconstruct the NA's ContextRecord/context_digest.
3. **Keep deadlines typed.** Represent permission validity, execution-start
   deadline, outcome-report deadline and transport timeout separately. Apply the
   applicable strictest bound at the correct boundary. Missing execution-time
   permission data means that guarantee is unavailable, not that `report_by` can
   supply it. Local safety limits may narrow an authority decision, never widen it.
4. **Make offline operation explicit.** A live-required profile refuses authority
   loss. An offline profile must consume an actual core-issued scoped grant via
   the existing grant holder/edge agent, within its limits. Declare the remaining
   revocation exposure and trusted-clock/rollback assumptions. No automatic
   break-glass, cached generic allow or transport-level permission substitute.
5. **Separate replay, request deduplication and retry.** Authenticate before
   accepting replay state; persist outbound counters/intent before irreversible
   effects where required. Reusing an operation ID with changed intent must be
   refused by an adapter claiming idempotency. A lost result must not trigger
   automatic physical redispatch. A read retry needs a fresh authorization and
   version check; Connect currently has no durable request-ID/result lookup.
6. **Fail before protected release when admission fails.** Refused Connect reads
   release zero file payload bytes; refused radio dispatch sends no actionable
   command. This does not promise zero network traffic, nor recall bytes or
   commands already sent. After interruption, record the stage actually reached.
7. **Distinguish observations from outcomes.** Keep authorization, preparation,
   dispatch, observed device result, client-verified bytes, and uncertainty as
   separate claims with a bound intent/authorization reference, signer and
   observation time. Existing core evidence is used where its schema fits;
   application receipts remain labeled as such. Never turn a transport ACK,
   timeout, reporting queue acceptance or lost confirmation into success.
8. **Recover without erasing trust.** Missing/corrupt state, counter rollback,
   expired credentials and uncertain actions require explicit reconciliation.
   Preserve device identity and durable watermarks. A receipt/report retry can
   reuse its original operation without rerunning the physical action. Whole
   storage rollback needs an external monotonic anchor where that threat matters.

A future normalized host-side operation/evidence view could expose these fields
for tooling, but it must retain the original signed/MAC records and provenance.
It would not become another authority or force certificates into 51-byte frames.

## Separate adapters

- **Connect adapter:** Iroh/QUIC endpoint and exporter binding, certified-node
  proof, platform vault, SDK verifier and local/bridged lifecycle calls, live
  read authorization, filesystem snapshot and Connect receipts. Tunneling remains
  future product work, not an implemented VPN claim.
- **Radio host adapter:** existing edge authorize/outcome API, durable SQLite
  intent/counters, source-to-resource mapping, exact command/result correlation
  and delayed evidence synchronization.
- **Constrained device adapter:** allocation-free framing, provisioned MAC key,
  local bounds, trusted clock, replay state, atomic durable acceptance, actuator
  and transport traits. RAK4631 FRAM/RTC/bootloader and power-loss behavior need
  actual board tests.
- **Radio transport adapters remain distinct:** Meshtastic application payloads
  through its USB/serial API; custom LoRa modem framing and its radio stack; and
  LoRaWAN FPort/MQTT through TTS with its own joins, network counters, receive
  windows and payload budgets. These are not interchangeable wire protocols.

## Decisions still open

1. Approve this semantic contract and nominate a canonical cross-repository home
   plus a versioned conformance-vector owner. Keep this as a draft until both
   tracks and core maintainers review it; two similar documents do not resolve
   duplication.
2. Core/edge must define any execution-time delegated authority/deadline needed
   by offline radio devices. Current radio authorization is for dispatch. Moving
   certificate/grant verification onto the device is a separate size, crypto,
   time, revocation and key-protection feasibility decision.
3. Decide whether and how core should ingest read receipts or represent reads.
   Connect must not invent a create/update ResourceChangeRecord for a read.
   Radio's shared-MAC outcome must keep its bridge-asserted provenance.
4. Specify Connect's lost-result lookup/idempotency and enrollment reconciliation
   before advertising those recovery guarantees. The radio journal is useful
   precedent, not an automatically reusable implementation.
5. Agree per-profile revocation/offline exposure budgets, clock assumptions and
   evidence retention/acknowledgment semantics. A common five-minute default
   would not establish equivalent protection across these devices.
6. Only then assess host implementation reuse (SDK wrappers, normalized evidence
   verification, vectors and the overlapping `sdk-rust/edge` lifecycle). Measure
   no_std, allocation, code size and platform
   dependencies before considering a constrained-device crate.
7. Add a negative conformance case for a genuine decision issued for a different
   capability/ContextRecord while an application supplies the same context_id
   commitment and policy ID. Core BoundaryDecision has no standalone capability
   field; capability belongs to ContextRecord, and SDK signature verification
   alone does not reconstruct that record. Connect currently forms the read
   request at its trusted host adapter and checks the signed intent commitment.
   Decide whether independent scope auditing requires returning/fetching and
   verifying the original core context. The radio review proposed this check;
   this turn did not reproduce a cross-capability exploit. Do not add an invented
   capability field to core decisions or a second application policy engine.

## Evidence inspected

Connect: `crates/connect-core/src/{authority,device,session}`, especially
`session/trust.rs`, `session/wire.rs` and `session/sharing/{mod,transfer}.rs`;
`tests/live_authority.rs`; SDK pin in `crates/connect-core/Cargo.toml`.

Radio: `src/genesismesh_radio/{edge,bridge,journal,protocol}.py`,
`firmware/rust/genesismesh-radio-device/{Cargo.toml,README.md}` and its device,
protocol and state modules; `docs/{architecture,protocol,rak4631-pilot}.md`.
Radio's AGENTS.md assigns core trust semantics to existing core/edge projects.

Existing host edge agent: `sdk-rust/edge/{Cargo.toml,src/agent.rs,src/state.rs,
src/api.rs}`; radio's `docs/live-lab.md` identifies the actual agent/verifier
binaries consumed by its real-service tests.

Software and physical acceptance remain distinct. Current Connect acceptance
and blockers are in [the two-device matrix](two-device-acceptance.md).
