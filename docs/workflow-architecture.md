# Guided Genesis Mesh workflows

Connect's implementation programme covers the complete public-core outcome set,
including CLI/Python-only workflows. Delivery is phased. The
[capability report](capability-coverage.md) records all classified journeys;
neither an entry in that inventory nor this architecture enables an operation.
The implementation plan supplied on 5 November 2026 is retained locally under
ignored `temp/`. The current phase establishes compatibility, coverage and
workflow boundaries before adding general administration.

## Existing boundary and target boundary

Today, Rust holds device identity, protected storage, Iroh authentication and
typed app commands. The inherited-pipe Python sidecar exposes a fixed owner
operation set and calls the real core. The frontend never receives root or
operator private keys. Existing resource policies are enforced by the authority
and the sharing endpoint, not by a hidden frontend control.

The next operation registry extends those boundaries; it is not an arbitrary
HTTP proxy, shell runner or a replacement policy engine. An assistant and the
manual UI must invoke exactly the same typed operations. The existing MCP
adapter is a schema/workflow reference, not an already-qualified multi-owner
Connect administration service. No model, external metadata transmission or
general MCP administration is enabled by this phase.

| Actor or key | Boundary |
| --- | --- |
| Ordinary member/device | Membership and access to resources explicitly granted to that identity; membership never implies ownership |
| Independent agent/executor | Its own identity and bounded operation/resource scope; no reuse of a human operator credential |
| Owner device | A future separately enrolled administrative relationship; ordinary pairing approval does not establish it |
| Online authority/operator | Core checks operation-specific role, key tier and current policy before mutation |
| Independent approver | Core-supported distinct holder/approval requirements; a second tap by the same holder is not independent approval |
| Offline sovereign root | Rare explicit signing ceremonies; never an assistant credential or a generic remote-owner request |

Remote owner administration needs its own versioned, authenticated protocol. The
current fixed authority bridge is not permission to send owner operations from a
phone. This phase does not broaden that bridge or change root custody.

The [owner-control contract](owner-control-contract.md) now implements the first
portable enrollment/signature/replay boundary for pairing-only administration.
It remains deliberately unexposed until native custody, authenticated transport,
fixed adapter enforcement, Requests UX and recovery are qualified. It is not a
new core operator role or a general administrator workflow.

## Common journey

Every supported journey must resolve intent, verified context, meaningful
choices, exact-scope preview, required approval, typed execution, authoritative
verification and a recoverable outcome. Keys, CRLs and signed JSON remain
details; normal users see the network, actor, target, duration and consequences.

The proposed operation envelope carries:

- A stable operation type and schema version; bounded, operation-specific input.
- Operation ID, pinned network/root, authenticated actor and execution audience.
- Target identifiers resolved from verified state, never invented by the model.
- Relevant policy/state versions and operation-specific preconditions.
- Expiry, nonce and immutable digest over the complete canonical intent.
- Approval references bound to that digest, actor/audience and expiry.
- Authoritative result and original evidence references, plus verification state.

Immediately before mutation, native/host code must recheck current actor rights,
features, versions, targets and preconditions. A changed recipient, resource,
limit or policy invalidates approval. Untrusted imported artifacts and agent
messages cannot authorize execution. The registry must not accept arbitrary
routes, authority URLs, filesystem/key paths, executables or raw admin payloads.

Each operation needs an explicit read/write/sign/provision/maintenance class,
actor/key tier, input and result schema, preview semantics, retry contract,
reconciliation method and expected evidence. The upstream public inventory does
**not** supply complete HTTP/CLI input/output schemas; those remain work for
CONNECT-02 and cannot be inferred from a route name.

Preview must say whether it is a local explanation, a real authority evaluation
that creates records, or an actual side-effect-free core preview. A policy
evaluation is not automatically a harmless simulation.

## Durable state and uncertainty

The proposed journal stores an intent before dispatch, preserving its identity
across restart. The workflow stage and authorization/execution result are
separate facts:

| Fact | Examples |
| --- | --- |
| Workflow stage | draft, awaiting approval, approved, submitted, reconciled, cancelled |
| Authorization | not evaluated, allowed, denied, expired |
| Execution | not submitted, started, completed, failed, cancelled, unknown |
| Evidence | not expected, pending, received, independently verified, refused |

An allowed decision can coexist with execution **unknown**. A receipt may prove
authorization without proving downstream success. Connect-specific transfer
receipts must retain their claim types; they are not silently converted to core
ResourceChangeRecords or audit packs.

After a request may have reached an authority/controller, timeout or a lost
reply is uncertain. Retry only after operation-specific readback, an actual core
idempotency contract or proof that dispatch did not happen. Generating a UUID
does not create exactly-once execution. Cancellation likewise must report
whether it prevented dispatch, stopped execution or arrived after effects.

Safe reads may use bounded backoff. No blanket mutation retry or automatic
emergency fallback is permitted. Existing Connect sharing remains live-required;
future grants are a separate explicit workflow with their actual expiry,
budget, time-token and revocation assumptions. SDK and edge fallback semantics
must be preserved separately, never flattened into an invented offline allow.

## Prerequisites and execution adapters

CONNECT-04 must discover authority version, operation support, feature flags,
verifier/artifact compatibility, deployment profile and current actor permission.
The build inventory is not authenticated runtime discovery. Until a feature's
prerequisites can be established, it must remain unavailable with a precise
explanation; a hidden button is not authorization enforcement.

Each new external domain needs an adapter that enforces the decision at the
actual resource/tool boundary and reports actual outcomes. Registration,
discovery and a TCP connection grant do not provide per-tool control. Desktop
provisioning, agent invocation and compute isolation/scheduling remain explicit
future adapter work, with reused execution technologies rather than a new core
scheduler. Remote hosts may inspect plaintext unless separately verified
confidential-computing mechanisms apply.

Phone management targets an existing supported desktop/NAS/server first.
On-phone authority runtime work is separate; mobile lifecycle and notifications
do not promise continuous hosting. Migration/recovery must preserve keys and
pins, identify missing history and fence old hosts before claiming continuity.

## Acceptance and next implementation slices

| Slice | Current result / remaining gate |
| --- | --- |
| CONNECT-01 coverage and version inventory | Implemented; reviewed immutable snapshot, complete public declaration mapping, drift checks and CI definition |
| Dependency qualification | Real-core Windows owner tests and Linux QUIC/authority checks pass; full Windows native gate blocked by Application Control; other platforms remain separate |
| CONNECT-02 typed operation registry and exact-intent preview | Closed resource operation registry, generated value schemas and access review/commit implemented; broad core operations and assisted coverage remain planned |
| CONNECT-03 durable journal | Access-update dispatch/crash/readback journal implemented; enrollment, recovery and general workflows remain planned |
| CONNECT-04 runtime prerequisite discovery | Authenticated local/remote resource-host release/profile/ownership/operation discovery implemented; arbitrary external authorities and general owner/agent roles remain planned |
| CONNECT-05 owner-device control and Requests | Portable explicit enrollment, separate-key proofs, exact pairing targets and durable nonce reservation implemented; native custody, owner transport, fixed dispatch, Requests and physical acceptance remain planned |
| CONNECT-11 Activity / Evidence | Ordinary device-local access history, archived records, eligible read-only reconciliation and unsigned JSON export implemented; general signed audit-pack inspection/verification remains planned |
| Later phases | All agents, policies, federation, oversight, evidence, offline and operations outcomes remain visible in the reviewed mapping |

For every implemented slice, retain denial, expiry, replay, changed intent,
wrong actor/root, conflicting versions, lost replies, restart and actual effect
measurements. Run a real disposable authority/controller; a mock acknowledgement
is not execution evidence. Keep compiled, installed, launched, physically tested
and usable-by-a-first-time-person results distinct. Missing Mac/phone access or
security-policy blocks are explicit unperformed gates, never passes.

See the [access workflow and its precise verification limits](access-workflow.md)
for the first implemented execution slice. This does not complete CONNECT-02,
CONNECT-03 or CONNECT-04 for the whole public-core surface.

An independent operator and a separately implemented authority are distinct
federation acceptance milestones. Neither same-host tests nor two authorities
operated by the maintainer establish production federation or million-user scale.
