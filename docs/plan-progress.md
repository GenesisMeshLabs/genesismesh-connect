# Developer-plan alignment

The supplied 5 November 2026 plan remains the full programme: supported public
core outcomes, understandable manual workflows and optional assistance through
the same typed authorization path. It includes CLI/Python-only capabilities.
The latest supplied attachment matches the retained `temp/connect-developer-plan.md`.

The inventory maps 419 public declarations to 25 journeys. These are overlapping
declarations, not 419 user features. No complete outcome has passed every
manual/assisted/platform acceptance gate; no parity percentage is claimed.

| Ticket | Implemented foundation / existing workflow | Remaining product acceptance |
| --- | --- | --- |
| CONNECT-01 coverage | Reviewed immutable inventory, pin qualification, drift and false-acceptance checks | Hosted CI execution and continued release/platform qualification |
| CONNECT-02 typed operations | Closed resource/local-history registry, generated schemas, exact access review | General core outcome schemas and manual/assisted parity |
| CONNECT-03 durable workflows | Access dispatch/readback journal, archives; owner nonce reservations | Durable join/renewal/recovery/admin enrollment and operation-specific reconciliation |
| CONNECT-04 prerequisites | Authenticated resource-host release/profile/ownership discovery | General feature, verifier, actor and deployment discovery |
| CONNECT-05 owner Requests | Explicit pairing-only enrollment/signature/replay contract; separate native key custody and controller preparation | Owner transport, fixed core/target dispatch, explicit enrollment/revocation UI, usable phone Requests and recovery |
| CONNECT-06 lifecycle | Existing disconnect/reconnect/leave; administrative native-store refusal and cleanup | Physical lock/suspend/force-quit/reboot/network switching and user-presence handling |
| CONNECT-07 distribution/hosting | Existing Tauri packaging and headless Linux server | Signed fresh-machine installer/update/service/uninstall acceptance and guided host setup |
| CONNECT-08 continuity | Existing encrypted recovery and server restore | Checkpoints, missing-history reconciliation, restricted restore and old-host fencing |
| CONNECT-09 agents | Existing member/edge mechanisms | Generic agent onboarding, separate identities/descriptors, allowed/refused real operations and independent revocation |
| CONNECT-10 general policies | Resource recipients/expiry/size/duration and extra gates | Visual general policy templates/selectors/gates, impact preview and semantic round-trip |
| CONNECT-11 Activity/evidence | Ordinary local access history, attention filtering, status readback and unsigned record export | Core signed evidence timeline/audit packs/independent verification and execution attribution |
| CONNECT-12 assistance | Shared typed operation boundary; no model configured or enabled | Opt-in constrained assistance using the exact manual review/authorization/dispatch path and privacy controls |

The remaining programme also includes attestations, agreements/delegation,
federation/trust paths, remediation/oversight, offline grants, data governance,
invocation/freshness, selective disclosure/integrity, interop, fleets,
succession/HA and exit. The [complete journey mapping](../contract/connect-journeys.json)
retains their scope and acceptance gaps. Core remains responsible for trust and
policy semantics; Connect supplies the usable workflows and fixed adapters.

## Next user-visible acceptance milestone

**“Use my phone to review and approve a new device joining my network.”**

An existing member explicitly requests limited administration; the host owner
reviews the exact device, permissions, duration and consequences. Only then may
the phone see the permitted pairing queue over separately authenticated host
control. It compares the actual candidate's code, reviews membership effects,
confirms one exact request, and sees a verified result or explicit uncertainty.
No public-key copying, terminal command, raw JSON or model is required.

Acceptance must cover an ordinary member's refusal, changed targets or scope,
revoked/expired credentials, replay, interrupted approval, lost replies and
restart. The host still checks actual core role/key tier and current pending
target. A model may propose the same operation only after the manual flow exists;
it receives no separate privilege. Native custody alone does not complete this
journey or justify enabling a phone's administrator button.

Each delivery records code, automated/core integration, native build,
installation, physical lifecycle and first-time usability as separate facts.
Current Windows Application Control and unperformed mobile/signing/device gates
remain explicit. A compiled adapter or signed intent is not evidence that a
nontechnical person completed the installed-app workflow.
