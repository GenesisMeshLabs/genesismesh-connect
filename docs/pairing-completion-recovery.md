# Explicit pairing completion recovery

This is a native, qualification-only capability. The public app has no recovery
command or automatic startup action. Enable the core `pairing-completion-recovery`
feature only in qualification; the existing Android owner qualification feature
forwards that gate. Default builds refuse before recovery I/O.

An enrolled device can lose the final pairing reply while its host has already
saved the approved relationship. It must preserve its identity and enrollment.
Membership, a matching device name or a matching relationship alone cannot tell
it whether the original approval completed.

## Retained evidence

Qualified pairing explicitly negotiates completion-reference support. Ordinary
pairing keeps its existing wire messages and stores no completion metadata.

The host signs one reference covering the network/root pin, host key, candidate
key, original request ID, name, comparison code and host session endpoint. It
reserves that reference in its sealed profile before issuing the invitation.
The client validates it against the original authenticated ceremony and saves it
before enrollment. References contain no invitation, operator credential or key.

After fresh core trust and an authenticated candidate session proof, the host
atomically saves the relationship, the candidate endpoint and a binding to that
original reference. A reservation is not completion. An ordinary relationship
write clears its prior binding, even when it writes identical values. Removing a
peer also clears the binding; historical references do not recreate that peer.

The profile retains at most 32 host references. Ambiguous identities, invalid
proofs, conflicting bindings and substituted endpoints refuse on open. Legacy
profiles omit these optional fields and gain no evidence merely by opening.
Opt-in qualification profiles are not a downgrade format for older apps.

## Explicit recovery

`inspect_pairing_completion` is read-only with respect to relationships. It
requires the saved reference, original enrolled key/certificate, original
transport key and saved authority-host route. It never renews membership.

A fixed readback operation uses the existing mutually authenticated authority
bridge, bound to a fresh challenge and the exact reference. The native host
checks fresh core trust for itself and that authenticated client, its retained
committed evidence, active binding and exact peer endpoint. It cannot approve,
invite, enroll, restore or select an authority through this operation.

`finish_pairing_completion` is a separate explicit local action. It repeats
readback, proves the original host over QUIC using the existing client transport,
and repeats fresh readback/trust checks before one atomic local relationship
commit. Earlier inspection replies are not reusable permissions. Repeating the
explicit action checks current evidence and trust again before reporting an
already-completed local result.

Missing/unavailable, reserved, superseded, conflicting, expired or revoked state
remains refused or uncertain. No path replaces keys, reconstructs approval from
membership, repeats enrollment, automatically finishes, or attributes later
matching state to an old unobserved click. The existing read-only pending
membership inspector is separate and unchanged.

## Repeatable validation

The focused Android owner workflow explicitly selects proof, vault, gate and
disposable embedded-core/QUIC tests. The recovery fixture target is
`crates/connect-core/tests/pairing_completion_recovery.rs`; it requires the core
feature above and `CONNECT_FOREGROUND_FIXTURE_PYTHON` pointing to an environment
installed from the existing authority requirements file. Run that target with
`--ignored` only when intentionally qualifying disposable host fixtures.

Coverage includes final-reply loss, both profiles reopening without new
issuance, explicit-only finish, idempotent finish, unavailable readback, legacy
missing references, reserved approval plus matching graph, superseded identical
relationships, and fresh client/host revocation. Source tests cover tampering,
wrong scope, stale challenges, ambiguous retained history and the default-off
gate.

These are host/source checks. They do not qualify a phone lifecycle, the public
app journey, human comparison-code review, backup/recovery after device loss, or
independent audit evidence. No hosted CI, device installation or deployment is
implied by a local pass.
