# Connect capability inventory

This directory tracks **classification**, not implementation or full product
parity. Do not use the number of routes as a user-feature denominator.

- `core-public-surface.json`: exact bytes from the released immutable core
  revision in `core-source.json`. Internal routes are retained for drift review
  but excluded from the public outcome count.
- `core-source.json`: repository, release, immutable commit and SHA-256 provenance.
- `connect-journeys.json`: reviewed exact operation lists, declaration fingerprints,
  reference fingerprints, manual/assisted and platform status, prerequisites,
  actor/approval/retry boundaries, schema gaps and evidence accounting.
- `connect-coverage.json`: generated inventory. The readable generated report is
  `docs/capability-coverage.md`.

The public contract lists HTTP paths/methods and Python call signatures, not
complete HTTP/CLI request/response value schemas. Typed operation work must
derive and test those separately. The inventory enables no runtime dispatch.

## Check and regenerate

```sh
node scripts/connect-contract.mjs check
node --test scripts/tests/connect-contract.test.mjs
node scripts/connect-contract.mjs verify-upstream
```

No package install, authority keys, Python environment or running authority is
needed for these checks. `verify-upstream` reads only the public immutable GitHub
revision and refuses different bytes. Local `check` is deterministic and offline.
The Windows verification script and the Windows/Linux CI matrix run the local
gate. The CI definition additionally verifies upstream provenance; adding the
definition is not a claim that a hosted CI run has executed.

## Review an upstream update

1. Read the Renovate dependency change and qualify the core/SDK combination.
2. Obtain the candidate released public contract into an ignored local file.
   Compare **before** replacing the reviewed snapshot:

   ```sh
   node scripts/connect-contract.mjs compare temp/candidate-public-surface.json
   ```

3. Review every added, removed and changed operation/signature, reference rule,
   error vocabulary and package support declaration. Update the exact journey
   assignment and relevant schema, permission and acceptance requirements.
4. Record the immutable released source revision/digest; replace the snapshot
   with the exact reviewed bytes. Update only the affected reviewed declaration
   and reference fingerprints after reviewing their semantic changes. Do not
   derive acceptance from matching IDs or blindly accept all fingerprints.
5. Run `node scripts/connect-contract.mjs generate`, review its diff, then rerun
   all checks. LF attributes preserve the source digest across Windows checkout.
6. Run dependency, authority, application and affected platform/workflow gates.

A new public operation is never automatically classified by a path prefix. A
renamed/removed mapping, stale lockfile, altered declaration or stale generated
output fails. Verified outcomes require both manual and assisted acceptance,
schemas, automated/physical evidence and no open acceptance gaps. References are
validated for existence and public repository location; these structural checks
do not execute a referenced test or establish physical/usability acceptance.

All upstream error codes and package/rule declarations are retained separately.
Their presence is not proof that every error has a guided recovery action.
