# Typed resource operations

`connect_core::operations` is a closed registry of implemented Connect operations.
Its descriptors name the operation class, resource-host actor requirement,
member-device key tier, execution location, approval, retry and evidence limits.
It does not accept arbitrary core routes, administrator URLs, key paths or shell
commands. It does not enable an assistant or give membership administrative power.

The initial entries discover a resource's prerequisites, inspect its access and
review/commit an access change. The live Tauri handlers consume the registry's `ResourceQuery`,
`AccessReviewInput` and `AccessCommitInput` types. Commit receives only a stored
review ID and digest; the [access workflow](access-workflow.md) resolves current
identity, policy and approval context separately. A future assisted entry point
must use the same native operation types and execution path. The registry marks
assistance unavailable today.

The generated [JSON contract](../contract/connect-operations.json) links each
operation to its actual input, preview, commit and output schemas. Schemas derive
from the Rust/Serde types using the optional build-time `operation-schemas`
feature and [Schemars](https://docs.rs/schemars/1.2.3/schemars/). Normal application
builds do not need the generator. Object shapes deny unexpected fields and carry
numeric/collection limits. SDK strict parsing additionally refuses duplicate JSON
keys in proposed operation envelopes.

Schema shape is only one validation layer. Current ownership, pinned identity,
expiry, version comparisons, encoded byte limits and core gate semantics remain
native/core checks. Possessing a schema or parsing a proposal never authorizes
execution. Extra gate JSON remains a core-validated field; these schemas are not
the planned general visual policy editor.

Explicitly regenerate after reviewing type/semantics changes:

```sh
cargo run -p connect-core --features operation-schemas \
  --example operation_contract --locked -- generate
cargo test -p connect-core --features operation-schemas \
  --test operation_registry --locked
```

The example's default `check` mode and the test refuse stale output without
rewriting it. CI and the Windows verification script include the test. The
broader public-core inventory remains a separate outcome map; these initial
typed resource operations do not establish full CONNECT-02 coverage.
