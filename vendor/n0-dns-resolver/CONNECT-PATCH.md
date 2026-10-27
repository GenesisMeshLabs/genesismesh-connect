# Temporary iOS system resolver patch

Vendored from crates.io n0-dns-resolver 0.1.0, upstream commit
16a791ce8cfd6456518970872ba3251b0756112d. Upstream project:
https://github.com/n0-computer/n0-dns-resolver. MIT/Apache licenses retained.

0.1.0 selects macOS DynamicStore APIs for all Apple targets. Those symbols do
not link in the physical iOS archive. This patch limits that backend/dependency
to macOS and obtains iOS nameservers (including IPv6 scope/port), search domains
and ndots with the public SDK res_ninit/res_getservers/res_ndestroy calls in
libresolv. A C shim uses the SDK's own resolver-state ABI, bounds all output and
destroys initialized state on every exit. It sends no DNS query.

The resolver's existing fallback behavior is unchanged; no new public resolver
or lookup policy is added. Split-DNS/network-change and physical runtime behavior
still need device validation. This reads a primary resolver configuration, not
all VPN/per-domain resolver policy. Do not claim full system-resolver parity.

Changes: target dependency selection, iOS module, C shim, build script and cc
build dependency. Unit tests cover IPv4/IPv6 scope, malformed and bounded output.
The Apple-host C check is `cc src/system_config/ios_resolv.c
tests/ios_resolv_host.c -lresolv -o <temporary-output>`, then run that executable.
It validates real host configuration and buffer boundaries without printing the
DNS configuration or sending queries; it is not an iPhone runtime result.
Remove this path patch after an upstream iOS implementation is released and
validated. No upstream issue/PR was created by this local patch.
