# Protected-read acceptance: software and physical devices

Updated 2026-10-26. The Windows test suite uses real authority routes, SDK
verification and real QUIC, with both identities on one computer. This does not
pass the physical Windows/iPhone acceptance gate.

## Current status and remaining blockers

The newer guided consumer workflow adds Windows authority setup, expiring
owner-approved pairing, iOS Keychain storage and authorized file pages. Nine
real-authority integration tests pass, including pairing and listing denial;
the iOS target compiles and passes Clippy. These changes do not yet establish
physical iPhone pairing, Keychain persistence or protected browsing. The
installation below records the earlier build until superseded by verified
consumer archive/install evidence. See [everyday workflow](everyday-workflow.md).

The updated workspace UI (0.1.0, build 2) is now signed, installed and launched
on the physical iPhone. Its signature/profile and all 18 generated Genesis
Mesh icon sizes verify. This installation does not pass enrolled protected-read
acceptance. The operator also reports public relay communication in both
directions; no new independent path/latency measurements were supplied.

- Mac access was restored after the earlier timeout. The existing authorized
  SSH alias works, Xcode 27.1 is available and the paired iPhone is listed as
  available. The current unsigned physical-iPhone archive now builds and its
  Mach-O platform is iOS. See [the build notes](iphone-spike.md).
- Signing setup is now complete and Connect is installed on the physical iPhone.
  The signature verifies; its unexpired profile matches the app and includes the
  connected phone. After the user's developer-trust approval, app launch and the
  running process were verified. The phone UI shows a running transport endpoint;
  its first probe to Windows timed out. A Windows-initiated round trip to the
  physical iPhone subsequently passed: 13 bytes in 373 ms on an Iroh direct
  path, with public relays disabled. The user also reported phone-initiated
  success, with one incoming probe observed on Windows. Physical lifecycle
  checks remain pending; the diagnostic is not Genesis Mesh authenticated.
- Windows DPAPI and iOS device-only Keychain storage are implemented. The older
  installed build below predates Keychain enrollment. Physical testing of the
  new Keychain/pairing workflow remains required; connectivity alone does not
  establish persistent enrollment or protected reads.

Next: install the consumer build, verify Keychain persistence and complete
pairing/browsing and remaining lifecycle checks with a disposable authority and dedicated
test folder for the matrix below. No real user files or operator private keys
belong in the app.

## Acceptance matrix

| Scenario | Same-host software evidence | Physical Windows/iPhone |
| --- | --- | --- |
| Allowed text and 64 KiB binary read | Live-authority test checks payload/digest and signed client acknowledgment | Pending |
| Unknown collection/path/ADS | Refused; payload-release counter unchanged | Pending |
| Authority policy denies selected peer/collection | Refused; payload-release counter unchanged; reactivation permits a fresh read | Pending |
| Host attestation revoked | Live authority refuses; payload-release counter unchanged | Pending |
| Selected peer's certificate revoked | Host's fresh trust refuses the old credential; payload-release counter unchanged | Pending |
| Current expected digest no longer matches | Refused before file release | Pending |
| Receipt storage unavailable | Refused before file release | Pending |
| Authority unavailable before release | Refused; payload-release counter unchanged | Pending |
| Host suspension while authority decision is pending | Test rendezvous pauses real route, host suspension closes operation before release; explicit refresh and fresh read recover | Pending |
| Session proof replay on another connection | Existing QUIC/exporter negative test refuses captured proof | Pending |
| Phone locks/backgrounds or network changes during payload | Not established by the pre-authorization interruption test | Pending |
| Lost final acknowledgment/receipt and app restart | Prepared and client-verified claims differ; no durable request-result recovery workflow yet | Pending |
| Revocation after payload release begins | Five-second release/per-chunk validity checks implemented; measured cutoff under actual transfer is pending | Pending |

The software payload counter counts file bytes queued through the server send
path; metadata, authentication traffic and denial frames are not file data.
Client errors alone are insufficient evidence of zero release. Assertions compare
the host counter before and after each tested pre-release refusal. Physical tests
must retain both the host measurement and a client observation that no payload
frame was accepted. Network encryption means an ordinary packet capture alone
does not identify application file bytes.

## Run and record physical cases

1. Record source/build hashes on both devices, authority revision, SDK lock,
   OS/app versions, network conditions and whether the path is direct or relayed.
   The current authenticated endpoint disables public relays; remote/cellular
   operation needs explicit implementation/configuration and separate validation.
2. Use fresh disposable host/client identities. The host needs its local edge
   invite, host-bound attestation and exact peer/collection policy. Create known
   test files with recorded size and SHA-256. Keep the genuine device vaults
   unchanged. Follow [protected-read setup](protected-read.md).
3. Establish an allowed baseline. Retain the authority decision, prepared and
   client-verified receipts, verified client byte count/digest and host release
   measurement. Existing public library counters support the host integration
   harness; exposing suitable redacted diagnostic measurements on the physical
   app is still required. Do not claim a current physical zero-byte result.
4. Independently run the denial cases above. Reset measurement baselines for
   each case. Distinguish a revoked certificate from a revoked node: revoke all
   active credentials to test whole-device exclusion. The software test also
   demonstrates that a separately renewed, unrevoked credential remains valid;
   this is certificate-specific behavior, not compromise recovery.
5. Interrupt before authorization, during payload, before client acknowledgment
   and after acknowledgment but before final confirmation. Record the last
   persisted stage. A late failure may follow released bytes. Do not automatically
   reuse a stale allow decision, report success, or label every error zero-byte.
6. Reopen/reconnect with current trust and perform an explicit fresh read with
   an expected snapshot digest. A changed file must refuse that version. Until
   resume/result lookup exists, label it a new read, not continuation or exactly
   once delivery. Host restart leaves sharing disabled until reconfigured.

Run `scripts/verify.ps1` for the software gate. Test results and environment
measurements belong in ignored `temp/` notes, with public summaries excluding
private keys, invites, user files and device identifiers.
