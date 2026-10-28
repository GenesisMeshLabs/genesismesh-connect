# Help and advanced tools

Open **Settings → Advanced → Open advanced tools**. Start here offers tasks
rather than manual setup forms. When setup, a disconnected device or unfinished
cleanup needs attention, a suggested next action leads back to Connect.
The help header describes this device's overall network state. Manual session
readiness is shown only inside the expert device setup page; it does not establish
that the authority or a shared resource is available.

## Fix a connection

1. Keep Connect open on both devices and the computer running the network.
2. Choose the saved device directly in Connection help. Use Devices to add or
   rename one, or Settings to reconnect this device.
3. Choose **Check saved device**. The result explains what happened and the next
   step. A successful check confirms the encrypted round trip and device
   identity; each file or service request still evaluates its own policy.

Timeouts and a network connection refusal are distinct from rejected identities
and expired credentials. Technical error details stay collapsed. Changing the
selected device or network clears the earlier result; an in-flight result from
the previous selection is discarded. A selected device can be checked even when
its connection is not currently ready, allowing the native reconnect path.

## Understand access

Access help explains joining, resource sharing and request-time checks. To edit
a resource, return to **Shared → Manage → Manage access** on its sharing device.
Review or remove devices from the everyday Devices screen. Identity and trust
details remain available for inspection; changing an authority route requires
opening a separate expert editor.

## Review technical activity

This view contains up to 50 checks and manual operations from these tools in the
current app session. **Show needs attention** filters failures. The list resets
when the app closes. Everyday sharing and sends are not shown here; this view is
not the authority audit ledger or an inventory of all signed receipts.

## Expert tools

The expert menu is collapsed on entry and when returning to Start here. Existing
manual identity/enrollment, session tickets, authority routing and protocol tests
remain available with their original native checks. Opening a help page does not
create an identity, enroll, change a route, or start a diagnostic endpoint.

The legacy file test is limited to its original small-file protocol. Use Shared
for normal browsing and larger transfers. The raw connection test requires
manual ticket exchange and checks reachability without authenticating a Genesis
Mesh device. Connection help is the first path for enrolled, saved devices.

The back bar, logo and phone Back gesture return to Connect. Task links return
to Shared, Devices or Settings without exposing public-key fields. Desktop and
phone browser tests exercise these flows with mocked native commands; native
installation and physical-device acceptance remain separate.
