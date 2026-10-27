# Share apps and services

On the device running a service, open **Shared → App or service**. Choose a
preset (web app, Home Assistant, Jellyfin, Plex, development site, SSH or custom
TCP), name it, check its port under **Connection details**, and select the
devices allowed to use it. The service must already be running on this device
and listening on IPv4 loopback (`127.0.0.1`). Connect does not install it.

On an allowed device, find the resource under **Apps & services**. Web apps
have **Open app**. SSH and custom TCP have **Connect**, which supplies a local
address to copy into the appropriate client. **Close connection** stops that
local listener and its active streams. The service's own login still applies.

Web apps open outside the privileged Connect interface: an external browser on
desktop, a native browser view on iOS, and a separate WebView without the Tauri
bridge on Android. HTTP is permitted for the loopback tunnel; traffic between
devices uses authenticated, encrypted Iroh connections. The mobile exception is
scoped to loopback, following the [Android network configuration](https://developer.android.com/privacy-and-security/security-config)
and [Apple ATS IP exceptions](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowslocalnetworking).

## Maintain access in Connect

On a resource shared by this device, choose **Manage → Manage access**. The
editor changes the actual Genesis Mesh policy at the network authority:

- Choose allowed devices and an optional expiry.
- Set a whole-file size limit, or the combined byte budget for a service session.
- Set service session duration, up to one hour.
- Expand additional rules to edit Genesis Mesh gate JSON. Existing custom rules
  are retained; invalid rules and attempts to replace the resource's reserved
  scope gates are rejected.

Changes create a new policy version. If another edit changed the version first,
reopen the editor before saving. Only the device that shared the resource can
edit it through this interface. Recipient identities are validated by native
code and the authority bridge. Policy renewal preserves custom rules and the
explicit expiry. This is a resource access editor, not unrestricted authority
administration or a complete visual editor for every core gate.

Every service connection requires mutual device authentication, a fresh signed
`connect.service.connect` decision, and a host-signed authorization receipt
before the host opens its configured port. The peer cannot choose the target
address or port. The network authority port cannot be shared. Access is checked
again at most ten seconds later, or sooner when the decision expires; forwarding
pauses during the check. Denial, expired credentials or an unavailable authority
ends the stream. A receipt proves authorization, not application-level delivery.

## Scope and current limits

- TCP only. There is no UDP forwarding, system VPN, embedded SSH terminal,
  service installation or mobile background service.
- Web presets forward HTTP bytes. Apps with absolute URLs, fixed Host headers,
  external login redirects or HTTPS-only listeners may need their own URL
  configuration or a suitable TCP client. Presets are convenience defaults,
  not certification that every version of those products works unchanged.
- Keep Connect running on both devices. Phones may suspend connections when
  backgrounded; opening a separate SSH client can trigger this restriction.
- Eight open local listeners, eight connections per listener, and a maximum
  one-hour lifetime per listener/session. Reopen after expiry. Byte limits count
  both directions per TCP connection, not a daily allowance across connections.
- Local listeners bind only loopback. Other applications on that same device
  can use them while open; the permission boundary is the approved device.
- Service resources use a separate protocol/discovery operation. Older clients
  can continue browsing files but do not list or open services.

## Verification

The automated live-authority test uses two authenticated Iroh endpoints and a
real local TCP echo service. It checks successful bytes, refusal of a wrong
resource or kind before dialing, authority-port rejection, denial of a new
connection, and termination of an active connection after policy changes.
Owner tests cover policy versions, expiry, limits and custom-rule preservation.
UI tests use mocked native commands on desktop and phone viewports; those are
not physical-device service acceptance. Platform builds and installation are
reported separately.
