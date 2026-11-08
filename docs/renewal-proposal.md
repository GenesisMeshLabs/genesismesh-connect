# Certificate renewal: decision proposal

Status: **proposal; nothing here is implemented or agreed.** The documented
freshness policy in the [authority spike](authority-spike.md) stays in force
until the owner decides. Written 8 November 2026 from the phone runs recorded in
[plan progress](plan-progress.md).

## What happens today

- A session accepts a certificate issued less than **300 seconds** ago, checked
  for each side (`session/trust.rs`).
- A device renews when its certificate is at least **240 seconds** old
  (`EnrolledDevice::renewal_due`). The app checks every 30 seconds, so a renewal
  happens about every 4 minutes for as long as Connect runs.
- Before renewing, the device **suspends** its session endpoint and, on the
  network computer, its bridge host (`DeviceController::refresh_inner`), for as
  long as the renewal takes. The new certificate is saved, then the endpoint is
  refreshed with it and resumes.
- **Every** trust refresh, renewal or not, replaces the endpoint's credentials
  (`SessionEndpoint::refresh`), and that ends exchanges in flight ("Trust changed
  during read"). This happens every 30 seconds; since #36 and #40 a read cut this
  way is asked again.
- Revocation reaches other devices through the CRL in the trust snapshot, which
  must have been observed less than 60 seconds ago. Removing a device revokes all
  of its certificates at once. The 300-second issue age is a backstop: it bounds
  how long a certificate stays usable when a revocation has not reached a peer's
  snapshot.

## What it costs, measured

| Observation | Source |
| --- | --- |
| The phone's authority issued 196 certificates to the phone in 18.7 hours; its database, all tables, was about 12 MB | Phone owner build, 7 November |
| Renewals 241 to 242 seconds apart, on screen and across a close and return | `f69c055`, `df84d82` |
| In five restart cycles, 6 reads failed "Connection is suspended" and 2 "session ended". Renewals, refreshes and the restarts themselves all suspend or end sessions; which caused each failure was not recorded | `7b060bd` |

The authority spike already says: "The frequent renewal policy also needs load
evaluation before deployment." That evaluation has not been done.

## Options

### A. Keep the policy as it is

No change. Every running device asks the network computer for a certificate
every 4 minutes, and suspends its sessions while it waits for the answer.

### B. Renew without suspending first (the policy is unchanged)

Renew while the current certificate is still valid, then swap to the new one,
without suspending first. The current certificate has 60 seconds left when
renewal starts, so sessions can keep using it until the new one is saved.
Failure handling stays as it is: a failed renewal or trust check still suspends,
and a certificate past 300 seconds is still refused.

- Gains: no suspended window during each renewal's round trip, so new reads
  started in that window no longer fail "Connection is suspended". The window is
  usually short; on a slow or restarting network computer it lasts up to the
  15-second bridge deadline.
- Unchanged: the 300-second limit, the 240-second renewal point, the number of
  certificates issued, the database growth, and the cut of exchanges in flight
  at every refresh.
- How much this helps has not been measured. It should be measured on the phone
  before and after, as the earlier changes were.

### B2. Let an exchange in flight finish across a refresh (changes the policy)

The authority spike says a refresh "invalidates in-flight diagnostic exchanges".
An exchange could instead finish under the credentials it started with, as long
as its certificate is within its 300 seconds and the new snapshot does not
revoke it. This would stop the cut every 30 seconds, but it changes a documented
rule, so it is a decision, not a fix.

### C. A longer issue-age limit (changes the policy)

For example, a 15-minute limit with renewal at 12 minutes, or an hour with
renewal at 50 minutes.

- Gains: 3 or 12 times fewer certificates and database rows; fewer swaps.
- Cost: the backstop window grows from 5 minutes to the new limit. Revocation
  through the CRL is unchanged, but a certificate whose revocation has not reached
  a peer stays usable longer. This is a security decision.

### D. Prune old issued certificates on the authority

This is outside Connect: it belongs to the core's authority. It limits database
growth under any of A to C, and needs its own core decision on retention.

## Recommendation

**B first.** It keeps every documented limit, removes the suspended window
during each renewal, and can be measured on the phone the same way as the earlier
changes. Its gain may be small, because the cut at every refresh stays. Decide
**B2** and **C** separately, as decisions about documented rules, with B's
results in hand. Raise **D** with the core if database growth matters for a phone
that runs for weeks.

## Decisions needed from the owner

1. May B be implemented under the current policy?
2. Should B2 be considered: may an exchange already in flight finish across a
   refresh under the credentials it started with?
3. Should C be considered at all, and if so, which window is acceptable?
4. Should D go to the core?
