# Restoring a network safely: proposal

Status: needs decisions from the Maintainer. Nothing here changes trust
behaviour yet.

Journey 6 asks that a network can be restored onto another device, that missing
history is explained, and that an old host and a restored host cannot operate as
competing copies. This note records what restore does today, a defect found
while testing it, and the options.

## What restore does today

A recovery file holds the network computer's identity and its authority as they
were when the file was saved (`crates/connect-core/src/recovery.rs`). Restore
brings exactly that back on another device: the same root, the same signing
keys, the same device identity. Nothing after the file was saved is in it.

Since this change, the restore screen and the result say when the file was
saved, that devices which joined later must join again, that devices removed
later may have access again, and that the old device must not run the network
again. That is advice only; nothing enforces it.

## Defect: devices that saw a later removal refuse the restored network

Every device keeps a checkpoint of the newest revocation list (CRL) it has
verified, and refuses an older one as a rollback
(`crates/connect-core/src/authority/store.rs`). Restoring from a file saved
before a removal brings back an authority whose revocation list is older than
what the network's devices have already seen.

Measured with the real authority
(`devices_that_saw_a_later_removal_refuse_a_network_restored_from_an_older_file`
in `crates/connect-core/tests/owner_runtime.rs`):

| Step | Revocation list sequence |
| --- | --- |
| Recovery file saved | 0 |
| A device removed on the old network; another device refreshes | 1 seen by that device |
| Network restored from the file | 0 |
| Devices refresh against the restored network | Refused: "CRL rollback", both the device that saw the removal and the removed one |

Refusing is the safe outcome: a device never trusts an older view of the network
without noticing. But the journey breaks: those devices cannot use the restored
network, nothing explains why, and the restored authority's next revocation list
would reuse sequence 1 with different contents, which devices treat as
equivocation. The existing restore tests did not see this because they restore
straight after saving the file.

## Competing copies

If the device the file came from is switched on again, both copies hold the same
keys and identity. Devices accept documents from either; each can issue
certificates and revocations the other does not know.

## Options

**A. Explain and fail closed (done in this change, interim).** Advice on the
restore screen and in the result; devices that refuse say so. Devices that saw a
later removal must leave and join again with a new invitation.

**B. Catch up from what devices hold.** Devices keep the newest signed revocation
list they verified. It is signed by the network's own key, so a restored network
computer can ask its devices for it, check the signature, take in the
revocations it lacks, and issue its next list above that sequence. Removals made
after the file was saved are then kept, and devices accept the restored network.
Needs an authority operation to adopt a verified list from the same network,
which core does not offer today.

**C. Jump the sequence, lose later removals.** The restored authority issues its
next revocation list well above any sequence the old one could have reached.
Devices accept it, but removals after the file are lost until the owner removes
those devices again (the restore result already asks the owner to check
Devices). Needs the authority to issue a list at a chosen sequence.

**D. Fence the old copy with a key succession.** On restore, the restored
network performs a core key succession: a new signing key vouched for by the
old one. Devices that see the succession refuse documents signed only by the
superseded key (`minimum_key_sequence` in the trust store), so an old copy
started later is refused by every device that has heard from the restored one.
Core already verifies successions on devices; Connect would need the owner
runtime to perform one at restore.

**E. Check before serving.** Before the restored copy starts serving, it tries
to reach the old network computer by its identity and refuses to continue while
that answers. Cheap, but it cannot detect a copy that is switched off now and on
later, so it only complements D.

## Recommendation

D to fence competing copies, B to keep later removals (C as a stopgap if B needs
core work first), E as an early warning, and A until then.

## Decisions needed

1. Is a key succession on every restore acceptable (D)? It changes what devices
   trust and is the same kind of decision as the renewal policy.
2. Catch up from devices' signed lists (B, needs a core operation) or jump the
   sequence and lose later removals (C)?
3. Should restore refuse to continue while the old network computer still
   answers (E), or only warn?
