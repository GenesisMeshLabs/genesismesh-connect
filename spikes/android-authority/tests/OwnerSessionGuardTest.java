package org.genesismesh.connect.authority;

import java.util.UUID;

public final class OwnerSessionGuardTest {
    private static void refused(Runnable operation) {
        try { operation.run(); } catch (RuntimeException expected) { return; }
        throw new AssertionError("Unqualified session operation accepted");
    }
    public static void main(String[] args) {
        OwnerSessionGuard guard = new OwnerSessionGuard();
        String session = UUID.randomUUID().toString();
        refused(() -> guard.reserve(session, 1));
        guard.begin(session);
        refused(() -> guard.begin(session));
        refused(() -> guard.begin(UUID.randomUUID().toString()));
        refused(() -> guard.reserve(UUID.randomUUID().toString(), 1));
        refused(() -> guard.reserve(session, 2));
        guard.reserve(session, 1);
        refused(() -> guard.reserve(session, 1));
        guard.reserve(session, 2);
        guard.released(session); // Not stopped yet: a live session is never released.
        refused(() -> guard.begin(UUID.randomUUID().toString()));
        guard.stop();
        if (guard.current(session) || !guard.belongs(session)) throw new AssertionError("Stopped scope changed");
        refused(() -> guard.reserve(session, 3));
        // Stopped but not closed: the owner may still hold storage.
        refused(() -> guard.begin(UUID.randomUUID().toString()));
        guard.released(UUID.randomUUID().toString()); // Another session's close changes nothing.
        refused(() -> guard.begin(UUID.randomUUID().toString()));
        guard.released(session);
        refused(() -> guard.begin(session)); // The closed session's identity is never reused.
        String next = UUID.randomUUID().toString();
        guard.begin(next);
        if (!guard.current(next) || guard.belongs(session)) throw new AssertionError("New session scope wrong");
        refused(() -> guard.reserve(next, 2));
        guard.reserve(next, 1); // Sequences restart with the new session.
    }
}
