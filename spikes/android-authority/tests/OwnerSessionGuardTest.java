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
        refused(() -> guard.reserve(UUID.randomUUID().toString(), 1));
        refused(() -> guard.reserve(session, 2));
        guard.reserve(session, 1);
        refused(() -> guard.reserve(session, 1));
        guard.reserve(session, 2);
        guard.stop();
        if (guard.current(session) || !guard.belongs(session)) throw new AssertionError("Stopped scope changed");
        refused(() -> guard.reserve(session, 3));
        refused(() -> guard.begin(UUID.randomUUID().toString()));
    }
}
