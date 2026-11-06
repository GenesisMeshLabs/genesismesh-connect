package org.genesismesh.connect.authority;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/** Independent read-session reservations. Never resets/reuses the writer's guard. */
public final class RecoveryInspectionGuard {
    private final Set<String> seen = new HashSet<>();
    public synchronized void reserve(String id, long sequence, OwnerSessionGuard writer) {
        if (id == null || !UUID.fromString(id).toString().equals(id) || sequence != 1
                || writer.belongs(id) || seen.size() >= 64 || !seen.add(id)) {
            throw new IllegalStateException("Use a fresh bounded recovery inspection session.");
        }
    }
}
