package org.genesismesh.connect.authority;

import java.util.UUID;

/** One process session; reservation precedes Python execution. No replay/reset API. */
public final class OwnerSessionGuard {
    private static final long MAX_SEQUENCE = (1L << 53) - 1;
    private String session;
    private long next = 1;
    private boolean stopped;

    public synchronized void begin(String id) {
        if (stopped || session != null || id == null || !UUID.fromString(id).toString().equals(id)) {
            throw new IllegalStateException("Restart the qualification app before another owner session.");
        }
        session = id;
    }

    public synchronized void reserve(String id, long sequence) {
        if (stopped || session == null || !session.equals(id) || sequence != next || next > MAX_SEQUENCE) {
            throw new IllegalStateException("Stale or repeated owner operation.");
        }
        next++;
    }

    public synchronized boolean current(String id) { return !stopped && session != null && session.equals(id); }
    public synchronized boolean belongs(String id) { return session != null && session.equals(id); }
    public synchronized void stop() { stopped = true; }
}
